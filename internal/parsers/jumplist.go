package parsers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Jump lists record the files a user opened with each application. There are
// two kinds. AutomaticDestinations files are OLE compound files holding one
// shortcut per entry plus a DestList stream that says when each was last
// used. CustomDestinations files are shortcuts written one after another.
// Either way each entry is evidence that a file or folder was opened.

type jumpListParser struct{}

func (jumpListParser) Name() string { return "jump-list" }
func (jumpListParser) Version() string {
	return "4 (native: compound file, DestList, shell links; known folders and applications named)"
}

const jumpListMax = 256 << 20

// ------------------------------------------------- compound file (CFB) ----

type cfb struct {
	data     []byte
	sector   int
	fat      []uint32
	miniFAT  []uint32
	mini     []byte // the mini stream, held by the root entry
	miniSize int
	cutoff   uint32
	streams  map[string][2]uint32 // name -> start sector, size
}

const cfbEnd = 0xFFFFFFFE

func (c *cfb) at(sector uint32) []byte {
	off := (int(sector) + 1) * c.sector
	if off < 0 || off+c.sector > len(c.data) {
		return nil
	}
	return c.data[off : off+c.sector]
}

// chain reads a stream by following its sectors in the allocation table.
// The length of every chain is bounded by the size of the file, so a table
// that points round in a circle ends in an error instead of a loop.
func (c *cfb) chain(start uint32, size int) ([]byte, error) {
	var out []byte
	limit := len(c.data)/c.sector + 1
	for s, n := start, 0; s < 0xFFFFFFFA; n++ {
		if n > limit || int(s) >= len(c.fat) {
			return nil, errors.New("compound file allocation chain is damaged")
		}
		b := c.at(s)
		if b == nil {
			return nil, errors.New("compound file sector lies outside the file")
		}
		out = append(out, b...)
		if size >= 0 && len(out) >= size {
			break
		}
		s = c.fat[s]
	}
	if size >= 0 && len(out) > size {
		out = out[:size]
	}
	return out, nil
}

func (c *cfb) miniChain(start uint32, size int) ([]byte, error) {
	var out []byte
	limit := len(c.mini)/c.miniSize + 1
	for s, n := start, 0; s < 0xFFFFFFFA && len(out) < size; n++ {
		off := int(s) * c.miniSize
		if n > limit || int(s) >= len(c.miniFAT) || off+c.miniSize > len(c.mini) {
			return nil, errors.New("compound file mini stream is damaged")
		}
		out = append(out, c.mini[off:off+c.miniSize]...)
		s = c.miniFAT[s]
	}
	if len(out) > size {
		out = out[:size]
	}
	return out, nil
}

func openCFB(data []byte) (*cfb, error) {
	le := binary.LittleEndian
	if len(data) < 512 || !bytes.Equal(data[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
		return nil, errors.New("not a compound file")
	}
	shift, miniShift := le.Uint16(data[30:]), le.Uint16(data[32:])
	if (shift != 9 && shift != 12) || miniShift != 6 {
		return nil, errors.New("compound file has unsupported sector sizes")
	}
	c := &cfb{data: data, sector: 1 << shift, miniSize: 1 << miniShift, cutoff: le.Uint32(data[56:]), streams: map[string][2]uint32{}}
	// The header lists the first 109 sectors of the allocation table; more
	// are listed in a chain of DIFAT sectors.
	var fatSectors []uint32
	for i := 0; i < 109; i++ {
		if s := le.Uint32(data[76+i*4:]); s < 0xFFFFFFFA {
			fatSectors = append(fatSectors, s)
		}
	}
	per := c.sector/4 - 1
	for s, n := le.Uint32(data[68:]), 0; s < 0xFFFFFFFA; n++ {
		b := c.at(s)
		if b == nil || n > len(data)/c.sector {
			return nil, errors.New("compound file DIFAT is damaged")
		}
		for i := 0; i < per; i++ {
			if x := le.Uint32(b[i*4:]); x < 0xFFFFFFFA {
				fatSectors = append(fatSectors, x)
			}
		}
		s = le.Uint32(b[per*4:])
	}
	for _, s := range fatSectors {
		b := c.at(s)
		if b == nil {
			return nil, errors.New("compound file allocation table lies outside the file")
		}
		for i := 0; i+4 <= len(b); i += 4 {
			c.fat = append(c.fat, le.Uint32(b[i:]))
		}
	}
	dir, err := c.chain(le.Uint32(data[48:]), -1)
	if err != nil {
		return nil, err
	}
	if mf := le.Uint32(data[60:]); mf < 0xFFFFFFFA {
		raw, err := c.chain(mf, -1)
		if err != nil {
			return nil, err
		}
		for i := 0; i+4 <= len(raw); i += 4 {
			c.miniFAT = append(c.miniFAT, le.Uint32(raw[i:]))
		}
	}
	for i := 0; i+128 <= len(dir) && i/128 < 100000; i += 128 {
		e := dir[i : i+128]
		nameLen := int(le.Uint16(e[64:]))
		if nameLen < 2 || nameLen > 64 {
			continue
		}
		u := make([]uint16, nameLen/2-1)
		for j := range u {
			u[j] = le.Uint16(e[j*2:])
		}
		name := string(utf16.Decode(u))
		start, size := le.Uint32(e[116:]), le.Uint32(e[120:])
		switch e[66] {
		case 5: // root entry: its stream is the mini stream
			if start < 0xFFFFFFFA {
				if c.mini, err = c.chain(start, int(size)); err != nil {
					return nil, err
				}
			}
		case 2:
			c.streams[name] = [2]uint32{start, size}
		}
	}
	return c, nil
}

func (c *cfb) stream(name string) ([]byte, error) {
	s, ok := c.streams[name]
	if !ok {
		return nil, errors.New("no such stream")
	}
	if s[1] > uint32(len(c.data)) {
		return nil, errors.New("stream is larger than the file that holds it")
	}
	if s[1] < c.cutoff {
		return c.miniChain(s[0], int(s[1]))
	}
	return c.chain(s[0], int(s[1]))
}

// ------------------------------------------------------------ DestList ----

type destEntry struct {
	number   uint32
	modified uint64
	pinned   bool
	path     string
	host     string
	count    uint32
}

// parseDestList reads the index of an AutomaticDestinations jump list. The
// layout changed between Windows 7 (version 1) and Windows 10 and 11
// (versions 3 to 6): later versions have a longer fixed part, and after each
// path a four-byte length followed by that many bytes of properties. The
// length is usually zero, but entries for web addresses and some
// applications carry several kilobytes there (seen in real Windows 11 files).
func parseDestList(b []byte) ([]destEntry, uint32, error) {
	le := binary.LittleEndian
	if len(b) < 32 {
		return nil, 0, errors.New("DestList stream is truncated")
	}
	version := le.Uint32(b)
	fixed, trailer := 114, 0
	if version >= 2 {
		fixed, trailer = 130, 4
	}
	var out []destEntry
	for off := 32; off+fixed <= len(b) && len(out) < 100000; {
		e := b[off:]
		n := int(le.Uint16(e[fixed-2:]))
		if off+fixed+n*2 > len(b) {
			break
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = le.Uint16(e[fixed+i*2:])
		}
		d := destEntry{number: le.Uint32(e[88:]), modified: le.Uint64(e[100:]), pinned: int32(le.Uint32(e[108:])) != -1,
			path: clean(string(utf16.Decode(u))), host: clean(cstr(e[72:88]))}
		if version >= 2 {
			d.count = le.Uint32(e[116:])
		}
		out = append(out, d)
		off += fixed + n*2
		if trailer > 0 {
			if off+4 > len(b) {
				break
			}
			extra := int(le.Uint32(b[off:]))
			if extra < 0 || off+4+extra > len(b) {
				break
			}
			off += 4 + extra
		}
	}
	return out, version, nil
}

// ------------------------------------------------------------- parsing ----

var lnkHeader = []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}

// CustomJumpList reports whether head looks like a CustomDestinations file:
// a short header and then a shortcut, which begins with its class identifier.
func CustomJumpList(head []byte) bool {
	i := bytes.Index(head, lnkHeader[4:])
	return i >= 16 && i <= 64 && len(head) > 4 && binary.LittleEndian.Uint32(head) <= 16
}

func (jumpListParser) Parse(ctx *Context) error {
	if ctx.Size > jumpListMax {
		return fmt.Errorf("jump list is implausibly large (%d bytes)", ctx.Size)
	}
	data, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return err
	}
	// The application is identified by a hash in the file's name. The name
	// is not used to decide what the file is, only reported.
	app := ctx.Name
	if i := strings.IndexByte(app, '.'); i > 0 {
		app = app[:i]
	}
	if !bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0}) {
		return customJumpList(ctx, data, app)
	}
	c, err := openCFB(data)
	if err != nil {
		return err
	}
	raw, err := c.stream("DestList")
	if err != nil {
		// A compound file that is not a jump list: an old Office document,
		// an installer. Generic handling takes it.
		return ErrNothingExtracted
	}
	entries, version, err := parseDestList(raw)
	if err != nil {
		return err
	}
	emitted := 0
	for _, d := range entries {
		stream := fmt.Sprintf("%x", d.number)
		fields := map[string]any{"app_id": app, "entry": d.number, "pinned": d.pinned, "destlist_version": version, "target": d.path}
		label := app
		if name := appName(app); name != "" {
			fields["application"] = name
			label = name
		}
		// A target written as "knownfolder:{GUID}" is a special folder; name it where the GUID is known.
		if low := strings.ToLower(d.path); strings.HasPrefix(low, "knownfolder:{") && strings.HasSuffix(low, "}") {
			if n, ok := knownFolders[low[len("knownfolder:{"):len(low)-1]]; ok {
				fields["known_folder"] = n
			}
		}
		if d.host != "" {
			fields["target_host"] = d.host
		}
		if d.count > 0 {
			fields["access_count"] = d.count
		}
		if stamp, ok := timeutil.FromFiletime(d.modified); ok {
			emitted++
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: "jumplist-entry-last-used", Category: CatFileOpening, Source: "jumplist",
				Host: ctx.Host, Path: d.path,
				Message: fmt.Sprintf("Jump list (%s): %s last opened", label, d.path),
				Fields:  fields, Ref: fmt.Sprintf("DestList entry %d", d.number),
			}); err != nil {
				return err
			}
		}
		// The entry's own shortcut carries the target's file times.
		if lnk, err := c.stream(stream); err == nil {
			n, err := parseLnk(ctx, lnk, "jump list "+app+" entry "+stream, "jump list stream "+stream)
			if err != nil {
				ctx.Warn("entry %s: %v", stream, err)
			}
			emitted += n
		} else {
			ctx.Warn("entry %s is listed but its shortcut could not be read: %v", stream, err)
		}
	}
	if len(entries) == 0 {
		ctx.Note("this jump list is empty: the application has one, with no entries in it")
		return ErrNothingExtracted
	}
	if emitted == 0 {
		ctx.Note("jump list has no entries with a usable time")
		return ErrNothingExtracted
	}
	if want := binary.LittleEndian.Uint32(raw[4:]); int(want) != len(entries) {
		ctx.Warn("the jump list says it has %d entries but %d could be read", want, len(entries))
	}
	return nil
}

func customJumpList(ctx *Context, data []byte, app string) error {
	var offsets []int
	for i := 0; ; {
		j := bytes.Index(data[i:], lnkHeader[4:])
		if j < 0 {
			break
		}
		// The class identifier follows the four-byte header size.
		if at := i + j - 4; at >= 0 && binary.LittleEndian.Uint32(data[at:]) == 0x4C {
			offsets = append(offsets, at)
		}
		i += j + 16
	}
	sort.Ints(offsets)
	emitted := 0
	for n, at := range offsets {
		end := len(data)
		if n+1 < len(offsets) {
			end = offsets[n+1]
		}
		got, err := parseLnk(ctx, data[at:end], fmt.Sprintf("jump list %s entry %d", app, n+1), fmt.Sprintf("shortcut at offset %d", at))
		if err != nil {
			ctx.Warn("shortcut at offset %d: %v", at, err)
		}
		emitted += got
	}
	if emitted == 0 {
		return ErrNothingExtracted
	}
	return nil
}
