package imagefs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// ISO 9660 (ECMA-119), with the Joliet extension for long Unicode names.
// UDF, which DVDs and some large installers use instead, is not read: where a
// disc has a UDF structure as well, Describe says so, because the ISO 9660
// view of such a disc can be a stub.

const isoSector = 2048

type isoFS struct {
	r      io.ReaderAt
	size   int64
	root   isoRecord
	joliet bool
	udf    bool
	label  string
}

type isoRecord struct {
	extent int64 // first sector
	length int64 // bytes
	isDir  bool
	name   string
	mod    int64
}

func openISO(r io.ReaderAt, size int64) (FS, error) {
	fs := &isoFS{r: r, size: size}
	found := false
	for s := int64(16); s < 64; s++ {
		d, err := readAt(r, s*isoSector, isoSector)
		if err != nil {
			break
		}
		id := string(d[1:6])
		if id == "NSR02" || id == "NSR03" {
			fs.udf = true
		}
		if id != "CD001" {
			if id == "BEA01" || id == "NSR02" || id == "NSR03" || id == "TEA01" || id == "BOOT2" {
				continue
			}
			break
		}
		switch d[0] {
		case 1:
			if !fs.joliet {
				fs.root, found = parseISORecord(d[156:190], false), true
				fs.label = strings.Trim(string(d[40:72]), " \x00")
			}
		case 2:
			// Joliet announces itself with one of three escape sequences.
			if esc := string(d[88:91]); esc == "%/@" || esc == "%/C" || esc == "%/E" {
				fs.root, fs.joliet, found = parseISORecord(d[156:190], true), true, true
				if l := strings.Trim(ucs2(d[40:72]), " \x00"); l != "" {
					fs.label = l
				}
			}
		}
	}
	if !found || !fs.root.isDir || fs.root.extent <= 0 || fs.root.extent*isoSector >= size {
		return nil, ErrNoFileSystem
	}
	return fs, nil
}

func ucs2(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.BigEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}

func parseISORecord(b []byte, joliet bool) isoRecord {
	rec := isoRecord{
		extent: int64(binary.LittleEndian.Uint32(b[2:])),
		length: int64(binary.LittleEndian.Uint32(b[10:])),
		isDir:  b[25]&2 != 0,
	}
	// Recording time: years since 1900, then month, day, hour, minute,
	// second, and the offset from GMT in quarter hours.
	if y, m := int(b[18]), int(b[19]); m >= 1 && m <= 12 {
		t := time.Date(1900+y, time.Month(m), int(b[20]), int(b[21]), int(b[22]), int(b[23]), 0, time.UTC)
		t = t.Add(-time.Duration(int8(b[24])) * 15 * time.Minute)
		if t.Year() >= 1970 && t.Year() < 2200 {
			rec.mod = t.UnixNano()
		}
	}
	n := int(b[32])
	if 33+n > len(b) {
		n = len(b) - 33
	}
	raw := b[33 : 33+n]
	switch {
	case n == 1 && raw[0] == 0:
		rec.name = "."
	case n == 1 && raw[0] == 1:
		rec.name = ".."
	case joliet:
		rec.name = ucs2(raw)
	default:
		rec.name = string(raw)
	}
	if !rec.isDir && rec.name != "." && rec.name != ".." {
		// Files carry a version suffix, and plain ISO 9660 a trailing dot
		// when there is no extension.
		if i := strings.LastIndexByte(rec.name, ';'); i > 0 {
			rec.name = rec.name[:i]
		}
		if !joliet {
			rec.name = strings.TrimSuffix(rec.name, ".")
		}
	}
	return rec
}

func (f *isoFS) Describe() string {
	d := "ISO 9660 disc image"
	if f.joliet {
		d += " with Joliet names"
	}
	if f.label != "" {
		d += fmt.Sprintf(", volume label %q", f.label)
	}
	if f.udf {
		d += ". The disc also has a UDF file system, which Atropos does not read; if files seem to be missing, they are only in the UDF structure"
	}
	return d
}

func (f *isoFS) Close() {}

// read returns the records of a directory.
func (f *isoFS) read(dir isoRecord) ([]isoRecord, error) {
	if dir.length <= 0 || dir.length > 256<<20 || dir.extent*isoSector+dir.length > f.size {
		return nil, errors.New("directory lies outside the image")
	}
	data, err := readAt(f.r, dir.extent*isoSector, int(dir.length))
	if err != nil {
		return nil, err
	}
	var out []isoRecord
	for off := 0; off < len(data); {
		n := int(data[off])
		if n == 0 {
			// Records never cross a sector; the rest of this one is padding.
			off = (off/isoSector + 1) * isoSector
			continue
		}
		if n < 34 || off+n > len(data) {
			break
		}
		rec := parseISORecord(data[off:off+n], f.joliet)
		off += n
		if rec.name == "." || rec.name == ".." || rec.name == "" {
			continue
		}
		out = append(out, rec)
		if len(out) >= MaxListing {
			break
		}
	}
	return out, nil
}

func (f *isoFS) walk(parts []string) (isoRecord, error) {
	cur := f.root
	// A directory that points back at an ancestor would otherwise be followed
	// for ever; real paths are nowhere near this deep.
	if len(parts) > 64 {
		return cur, errors.New("path is too deep")
	}
	for _, p := range parts {
		if !cur.isDir {
			return cur, errors.New("not a directory")
		}
		recs, err := f.read(cur)
		if err != nil {
			return cur, err
		}
		found := false
		for _, r := range recs {
			if strings.EqualFold(r.name, p) {
				cur, found = r, true
				break
			}
		}
		if !found {
			return cur, errors.New("not found on this disc")
		}
	}
	return cur, nil
}

func (f *isoFS) List(path string) ([]Entry, error) {
	dir, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	d, err := f.walk(parts)
	if err != nil {
		return nil, err
	}
	if !d.isDir {
		return nil, errors.New("not a directory")
	}
	recs, err := f.read(d)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(recs))
	for _, r := range recs {
		out = append(out, Entry{Name: r.name, Path: join(dir, r.name), IsDir: r.isDir, Size: map[bool]int64{true: 0, false: r.length}[r.isDir], Modified: r.mod})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (f *isoFS) Open(path string) (io.Reader, int64, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	rec, err := f.walk(parts)
	if err != nil {
		return nil, 0, err
	}
	if rec.isDir {
		return nil, 0, errors.New("that is a directory")
	}
	if rec.extent*isoSector+rec.length > f.size {
		return nil, 0, errors.New("the file lies outside the image, which is truncated or damaged")
	}
	return io.NewSectionReader(f.r, rec.extent*isoSector, rec.length), rec.length, nil
}
