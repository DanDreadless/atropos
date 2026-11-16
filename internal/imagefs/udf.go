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

// UDF: DVDs, Blu-ray discs, and the install discs of Windows, whose largest
// files are only in the UDF part of a disc that is also ISO 9660.
//
// Written from the structure definitions of ECMA-167 and the OSTA UDF
// specification as the Linux kernel declares them (fs/udf/ecma_167.h and
// osta_udf.h), and checked on discs written by Windows' own IMAPI2 in UDF
// revisions 1.02, 1.50, 2.00, 2.01 and 2.50.
//
// Read: the anchor at sector 256 (or the last sector), the main volume
// descriptor sequence (partition and logical volume descriptors), type 1
// partition maps, sparable maps (read without their sparing tables, which
// matter only on a damaged rewritable disc) and the metadata partition of
// UDF 2.50 and later, the file set, file entries and extended file entries
// (after any indirect entries), all four kinds of allocation descriptor with
// their continuation extents, file identifiers with OSTA compressed Unicode
// names. Not read: virtual partitions (VAT, written to CD-R packet by packet;
// such a disc is refused with a note), named streams, extended attributes.

const (
	udfSector     = 2048
	udfMaxDir     = 64 << 20
	udfMaxDepth   = 64
	udfMaxExtents = 1 << 20
	udfMaxDescSeq = 256
)

type udfPart struct {
	start, length int64    // physical, in blocks
	meta          *udfFile // metadata partition: its blocks are the metadata file's
	ref           int      // the physical partition a metadata partition sits on
}

type udfFS struct {
	r        io.ReaderAt
	size     int64
	bs       int64
	parts    []udfPart // by partition reference number
	root     udfLB
	volume   string
	revision uint16
	alsoISO  bool
}

type udfLB struct {
	block uint32
	part  uint16
}

type udfExtent struct {
	at, n int64 // byte offset on the disc, or -1 for a hole
}

type udfFile struct {
	typ        byte
	size       int64
	extents    []udfExtent
	inline     []byte // data held in the entry itself
	modified   time.Time
	accessed   time.Time
	attr       time.Time
	created    time.Time
	localTimes bool
	links      uint16
	uniqueID   uint64
}

func udfTagOK(b []byte, ident uint16) bool {
	if len(b) < 16 || binary.LittleEndian.Uint16(b) != ident {
		return false
	}
	var sum byte
	for i := 0; i < 16; i++ {
		if i != 4 {
			sum += b[i]
		}
	}
	return sum == b[4]
}

// udfTime decodes a timestamp; local is set when it carries no zone.
func udfTime(b []byte) (t time.Time, local bool) {
	le := binary.LittleEndian
	tz := le.Uint16(b)
	year := int(le.Uint16(b[2:]))
	if year == 0 || b[4] == 0 || b[4] > 12 || b[5] == 0 || b[5] > 31 || b[6] > 23 || b[7] > 59 || b[8] > 59 {
		return time.Time{}, false
	}
	usec := int(b[9])*10000 + int(b[10])*100 + int(b[11])
	t = time.Date(year, time.Month(b[4]), int(b[5]), int(b[6]), int(b[7]), int(b[8]), usec*1000, time.UTC)
	off := int(int16(tz<<4) >> 4) // 12-bit signed minutes
	if tz>>12 != 1 || off == -2047 || off < -1440 || off > 1440 {
		return t, true
	}
	return t.Add(-time.Duration(off) * time.Minute), false
}

// udfName decodes an OSTA compressed Unicode string (8 or 16 bits a
// character, after the compression byte).
func udfName(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case 8, 254:
		r := make([]rune, 0, len(b)-1)
		for _, c := range b[1:] {
			r = append(r, rune(c))
		}
		return string(r)
	case 16, 255:
		u := make([]uint16, 0, len(b)/2)
		for i := 1; i+1 < len(b); i += 2 {
			u = append(u, binary.BigEndian.Uint16(b[i:]))
		}
		return string(utf16.Decode(u))
	}
	return ""
}

// udfDString decodes a d-string: a field whose last byte is the length used.
func udfDString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n := int(b[len(b)-1])
	if n == 0 || n > len(b)-1 {
		return ""
	}
	return strings.TrimRight(udfName(b[:n]), "\x00 ")
}

func openUDF(r io.ReaderAt, size int64) (*udfFS, error) {
	u := &udfFS{r: r, size: size, bs: udfSector}
	// The volume recognition sequence: NSR02 or NSR03 after BEA01.
	nsr := false
	for s := int64(16); s < 64; s++ {
		d, err := readAt(r, s*udfSector, 7)
		if err != nil {
			break
		}
		switch string(d[1:6]) {
		case "NSR02", "NSR03":
			nsr = true
		case "CD001":
			u.alsoISO = true
		}
		if d[1] == 0 && string(d[1:6]) != "BEA01" && s > 18 && !nsr {
			break
		}
	}
	if !nsr {
		return nil, errors.New("no UDF volume recognition sequence")
	}
	var avdp []byte
	for _, s := range []int64{256, size/udfSector - 1, size/udfSector - 257} {
		if s <= 0 {
			continue
		}
		if b, err := readAt(r, s*udfSector, 512); err == nil && udfTagOK(b, 2) {
			avdp = b
			break
		}
	}
	if avdp == nil {
		return nil, errors.New("no UDF anchor volume descriptor")
	}
	le := binary.LittleEndian
	seqLen, seqLoc := int64(le.Uint32(avdp[16:])), int64(le.Uint32(avdp[20:]))
	pds := map[uint16][2]int64{}
	var lvd []byte
	for i := int64(0); i < seqLen/udfSector && i < udfMaxDescSeq; i++ {
		d, err := readAt(r, (seqLoc+i)*udfSector, udfSector)
		if err != nil {
			break
		}
		switch le.Uint16(d) {
		case 1:
			if udfTagOK(d, 1) && u.volume == "" {
				u.volume = udfDString(d[24:56])
			}
		case 5:
			if udfTagOK(d, 5) {
				pds[le.Uint16(d[22:])] = [2]int64{int64(le.Uint32(d[188:])), int64(le.Uint32(d[192:]))}
			}
		case 6:
			if udfTagOK(d, 6) {
				lvd = d
			}
		case 8:
			i = seqLen // terminating descriptor
		}
	}
	if lvd == nil {
		return nil, errors.New("UDF volume has no logical volume descriptor")
	}
	u.bs = int64(le.Uint32(lvd[212:]))
	if u.bs < 512 || u.bs > 65536 || u.bs&(u.bs-1) != 0 {
		return nil, fmt.Errorf("UDF logical block size %d is not possible", u.bs)
	}
	if string(lvd[217:236]) == "*OSTA UDF Compliant" {
		u.revision = le.Uint16(lvd[216+24:])
	}
	fsdLen, fsdBlock, fsdPart := le.Uint32(lvd[248:]), le.Uint32(lvd[252:]), le.Uint16(lvd[256:])
	maps, nmaps := int(le.Uint32(lvd[264:])), int(le.Uint32(lvd[268:]))
	if 440+maps > len(lvd) || nmaps > 64 {
		return nil, errors.New("UDF partition maps are out of bounds")
	}
	type metaMap struct {
		idx  int
		file uint32
	}
	var metas []metaMap
	for p, i := 440, 0; i < nmaps && p+2 <= 440+maps; i++ {
		typ, ln := lvd[p], int(lvd[p+1])
		if ln < 6 || p+ln > len(lvd) {
			return nil, errors.New("UDF partition map is out of bounds")
		}
		m := lvd[p : p+ln]
		part := udfPart{}
		switch typ {
		case 1:
			pd, ok := pds[le.Uint16(m[4:])]
			if !ok {
				return nil, fmt.Errorf("UDF partition %d has no partition descriptor", le.Uint16(m[4:]))
			}
			part.start, part.length = pd[0], pd[1]
		case 2:
			ident := strings.TrimRight(string(m[5:28]), "\x00")
			pd, ok := pds[le.Uint16(m[38:])]
			if !ok {
				return nil, fmt.Errorf("UDF partition %d has no partition descriptor", le.Uint16(m[38:]))
			}
			switch ident {
			case "*UDF Sparable Partition":
				part.start, part.length = pd[0], pd[1]
			case "*UDF Metadata Partition":
				if ln < 48 {
					return nil, errors.New("UDF metadata partition map is too short")
				}
				part.start, part.length = pd[0], pd[1]
				metas = append(metas, metaMap{len(u.parts), le.Uint32(m[40:])})
			case "*UDF Virtual Partition":
				return nil, errors.New("this UDF disc keeps its directory in a virtual allocation table (written packet by packet, as on CD-R), which this version does not read")
			default:
				return nil, fmt.Errorf("UDF partition map %q is not one this version reads", ident)
			}
		default:
			return nil, fmt.Errorf("UDF partition map type %d is not possible", typ)
		}
		u.parts = append(u.parts, part)
		p += ln
	}
	if len(u.parts) == 0 {
		return nil, errors.New("UDF volume has no partitions")
	}
	// A metadata partition's blocks are those of the metadata file, which
	// sits in the physical partition the map names.
	for _, mm := range metas {
		phys := u.parts[mm.idx]
		u.parts[mm.idx] = udfPart{start: phys.start, length: phys.length}
		f, err := u.entry(udfLB{mm.file, uint16(mm.idx)}, 0)
		if err != nil {
			return nil, fmt.Errorf("UDF metadata file: %v", err)
		}
		u.parts[mm.idx].meta = f
	}
	if fsdLen == 0 {
		return nil, errors.New("UDF volume does not say where its file set is")
	}
	fsd, err := u.block(udfLB{fsdBlock, fsdPart})
	if err != nil || !udfTagOK(fsd, 256) {
		return nil, errors.New("UDF file set descriptor not found")
	}
	if u.volume == "" {
		u.volume = udfDString(fsd[112:240])
	}
	u.root = udfLB{le.Uint32(fsd[404:]), le.Uint16(fsd[408:])}
	return u, nil
}

// offset turns a logical block in a partition into a byte offset on the disc.
func (u *udfFS) offset(lb udfLB) (int64, error) {
	if int(lb.part) >= len(u.parts) {
		return 0, fmt.Errorf("partition reference %d does not exist", lb.part)
	}
	p := u.parts[lb.part]
	if p.meta != nil {
		pos := int64(lb.block) * u.bs
		for _, e := range p.meta.extents {
			if pos < e.n {
				if e.at < 0 {
					return 0, errors.New("a metadata block falls in a hole")
				}
				return e.at + pos, nil
			}
			pos -= e.n
		}
		return 0, fmt.Errorf("block %d is past the end of the metadata partition", lb.block)
	}
	if p.length > 0 && int64(lb.block) >= p.length {
		return 0, fmt.Errorf("block %d is past the end of partition %d", lb.block, lb.part)
	}
	return (p.start + int64(lb.block)) * u.bs, nil
}

func (u *udfFS) block(lb udfLB) ([]byte, error) {
	at, err := u.offset(lb)
	if err != nil {
		return nil, err
	}
	return readAt(u.r, at, int(u.bs))
}

// entry reads a file entry, following indirect entries.
func (u *udfFS) entry(lb udfLB, depth int) (*udfFile, error) {
	if depth > 8 {
		return nil, errors.New("indirect entries loop")
	}
	b, err := u.block(lb)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	switch {
	case udfTagOK(b, 259): // indirect entry
		return u.entry(udfLB{le.Uint32(b[40:]), le.Uint16(b[44:])}, depth+1)
	case udfTagOK(b, 261), udfTagOK(b, 266):
	default:
		return nil, fmt.Errorf("no file entry at block %d of partition %d", lb.block, lb.part)
	}
	ext := le.Uint16(b) == 266
	f := &udfFile{typ: b[27], links: le.Uint16(b[48:]), size: int64(le.Uint64(b[56:]))}
	var eaLen, adLen, adAt int
	var lt bool
	if ext {
		f.accessed, lt = udfTime(b[80:])
		f.modified, f.localTimes = udfTime(b[92:])
		f.created, _ = udfTime(b[104:])
		f.attr, _ = udfTime(b[116:])
		f.uniqueID = le.Uint64(b[200:])
		eaLen, adLen, adAt = int(le.Uint32(b[208:])), int(le.Uint32(b[212:])), 216
	} else {
		f.accessed, lt = udfTime(b[72:])
		f.modified, f.localTimes = udfTime(b[84:])
		f.attr, _ = udfTime(b[96:])
		f.uniqueID = le.Uint64(b[160:])
		eaLen, adLen, adAt = int(le.Uint32(b[168:])), int(le.Uint32(b[172:])), 176
	}
	f.localTimes = f.localTimes || lt
	if eaLen < 0 || adLen < 0 || adAt+eaLen+adLen > len(b) || f.size < 0 {
		return nil, errors.New("file entry's lengths run past its block")
	}
	ads := b[adAt+eaLen : adAt+eaLen+adLen]
	flags := le.Uint16(b[34:]) & 7
	if flags == 3 {
		if int64(len(ads)) < f.size {
			f.size = int64(len(ads))
		}
		f.inline = append([]byte(nil), ads[:f.size]...)
		return f, nil
	}
	if err := u.allocations(f, ads, flags, lb.part, 0); err != nil {
		return f, err
	}
	return f, nil
}

// allocations reads a list of allocation descriptors into f's extents.
func (u *udfFS) allocations(f *udfFile, ads []byte, kind uint16, part uint16, depth int) error {
	if depth > 64 {
		return errors.New("allocation extents loop")
	}
	le := binary.LittleEndian
	size := map[uint16]int{0: 8, 1: 16, 2: 20}[kind]
	if size == 0 {
		return fmt.Errorf("allocation descriptor kind %d is not possible", kind)
	}
	for i := 0; i+size <= len(ads); i += size {
		if len(f.extents) >= udfMaxExtents {
			return errors.New("too many extents")
		}
		raw := le.Uint32(ads[i:])
		n, typ := int64(raw&0x3FFFFFFF), raw>>30
		if n == 0 {
			break
		}
		var lb udfLB
		switch kind {
		case 0:
			lb = udfLB{le.Uint32(ads[i+4:]), part}
		case 1:
			lb = udfLB{le.Uint32(ads[i+4:]), le.Uint16(ads[i+8:])}
		case 2:
			lb = udfLB{le.Uint32(ads[i+12:]), le.Uint16(ads[i+16:])}
		}
		if typ == 3 {
			// The rest of the list continues in an allocation extent.
			b, err := u.block(lb)
			if err != nil || !udfTagOK(b, 258) {
				return errors.New("allocation extent descriptor not found")
			}
			l := int(le.Uint32(b[20:]))
			if 24+l > len(b) {
				return errors.New("allocation extent runs past its block")
			}
			return u.allocations(f, b[24:24+l], kind, part, depth+1)
		}
		if typ != 0 {
			f.extents = append(f.extents, udfExtent{-1, n}) // allocated or not, but not recorded: zeros
			continue
		}
		at, err := u.offset(lb)
		if err != nil {
			return err
		}
		f.extents = append(f.extents, udfExtent{at, n})
	}
	return nil
}

// data returns a reader of a file's content.
func (u *udfFS) data(f *udfFile) io.Reader {
	if f.inline != nil {
		return strings.NewReader(string(f.inline))
	}
	var segs []dataSeg
	left := f.size
	for _, e := range f.extents {
		if left <= 0 {
			break
		}
		n := e.n
		if n > left {
			n = left
		}
		segs = append(segs, dataSeg{e.at, n})
		left -= n
	}
	if left > 0 {
		segs = append(segs, dataSeg{-1, left})
	}
	return &segReader{r: u.r, segs: segs}
}

type udfEntry struct {
	name    string
	dir     bool
	deleted bool
	icb     udfLB
}

// dir reads a directory's file identifiers.
func (u *udfFS) dir(f *udfFile) ([]udfEntry, error) {
	if f.size > udfMaxDir {
		return nil, fmt.Errorf("directory of %d bytes is larger than any real one", f.size)
	}
	b, err := io.ReadAll(io.LimitReader(u.data(f), f.size))
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	var out []udfEntry
	for pos := 0; pos+38 <= len(b); {
		d := b[pos:]
		if !udfTagOK(d, 257) {
			break
		}
		chars, lfi, liu := d[18], int(d[19]), int(le.Uint16(d[36:]))
		total := (38 + liu + lfi + 3) &^ 3
		if 38+liu+lfi > len(d) {
			break
		}
		if chars&0x08 == 0 { // not the parent
			out = append(out, udfEntry{name: udfName(d[38+liu : 38+liu+lfi]), dir: chars&0x02 != 0, deleted: chars&0x04 != 0,
				icb: udfLB{le.Uint32(d[24:]), le.Uint16(d[28:])}})
		}
		pos += total
	}
	return out, nil
}

// ---- the FS interface ----

type udfView struct{ u *udfFS }

func (v *udfView) Describe() string {
	s := "UDF disc"
	if v.u.revision != 0 {
		s = fmt.Sprintf("UDF %x.%02x disc", v.u.revision>>8, v.u.revision&0xFF)
	}
	if v.u.volume != "" {
		s += fmt.Sprintf(" %q", v.u.volume)
	}
	if v.u.alsoISO {
		s += " (also ISO 9660; the UDF side is shown, which holds files of any size)"
	}
	return s
}

func (v *udfView) Close() {}

func (v *udfView) lookup(parts []string) (*udfFile, error) {
	f, err := v.u.entry(v.u.root, 0)
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		if f.typ != 4 {
			return nil, fmt.Errorf("%s is not a folder", p)
		}
		list, err := v.u.dir(f)
		if err != nil {
			return nil, err
		}
		var next *udfEntry
		for i := range list {
			if !list[i].deleted && strings.EqualFold(list[i].name, p) {
				next = &list[i]
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("%s: no such file or folder", p)
		}
		if f, err = v.u.entry(next.icb, 0); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func udfNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func (v *udfView) List(path string) ([]Entry, error) {
	dirPath, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	f, err := v.lookup(parts)
	if err != nil {
		return nil, err
	}
	if f.typ != 4 {
		return nil, fmt.Errorf("%s is a file", path)
	}
	list, err := v.u.dir(f)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range list {
		if e.deleted || e.name == "" {
			continue
		}
		x := Entry{Name: e.name, Path: join(dirPath, e.name), IsDir: e.dir}
		if c, err := v.u.entry(e.icb, 0); err == nil {
			if !x.IsDir {
				x.Size = c.size
			}
			x.Modified, x.Accessed, x.Changed, x.Born = udfNano(c.modified), udfNano(c.accessed), udfNano(c.attr), udfNano(c.created)
			x.LocalTime = c.localTimes
			if c.localTimes {
				x.Note = "times recorded without a time zone"
			}
		} else {
			x.Note = "its file entry could not be read: " + err.Error()
		}
		out = append(out, x)
		if len(out) >= MaxListing {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (v *udfView) Open(path string) (io.Reader, int64, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	if len(parts) == 0 {
		return nil, 0, errors.New("the root is a folder")
	}
	f, err := v.lookup(parts)
	if err != nil {
		return nil, 0, err
	}
	if f.typ == 4 {
		return nil, 0, fmt.Errorf("%s is a folder", path)
	}
	return v.u.data(f), f.size, nil
}

func openUDFView(r io.ReaderAt, size int64) (FS, error) {
	u, err := openUDF(r, size)
	if err != nil {
		return nil, err
	}
	if _, err := u.entry(u.root, 0); err != nil {
		return nil, fmt.Errorf("UDF root folder: %v", err)
	}
	return &udfView{u: u}, nil
}
