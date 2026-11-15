package imagefs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"sync"
	"unicode/utf16"
)

// Virtual disks: Microsoft VHD and VHDX, and VMware VMDK sparse extents.
// Each is a block device (an io.ReaderAt over the disk it holds) that the
// rest of this package opens as it would a raw disk.
//
// Written from Joachim Metz's format documents (libvhdi: "Virtual Hard Disk
// (VHD) image format", "Virtual Hard Disk version 2 (VHDX) image format";
// libvmdk: "VMware Virtual Disk (VMDK) format").
//
// A differencing disk holds only what changed since its parent. The parent
// is found among the other files offered, by the identifier the two share,
// never by its name.

const maxVDiskChain = 16

// vdisk is a virtual disk's contents.
type vdisk interface {
	io.ReaderAt
	Size() int64
	Describe() string
}

type vdiskFS struct {
	FS
	what string
}

func (f vdiskFS) Describe() string { return f.FS.Describe() + ", inside " + f.what }

func openVDisk(d vdisk) (FS, error) {
	inner, err := Open(d, d.Size())
	if err != nil {
		if errors.Is(err, ErrNoFileSystem) {
			return nil, fmt.Errorf("%s opened (%d bytes of disk), but %w", d.Describe(), d.Size(), err)
		}
		return nil, err
	}
	return vdiskFS{inner, d.Describe()}, nil
}

// readFull reads from r, treating a short read at the end as an error.
func readFull(r io.ReaderAt, off int64, n int) ([]byte, error) {
	if n < 0 || n > 64<<20 {
		return nil, fmt.Errorf("a read of %d bytes is not credible", n)
	}
	return readAt(r, off, n)
}

// ---------------------------------------------------------------- VHD ----

type vhd struct {
	r         io.ReaderAt
	size      int64
	typ       uint32 // 2 fixed, 3 dynamic, 4 differencing
	blockSize int64
	bitmap    int64 // bytes of sector bitmap before each block
	bat       []uint32
	parent    vdisk
	id        [16]byte
	chain     int
}

func vhdFooter(r io.ReaderAt, size int64) ([]byte, bool) {
	for _, off := range []int64{size - 512, size - 511, 0} {
		if off < 0 {
			continue
		}
		if f, err := readAt(r, off, 512); err == nil && string(f[:8]) == "conectix" {
			return f, true
		}
	}
	return nil, false
}

func openVHD(r io.ReaderAt, size int64, others []EWFSegment, depth int) (*vhd, error) {
	if depth > maxVDiskChain {
		return nil, errors.New("VHD parent chain is longer than any real one")
	}
	f, ok := vhdFooter(r, size)
	if !ok {
		return nil, errors.New(`not a VHD image: no "conectix" footer`)
	}
	be := binary.BigEndian
	v := &vhd{r: r, size: int64(be.Uint64(f[48:])), typ: be.Uint32(f[60:]), chain: depth}
	copy(v.id[:], f[68:84])
	if v.size <= 0 || v.size > 1<<44 {
		return nil, fmt.Errorf("VHD declares a disk of %d bytes", v.size)
	}
	switch v.typ {
	case 2:
		if v.size > size {
			return nil, errors.New("fixed VHD is shorter than the disk it declares")
		}
		return v, nil
	case 3, 4:
	default:
		return nil, fmt.Errorf("VHD disk type %d is not one this version reads", v.typ)
	}
	hdrOff := int64(be.Uint64(f[16:]))
	h, err := readFull(r, hdrOff, 1024)
	if err != nil || string(h[:8]) != "cxsparse" {
		return nil, errors.New("dynamic VHD has no dynamic disk header where its footer says")
	}
	batOff, n := int64(be.Uint64(h[16:])), int64(be.Uint32(h[28:]))
	v.blockSize = int64(be.Uint32(h[32:]))
	if v.blockSize < 512 || v.blockSize%512 != 0 || v.blockSize > 256<<20 || n <= 0 || n*v.blockSize < v.size || n > 1<<26 {
		return nil, errors.New("dynamic VHD has an impossible block table")
	}
	raw, err := readFull(r, batOff, int(n*4))
	if err != nil {
		return nil, errors.New("dynamic VHD block table is cut short")
	}
	v.bat = make([]uint32, n)
	for i := range v.bat {
		v.bat[i] = be.Uint32(raw[i*4:])
	}
	v.bitmap = (v.blockSize/512/8 + 511) / 512 * 512
	if v.typ == 4 {
		var pid [16]byte
		copy(pid[:], h[40:56])
		for _, o := range others {
			if p, ok := vhdFooter(o.R, o.Size); ok && bytes.Equal(p[68:84], pid[:]) {
				if parent, err := openVHD(o.R, o.Size, others, depth+1); err == nil {
					v.parent = parent
					break
				}
			}
		}
		if v.parent == nil {
			name := utf16be(h[64:576])
			return nil, fmt.Errorf("the differencing VHD's parent (%q) is not in the case. Add it, and open this image again", name)
		}
	}
	return v, nil
}

func utf16be(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.BigEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func (v *vhd) Size() int64 { return v.size }

func (v *vhd) Describe() string {
	switch v.typ {
	case 2:
		return "a fixed VHD image"
	case 3:
		return "a dynamic VHD image"
	}
	return fmt.Sprintf("a differencing VHD image (over %s)", v.parent.Describe())
}

func (v *vhd) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if v.typ == 2 {
		if off >= v.size {
			return 0, io.EOF
		}
		if int64(len(p)) > v.size-off {
			n, err := v.r.ReadAt(p[:v.size-off], off)
			if err == nil {
				err = io.EOF
			}
			return n, err
		}
		return v.r.ReadAt(p, off)
	}
	done := 0
	for done < len(p) {
		if off >= v.size {
			return done, io.EOF
		}
		// One sector at a time within a block, as the bitmap is per sector.
		sector := off / 512
		in := off % 512
		n := int64(len(p) - done)
		if n > 512-in {
			n = 512 - in
		}
		if n > v.size-off {
			n = v.size - off
		}
		if err := v.sector(p[done:done+int(n)], sector, in); err != nil {
			return done, err
		}
		done += int(n)
		off += n
	}
	return done, nil
}

func (v *vhd) sector(p []byte, sector, in int64) error {
	per := v.blockSize / 512
	b, s := sector/per, sector%per
	if b >= int64(len(v.bat)) {
		return fmt.Errorf("VHD sector %d is outside its block table", sector)
	}
	fromParent := func() error {
		if v.parent == nil {
			clear(p)
			return nil
		}
		_, err := v.parent.ReadAt(p, sector*512+in)
		if err == io.EOF {
			err = nil
		}
		return err
	}
	if v.bat[b] == 0xFFFFFFFF {
		return fromParent()
	}
	start := int64(v.bat[b]) * 512
	bm := make([]byte, 1)
	if _, err := v.r.ReadAt(bm, start+s/8); err != nil {
		return fmt.Errorf("VHD block %d: %v", b, err)
	}
	if bm[0]&(0x80>>(s%8)) == 0 {
		return fromParent()
	}
	_, err := v.r.ReadAt(p, start+v.bitmap+s*512+in)
	return err
}

// --------------------------------------------------------------- VHDX ----

var crc32c = crc32.MakeTable(crc32.Castagnoli)

const (
	vhdxBAT      = "2dc27766-f623-4200-9d64-115e9bfd4a08"
	vhdxMetadata = "8b7ca206-4790-4b9a-b8fe-575f050f886e"
	vhdxSize     = "2fa54224-cd1b-4876-b211-5dbed83bf4b8"
	vhdxLogical  = "8141bf1d-a96f-4709-ba47-f233a8faab5f"
	vhdxParent   = "a8d35f2d-b30b-454d-abf7-d3d84834ab0c"
	vhdxParams   = "caa16737-fa36-4d43-b3b6-33f0aa44e76b"
)

type vhdx struct {
	r          io.ReaderAt
	size       int64
	blockSize  int64
	sector     int64
	ratio      int64 // payload blocks per sector-bitmap block
	bat        []uint64
	parent     vdisk
	dataWrite  string
	logPending bool
	chain      int
}

// vhdxHeader returns the current image header: of the two, the valid one
// with the higher sequence number.
func vhdxHeader(r io.ReaderAt) ([]byte, error) {
	var best []byte
	var seq uint64
	for _, off := range []int64{64 << 10, 128 << 10} {
		h, err := readAt(r, off, 4096)
		if err != nil || string(h[:4]) != "head" {
			continue
		}
		sum := binary.LittleEndian.Uint32(h[4:])
		c := append([]byte(nil), h...)
		binary.LittleEndian.PutUint32(c[4:], 0)
		if crc32.Checksum(c, crc32c) != sum {
			continue
		}
		if s := binary.LittleEndian.Uint64(h[8:]); best == nil || s > seq {
			best, seq = h, s
		}
	}
	if best == nil {
		return nil, errors.New("VHDX has no valid image header")
	}
	return best, nil
}

func openVHDX(r io.ReaderAt, size int64, others []EWFSegment, depth int) (*vhdx, error) {
	if depth > maxVDiskChain {
		return nil, errors.New("VHDX parent chain is longer than any real one")
	}
	le := binary.LittleEndian
	if sig, err := readAt(r, 0, 8); err != nil || string(sig) != "vhdxfile" {
		return nil, errors.New(`not a VHDX image: no "vhdxfile" signature`)
	}
	h, err := vhdxHeader(r)
	if err != nil {
		return nil, err
	}
	v := &vhdx{r: r, chain: depth, dataWrite: guidString(h[32:48])}
	v.logPending = !bytes.Equal(h[48:64], make([]byte, 16))
	// The region table, or its copy.
	var regions map[string][2]int64
	for _, off := range []int64{192 << 10, 256 << 10} {
		t, err := readAt(r, off, 64<<10)
		if err != nil || string(t[:4]) != "regi" {
			continue
		}
		sum := le.Uint32(t[4:])
		c := append([]byte(nil), t...)
		le.PutUint32(c[4:], 0)
		if crc32.Checksum(c, crc32c) != sum {
			continue
		}
		n := int(le.Uint32(t[8:]))
		if n > 2047 {
			continue
		}
		regions = map[string][2]int64{}
		for i := 0; i < n; i++ {
			e := t[16+32*i:]
			regions[guidString(e[:16])] = [2]int64{int64(le.Uint64(e[16:])), int64(le.Uint32(e[24:]))}
		}
		break
	}
	batR, ok1 := regions[vhdxBAT]
	metaR, ok2 := regions[vhdxMetadata]
	if !ok1 || !ok2 {
		return nil, errors.New("VHDX has no valid region table")
	}
	meta, err := readFull(r, metaR[0], 64<<10)
	if err != nil || string(meta[:8]) != "metadata" {
		return nil, errors.New("VHDX metadata table is missing")
	}
	items := map[string][]byte{}
	for i := 0; i < int(le.Uint16(meta[10:])) && 32+32*i+32 <= len(meta); i++ {
		e := meta[32+32*i:]
		off, n := int64(le.Uint32(e[16:])), int(le.Uint32(e[20:]))
		if n > 0 && n <= 1<<20 {
			if b, err := readFull(r, metaR[0]+off, n); err == nil {
				items[guidString(e[:16])] = b
			}
		}
	}
	params, sz, logical := items[vhdxParams], items[vhdxSize], items[vhdxLogical]
	if len(params) < 8 || len(sz) < 8 || len(logical) < 4 {
		return nil, errors.New("VHDX metadata lacks the disk's size or block size")
	}
	v.blockSize, v.size, v.sector = int64(le.Uint32(params)), int64(le.Uint64(sz)), int64(le.Uint32(logical))
	hasParent := le.Uint32(params[4:])&2 != 0
	if v.blockSize < 1<<20 || v.blockSize > 256<<20 || v.blockSize&(v.blockSize-1) != 0 || (v.sector != 512 && v.sector != 4096) || v.size <= 0 || v.size > 64<<40 {
		return nil, errors.New("VHDX metadata is not credible")
	}
	v.ratio = (1 << 23) * v.sector / v.blockSize
	// The table is laid out in chunks: ratio payload entries, then the
	// chunk's sector-bitmap entry, the last chunk padded to its full length.
	blocks := (v.size + v.blockSize - 1) / v.blockSize
	need := blocks + (blocks-1)/v.ratio
	entries := (blocks + v.ratio - 1) / v.ratio * (v.ratio + 1)
	if entries*8 > batR[1] {
		entries = batR[1] / 8
	}
	if entries < need || entries > 1<<26 {
		return nil, errors.New("VHDX block table is too small for the disk")
	}
	raw, err := readFull(r, batR[0], int(entries*8))
	if err != nil {
		return nil, errors.New("VHDX block table is cut short")
	}
	v.bat = make([]uint64, entries)
	for i := range v.bat {
		v.bat[i] = le.Uint64(raw[i*8:])
	}
	if hasParent {
		link := strings.Trim(strings.ToLower(vhdxLocator(items[vhdxParent])["parent_linkage"]), "{}")
		for _, o := range others {
			if ph, err := vhdxHeader(o.R); err == nil && link != "" && guidString(ph[32:48]) == link {
				if p, err := openVHDX(o.R, o.Size, others, depth+1); err == nil {
					v.parent = p
					break
				}
			}
		}
		if v.parent == nil {
			loc := vhdxLocator(items[vhdxParent])
			return nil, fmt.Errorf("the differencing VHDX's parent (%q) is not in the case. Add it, and open this image again", loc["relative_path"]+loc["absolute_win32_path"])
		}
	}
	return v, nil
}

// vhdxLocator reads the parent locator's keys and values.
func vhdxLocator(b []byte) map[string]string {
	out := map[string]string{}
	le := binary.LittleEndian
	if len(b) < 20 {
		return out
	}
	str := func(off, n int) string {
		if off < 0 || n < 0 || off+n > len(b) {
			return ""
		}
		u := make([]uint16, 0, n/2)
		for i := off; i+1 < off+n; i += 2 {
			u = append(u, le.Uint16(b[i:]))
		}
		return string(utf16.Decode(u))
	}
	for i := 0; i < int(le.Uint16(b[18:])) && 20+12*i+12 <= len(b); i++ {
		e := b[20+12*i:]
		out[str(int(le.Uint32(e)), int(le.Uint16(e[8:])))] = str(int(le.Uint32(e[4:])), int(le.Uint16(e[10:])))
	}
	return out
}

func (v *vhdx) Size() int64 { return v.size }

func (v *vhdx) Describe() string {
	what := "a VHDX image"
	if v.parent != nil {
		what = fmt.Sprintf("a differencing VHDX image (over %s)", v.parent.Describe())
	}
	if v.logPending {
		what += " whose log was not replayed (its last changes may be missing)"
	}
	return what
}

func (v *vhdx) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	done := 0
	for done < len(p) {
		if off >= v.size {
			return done, io.EOF
		}
		n := int64(len(p) - done)
		// Stay within one sector: a partly present block is per sector.
		if lim := v.sector - off%v.sector; n > lim {
			n = lim
		}
		if n > v.size-off {
			n = v.size - off
		}
		if err := v.read(p[done:done+int(n)], off); err != nil {
			return done, err
		}
		done += int(n)
		off += n
	}
	return done, nil
}

func (v *vhdx) read(p []byte, off int64) error {
	b := off / v.blockSize
	idx := b + b/v.ratio
	if idx >= int64(len(v.bat)) {
		return fmt.Errorf("VHDX offset %d is outside its block table", off)
	}
	e := v.bat[idx]
	fromParent := func() error {
		if v.parent == nil {
			clear(p)
			return nil
		}
		_, err := v.parent.ReadAt(p, off)
		if err == io.EOF {
			err = nil
		}
		return err
	}
	at := int64(e>>20) * (1 << 20)
	switch e & 7 {
	case 6: // fully present
		_, err := v.r.ReadAt(p, at+off%v.blockSize)
		return err
	case 7: // partly present: the sector bitmap says which sectors are here
		chunk := b / v.ratio
		si := chunk*(v.ratio+1) + v.ratio
		if si >= int64(len(v.bat)) {
			return fmt.Errorf("VHDX block %d has no sector bitmap in the block table", b)
		}
		sb := v.bat[si]
		if sb&7 != 6 {
			return fromParent()
		}
		sector := off / v.sector
		bit := sector % (1 << 23)
		var x [1]byte
		if _, err := v.r.ReadAt(x[:], int64(sb>>20)*(1<<20)+bit/8); err != nil {
			return err
		}
		if x[0]&(1<<(bit%8)) != 0 {
			_, err := v.r.ReadAt(p, at+off%v.blockSize)
			return err
		}
		return fromParent()
	case 0, 1, 3:
		// Not present: in the parent, if there is one; otherwise zeros.
		return fromParent()
	}
	clear(p) // zero block
	return nil
}

// --------------------------------------------------------------- VMDK ----

type vmdk struct {
	r          io.ReaderAt
	fsize      int64
	size       int64
	grain      int64 // bytes
	gtes       int64
	gd         []uint32
	zeroed     bool
	compressed bool
	mu         sync.Mutex
	gts        map[uint32][]uint32
}

func openVMDK(r io.ReaderAt, size int64) (*vmdk, error) {
	le := binary.LittleEndian
	h, err := readAt(r, 0, 512)
	if err != nil || string(h[:4]) != "KDMV" {
		return nil, errors.New(`not a VMDK sparse extent: no "KDMV" signature`)
	}
	flags := le.Uint32(h[8:])
	gdSector := int64(le.Uint64(h[56:]))
	if gdSector == -1 || uint64(gdSector) == 0xFFFFFFFFFFFFFFFF {
		// Stream-optimised: the real header is a footer before the end.
		f, err := readAt(r, size-1024, 512)
		if err != nil || string(f[:4]) != "KDMV" {
			return nil, errors.New("stream-optimised VMDK has no footer")
		}
		h = f
		gdSector = int64(le.Uint64(h[56:]))
	}
	if gdSector == 0 {
		gdSector = int64(le.Uint64(h[48:]))
	}
	v := &vmdk{r: r, fsize: size, size: int64(le.Uint64(h[12:])) * 512, grain: int64(le.Uint64(h[20:])) * 512,
		gtes: int64(le.Uint32(h[44:])), zeroed: flags&4 != 0, compressed: le.Uint16(h[77:]) == 1, gts: map[uint32][]uint32{}}
	if v.grain < 4096 || v.grain > 64<<20 || v.gtes <= 0 || v.gtes > 1<<16 || v.size <= 0 || v.size > 64<<40 || gdSector <= 0 {
		return nil, errors.New("VMDK header is not credible")
	}
	n := (v.size + v.grain*v.gtes - 1) / (v.grain * v.gtes)
	raw, err := readFull(r, gdSector*512, int(n*4))
	if err != nil {
		return nil, errors.New("VMDK grain directory is cut short")
	}
	v.gd = make([]uint32, n)
	for i := range v.gd {
		v.gd[i] = le.Uint32(raw[i*4:])
	}
	return v, nil
}

func (v *vmdk) Size() int64 { return v.size }

func (v *vmdk) Describe() string {
	if v.compressed {
		return "a stream-optimised VMDK image"
	}
	return "a sparse VMDK image"
}

func (v *vmdk) table(sector uint32) ([]uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if t, ok := v.gts[sector]; ok {
		return t, nil
	}
	raw, err := readFull(v.r, int64(sector)*512, int(v.gtes*4))
	if err != nil {
		return nil, err
	}
	t := make([]uint32, v.gtes)
	for i := range t {
		t[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	if len(v.gts) > 4096 {
		v.gts = map[uint32][]uint32{}
	}
	v.gts[sector] = t
	return t, nil
}

func (v *vmdk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	done := 0
	for done < len(p) {
		if off >= v.size {
			return done, io.EOF
		}
		g := off / v.grain
		in := off % v.grain
		n := int64(len(p) - done)
		if n > v.grain-in {
			n = v.grain - in
		}
		if n > v.size-off {
			n = v.size - off
		}
		dst := p[done : done+int(n)]
		gdi, gti := g/v.gtes, g%v.gtes
		var gte uint32
		if gdi < int64(len(v.gd)) && v.gd[gdi] != 0 && !(v.zeroed && v.gd[gdi] == 1) {
			t, err := v.table(v.gd[gdi])
			if err != nil {
				return done, fmt.Errorf("VMDK grain table: %v", err)
			}
			gte = t[gti]
		}
		switch {
		case gte == 0 || v.zeroed && gte == 1:
			clear(dst)
		case v.compressed:
			grain, err := v.compressedGrain(gte)
			if err != nil {
				return done, err
			}
			if int64(len(grain)) < in+n {
				return done, fmt.Errorf("VMDK grain %d is shorter than a grain", g)
			}
			copy(dst, grain[in:in+n])
		default:
			if _, err := v.r.ReadAt(dst, int64(gte)*512+in); err != nil {
				return done, err
			}
		}
		done += int(n)
		off += n
	}
	return done, nil
}

func (v *vmdk) compressedGrain(sector uint32) ([]byte, error) {
	at := int64(sector) * 512
	h, err := readAt(v.r, at, 12)
	if err != nil {
		return nil, err
	}
	n := int64(binary.LittleEndian.Uint32(h[8:]))
	if n <= 0 || n > v.grain*2 || at+12+n > v.fsize {
		return nil, fmt.Errorf("VMDK compressed grain at sector %d has an impossible size", sector)
	}
	zr, err := zlib.NewReader(io.NewSectionReader(v.r, at+12, n))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(zr, v.grain))
}
