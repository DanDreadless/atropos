package imagefs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ext2, ext3 and ext4: Linux, most NAS boxes, Android's data partitions.
//
// Written from the Linux kernel's "ext4 Data Structures and Algorithms"
// (Documentation/filesystems/ext4) and Joachim Metz's notes on the format
// (libfsext). Read: the superblock, group descriptors (with 64-bit
// descriptors and meta_bg), inodes of any size, extent trees and the older
// block maps, inline data, linear and hashed directories (a hashed
// directory's leaves are ordinary directory blocks). Not read: the journal
// (a volume whose journal still needs replaying is said to be so),
// extended attributes, encrypted names.
//
// Times are seconds since 1970 UTC, with nanoseconds and two more bits of
// seconds in the larger inodes ext4 uses; creation time only in those.

const (
	extMaxDir     = 64 << 20
	extMaxDepth   = 64
	extMaxExtents = 1 << 20
	extMaxGroups  = 1 << 22

	extIncompatFiletype  = 0x2
	extIncompatRecover   = 0x4
	extIncompatMetaBG    = 0x10
	extIncompatExtents   = 0x40
	extIncompat64Bit     = 0x80
	extIncompatFlexBG    = 0x200
	extIncompatInline    = 0x8000
	extIncompatEncrypt   = 0x10000
	extROCompatSparse    = 0x1
	extCompatJournal     = 0x4
	extFlagIndex         = 0x1000
	extFlagExtents       = 0x80000
	extFlagInline        = 0x10000000
	extModeType          = 0xF000
	extModeDir           = 0x4000
	extModeFile          = 0x8000
	extModeLink          = 0xA000
	extRootInode         = 2
	extDirentMin         = 8
	extInodeSizeOriginal = 128
)

// ExtTime is an inode time. Valid is false when the inode does not hold it.
type ExtTime struct {
	T     time.Time
	Valid bool
}

// ExtEntry is one name in an ext volume, in use or deleted, with its inode.
type ExtEntry struct {
	Path                              string
	Inode                             uint32
	Type                              string // file, directory, symbolic link, device, fifo, socket, or unknown
	IsDir                             bool
	Size                              int64
	Mode                              uint16 // permissions and type, as stat gives them
	UID                               uint32
	GID                               uint32
	Links                             uint16
	Target                            string // a symbolic link's target, when held in the inode
	Modified, Accessed, Changed, Born ExtTime
	// Deleted: the name was found in the unused space of a directory block.
	Deleted bool
	// InodeFree: the inode is no longer in use, so its times are the
	// deleted file's, and DeletedAt (dtime) is when it was freed.
	InodeFree bool
	DeletedAt ExtTime
	// InodeReused: the deleted name's inode now belongs to another file, so
	// its times say nothing about this one and are left out.
	InodeReused bool
	Dir         uint32 // inode of the directory holding the name
	DirOffset   int64  // the name's byte offset in that directory's data
}

type extFS struct {
	r           io.ReaderAt
	size        int64
	block       int64
	blocks      uint64
	inodes      uint32
	firstData   uint64
	perGroup    uint64
	ipg         uint32
	inodeSize   int64
	descSize    int64
	groups      uint32
	firstMetaBG uint32
	compat      uint32
	incompat    uint32
	rocompat    uint32
	label       string
	uuid        [16]byte
	lastMount   string
	mu          sync.Mutex
	descCache   map[uint64][]byte
}

func openExt(r io.ReaderAt, off, size int64) (*extFS, error) {
	if off != 0 {
		r = &shifted{r, off}
		size -= off
	}
	sb, err := readAt(r, 1024, 1024)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if le.Uint16(sb[0x38:]) != 0xEF53 {
		return nil, errors.New("not an ext superblock")
	}
	f := &extFS{r: r, size: size, descCache: map[uint64][]byte{}}
	logBlock := le.Uint32(sb[0x18:])
	if logBlock > 6 {
		return nil, errors.New("ext superblock has an impossible block size")
	}
	f.block = 1024 << logBlock
	f.inodes = le.Uint32(sb[0x0:])
	f.blocks = uint64(le.Uint32(sb[0x4:]))
	f.firstData = uint64(le.Uint32(sb[0x14:]))
	f.perGroup = uint64(le.Uint32(sb[0x20:]))
	f.ipg = le.Uint32(sb[0x28:])
	f.compat, f.incompat, f.rocompat = le.Uint32(sb[0x5C:]), le.Uint32(sb[0x60:]), le.Uint32(sb[0x64:])
	f.inodeSize = extInodeSizeOriginal
	if le.Uint32(sb[0x4C:]) >= 1 {
		f.inodeSize = int64(le.Uint16(sb[0x58:]))
	}
	f.descSize = 32
	if f.incompat&extIncompat64Bit != 0 {
		f.blocks |= uint64(le.Uint32(sb[0x150:])) << 32
		f.descSize = int64(le.Uint16(sb[0xFE:]))
	}
	f.firstMetaBG = le.Uint32(sb[0x104:])
	copy(f.uuid[:], sb[0x68:0x78])
	f.label = cstr(sb[0x78:0x88])
	f.lastMount = cstr(sb[0x88:0xC8])
	switch {
	case f.perGroup == 0 || f.ipg == 0 || f.inodes == 0 || f.blocks <= f.firstData:
		return nil, errors.New("ext superblock has no groups")
	case f.inodeSize < extInodeSizeOriginal || f.inodeSize > f.block || f.inodeSize&(f.inodeSize-1) != 0:
		return nil, fmt.Errorf("ext superblock gives an impossible inode size, %d", f.inodeSize)
	case f.descSize < 32 || f.descSize > f.block || f.descSize&(f.descSize-1) != 0:
		return nil, fmt.Errorf("ext superblock gives an impossible group descriptor size, %d", f.descSize)
	case uint64(f.ipg) > uint64(f.block)*8:
		return nil, errors.New("ext superblock gives more inodes to a group than it can hold")
	}
	groups := (f.blocks - f.firstData + f.perGroup - 1) / f.perGroup
	if groups > extMaxGroups || groups*uint64(f.ipg) < uint64(f.inodes) {
		return nil, errors.New("ext superblock's group and inode counts disagree")
	}
	f.groups = uint32(groups)
	return f, nil
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(string(b), "?")
}

func (f *extFS) kind() string {
	switch {
	case f.incompat&(extIncompatExtents|extIncompat64Bit|extIncompatFlexBG) != 0 || f.rocompat&0x478 != 0:
		return "ext4"
	case f.compat&extCompatJournal != 0:
		return "ext3"
	}
	return "ext2"
}

func (f *extFS) hasSuper(g uint64) bool {
	if f.rocompat&extROCompatSparse == 0 || g <= 1 {
		return true
	}
	for _, p := range []uint64{3, 5, 7} {
		n := p
		for n < g {
			n *= p
		}
		if n == g {
			return true
		}
	}
	return false
}

// descriptor returns group g's descriptor.
func (f *extFS) descriptor(g uint32) ([]byte, error) {
	if g >= f.groups {
		return nil, fmt.Errorf("group %d is past the last", g)
	}
	perBlock := uint64(f.block / f.descSize)
	var blk uint64
	if f.incompat&extIncompatMetaBG != 0 && uint64(g)/perBlock >= uint64(f.firstMetaBG) {
		first := uint64(g) / perBlock * perBlock
		blk = f.firstData + first*f.perGroup
		if f.hasSuper(first) {
			blk++
		}
	} else {
		blk = f.firstData + 1 + uint64(g)/perBlock
	}
	f.mu.Lock()
	b, ok := f.descCache[blk]
	f.mu.Unlock()
	if !ok {
		var err error
		if b, err = readAt(f.r, int64(blk)*f.block, int(f.block)); err != nil {
			return nil, fmt.Errorf("group descriptors at block %d: %v", blk, err)
		}
		f.mu.Lock()
		if len(f.descCache) > 4096 {
			f.descCache = map[uint64][]byte{}
		}
		f.descCache[blk] = b
		f.mu.Unlock()
	}
	at := int64(uint64(g)%perBlock) * f.descSize
	return b[at : at+f.descSize], nil
}

type extInode struct {
	n             uint32
	mode, links   uint16
	uid, gid      uint32
	size          int64
	flags         uint32
	iblock        []byte
	blocks512     uint64
	fileACL       uint64
	atime, ctime  ExtTime
	mtime, crtime ExtTime
	dtime         ExtTime
	rawDtime      uint32
}

func extStamp(base uint32, extra []byte) ExtTime {
	sec := int64(int32(base))
	var nsec int64
	if extra != nil {
		x := binary.LittleEndian.Uint32(extra)
		sec += int64(x&3) << 32
		if n := int64(x >> 2); n < 1e9 {
			nsec = n
		}
	}
	if sec == 0 && nsec == 0 {
		return ExtTime{}
	}
	return ExtTime{T: time.Unix(sec, nsec).UTC(), Valid: true}
}

func (f *extFS) inode(n uint32) (*extInode, error) {
	if n == 0 || n > f.inodes {
		return nil, fmt.Errorf("inode %d does not exist", n)
	}
	g, idx := (n-1)/f.ipg, (n-1)%f.ipg
	d, err := f.descriptor(g)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	table := uint64(le.Uint32(d[0x8:]))
	if f.descSize >= 64 {
		table |= uint64(le.Uint32(d[0x28:])) << 32
	}
	if table == 0 || table >= f.blocks {
		return nil, fmt.Errorf("inode %d: group %d's inode table is at an impossible block", n, g)
	}
	b, err := readAt(f.r, int64(table)*f.block+int64(idx)*f.inodeSize, int(f.inodeSize))
	if err != nil {
		return nil, fmt.Errorf("inode %d: %v", n, err)
	}
	in := &extInode{n: n, mode: le.Uint16(b[0:]), links: le.Uint16(b[0x1A:]), flags: le.Uint32(b[0x20:]),
		uid: uint32(le.Uint16(b[0x2:])) | uint32(le.Uint16(b[0x78:]))<<16, gid: uint32(le.Uint16(b[0x18:])) | uint32(le.Uint16(b[0x7A:]))<<16,
		size: int64(le.Uint32(b[0x4:])), iblock: b[0x28:0x64], blocks512: uint64(le.Uint32(b[0x1C:])),
		fileACL: uint64(le.Uint32(b[0x68:])) | uint64(le.Uint16(b[0x76:]))<<32, rawDtime: le.Uint32(b[0x14:])}
	// The size's upper half: for files; for directories only with the
	// large directory feature (ext2 kept a directory's ACL there).
	if in.mode&extModeType == extModeFile || in.mode&extModeType == extModeDir && f.incompat&0x4000 != 0 {
		in.size |= int64(le.Uint32(b[0x6C:])) << 32
	}
	if in.size < 0 {
		in.size = 0
	}
	// The extra fields exist when the inode is large enough and says so.
	extra := 0
	if f.inodeSize > extInodeSizeOriginal {
		extra = int(le.Uint16(b[0x80:]))
		if 0x80+extra > int(f.inodeSize) {
			extra = 0
		}
	}
	field := func(at int) []byte {
		if at+4 <= 0x80+extra {
			return b[at : at+4]
		}
		return nil
	}
	in.ctime = extStamp(le.Uint32(b[0xC:]), field(0x84))
	in.mtime = extStamp(le.Uint32(b[0x10:]), field(0x88))
	in.atime = extStamp(le.Uint32(b[0x8:]), field(0x8C))
	if c := field(0x90); c != nil {
		in.crtime = extStamp(le.Uint32(c), field(0x94))
	}
	in.dtime = extStamp(in.rawDtime, nil)
	return in, nil
}

func extType(mode uint16) string {
	switch mode & extModeType {
	case extModeFile:
		return "file"
	case extModeDir:
		return "directory"
	case extModeLink:
		return "symbolic link"
	case 0x2000, 0x6000:
		return "device"
	case 0x1000:
		return "fifo"
	case 0xC000:
		return "socket"
	}
	return "unknown"
}

// dataSeg is a run of a file's bytes: at a volume offset, or a hole (at < 0).
type dataSeg struct{ at, n int64 }

type segReader struct {
	r    io.ReaderAt
	segs []dataSeg
	i    int
	in   int64
}

func (s *segReader) Read(p []byte) (int, error) {
	for s.i < len(s.segs) && s.in >= s.segs[s.i].n {
		s.i++
		s.in = 0
	}
	if s.i >= len(s.segs) {
		return 0, io.EOF
	}
	c := s.segs[s.i]
	n := int64(len(p))
	if left := c.n - s.in; n > left {
		n = left
	}
	if c.at < 0 {
		clear(p[:n])
		s.in += n
		return int(n), nil
	}
	k, err := s.r.ReadAt(p[:n], c.at+s.in)
	s.in += int64(k)
	if err == io.EOF && int64(k) == n {
		err = nil
	} else if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return k, err
}

type extRun struct {
	logical, physical, count uint64
	zero                     bool
}

// runs maps an inode's data: from its extent tree, or its block map.
func (f *extFS) runs(in *extInode) ([]extRun, error) {
	want := (uint64(in.size) + uint64(f.block) - 1) / uint64(f.block)
	var out []extRun
	add := func(r extRun) error {
		if r.count == 0 || r.logical >= want {
			return nil
		}
		if !r.zero && (r.physical == 0 || r.physical+r.count > f.blocks) {
			return fmt.Errorf("inode %d: data at blocks %d to %d is outside the volume", in.n, r.physical, r.physical+r.count)
		}
		if len(out) >= extMaxExtents {
			return fmt.Errorf("inode %d has more than %d extents", in.n, extMaxExtents)
		}
		if k := len(out); k > 0 && !r.zero && !out[k-1].zero && out[k-1].logical+out[k-1].count == r.logical && out[k-1].physical+out[k-1].count == r.physical {
			out[k-1].count += r.count
			return nil
		}
		out = append(out, r)
		return nil
	}
	le := binary.LittleEndian
	if in.flags&extFlagExtents != 0 {
		visited := 0
		var walk func(node []byte, depth int) error
		walk = func(node []byte, depth int) error {
			if len(node) < 12 || le.Uint16(node) != 0xF30A {
				return fmt.Errorf("inode %d: extent node without its signature", in.n)
			}
			entries, d := int(le.Uint16(node[2:])), int(le.Uint16(node[6:]))
			if d > 5 || depth > 5 || 12+entries*12 > len(node) {
				return fmt.Errorf("inode %d: impossible extent node", in.n)
			}
			for i := 0; i < entries; i++ {
				e := node[12+i*12:]
				if d == 0 {
					n := uint64(le.Uint16(e[4:]))
					zero := n > 32768
					if zero {
						n -= 32768
					}
					phys := uint64(le.Uint16(e[6:]))<<32 | uint64(le.Uint32(e[8:]))
					if err := add(extRun{uint64(le.Uint32(e)), phys, n, zero}); err != nil {
						return err
					}
					continue
				}
				leaf := uint64(le.Uint16(e[8:]))<<32 | uint64(le.Uint32(e[4:]))
				if leaf == 0 || leaf >= f.blocks {
					return fmt.Errorf("inode %d: extent index points outside the volume", in.n)
				}
				if visited++; visited > extMaxExtents {
					return fmt.Errorf("inode %d: too many extent nodes", in.n)
				}
				b, err := readAt(f.r, int64(leaf)*f.block, int(f.block))
				if err != nil {
					return err
				}
				if err := walk(b, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(in.iblock, 0); err != nil {
			return out, err
		}
	} else {
		// Twelve direct blocks, then single, double and triple indirect.
		per := uint64(f.block / 4)
		logical := uint64(0)
		var walk func(blk uint64, level int) error
		walk = func(blk uint64, level int) error {
			span := uint64(1)
			for i := 0; i < level; i++ {
				span *= per
			}
			if blk == 0 {
				logical += span
				return nil
			}
			if level == 0 {
				err := add(extRun{logical, blk, 1, false})
				logical++
				return err
			}
			if blk >= f.blocks {
				return fmt.Errorf("inode %d: indirect block outside the volume", in.n)
			}
			b, err := readAt(f.r, int64(blk)*f.block, int(f.block))
			if err != nil {
				return err
			}
			for i := uint64(0); i < per && logical < want; i++ {
				if err := walk(uint64(le.Uint32(b[i*4:])), level-1); err != nil {
					return err
				}
			}
			return nil
		}
		for i := 0; i < 15 && logical < want; i++ {
			level := 0
			if i >= 12 {
				level = i - 11
			}
			if err := walk(uint64(le.Uint32(in.iblock[i*4:])), level); err != nil {
				return out, err
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].logical < out[j].logical })
	return out, nil
}

// data returns a reader of the first limit bytes of an inode's content.
func (f *extFS) data(in *extInode, limit int64) (io.Reader, int64, error) {
	size := in.size
	if size > limit {
		size = limit
	}
	if in.flags&extFlagInline != 0 {
		// The first 60 bytes live in the inode; any more in an extended
		// attribute, which is not read.
		if size > int64(len(in.iblock)) {
			return strings.NewReader(string(in.iblock)), int64(len(in.iblock)), fmt.Errorf("inode %d: inline data past the first %d bytes is not read", in.n, len(in.iblock))
		}
		return strings.NewReader(string(in.iblock[:size])), size, nil
	}
	runs, err := f.runs(in)
	var segs []dataSeg
	pos := int64(0)
	for _, r := range runs {
		start := int64(r.logical) * f.block
		if start >= size {
			break
		}
		if start > pos {
			segs = append(segs, dataSeg{-1, start - pos})
			pos = start
		}
		n := int64(r.count) * f.block
		if pos+n > size {
			n = size - pos
		}
		if r.zero {
			segs = append(segs, dataSeg{-1, n})
		} else {
			segs = append(segs, dataSeg{int64(r.physical) * f.block, n})
		}
		pos += n
	}
	if pos < size {
		segs = append(segs, dataSeg{-1, size - pos})
	}
	return &segReader{r: f.r, segs: segs}, size, err
}

// target returns a symbolic link's target when the inode holds it.
func (f *extFS) target(in *extInode) string {
	if in.mode&extModeType != extModeLink || in.size >= 60 || in.flags&(extFlagExtents|extFlagInline) != 0 {
		if in.mode&extModeType == extModeLink && in.size < 4096 {
			if r, n, err := f.data(in, in.size); err == nil {
				b := make([]byte, n)
				if _, err := io.ReadFull(r, b); err == nil {
					return strings.ToValidUTF8(string(b), "?")
				}
			}
		}
		return ""
	}
	return strings.ToValidUTF8(string(in.iblock[:in.size]), "?")
}

type extDirent struct {
	inode   uint32
	name    string
	ftype   byte
	offset  int64
	deleted bool
}

func plausibleExtName(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c == 0 || c == '/' {
			return false
		}
	}
	return true
}

// dirents reads a directory's names, in use and, from the unused space in
// its blocks, deleted.
func (f *extFS) dirents(dir *extInode) ([]extDirent, error) {
	r, n, err := f.data(dir, extMaxDir)
	if r == nil {
		return nil, err
	}
	b := make([]byte, n)
	k, rerr := io.ReadFull(r, b)
	b = b[:k]
	if err == nil {
		err = rerr
	}
	le := binary.LittleEndian
	hashed := dir.flags&extFlagIndex != 0
	start := 0
	chunk := int(f.block)
	if dir.flags&extFlagInline != 0 {
		// Inline: the parent's inode number, then entries to the end.
		start, chunk = 4, len(b)
	}
	var out []extDirent
	for blk := start; blk < len(b); blk += chunk {
		end := blk + chunk
		if end > len(b) {
			end = len(b)
		}
		if blk == start && start == 4 {
			end = len(b)
		}
		for pos := blk; pos+extDirentMin <= end; {
			ino, rec, nl := le.Uint32(b[pos:]), int(le.Uint16(b[pos+4:])), int(b[pos+6])
			if f.incompat&extIncompatFiletype == 0 {
				nl |= int(b[pos+7]) << 8
			}
			if rec < extDirentMin || rec%4 != 0 || pos+rec > end || nl > rec-extDirentMin {
				break
			}
			name := b[pos+8 : pos+8+nl]
			if ino != 0 && nl > 0 && ino <= f.inodes {
				out = append(out, extDirent{inode: ino, name: string(name), ftype: b[pos+7], offset: int64(pos)})
			}
			// A hashed directory keeps its index in what looks like the
			// unused space after "..", and in blocks of one empty entry.
			index := hashed && (string(name) == ".." || ino == 0 && rec == chunk)
			used := extDirentMin + (nl+3)&^3
			if ino != 0 && !index && rec-used >= extDirentMin+4 {
				out = append(out, f.slack(b[pos+used:pos+rec], int64(pos+used))...)
			}
			pos += rec
		}
	}
	return out, err
}

// slack finds deleted entries in the unused space after an entry: removing
// a name makes the entry before it longer, and its bytes stay.
func (f *extFS) slack(b []byte, base int64) []extDirent {
	le := binary.LittleEndian
	var out []extDirent
	for q := 0; q+extDirentMin < len(b); {
		ino, rec, nl, ft := le.Uint32(b[q:]), int(le.Uint16(b[q+4:])), int(b[q+6]), b[q+7]
		if ino != 0 && ino <= f.inodes && rec >= extDirentMin && rec%4 == 0 && nl > 0 && q+extDirentMin+nl <= len(b) &&
			(f.incompat&extIncompatFiletype == 0 || ft >= 1 && ft <= 7) && plausibleExtName(b[q+8:q+8+nl]) {
			name := string(b[q+8 : q+8+nl])
			if name != "." && name != ".." {
				out = append(out, extDirent{inode: ino, name: name, ftype: ft, offset: base + int64(q), deleted: true})
			}
			q += extDirentMin + (nl+3)&^3
			continue
		}
		q += 4
	}
	return out
}

func (f *extFS) entry(dir uint32, path string, d extDirent) (ExtEntry, *extInode) {
	e := ExtEntry{Path: path, Inode: d.inode, Deleted: d.deleted, Dir: dir, DirOffset: d.offset}
	in, err := f.inode(d.inode)
	if err != nil {
		e.Type = "unknown"
		return e, nil
	}
	free := in.links == 0
	if d.deleted && !free {
		// The inode has been given to another file since.
		e.InodeReused = true
		e.Type = map[byte]string{1: "file", 2: "directory", 7: "symbolic link"}[d.ftype]
		if e.Type == "" {
			e.Type = "unknown"
		}
		e.IsDir = d.ftype == 2
		return e, nil
	}
	e.Type, e.IsDir = extType(in.mode), in.mode&extModeType == extModeDir
	e.Size, e.Mode, e.UID, e.GID, e.Links = in.size, in.mode, in.uid, in.gid, in.links
	if e.IsDir {
		e.Size = 0
	}
	e.Modified, e.Accessed, e.Changed, e.Born = in.mtime, in.atime, in.ctime, in.crtime
	if free {
		e.InodeFree = true
		e.DeletedAt = in.dtime
	}
	e.Target = f.target(in)
	return e, in
}

// WalkExt calls fn for every name in an ext volume that starts at the
// beginning of r, deleted ones found in directory slack included,
// directories before their contents.
func WalkExt(r io.ReaderAt, size int64, fn func(ExtEntry) error) error {
	f, err := openExt(r, 0, size)
	if err != nil {
		return err
	}
	root, err := f.inode(extRootInode)
	if err != nil {
		return err
	}
	seen := map[uint32]bool{extRootInode: true}
	var firstErr error
	var walk func(path string, dir *extInode, depth int) error
	walk = func(path string, dir *extInode, depth int) error {
		if depth > extMaxDepth {
			return nil
		}
		list, err := f.dirents(dir)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %v", path, err)
		}
		for _, d := range list {
			if d.name == "." || d.name == ".." {
				continue
			}
			e, in := f.entry(dir.n, join(path, strings.ToValidUTF8(d.name, "?")), d)
			if err := fn(e); err != nil {
				return err
			}
			// A deleted directory's blocks are freed and may hold anything.
			if e.IsDir && !e.Deleted && in != nil && !seen[d.inode] {
				seen[d.inode] = true
				if err := walk(e.Path, in, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("/", root, 0); err != nil {
		return err
	}
	return firstErr
}

// ---- the FS interface ----

type extView struct{ f *extFS }

func (v *extView) Describe() string {
	f := v.f
	s := f.kind() + " volume"
	if f.label != "" {
		s += fmt.Sprintf(" %q", f.label)
	}
	u := f.uuid
	s += fmt.Sprintf(", UUID %x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	if f.lastMount != "" {
		s += ", last mounted at " + f.lastMount
	}
	if f.incompat&extIncompatRecover != 0 {
		s += ". Its journal has not been replayed, so the newest changes may be missing"
	}
	if f.incompat&extIncompatEncrypt != 0 {
		s += ". Some directories may be encrypted; their names are not readable"
	}
	return s
}

func (v *extView) Close() {}

func (v *extView) lookup(parts []string) (*extInode, string, error) {
	in, err := v.f.inode(extRootInode)
	if err != nil {
		return nil, "", err
	}
	path := "/"
	for _, p := range parts {
		if in.mode&extModeType != extModeDir {
			return nil, "", fmt.Errorf("%s is not a directory", path)
		}
		list, _ := v.f.dirents(in)
		var next uint32
		for _, d := range list {
			if !d.deleted && d.name == p {
				next = d.inode
				break
			}
		}
		if next == 0 {
			return nil, "", fmt.Errorf("%s: no such file or directory", join(path, p))
		}
		if in, err = v.f.inode(next); err != nil {
			return nil, "", err
		}
		path = join(path, p)
	}
	return in, path, nil
}

func unixNano(t ExtTime) int64 {
	if !t.Valid {
		return 0
	}
	return t.T.UnixNano()
}

func (v *extView) List(path string) ([]Entry, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	dir, dpath, err := v.lookup(parts)
	if err != nil {
		return nil, err
	}
	if dir.mode&extModeType != extModeDir {
		return nil, fmt.Errorf("%s is a file", path)
	}
	list, _ := v.f.dirents(dir)
	var out []Entry
	for _, d := range list {
		if d.deleted || d.name == "." || d.name == ".." {
			continue
		}
		e, _ := v.f.entry(dir.n, join(dpath, d.name), d)
		x := Entry{Name: d.name, Path: e.Path, IsDir: e.IsDir, Size: e.Size,
			Modified: unixNano(e.Modified), Accessed: unixNano(e.Accessed), Changed: unixNano(e.Changed), Born: unixNano(e.Born)}
		switch e.Type {
		case "file", "directory":
		case "symbolic link":
			x.Note = "symbolic link to " + e.Target
		default:
			x.Note = e.Type
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
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (v *extView) Open(path string) (io.Reader, int64, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	if len(parts) == 0 {
		return nil, 0, errors.New("the root is a directory")
	}
	in, _, err := v.lookup(parts)
	if err != nil {
		return nil, 0, err
	}
	switch in.mode & extModeType {
	case extModeFile:
	case extModeDir:
		return nil, 0, fmt.Errorf("%s is a directory", path)
	case extModeLink:
		return nil, 0, fmt.Errorf("%s is a symbolic link to %s; links are not followed", path, v.f.target(in))
	default:
		return nil, 0, fmt.Errorf("%s is a %s, which has no content", path, extType(in.mode))
	}
	r, n, err := v.f.data(in, in.size)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %v", path, err)
	}
	return r, n, nil
}

func openExtView(r io.ReaderAt, off, size int64) (FS, error) {
	f, err := openExt(r, off, size)
	if err != nil {
		return nil, err
	}
	return &extView{f: f}, nil
}

// ExtVolume is an ext2/3/4 volume found in an image.
type ExtVolume struct {
	Where    string
	Describe string
	Kind     string // ext2, ext3 or ext4
	UUID     string
	Label    string
	R        io.ReaderAt
	Size     int64
}

// ExtVolumes returns the ext volumes an opened image holds.
func ExtVolumes(fsys FS) []ExtVolume {
	vol := func(v *extView, where string) ExtVolume {
		u := v.f.uuid
		return ExtVolume{Where: where, Describe: v.Describe(), Kind: v.f.kind(), Label: v.f.label, R: v.f.r, Size: v.f.size,
			UUID: fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])}
	}
	switch v := fsys.(type) {
	case *extView:
		return []ExtVolume{vol(v, "/")}
	case *disk:
		var out []ExtVolume
		for _, p := range v.parts {
			if ev, ok := p.fs.(*extView); ok {
				out = append(out, vol(ev, fmt.Sprintf("/p%d", p.index)))
			}
		}
		return out
	case vdiskFS:
		return ExtVolumes(v.FS)
	case ewfFS:
		return ExtVolumes(v.FS)
	}
	return nil
}
