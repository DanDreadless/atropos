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
	"unicode/utf16"
)

// FAT12, FAT16, FAT32 and exFAT: USB sticks, memory cards, cameras.
//
// Written from Joachim Metz's "File Allocation Table (FAT) file system
// format" (libfsfat) and, for exFAT, Microsoft's "exFAT file system
// specification".
//
// FAT12/16/32 store local wall-clock times with no zone, to two seconds
// (creation to 10 ms), and the day of last access without a time. exFAT
// stores each time with the offset from UTC of the clock that wrote it,
// when that clock knew it.

const (
	maxFATTable  = 512 << 20
	maxDirBytes  = 64 << 20
	maxFATDepth  = 64
	maxFATChain  = 1 << 26
	fatAttrDir   = 0x10
	fatAttrLabel = 0x08
	fatAttrLFN   = 0x0F
)

// FATTime is a time as a FAT or exFAT directory entry stores it.
type FATTime struct {
	Wall     time.Time // the clock reading, in a zone-less time.Time (its location is UTC but means nothing)
	Valid    bool
	DateOnly bool // FAT's last access: a day, no time
	// HasOffset is set when exFAT recorded the clock's offset from UTC;
	// OffsetMinutes is then that offset, and UTC() is the true time.
	HasOffset     bool
	OffsetMinutes int
}

// UTC is the true time, when the offset is known.
func (t FATTime) UTC() time.Time { return t.Wall.Add(-time.Duration(t.OffsetMinutes) * time.Minute) }

// FATEntry is one file or directory, in use or deleted.
type FATEntry struct {
	Path      string
	ShortName string // the 8.3 name, FAT12/16/32 only
	IsDir     bool
	Deleted   bool // the entry is marked unused; its name's first character is lost on FAT12/16/32
	// NameRecovered: a deleted FAT12/16/32 entry whose long name survived,
	// and whose short name's first character was worked out from it.
	NameRecovered bool
	Size          int64
	Cluster       uint32
	Created       FATTime
	Modified      FATTime
	Accessed      FATTime
	Offset        int64 // of the directory entry, in the volume
}

type fatFS struct {
	r          io.ReaderAt
	size       int64
	exfat      bool
	bits       int // 12, 16 or 32 (FAT)
	bps        int64
	cluster    int64
	fatOff     int64
	dataOff    int64 // byte offset of cluster 2
	clusters   uint32
	rootOff    int64 // FAT12/16: the fixed root directory
	rootLen    int64
	rootClust  uint32
	label      string
	serial     uint32
	mu         sync.Mutex
	fat        []byte // FAT12/16/32: the whole table
	exfatCache map[uint32]uint32
}

// openFAT opens a FAT or exFAT volume that starts at off.
func openFAT(r io.ReaderAt, off int64, size int64) (*fatFS, error) {
	if off != 0 {
		r = &shifted{r, off}
		size -= off
	}
	b, err := readAt(r, 0, 512)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	f := &fatFS{r: r, size: size}
	if string(b[3:11]) == "EXFAT   " {
		f.exfat = true
		if b[108] < 9 || b[108] > 12 || int(b[108])+int(b[109]) > 25 {
			return nil, errors.New("exFAT boot sector has an impossible sector or cluster size")
		}
		f.bps = 1 << b[108]
		f.cluster = f.bps << b[109]
		f.fatOff = int64(le.Uint32(b[80:])) * f.bps
		f.dataOff = int64(le.Uint32(b[88:])) * f.bps
		f.clusters = le.Uint32(b[92:])
		f.rootClust = le.Uint32(b[96:])
		f.serial = le.Uint32(b[100:])
		f.exfatCache = map[uint32]uint32{}
		if f.rootClust < 2 || f.clusters == 0 || f.rootClust > f.clusters+1 {
			return nil, errors.New("exFAT boot sector has no usable root directory")
		}
		return f, nil
	}
	f.bps = int64(le.Uint16(b[11:]))
	spc := int64(b[13])
	reserved := int64(le.Uint16(b[14:]))
	nfats := int64(b[16])
	rootEntries := int64(le.Uint16(b[17:]))
	total := int64(le.Uint16(b[19:]))
	if total == 0 {
		total = int64(le.Uint32(b[32:]))
	}
	fatSize := int64(le.Uint16(b[22:]))
	if fatSize == 0 {
		fatSize = int64(le.Uint32(b[36:]))
	}
	if f.bps < 512 || f.bps > 4096 || f.bps&(f.bps-1) != 0 || spc == 0 || spc&(spc-1) != 0 || reserved == 0 || nfats == 0 || fatSize == 0 || total == 0 {
		return nil, errors.New("not a FAT boot sector")
	}
	f.cluster = f.bps * spc
	rootSectors := (rootEntries*32 + f.bps - 1) / f.bps
	firstData := reserved + nfats*fatSize + rootSectors
	if firstData >= total {
		return nil, errors.New("FAT boot sector leaves no room for data")
	}
	n := (total - firstData) / spc
	f.clusters = uint32(n)
	switch {
	case n < 4085:
		f.bits = 12
	case n < 65525:
		f.bits = 16
	default:
		f.bits = 32
	}
	f.fatOff = reserved * f.bps
	f.dataOff = firstData * f.bps
	if f.bits == 32 {
		f.rootClust = le.Uint32(b[44:])
		f.serial = le.Uint32(b[67:])
		f.label = strings.TrimSpace(string(b[71:82]))
	} else {
		f.rootOff = (reserved + nfats*fatSize) * f.bps
		f.rootLen = rootEntries * 32
		f.serial = le.Uint32(b[39:])
		f.label = strings.TrimSpace(string(b[43:54]))
	}
	tableLen := fatSize * f.bps
	if tableLen > maxFATTable {
		return nil, fmt.Errorf("FAT table of %d bytes is larger than this version reads", tableLen)
	}
	if f.fat, err = readAt(r, f.fatOff, int(tableLen)); err != nil {
		return nil, errors.New("FAT table is cut short")
	}
	return f, nil
}

// next returns the cluster after c, and whether the chain goes on.
func (f *fatFS) next(c uint32) (uint32, bool) {
	le := binary.LittleEndian
	switch {
	case f.exfat:
		f.mu.Lock()
		v, ok := f.exfatCache[c]
		f.mu.Unlock()
		if !ok {
			b, err := readAt(f.r, f.fatOff+int64(c)*4, 4)
			if err != nil {
				return 0, false
			}
			v = le.Uint32(b)
			f.mu.Lock()
			if len(f.exfatCache) > 1<<20 {
				f.exfatCache = map[uint32]uint32{}
			}
			f.exfatCache[c] = v
			f.mu.Unlock()
		}
		return v, v >= 2 && v < 0xFFFFFFF7
	case f.bits == 12:
		i := int(c) + int(c)/2
		if i+2 > len(f.fat) {
			return 0, false
		}
		v := uint32(le.Uint16(f.fat[i:]))
		if c&1 == 1 {
			v >>= 4
		} else {
			v &= 0xFFF
		}
		return v, v >= 2 && v < 0xFF7
	case f.bits == 16:
		i := int(c) * 2
		if i+2 > len(f.fat) {
			return 0, false
		}
		v := uint32(le.Uint16(f.fat[i:]))
		return v, v >= 2 && v < 0xFFF7
	default:
		i := int(c) * 4
		if i+4 > len(f.fat) {
			return 0, false
		}
		v := le.Uint32(f.fat[i:]) & 0x0FFFFFFF
		return v, v >= 2 && v < 0x0FFFFFF7
	}
}

// extents returns the byte ranges of a cluster chain, up to limit bytes.
// contiguous is exFAT's NoFatChain: the clusters follow one another.
func (f *fatFS) extents(first uint32, limit int64, contiguous bool) ([][2]int64, error) {
	if first < 2 {
		return nil, nil
	}
	if contiguous {
		return [][2]int64{{f.dataOff + int64(first-2)*f.cluster, limit}}, nil
	}
	var out [][2]int64
	seen := map[uint32]bool{}
	got := int64(0)
	for c := first; got < limit; {
		if c < 2 || c > f.clusters+1 || seen[c] || len(seen) > maxFATChain {
			return out, errors.New("the cluster chain is broken or loops")
		}
		seen[c] = true
		n := f.cluster
		if limit-got < n {
			n = limit - got
		}
		at := f.dataOff + int64(c-2)*f.cluster
		if k := len(out); k > 0 && out[k-1][0]+out[k-1][1] == at {
			out[k-1][1] += n
		} else {
			out = append(out, [2]int64{at, n})
		}
		got += n
		nx, more := f.next(c)
		if !more {
			break
		}
		c = nx
	}
	return out, nil
}

type extentReader struct {
	r    io.ReaderAt
	ext  [][2]int64
	i    int
	in   int64
	left int64
}

func (e *extentReader) Read(p []byte) (int, error) {
	for e.i < len(e.ext) && e.in >= e.ext[e.i][1] {
		e.i++
		e.in = 0
	}
	if e.left <= 0 || e.i >= len(e.ext) {
		return 0, io.EOF
	}
	n := int64(len(p))
	if r := e.ext[e.i][1] - e.in; n > r {
		n = r
	}
	if n > e.left {
		n = e.left
	}
	k, err := e.r.ReadAt(p[:n], e.ext[e.i][0]+e.in)
	e.in += int64(k)
	e.left -= int64(k)
	if err == io.EOF && k > 0 {
		err = nil
	}
	return k, err
}

// dirBytes reads a directory's entries.
func (f *fatFS) dirBytes(cluster uint32, contiguous bool, length int64) ([]byte, int64, error) {
	if !f.exfat && f.bits != 32 && cluster == 0 {
		b, err := readAt(f.r, f.rootOff, int(f.rootLen))
		return b, f.rootOff, err
	}
	limit := int64(maxDirBytes)
	if contiguous && length > 0 && length < limit {
		limit = length
	}
	ext, err := f.extents(cluster, limit, contiguous)
	if len(ext) == 0 {
		return nil, 0, err
	}
	total := int64(0)
	for _, e := range ext {
		total += e[1]
	}
	b, rerr := io.ReadAll(&extentReader{r: f.r, ext: ext, left: total})
	if rerr != nil {
		return b, ext[0][0], rerr
	}
	return b, ext[0][0], err
}

func fatTime(date, tm uint16, tenMs byte) FATTime {
	if date == 0 {
		return FATTime{}
	}
	y, mo, d := int(date>>9)+1980, time.Month(date>>5&0xF), int(date&0x1F)
	h, mi, s := int(tm>>11), int(tm>>5&0x3F), int(tm&0x1F)*2
	if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59 || tenMs > 199 {
		return FATTime{}
	}
	t := time.Date(y, mo, d, h, mi, s, 0, time.UTC).Add(time.Duration(tenMs) * 10 * time.Millisecond)
	return FATTime{Wall: t, Valid: true}
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// shortName renders an 8.3 name, honouring Windows NT's lower-case flags.
func shortName(e []byte) string {
	base := []byte(strings.TrimRight(latin1(e[0:8]), " "))
	ext := strings.TrimRight(latin1(e[8:11]), " ")
	if len(base) > 0 && base[0] == 0x05 {
		base[0] = 0xE5
	}
	b := string(base)
	if e[12]&0x08 != 0 {
		b = strings.ToLower(b)
	}
	if e[12]&0x10 != 0 {
		ext = strings.ToLower(ext)
	}
	if ext != "" {
		return b + "." + ext
	}
	return b
}

// plausibleShort rejects what cannot be a directory entry: a cluster that
// once held a directory, read now, may hold anything.
func plausibleShort(e []byte) bool {
	if e[11]&0xC0 != 0 {
		return false
	}
	for i := 1; i < 11; i++ {
		if e[i] < 0x20 || strings.IndexByte(`"*+,/:;<=>?[\]|`, e[i]) >= 0 {
			return false
		}
	}
	return true
}

// plausibleFirst says whether c can begin a short name.
func plausibleFirst(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80 || strings.IndexByte("!#$%&'()-@^_`{}~", c) >= 0
}

func lfnChecksum(e []byte) byte {
	var s byte
	for i := 0; i < 11; i++ {
		s = (s>>1 | s<<7) + e[i]
	}
	return s
}

// entries reads one directory: its files and subdirectories, in use and
// deleted. dir is the path of the directory.
func (f *fatFS) entries(dir string, cluster uint32, contiguous bool, length int64) ([]FATEntry, error) {
	b, base, err := f.dirBytes(cluster, contiguous, length)
	if f.exfat {
		return f.exfatEntries(dir, b, base), err
	}
	le := binary.LittleEndian
	var out []FATEntry
	var lfn []string
	var lfnSum byte
	lfnDeleted := false
	for i := 0; i+32 <= len(b); i += 32 {
		e := b[i : i+32]
		if e[0] == 0 {
			break
		}
		deleted := e[0] == 0xE5
		if e[11]&0x3F == fatAttrLFN {
			part := make([]uint16, 0, 13)
			for _, r := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
				for k := r[0]; k+1 < r[1]; k += 2 {
					part = append(part, le.Uint16(e[k:]))
				}
			}
			s := ""
			for k, c := range part {
				if c == 0 || c == 0xFFFF {
					part = part[:k]
					break
				}
			}
			s = string(utf16.Decode(part))
			if len(lfn) == 0 || e[13] != lfnSum || deleted != lfnDeleted {
				lfn = nil
			}
			lfnDeleted = deleted
			lfn = append([]string{s}, lfn...)
			lfnSum = e[13]
			continue
		}
		if e[11]&fatAttrLabel != 0 {
			lfn = nil
			continue
		}
		if deleted && !plausibleShort(e) {
			lfn = nil
			continue
		}
		short := shortName(e)
		if short == "." || short == ".." {
			lfn = nil
			continue
		}
		recovered := false
		if deleted {
			// Deleting overwrote the first character. The long name's
			// checksum covers it, and only one value of that byte gives the
			// checksum recorded, so a deleted long name gives it back.
			c := append([]byte(nil), e[:11]...)
			c[0] = '_'
			if len(lfn) > 0 && lfnDeleted {
				for v := 0x21; v < 0x100; v++ {
					c[0] = byte(v)
					if lfnChecksum(c) == lfnSum {
						break
					}
				}
				if lfnChecksum(c) == lfnSum && plausibleFirst(c[0]) {
					recovered = true
				} else {
					c[0] = '_'
				}
			}
			short = shortName(append(c, e[11:]...))
		}
		name := short
		if len(lfn) > 0 && (recovered || !deleted && !lfnDeleted && lfnSum == lfnChecksum(e)) {
			name = strings.Join(lfn, "")
		}
		lfn = nil
		clust := uint32(le.Uint16(e[26:]))
		if f.bits == 32 {
			clust |= uint32(le.Uint16(e[20:])) << 16
		}
		fe := FATEntry{Path: join(dir, name), ShortName: short, IsDir: e[11]&fatAttrDir != 0, Deleted: deleted, NameRecovered: recovered,
			Size: int64(le.Uint32(e[28:])), Cluster: clust, Offset: base + int64(i),
			Created:  fatTime(le.Uint16(e[16:]), le.Uint16(e[14:]), e[13]),
			Modified: fatTime(le.Uint16(e[24:]), le.Uint16(e[22:]), 0),
			Accessed: fatTime(le.Uint16(e[18:]), 0, 0)}
		fe.Accessed.DateOnly = fe.Accessed.Valid
		if fe.IsDir {
			fe.Size = 0
		}
		out = append(out, fe)
	}
	return out, err
}

func exfatOffset(t *FATTime, b byte) {
	if b&0x80 == 0 || !t.Valid {
		return
	}
	v := int(b & 0x7F)
	if v >= 64 {
		v -= 128
	}
	t.HasOffset, t.OffsetMinutes = true, v*15
}

func (f *fatFS) exfatEntries(dir string, b []byte, base int64) []FATEntry {
	le := binary.LittleEndian
	var out []FATEntry
	for i := 0; i+32 <= len(b); i += 32 {
		e := b[i : i+32]
		if e[0] == 0 {
			break
		}
		// A file entry, in use (0x85) or deleted (0x05): its set follows.
		if e[0]&0x7F != 0x05 {
			continue
		}
		deleted := e[0]&0x80 == 0
		count := int(e[1])
		if count < 2 || i+32*(count+1) > len(b) {
			continue
		}
		s := b[i+32 : i+32*(count+1)]
		if s[0]&0x7F != 0x40 { // stream extension
			continue
		}
		nameLen := int(s[3])
		var u []uint16
		for k := 1; k < count && len(u) < nameLen; k++ {
			n := s[32*k:]
			if n[0]&0x7F != 0x41 {
				break
			}
			for j := 2; j+1 < 32 && len(u) < nameLen; j += 2 {
				u = append(u, le.Uint16(n[j:]))
			}
		}
		name := string(utf16.Decode(u))
		if name == "" {
			continue
		}
		fe := FATEntry{Path: join(dir, name), IsDir: le.Uint16(e[4:])&fatAttrDir != 0, Deleted: deleted,
			Size: int64(le.Uint64(s[24:])), Cluster: le.Uint32(s[20:]), Offset: base + int64(i)}
		ts := func(at int) (uint16, uint16) { return le.Uint16(e[at+2:]), le.Uint16(e[at:]) }
		cd, ct := ts(8)
		md, mt := ts(12)
		ad, at := ts(16)
		fe.Created, fe.Modified, fe.Accessed = fatTime(cd, ct, e[20]), fatTime(md, mt, e[21]), fatTime(ad, at, 0)
		exfatOffset(&fe.Created, e[22])
		exfatOffset(&fe.Modified, e[23])
		exfatOffset(&fe.Accessed, e[24])
		if s[1]&0x02 != 0 {
			fe.Cluster |= 1 << 31 // remembered: NoFatChain, the data is contiguous
		}
		if fe.IsDir {
			fe.Size = int64(le.Uint64(s[24:]))
		}
		out = append(out, fe)
		if !deleted {
			// A deleted set may have been partly overwritten by a newer one,
			// so only a set in use is skipped over whole.
			i += 32 * count
		}
	}
	return out
}

func (fe FATEntry) start() (uint32, bool) { return fe.Cluster &^ (1 << 31), fe.Cluster&(1<<31) != 0 }

// WalkFAT calls fn for every file and directory in a FAT or exFAT volume
// that starts at the beginning of r, deleted ones included, directories
// before their contents.
func WalkFAT(r io.ReaderAt, size int64, fn func(FATEntry) error) error {
	f, err := openFAT(r, 0, size)
	if err != nil {
		return err
	}
	seen := map[uint32]bool{}
	var walk func(dir string, cluster uint32, contiguous bool, length int64, depth int) error
	walk = func(dir string, cluster uint32, contiguous bool, length int64, depth int) error {
		if depth > maxFATDepth {
			return nil
		}
		list, _ := f.entries(dir, cluster, contiguous, length)
		for _, e := range list {
			if err := fn(e); err != nil {
				return err
			}
			c, cont := e.start()
			// A deleted directory's clusters may since hold anything.
			if e.IsDir && !e.Deleted && c >= 2 && !seen[c] {
				seen[c] = true
				if err := walk(e.Path, c, cont, e.Size, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk("/", f.rootClust, false, 0, 0)
}

// ---- the FS interface, for browsing and copying out ----

type fatView struct {
	f     *fatFS
	label string
}

func (v *fatView) Describe() string {
	kind := fmt.Sprintf("FAT%d volume", v.f.bits)
	if v.f.exfat {
		kind = "exFAT volume"
	}
	if v.f.label != "" && v.f.label != "NO NAME" {
		kind += fmt.Sprintf(" %q", v.f.label)
	}
	return fmt.Sprintf("%s, serial %04X-%04X%s", kind, v.f.serial>>16, v.f.serial&0xFFFF, v.label)
}

func (v *fatView) Close() {}

// find returns the entry at a path, from the root down.
func (v *fatView) find(parts []string) (*FATEntry, error) {
	cluster, cont, length := v.f.rootClust, false, int64(0)
	var cur *FATEntry
	dir := "/"
	for _, p := range parts {
		list, _ := v.f.entries(dir, cluster, cont, length)
		var hit *FATEntry
		for i := range list {
			e := list[i]
			n := e.Path[strings.LastIndex(e.Path, "/")+1:]
			if !e.Deleted && (strings.EqualFold(n, p) || strings.EqualFold(e.ShortName, p)) {
				hit = &list[i]
				break
			}
		}
		if hit == nil {
			return nil, fmt.Errorf("%s: no such file or directory", p)
		}
		cur = hit
		dir = hit.Path
		cluster, cont = hit.start()
		length = hit.Size
	}
	return cur, nil
}

func (v *fatView) List(path string) ([]Entry, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	cluster, cont, length := v.f.rootClust, false, int64(0)
	dir := "/"
	if len(parts) > 0 {
		e, err := v.find(parts)
		if err != nil {
			return nil, err
		}
		if !e.IsDir {
			return nil, fmt.Errorf("%s is a file", path)
		}
		dir = e.Path
		cluster, cont = e.start()
		length = e.Size
	}
	list, _ := v.f.entries(dir, cluster, cont, length)
	var out []Entry
	for _, e := range list {
		if e.Deleted {
			continue
		}
		x := Entry{Name: e.Path[strings.LastIndex(e.Path, "/")+1:], Path: e.Path, IsDir: e.IsDir, Size: e.Size,
			LocalTime: !(e.Modified.HasOffset)}
		if !e.IsDir {
			x.Size = e.Size
		} else {
			x.Size = 0
		}
		set := func(t FATTime, to *int64) {
			if t.Valid {
				if t.HasOffset {
					*to = t.UTC().UnixNano()
				} else {
					*to = t.Wall.UnixNano()
				}
			}
		}
		set(e.Modified, &x.Modified)
		set(e.Accessed, &x.Accessed)
		set(e.Created, &x.Born)
		if x.LocalTime {
			x.Note = "times are the device's local clock, zone not recorded"
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

func (v *fatView) Open(path string) (io.Reader, int64, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	if len(parts) == 0 {
		return nil, 0, errors.New("the root is a directory")
	}
	e, err := v.find(parts)
	if err != nil {
		return nil, 0, err
	}
	if e.IsDir {
		return nil, 0, fmt.Errorf("%s is a directory", path)
	}
	if e.Size == 0 {
		return strings.NewReader(""), 0, nil
	}
	c, cont := e.start()
	ext, err := v.f.extents(c, e.Size, cont)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %v", path, err)
	}
	return &extentReader{r: v.f.r, ext: ext, left: e.Size}, e.Size, nil
}

func openFATView(r io.ReaderAt, off, size int64, label string) (FS, error) {
	f, err := openFAT(r, off, size)
	if err != nil {
		return nil, err
	}
	return &fatView{f: f, label: label}, nil
}

// IsFATVolume says whether r begins with a FAT or exFAT boot sector.
func IsFATVolume(r io.ReaderAt) bool {
	switch sniff(r, 0) {
	case "FAT", "FAT32", "exFAT":
		_, err := openFAT(r, 0, 1<<62)
		return err == nil
	}
	return false
}

// FATVolume is a FAT or exFAT volume found in an image.
type FATVolume struct {
	Where    string // "/" for a volume on its own, "/p1" for a partition
	Describe string
	Serial   uint32
	Label    string
	R        io.ReaderAt // the volume, from its boot sector
	Size     int64
}

// FATVolumes returns the FAT and exFAT volumes an opened image holds: the
// image itself, or its partitions.
func FATVolumes(fsys FS) []FATVolume {
	vol := func(v *fatView, where string) FATVolume {
		return FATVolume{Where: where, Describe: v.Describe(), Serial: v.f.serial, Label: v.f.label, R: v.f.r, Size: v.f.size}
	}
	switch v := fsys.(type) {
	case *fatView:
		return []FATVolume{vol(v, "/")}
	case *disk:
		var out []FATVolume
		for _, p := range v.parts {
			if fv, ok := p.fs.(*fatView); ok {
				out = append(out, vol(fv, fmt.Sprintf("/p%d", p.index)))
			}
		}
		return out
	case vdiskFS:
		return FATVolumes(v.FS)
	case ewfFS:
		return FATVolumes(v.FS)
	}
	return nil
}

// Partitions describes what each partition of an opened disk image holds,
// for the examiner; it is empty for a volume or disc on its own.
func Partitions(fsys FS) []string {
	switch v := fsys.(type) {
	case *disk:
		var out []string
		for _, p := range v.parts {
			out = append(out, fmt.Sprintf("p%d: %s; contains %s", p.index, p.label, p.content))
		}
		return out
	case vdiskFS:
		return Partitions(v.FS)
	case ewfFS:
		return Partitions(v.FS)
	}
	return nil
}
