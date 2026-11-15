package imagefs

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
)

// Expert Witness Format, version 1 (EnCase and FTK Imager ".E01" images).
//
// Written from Joachim Metz's "Expert Witness Compression Format (EWF)"
// specification (the libewf project). A segment file is a 13-byte header and
// a chain of sections, each with a 76-byte descriptor. The media is stored
// as chunks (64 sectors by default), each either zlib-compressed or stored
// with an Adler-32 after it; "table" sections give the chunks' offsets. An
// image is usually split across several segment files, which are matched
// here by the set identifier inside them and never by name.
//
// Not read: EWF-S01 (SMART), EnCase 1 (chunks inside the table section),
// logical evidence files (L01) and EWF version 2 (Ex01).

const (
	ewfSignature   = "EVF\x09\x0d\x0a\xff\x00"
	ewfDescriptor  = 76
	ewfVolumeSize  = 1052
	ewfMaxSections = 1 << 20
	ewfMaxChunk    = 64 << 20
	ewfMaxHeader   = 16 << 20
	ewfCacheChunks = 32
)

// EWFSegment is one segment file of an image.
type EWFSegment struct {
	R    io.ReaderAt
	Size int64
}

// EWFInfo is what one segment file says about itself and its image.
type EWFInfo struct {
	Segment         int    // this file's number in the set, from 1
	SetID           string // identifier shared by the segments of one image; empty when the writer set none
	HasGeometry     bool
	ChunkCount      uint32
	SectorsPerChunk uint32
	BytesPerSector  uint32
	Sectors         uint64
	Chunks          int               // chunks whose offsets this segment holds
	Last            bool              // this segment ends the set
	MD5             string            // of the media, as stored by the tool that made the image
	SHA1            string            // likewise, when present
	Header          map[string]string // acquisition details: case number, examiner and so on
	Notes           []string
}

// MediaSize is the size of the disk or volume the image was taken of.
func (i *EWFInfo) MediaSize() int64 { return int64(i.Sectors) * int64(i.BytesPerSector) }

func (i *EWFInfo) key() string {
	return fmt.Sprintf("%s/%d/%d/%d/%d", i.SetID, i.ChunkCount, i.SectorsPerChunk, i.BytesPerSector, i.Sectors)
}

// ewfHeaderNames are the acquisition details an image carries.
var ewfHeaderNames = map[string]string{"c": "case_number", "n": "evidence_number", "a": "description", "e": "examiner", "t": "notes",
	"av": "acquisition_software_version", "ov": "acquisition_platform", "m": "acquired", "u": "system_time_at_acquisition",
	"md": "device_model", "sn": "device_serial_number", "l": "device_label", "r": "compression"}

type ewfTable struct {
	base    int64    // what the entries' offsets are relative to
	end     int64    // where the last chunk of this table stops
	entries []uint32 // top bit: compressed
}

type ewfScan struct {
	EWFInfo
	tables []ewfTable
}

func ewfIsSignature(r io.ReaderAt) bool {
	b, err := readAt(r, 0, 8)
	return err == nil && string(b) == ewfSignature
}

// scanSegment walks the sections of one segment file.
func scanSegment(r io.ReaderAt, size int64) (*ewfScan, error) {
	head, err := readAt(r, 0, 13)
	if err != nil || string(head[:8]) != ewfSignature {
		return nil, errors.New("not an Expert Witness (E01) segment file")
	}
	s := &ewfScan{}
	s.Segment = int(binary.LittleEndian.Uint16(head[9:]))
	if s.Segment == 0 {
		return nil, errors.New("E01 segment number 0 is not valid")
	}
	note := func(f string, a ...any) {
		if len(s.Notes) < 50 {
			s.Notes = append(s.Notes, fmt.Sprintf(f, a...))
		}
	}
	var sectorsEnd int64 // end of the chunk data the next table describes
	var badTable bool    // the last table failed its checksum; its mirror may serve
	off := int64(13)
	for n := 0; ; n++ {
		if n >= ewfMaxSections {
			return nil, errors.New("E01 segment has more sections than any real image")
		}
		d, err := readAt(r, off, ewfDescriptor)
		if err != nil {
			return nil, fmt.Errorf("E01 section descriptor at offset %d cannot be read: the segment is cut short", off)
		}
		if adler32.Checksum(d[:72]) != binary.LittleEndian.Uint32(d[72:]) {
			return nil, fmt.Errorf("E01 section descriptor at offset %d fails its checksum", off)
		}
		kind := string(bytes.TrimRight(d[:16], "\x00"))
		next := int64(binary.LittleEndian.Uint64(d[16:]))
		secSize := int64(binary.LittleEndian.Uint64(d[24:]))
		data := off + ewfDescriptor
		// Some writers leave the size empty; the next section bounds it.
		dataLen := secSize - ewfDescriptor
		if secSize == 0 && next > off {
			dataLen = next - data
		}
		if dataLen < 0 || data+dataLen > size {
			if kind != "next" && kind != "done" {
				return nil, fmt.Errorf("E01 %q section at offset %d runs past the end of the segment", kind, off)
			}
			dataLen = 0
		}
		switch kind {
		case "header", "header2", "xheader":
			if s.Header == nil || kind == "header2" {
				if h := ewfHeader(r, data, dataLen); len(h) > 0 {
					s.Header = h
				}
			}
		case "volume", "disk", "data":
			if dataLen < ewfVolumeSize {
				if kind == "data" {
					break
				}
				return nil, fmt.Errorf("E01 %q section is %d bytes: this is the SMART (S01) or an early EnCase layout, which is not read", kind, dataLen)
			}
			v, err := readAt(r, data, ewfVolumeSize)
			if err != nil {
				return nil, err
			}
			if adler32.Checksum(v[:1048]) != binary.LittleEndian.Uint32(v[1048:]) {
				if kind == "data" {
					note("the %q section fails its checksum and was not used", kind)
					break
				}
				return nil, fmt.Errorf("E01 %q section fails its checksum", kind)
			}
			if s.HasGeometry && kind == "data" {
				break
			}
			s.HasGeometry = true
			s.ChunkCount = binary.LittleEndian.Uint32(v[4:])
			s.SectorsPerChunk = binary.LittleEndian.Uint32(v[8:])
			s.BytesPerSector = binary.LittleEndian.Uint32(v[12:])
			s.Sectors = binary.LittleEndian.Uint64(v[16:])
			if id := v[64:80]; !bytes.Equal(id, make([]byte, 16)) {
				s.SetID = hex.EncodeToString(id)
			}
		case "sectors":
			sectorsEnd = data + dataLen
		case "table", "table2":
			if kind == "table2" && !badTable {
				break // a mirror of the table before it
			}
			if sectorsEnd == 0 {
				return nil, errors.New("E01 table with no sectors section before it: the EnCase 1 layout, which is not read")
			}
			t, err := ewfReadTable(r, data, dataLen, sectorsEnd)
			if err != nil {
				if kind == "table" {
					badTable = true
					note("a chunk table fails its checksum (%v); its mirror copy is used if sound", err)
					break
				}
				return nil, fmt.Errorf("E01 chunk table and its mirror are both unusable: %v", err)
			}
			badTable = false
			s.tables = append(s.tables, *t)
			s.Chunks += len(t.entries)
		case "hash":
			if h, err := readAt(r, data, 36); err == nil && dataLen >= 36 && adler32.Checksum(h[:32]) == binary.LittleEndian.Uint32(h[32:]) {
				s.MD5 = hex.EncodeToString(h[:16])
			} else {
				note("the stored hash section is damaged and was not used")
			}
		case "digest":
			if h, err := readAt(r, data, 80); err == nil && dataLen >= 80 && adler32.Checksum(h[:76]) == binary.LittleEndian.Uint32(h[76:]) {
				if !bytes.Equal(h[:16], make([]byte, 16)) {
					s.MD5 = hex.EncodeToString(h[:16])
				}
				if !bytes.Equal(h[16:36], make([]byte, 20)) {
					s.SHA1 = hex.EncodeToString(h[16:36])
				}
			}
		case "done":
			s.Last = true
		}
		if kind == "done" || kind == "next" {
			break
		}
		if next <= off || next > size-ewfDescriptor {
			return nil, fmt.Errorf("E01 %q section at offset %d points to offset %d, which cannot be the next section", kind, off, next)
		}
		off = next
	}
	if badTable {
		return nil, errors.New("E01 chunk table fails its checksum and has no mirror")
	}
	return s, nil
}

func ewfReadTable(r io.ReaderAt, data, dataLen, sectorsEnd int64) (*ewfTable, error) {
	if dataLen < 24 {
		return nil, errors.New("table shorter than its header")
	}
	h, err := readAt(r, data, 24)
	if err != nil {
		return nil, err
	}
	if adler32.Checksum(h[:20]) != binary.LittleEndian.Uint32(h[20:]) {
		return nil, errors.New("table header checksum")
	}
	count := int64(binary.LittleEndian.Uint32(h[0:]))
	if count == 0 || count*4 > dataLen-24 {
		return nil, fmt.Errorf("table declares %d entries, which its %d bytes cannot hold", count, dataLen)
	}
	raw, err := readAt(r, data+24, int(count*4))
	if err != nil {
		return nil, err
	}
	// The footer checksum is absent in some writers' tables; when there is
	// room for it, it must agree.
	if dataLen >= 24+count*4+4 {
		if f, err := readAt(r, data+24+count*4, 4); err == nil && adler32.Checksum(raw) != binary.LittleEndian.Uint32(f) {
			return nil, errors.New("table entries checksum")
		}
	}
	t := &ewfTable{base: int64(binary.LittleEndian.Uint64(h[8:])), end: sectorsEnd, entries: make([]uint32, count)}
	if t.base < 0 {
		return nil, errors.New("table base offset")
	}
	for i := range t.entries {
		t.entries[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	return t, nil
}

// ewfHeader reads the acquisition details: zlib-compressed text, a table of
// tab-separated names on one line and values on the next.
func ewfHeader(r io.ReaderAt, off, n int64) map[string]string {
	if n <= 0 || n > ewfMaxHeader {
		return nil
	}
	zr, err := zlib.NewReader(io.NewSectionReader(r, off, n))
	if err != nil {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(zr, ewfMaxHeader))
	var text string
	if len(raw) >= 2 && (raw[0] == 0xFF && raw[1] == 0xFE) {
		u := make([]uint16, 0, len(raw)/2)
		for i := 2; i+1 < len(raw); i += 2 {
			u = append(u, binary.LittleEndian.Uint16(raw[i:]))
		}
		text = string(utf16.Decode(u))
	} else {
		text = string(raw)
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r", ""), "\n")
	out := map[string]string{}
	// The names are on the line after "main"; the values on the one after that.
	for i := 0; i+2 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "main" {
			continue
		}
		names, values := strings.Split(lines[i+1], "\t"), strings.Split(lines[i+2], "\t")
		for k, name := range names {
			if k >= len(values) || values[k] == "" {
				continue
			}
			label, known := ewfHeaderNames[strings.TrimSpace(name)]
			if !known {
				continue // includes the password hash, which is of no use to anyone
			}
			v := strings.ToValidUTF8(values[k], "�")
			if len(v) > 4000 {
				v = v[:4000]
			}
			out[label] = v
		}
		break
	}
	return out
}

// InspectEWF reads what one segment file says, without the other segments.
func InspectEWF(r io.ReaderAt, size int64) (*EWFInfo, error) {
	s, err := scanSegment(r, size)
	if err != nil {
		return nil, err
	}
	return &s.EWFInfo, nil
}

// EWF is the media inside an image, read through its segments.
type EWF struct {
	Info     EWFInfo // of the whole set: geometry, stored hashes, acquisition details
	Segments int

	segs      []EWFSegment
	tables    []ewfSetTable
	chunkSize int64
	size      int64

	mu    sync.Mutex
	cache map[int][]byte
	order []int
}

type ewfSetTable struct {
	ewfTable
	seg   int // index into segs
	first int // number of this table's first chunk
}

// OpenEWF assembles an image from the segment given and whichever of the
// candidates belong to the same set. Candidates that are not segments of
// this image are ignored.
func OpenEWF(primary EWFSegment, candidates []EWFSegment) (*EWF, error) {
	first, err := scanSegment(primary.R, primary.Size)
	if err != nil {
		return nil, err
	}
	if !first.HasGeometry {
		return nil, fmt.Errorf("E01 segment %d does not describe the media, so its set cannot be identified", first.Segment)
	}
	type member struct {
		scan *ewfScan
		seg  EWFSegment
	}
	// Candidates of the same set, by segment number. Without a set
	// identifier, two images of the same disk look alike, so a number may
	// have more than one claimant.
	claims := map[int][]member{}
	top := first.Segment
	for _, c := range candidates {
		if !ewfIsSignature(c.R) {
			continue
		}
		sc, err := scanSegment(c.R, c.Size)
		if err != nil || !sc.HasGeometry || sc.key() != first.key() || sc.Segment == first.Segment {
			continue
		}
		claims[sc.Segment] = append(claims[sc.Segment], member{sc, c})
		if sc.Segment > top {
			top = sc.Segment
		}
	}
	set := map[int]member{first.Segment: {first, primary}}
	for n, ms := range claims {
		// Only the highest segment can be the one that ends the set: a
		// lower one that does belongs to a shorter image of the same disk.
		var fit []member
		for _, m := range ms {
			if m.scan.Last == (n == top) || first.SetID != "" {
				fit = append(fit, m)
			}
		}
		if first.Last && n > first.Segment {
			continue // the segment given ends its set; nothing follows it
		}
		switch {
		case len(fit) == 1 || len(fit) > 1 && first.SetID != "":
			set[n] = fit[0]
		case len(fit) > 1:
			return nil, fmt.Errorf("%d different files all claim to be segment %d of an image with no set identifier; they cannot be told apart", len(fit), n)
		}
	}
	nums := make([]int, 0, len(set))
	for n := range set {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	var missing []string
	for want := 1; want <= nums[len(nums)-1]; want++ {
		if _, ok := set[want]; !ok && len(missing) < 20 {
			missing = append(missing, fmt.Sprint(want))
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the E01 image is incomplete: segment %s of its set is not in the case. Add every segment file (.E01, .E02 …) and open it again", strings.Join(missing, ", "))
	}
	last := set[nums[len(nums)-1]].scan
	if !last.Last {
		return nil, fmt.Errorf("the E01 image is incomplete: its set continues after segment %d, and the later segments are not in the case. Add every segment file (.E01, .E02 …) and open it again", last.Segment)
	}

	e := &EWF{Info: first.EWFInfo, Segments: len(nums), cache: map[int][]byte{}}
	e.chunkSize = int64(first.SectorsPerChunk) * int64(first.BytesPerSector)
	if first.BytesPerSector == 0 || first.BytesPerSector > 1<<16 || e.chunkSize <= 0 || e.chunkSize > ewfMaxChunk {
		return nil, fmt.Errorf("E01 geometry is not credible: %d sectors of %d bytes to a chunk", first.SectorsPerChunk, first.BytesPerSector)
	}
	e.size = first.MediaSize()
	total := 0
	for i, n := range nums {
		m := set[n]
		e.segs = append(e.segs, m.seg)
		for _, t := range m.scan.tables {
			e.tables = append(e.tables, ewfSetTable{ewfTable: t, seg: i, first: total})
			total += len(t.entries)
		}
		// Stored hashes and acquisition details sit in the first or the last segment.
		if m.scan.MD5 != "" {
			e.Info.MD5 = m.scan.MD5
		}
		if m.scan.SHA1 != "" {
			e.Info.SHA1 = m.scan.SHA1
		}
		if len(e.Info.Header) == 0 {
			e.Info.Header = m.scan.Header
		}
		e.Info.Notes = append(e.Info.Notes, m.scan.Notes...)
	}
	e.Info.Chunks, e.Info.Last = total, true
	if e.size <= 0 || e.size > int64(total)*e.chunkSize {
		return nil, fmt.Errorf("the E01 image declares %d bytes of media but holds %d chunks of %d bytes", e.size, total, e.chunkSize)
	}
	if uint32(total) != first.ChunkCount {
		e.Info.Notes = append(e.Info.Notes, fmt.Sprintf("the image declares %d chunks and its tables list %d", first.ChunkCount, total))
	}
	return e, nil
}

// Size is the size of the media.
func (e *EWF) Size() int64 { return e.size }

// chunk returns the content of chunk n, checked against its checksum.
func (e *EWF) chunk(n int) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if b, ok := e.cache[n]; ok {
		return b, nil
	}
	ti := sort.Search(len(e.tables), func(i int) bool { return e.tables[i].first > n }) - 1
	if ti < 0 {
		return nil, fmt.Errorf("E01 chunk %d is not in any table", n)
	}
	t := &e.tables[ti]
	i := n - t.first
	if i >= len(t.entries) {
		return nil, fmt.Errorf("E01 chunk %d is not in any table", n)
	}
	seg := e.segs[t.seg]
	start := t.base + int64(t.entries[i]&0x7FFFFFFF)
	end := t.end
	if i+1 < len(t.entries) {
		end = t.base + int64(t.entries[i+1]&0x7FFFFFFF)
	}
	if start < 13 || end <= start || end > seg.Size {
		return nil, fmt.Errorf("E01 chunk %d has an offset outside its segment", n)
	}
	want := e.chunkSize
	if rest := e.size - int64(n)*e.chunkSize; rest < want {
		want = rest
	}
	var out []byte
	if t.entries[i]&0x80000000 != 0 {
		zr, err := zlib.NewReader(io.NewSectionReader(seg.R, start, end-start))
		if err != nil {
			return nil, fmt.Errorf("E01 chunk %d: %v", n, err)
		}
		out, err = io.ReadAll(io.LimitReader(zr, e.chunkSize+1))
		if err != nil {
			return nil, fmt.Errorf("E01 chunk %d is damaged: %v", n, err)
		}
	} else {
		if end-start < 4 || end-start-4 > e.chunkSize {
			return nil, fmt.Errorf("E01 chunk %d is %d bytes, which is not a chunk and its checksum", n, end-start)
		}
		raw, err := readAt(seg.R, start, int(end-start))
		if err != nil {
			return nil, fmt.Errorf("E01 chunk %d: %v", n, err)
		}
		out = raw[:len(raw)-4]
		if adler32.Checksum(out) != binary.LittleEndian.Uint32(raw[len(raw)-4:]) {
			return nil, fmt.Errorf("E01 chunk %d fails its checksum: the image is damaged there", n)
		}
	}
	if int64(len(out)) < want || int64(len(out)) > e.chunkSize {
		return nil, fmt.Errorf("E01 chunk %d holds %d bytes where %d are expected", n, len(out), want)
	}
	out = out[:want]
	if len(e.order) >= ewfCacheChunks {
		delete(e.cache, e.order[0])
		e.order = e.order[1:]
	}
	e.cache[n], e.order = out, append(e.order, n)
	return out, nil
}

// ReadAt reads the media.
func (e *EWF) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	done := 0
	for done < len(p) {
		if off >= e.size {
			return done, io.EOF
		}
		c, err := e.chunk(int(off / e.chunkSize))
		if err != nil {
			return done, err
		}
		in := off % e.chunkSize
		if in >= int64(len(c)) {
			return done, io.EOF
		}
		n := copy(p[done:], c[in:])
		done += n
		off += int64(n)
	}
	return done, nil
}

// MediaHashes reads the whole of the media and returns its MD5 and SHA-1,
// for comparison with those the imaging tool stored. Every chunk is also
// checked against its own checksum on the way.
func (e *EWF) MediaHashes() (md5sum, sha1sum string, err error) {
	m, s := md5.New(), sha1.New()
	chunks := int((e.size + e.chunkSize - 1) / e.chunkSize)
	for n := 0; n < chunks; n++ {
		c, err := e.chunk(n)
		if err != nil {
			return "", "", err
		}
		m.Write(c)
		s.Write(c)
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

// MediaMD5 is the MD5 of the media.
func (e *EWF) MediaMD5() (string, error) {
	m, _, err := e.MediaHashes()
	return m, err
}

// ewfFS is a file system found inside an E01 image.
type ewfFS struct {
	FS
	segments int
}

func (f ewfFS) Describe() string {
	if f.segments == 1 {
		return f.FS.Describe() + ", inside an E01 image"
	}
	return fmt.Sprintf("%s, inside an E01 image of %d segments", f.FS.Describe(), f.segments)
}

func openEWF(r io.ReaderAt, size int64, others []EWFSegment) (FS, error) {
	e, err := OpenEWF(EWFSegment{r, size}, others)
	if err != nil {
		return nil, err
	}
	if ewfIsSignature(e) {
		return nil, errors.New("an E01 image inside an E01 image is not opened")
	}
	inner, err := Open(e, e.Size())
	if err != nil {
		if errors.Is(err, ErrNoFileSystem) {
			return nil, fmt.Errorf("the E01 image opened (%d bytes of media in %d segments), but %w", e.Size(), e.Segments, err)
		}
		return nil, err
	}
	return ewfFS{inner, e.Segments}, nil
}
