package imagefs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// Windows Explorer's thumbnail caches (thumbcache_*.db): small copies of
// pictures, videos and documents that were shown as thumbnails, often
// outliving the files. They hold no times. Each entry is named by an
// identifier, usually the file's ThumbnailCacheId in hexadecimal, which
// the Windows Search index records against the file's path.
//
// Written from Joachim Metz's "Windows Explorer Thumbnail Cache database
// format" (libwtcdb), and checked on real Windows 11 caches (format 32).
// A cache is shown as a folder of its thumbnails, to view and copy out.

const (
	thumbMaxEntries = 1 << 20
	thumbMaxData    = 64 << 20
)

type thumbEntry struct {
	name     string
	id       string
	dataOff  int64
	dataSize int64
	entryOff int64
}

type thumbFS struct {
	r        io.ReaderAt
	version  uint32
	cacheTyp uint32
	entries  []thumbEntry
	empty    int
	kinds    map[string]int
	stopped  string
}

// IsThumbcache says whether b begins a thumbnail cache.
func IsThumbcache(b []byte) bool {
	if len(b) < 24 || string(b[:4]) != "CMMM" {
		return false
	}
	switch binary.LittleEndian.Uint32(b[4:]) {
	case 20, 21, 30, 31, 32:
		return true
	}
	return false
}

func thumbKind(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("BM")):
		return "bmp"
	case bytes.HasPrefix(head, []byte("\x89PNG")):
		return "png"
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8}):
		return "jpg"
	}
	return "bin"
}

// thumbSafe keeps an identifier usable as a file name.
func thumbSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		s = "(no identifier)"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func openThumbcache(r io.ReaderAt, size int64) (*thumbFS, error) {
	h, err := readAt(r, 0, 24)
	if err != nil || !IsThumbcache(h) {
		return nil, errors.New("not a thumbnail cache")
	}
	le := binary.LittleEndian
	t := &thumbFS{r: r, version: le.Uint32(h[4:]), cacheTyp: le.Uint32(h[8:]), kinds: map[string]int{}}
	header := int64(56)
	if t.version == 21 {
		header = 48
	}
	seen := map[string]int{}
	for off := int64(24); off+header <= size; {
		if len(t.entries)+t.empty >= thumbMaxEntries {
			t.stopped = fmt.Sprintf("more than %d entries; the rest were not read", thumbMaxEntries)
			break
		}
		e, err := readAt(r, off, int(header))
		if err != nil {
			break
		}
		if string(e[:4]) != "CMMM" {
			t.stopped = fmt.Sprintf("an entry at offset %d has no signature; reading stopped there", off)
			break
		}
		esize := int64(le.Uint32(e[4:]))
		var idSize, pad, dataSize int64
		switch t.version {
		case 20:
			idSize, pad, dataSize = int64(le.Uint32(e[24:])), int64(le.Uint32(e[28:])), int64(le.Uint32(e[32:]))
		default:
			idSize, pad, dataSize = int64(le.Uint32(e[16:])), int64(le.Uint32(e[20:])), int64(le.Uint32(e[24:]))
		}
		if esize < header || off+esize > size || header+idSize+pad+dataSize > esize || idSize%2 != 0 || dataSize > thumbMaxData {
			if esize >= header && off+esize <= size && dataSize == 0 && idSize == 0 {
				off += esize // the free space at the end of the file
				continue
			}
			t.stopped = fmt.Sprintf("the entry at offset %d has impossible sizes; reading stopped there", off)
			break
		}
		idb, err := readAt(r, off+header, int(idSize))
		if err != nil {
			break
		}
		u := make([]uint16, idSize/2)
		for i := range u {
			u[i] = le.Uint16(idb[2*i:])
		}
		id := string(utf16.Decode(u))
		if dataSize == 0 {
			if idSize > 0 {
				t.empty++ // with neither, the entry is the file's free space
			}
			off += esize
			continue
		}
		dataOff := off + header + idSize + pad
		head, _ := readAt(r, dataOff, 4)
		kind := thumbKind(head)
		t.kinds[kind]++
		name := thumbSafe(id) + "." + kind
		if n := seen[name]; n > 0 {
			name = fmt.Sprintf("%s~%d.%s", thumbSafe(id), n+1, kind)
		}
		seen[thumbSafe(id)+"."+kind]++
		t.entries = append(t.entries, thumbEntry{name: name, id: id, dataOff: dataOff, dataSize: dataSize, entryOff: off})
		off += esize
	}
	return t, nil
}

func (t *thumbFS) Describe() string {
	era := map[uint32]string{20: "Windows Vista", 21: "Windows 7", 30: "Windows 8", 31: "Windows 8.1", 32: "Windows 10 or 11"}[t.version]
	s := fmt.Sprintf("Thumbnail cache (format %d, %s, cache type %d): %d thumbnails (%d JPEG, %d PNG, %d BMP, %d other), %d entries without a picture",
		t.version, era, t.cacheTyp, len(t.entries), t.kinds["jpg"], t.kinds["png"], t.kinds["bmp"], t.kinds["bin"], t.empty)
	if t.stopped != "" {
		s += "; " + t.stopped
	}
	return s
}

func (t *thumbFS) Close() {}

func (t *thumbFS) List(path string) ([]Entry, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	if len(parts) > 0 {
		return nil, fmt.Errorf("%s: a thumbnail cache has no folders", path)
	}
	out := make([]Entry, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, Entry{Name: e.name, Path: "/" + e.name, Size: e.dataSize,
			Note: fmt.Sprintf("thumbnail, identifier %s, cache entry at offset %d", e.id, e.entryOff)})
		if len(out) >= MaxListing {
			break
		}
	}
	return out, nil
}

func (t *thumbFS) Open(path string) (io.Reader, int64, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	if len(parts) != 1 {
		return nil, 0, errors.New("not a thumbnail")
	}
	for _, e := range t.entries {
		if e.name == parts[0] {
			return io.NewSectionReader(t.r, e.dataOff, e.dataSize), e.dataSize, nil
		}
	}
	return nil, 0, fmt.Errorf("%s: no such thumbnail", path)
}

// Thumbnails lists a cache's thumbnails: identifier, kind, size and where
// each is, for the parser.
type Thumbnail struct {
	ID, Name    string
	Size        int64
	EntryOffset int64
}

func Thumbnails(r io.ReaderAt, size int64) ([]Thumbnail, string, error) {
	t, err := openThumbcache(r, size)
	if err != nil {
		return nil, "", err
	}
	out := make([]Thumbnail, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, Thumbnail{ID: e.id, Name: e.name, Size: e.dataSize, EntryOffset: e.entryOff})
	}
	return out, t.Describe(), nil
}
