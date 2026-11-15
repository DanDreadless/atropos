// Package winnotepad decodes the state files the Windows 11 Notepad keeps so
// that it can reopen its tabs: one file per tab holding the text and, for a
// tab opened from a file, that file's path, with any typing not yet saved.
//
// The layout is not published. It is taken from the public research of
// ogmini (Notepad-State-Library) and checked here by the CRC-32 every part of
// a file carries: a decode is accepted only when the checksum agrees, so a
// layout this code does not know is refused rather than misread.
package winnotepad

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"unicode/utf16"
)

// Kinds of state file.
const (
	KindUnsavedTab = "tab without a file"
	KindFileTab    = "tab opened from a file"
	KindTabState   = "tab view state"
	KindWindow     = "window state"
)

// Edit is one piece of typing recorded after the tab's text was last
// written out: at Position, Deleted characters were removed and Added put in.
type Edit struct {
	Position uint64
	Deleted  uint64
	Added    string
}

// File is one decoded state file.
type File struct {
	Kind     string
	Sequence uint64

	// Tabs.
	Path          string // file tabs only
	SavedLength   uint64 // length of the file on disk when read, in characters
	Encoding      string
	LineEnding    string
	FileTime      uint64 // FILETIME of the file on disk; 0 when not recorded
	FileSHA256    []byte // of the file on disk; nil when not recorded
	Content       string
	ContentChars  uint64
	HasUnsaved    bool
	Edits         []Edit
	EditsUnread   bool // bytes after the last edit that did not decode
	SelectionFrom uint64
	SelectionTo   uint64

	// Window state.
	Tabs      []string // GUIDs of the tabs, in the order shown
	ActiveTab uint64
}

var (
	// ErrNotState means the bytes are not a Notepad state file at all.
	ErrNotState = errors.New("not a Windows Notepad state file")
	// ErrLayout means the file carries the signature but no known layout
	// gives a matching checksum.
	ErrLayout = errors.New("Windows Notepad state file in a layout that is not understood (no checksum agreed)")
)

type reader struct {
	b   []byte
	i   int
	bad bool
}

func (r *reader) byte() byte {
	if r.bad || r.i >= len(r.b) {
		r.bad = true
		return 0
	}
	r.i++
	return r.b[r.i-1]
}

func (r *reader) uleb() uint64 {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		c := r.byte()
		if r.bad {
			return 0
		}
		v |= uint64(c&0x7F) << shift
		if c&0x80 == 0 {
			return v
		}
	}
	r.bad = true
	return 0
}

func (r *reader) take(n uint64) []byte {
	if r.bad || n > uint64(len(r.b)-r.i) {
		r.bad = true
		return nil
	}
	r.i += int(n)
	return r.b[r.i-int(n) : r.i]
}

func (r *reader) text(chars uint64) string {
	if chars > uint64(len(r.b)) {
		r.bad = true
		return ""
	}
	raw := r.take(chars * 2)
	if r.bad {
		return ""
	}
	u := make([]uint16, chars)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(u))
}

// crc reads a stored checksum and reports whether it matches the bytes from
// start to here. The two-byte signature is never covered.
func (r *reader) crc(start int) bool {
	end := r.i
	stored := r.take(4)
	if r.bad {
		return false
	}
	return crc32.ChecksumIEEE(r.b[start:end]) == binary.BigEndian.Uint32(stored)
}

var encodings = map[byte]string{1: "ANSI", 2: "UTF-16 LE", 3: "UTF-16 BE", 4: "UTF-8 with BOM", 5: "UTF-8"}
var lineEndings = map[byte]string{1: "CRLF", 2: "CR", 3: "LF"}

// Signature reports whether b begins like a state file. Two letters prove
// little; Decode is the real test.
func Signature(b []byte) bool {
	return len(b) >= 8 && b[0] == 'N' && b[1] == 'P'
}

// Decode reads one state file. Each known layout is tried, and only one
// whose checksum agrees is returned.
func Decode(b []byte) (*File, error) {
	if !Signature(b) {
		return nil, ErrNotState
	}
	for _, try := range []func([]byte) *File{decodeTab, decodeCounted} {
		if f := try(b); f != nil {
			return f, nil
		}
	}
	return nil, ErrLayout
}

// options skips the display settings: three flags, then a counted block of
// further ones. Earlier builds wrote the three flags and one more byte.
func (r *reader) options(counted bool) {
	r.take(3)
	if counted {
		r.take(r.uleb())
	} else {
		r.take(1)
	}
}

func decodeTab(b []byte) *File {
	for _, counted := range []bool{true, false} {
		r := &reader{b: b, i: 2}
		f := &File{Sequence: r.uleb()}
		start := r.i // the checksum covers everything after the sequence number
		typ := r.uleb()
		switch typ {
		case 0:
			f.Kind = KindUnsavedTab
			r.byte()
		case 1:
			f.Kind = KindFileTab
			f.Path = r.text(r.uleb())
			f.SavedLength = r.uleb()
			f.Encoding, f.LineEnding = encodings[r.byte()], lineEndings[r.byte()]
			f.FileTime = r.uleb()
			hash := r.take(32)
			for _, c := range hash {
				if c != 0 {
					f.FileSHA256 = append([]byte(nil), hash...)
					break
				}
			}
			r.take(2)
		default:
			return nil
		}
		f.SelectionFrom, f.SelectionTo = r.uleb(), r.uleb()
		r.options(counted)
		f.ContentChars = r.uleb()
		f.Content = r.text(f.ContentChars)
		f.HasUnsaved = r.byte() != 0
		if !r.crc(start) || r.bad {
			continue
		}
		// Typing since the text above was written, each piece checksummed.
		for r.i < len(b) {
			start := r.i
			e := Edit{Position: r.uleb(), Deleted: r.uleb()}
			e.Added = r.text(r.uleb())
			if !r.crc(start) || r.bad {
				f.EditsUnread = true
				break
			}
			f.Edits = append(f.Edits, e)
		}
		return f
	}
	return nil
}

// decodeCounted reads the two small layouts that state their own length:
// a tab's companion file (where the cursor was) and the window's list of
// tabs. Their checksum covers the sequence number too.
func decodeCounted(b []byte) *File {
	r := &reader{b: b, i: 2}
	f := &File{Sequence: r.uleb()}
	n := r.uleb() // bytes from here to the checksum
	start := r.i
	if r.bad || n < 2 || n > uint64(len(b)-r.i) || start+int(n) > len(b)-4 {
		return nil
	}
	body := &reader{b: b[:start+int(n)], i: start}
	r.i = start + int(n)
	if !r.crc(2) {
		return nil
	}
	body.byte()
	// A window file lists whole 16-byte tab identifiers; a companion file is
	// far too short to hold one.
	if tabs := body.uleb(); !body.bad && tabs >= 1 && tabs <= (n-2)/16 {
		for i := uint64(0); i < tabs; i++ {
			f.Tabs = append(f.Tabs, guid(body.take(16)))
		}
		f.ActiveTab = body.uleb()
		if !body.bad {
			f.Kind = KindWindow
			return f
		}
	}
	f.Tabs, f.ActiveTab = nil, 0
	body.i = start + 1
	body.uleb() // size of the tab file it belongs to
	f.SelectionFrom, f.SelectionTo = body.uleb(), body.uleb()
	if body.bad {
		return nil
	}
	f.Kind = KindTabState
	return f
}

func guid(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	const hex = "0123456789abcdef"
	order := []int{3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15}
	out := make([]byte, 0, 36)
	for _, i := range order {
		if i < 0 {
			out = append(out, '-')
			continue
		}
		out = append(out, hex[b[i]>>4], hex[b[i]&15])
	}
	return string(out)
}

// Text returns the tab's text with the recorded typing applied, and whether
// every piece could be applied. Positions count UTF-16 units, as Notepad's do.
func (f *File) Text() (string, bool) {
	if len(f.Edits) == 0 {
		return f.Content, !f.EditsUnread
	}
	u := utf16.Encode([]rune(f.Content))
	ok := !f.EditsUnread
	for _, e := range f.Edits {
		if e.Position > uint64(len(u)) || e.Deleted > uint64(len(u))-e.Position {
			ok = false
			continue
		}
		add := utf16.Encode([]rune(e.Added))
		next := make([]uint16, 0, len(u)+len(add))
		next = append(next, u[:e.Position]...)
		next = append(next, add...)
		next = append(next, u[e.Position+e.Deleted:]...)
		u = next
	}
	return string(utf16.Decode(u)), ok
}
