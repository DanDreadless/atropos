package winnotepad

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
	"unicode/utf16"
)

// The builders below write the layout as the decoder understands it. The
// file-tab, companion and window layouts were confirmed against state files
// written by Windows 11 Notepad, whose checksums agree. A tab with unsaved
// typing, a recorded file time and a never-saved tab follow the published
// description only: no real file of those kinds was available.

func uleb(v uint64) []byte {
	var out []byte
	for {
		c := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			out = append(out, c|0x80)
			continue
		}
		return append(out, c)
	}
}

func wide(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:], c)
	}
	return out
}

func chars(s string) uint64 { return uint64(len(utf16.Encode([]rune(s)))) }

func sum(b []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, crc32.ChecksumIEEE(b))
	return out
}

var opts = []byte{1, 0, 0, 3, 0, 0, 1} // three flags, then a counted block of three

// buildFileTab makes a tab opened from a file.
func buildFileTab(path string, filetime uint64, hash []byte, content string, edits ...Edit) []byte {
	var body bytes.Buffer
	body.Write(uleb(1))
	body.Write(uleb(chars(path)))
	body.Write(wide(path))
	body.Write(uleb(chars(content)))
	body.Write([]byte{5, 1})
	body.Write(uleb(filetime))
	if hash == nil {
		hash = make([]byte, 32)
	}
	body.Write(hash)
	body.Write([]byte{0, 1})
	body.Write(uleb(0))
	body.Write(uleb(0))
	body.Write(opts)
	body.Write(uleb(chars(content)))
	body.Write(wide(content))
	if len(edits) > 0 {
		body.WriteByte(1)
	} else {
		body.WriteByte(0)
	}
	return finish(body.Bytes(), edits)
}

func buildUnsavedTab(content string, edits ...Edit) []byte {
	var body bytes.Buffer
	body.Write(uleb(0))
	body.WriteByte(1)
	body.Write(uleb(0))
	body.Write(uleb(0))
	body.Write(opts)
	body.Write(uleb(chars(content)))
	body.Write(wide(content))
	body.WriteByte(1)
	return finish(body.Bytes(), edits)
}

func finish(body []byte, edits []Edit) []byte {
	out := append([]byte{'N', 'P', 0}, body...)
	out = append(out, sum(body)...)
	for _, e := range edits {
		var c bytes.Buffer
		c.Write(uleb(e.Position))
		c.Write(uleb(e.Deleted))
		c.Write(uleb(chars(e.Added)))
		c.Write(wide(e.Added))
		out = append(out, c.Bytes()...)
		out = append(out, sum(c.Bytes())...)
	}
	return out
}

func buildWindow(seq uint64, active uint64, tabs ...[16]byte) []byte {
	var body bytes.Buffer
	body.WriteByte(0)
	body.Write(uleb(uint64(len(tabs))))
	for _, g := range tabs {
		body.Write(g[:])
	}
	body.Write(uleb(active))
	body.Write(make([]byte, 25)) // window position and size
	head := append(uleb(seq), uleb(uint64(body.Len()))...)
	covered := append(head, body.Bytes()...)
	out := append([]byte{'N', 'P'}, covered...)
	return append(out, sum(covered)...)
}

func TestFileTab(t *testing.T) {
	hash := bytes.Repeat([]byte{0xAB}, 32)
	b := buildFileTab(`C:\Users\alice\notes.txt`, 133500000000000000, hash, "hello world",
		Edit{Position: 5, Deleted: 6, Added: ", there"}, Edit{Position: 0, Deleted: 1, Added: "H"})
	f, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindFileTab || f.Path != `C:\Users\alice\notes.txt` || f.FileTime != 133500000000000000 ||
		!bytes.Equal(f.FileSHA256, hash) || f.Encoding != "UTF-8" || f.LineEnding != "CRLF" || len(f.Edits) != 2 || !f.HasUnsaved {
		t.Errorf("decoded %+v", f)
	}
	if text, ok := f.Text(); text != "Hello, there" || !ok {
		t.Errorf("text with typing applied: %q %v", text, ok)
	}

	// Saved, nothing pending: no time, no hash, no text.
	f, err = Decode(buildFileTab(`C:\x.txt`, 0, nil, ""))
	if err != nil || f.FileTime != 0 || f.FileSHA256 != nil || f.HasUnsaved {
		t.Errorf("saved tab: %+v %v", f, err)
	}
}

func TestUnsavedTab(t *testing.T) {
	f, err := Decode(buildUnsavedTab("pässword: hunter2 🙂", Edit{Position: 0, Deleted: 0, Added: "my "}))
	if err != nil || f.Kind != KindUnsavedTab {
		t.Fatalf("%+v %v", f, err)
	}
	if text, ok := f.Text(); text != "my pässword: hunter2 🙂" || !ok {
		t.Errorf("text: %q %v", text, ok)
	}
}

func TestWindow(t *testing.T) {
	g := [16]byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	f, err := Decode(buildWindow(64, 1, g, g))
	if err != nil || f.Kind != KindWindow || len(f.Tabs) != 2 || f.ActiveTab != 1 || f.Sequence != 64 {
		t.Fatalf("%+v %v", f, err)
	}
	if f.Tabs[0] != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Errorf("tab identifier %s", f.Tabs[0])
	}
}

func TestRefusals(t *testing.T) {
	good := buildFileTab(`C:\x.txt`, 0, nil, "abc")
	if _, err := Decode([]byte("NPC is a role in a game, not a state file")); err != ErrLayout {
		t.Errorf("prose beginning NP: %v", err)
	}
	if _, err := Decode([]byte("MZ")); err != ErrNotState {
		t.Errorf("other content: %v", err)
	}
	// Any damage to the checked part is refused, never half-read.
	for i := 3; i < len(good)-4; i++ {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0x40
		if _, err := Decode(bad); err == nil {
			t.Errorf("damage at byte %d passed the checksum", i)
		}
	}
	// Typing whose checksum fails is reported, and what came before is kept.
	withEdit := buildFileTab(`C:\x.txt`, 1, nil, "abc", Edit{Position: 3, Added: "d"})
	withEdit[len(withEdit)-1] ^= 1
	f, err := Decode(withEdit)
	if err != nil || !f.EditsUnread || len(f.Edits) != 0 || f.Content != "abc" {
		t.Errorf("damaged typing: %+v %v", f, err)
	}
	// Lengths that run past the file must not allocate or panic.
	huge := append([]byte{'N', 'P', 0, 1}, bytes.Repeat([]byte{0xFF}, 9)...)
	huge = append(huge, 0x01, 0, 0, 0, 0)
	if _, err := Decode(huge); err == nil {
		t.Error("an impossible length was accepted")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(buildFileTab(`C:\x.txt`, 5, nil, "abc", Edit{Position: 1, Deleted: 1, Added: "z"}))
	f.Add(buildUnsavedTab("abc"))
	f.Add(buildWindow(1, 0, [16]byte{1}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := Decode(b); err == nil {
			s.Text()
		}
	})
}
