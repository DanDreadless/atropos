package parsers

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// shimEntryBytes builds one Windows 10 ShimCache entry.
func shimEntryBytes(path string, ft uint64, data []byte) []byte {
	p := wide(path)
	e := []byte("10ts")
	e = binary.LittleEndian.AppendUint32(e, 0)
	e = binary.LittleEndian.AppendUint32(e, uint32(2+len(p)+8+4+len(data)))
	e = binary.LittleEndian.AppendUint16(e, uint16(len(p)))
	e = append(e, p...)
	e = binary.LittleEndian.AppendUint64(e, ft)
	e = binary.LittleEndian.AppendUint32(e, uint32(len(data)))
	return append(e, data...)
}

// tag is one tagged item of an entry's data (Windows 10 1703 and later).
func tag(t uint32, v []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, t)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(v)))
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// ShimCache times are read as stored (found by comparison with
// AppCompatCacheParser: the library cut them to seconds), entries in the
// slack after the last one are recovered, and the executed tag is read.
func TestShimCacheWindows10(t *testing.T) {
	v := make([]byte, 0x34)
	binary.LittleEndian.PutUint32(v, 0x34)
	t1, t2, t3 := filetime("2024-03-01T10:00:00Z")+1234567, filetime("2023-01-01T00:00:00Z"), filetime("2022-06-01T00:00:00Z")
	v = append(v, shimEntryBytes(`C:\Windows\System32\cmd.exe`, t1, tag(0x100, []byte{1, 0, 0, 0}))...)
	v = append(v, shimEntryBytes(`C:\Temp\a.exe`, t2, tag(0x200, []byte{9}))...)
	// The end of the live entries, then garbage, then an older entry, then a broken one.
	v = append(v, 0, 0, 0, 0, 0xEE, 0xEE, 0xEE)
	v = append(v, shimEntryBytes(`C:\Users\x\Downloads\old.exe`, t3, tag(0x100, nil))...)
	v = append(v, []byte("10ts\x00\x00\x00\x00\xff\xff\x00\x00")...)
	entries, slack := shimWin10(v)
	if len(entries) != 2 || entries[0].ft != t1 || !entries[0].executed || entries[1].ft != t2 || entries[1].executed || entries[0].path != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("entries: %+v", entries)
	}
	// After the last live entry: the older entry is recovered, the broken record is not.
	if len(slack) != 1 || slack[0].path != `C:\Users\x\Downloads\old.exe` || slack[0].ft != t3 || !slack[0].executed {
		t.Errorf("slack: %+v", slack)
	}
	// Live entries end where a signature is missing; what follows is slack.
	cut := append([]byte(nil), v...)
	second := 0x34 + len(shimEntryBytes(`C:\Windows\System32\cmd.exe`, t1, tag(0x100, []byte{1, 0, 0, 0})))
	copy(cut[second:], "XXXX")
	entries, slack = shimWin10(cut)
	if len(entries) != 1 || len(slack) != 1 || slack[0].path != `C:\Users\x\Downloads\old.exe` || slack[0].ft != t3 || !slack[0].executed {
		t.Fatalf("slack: entries %+v slack %+v", entries, slack)
	}
	// The older header has no tagged data: nothing is read as a tag.
	old := append([]byte(nil), v...)
	binary.LittleEndian.PutUint32(old, 0x30)
	if e, _ := shimWin10(old[:0x30+0]); len(e) != 0 {
		t.Errorf("entries from a header alone: %+v", e)
	}
	// Any other layout gives nothing.
	other := append([]byte(nil), v...)
	binary.LittleEndian.PutUint32(other, 0x80)
	if e, s := shimWin10(other); e != nil || s != nil {
		t.Error("an unknown header size was read as the Windows 10 layout")
	}
	// Cut anywhere: no panic, and never more entries than were written.
	for n := 0; n < len(v); n++ {
		e, s := shimWin10(v[:n])
		if len(e)+len(s) > 3 {
			t.Fatalf("cut at %d: %d entries", n, len(e)+len(s))
		}
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "shimcache", "*.bin"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		shimWin10(b)
	}
}
