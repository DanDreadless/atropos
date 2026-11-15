package parsers

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/detect"
)

// rootIndex returns the root directory's index record from the sample
// volume, as it is on disk (sector check values in place).
func rootIndex(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(sample(t, "test.ntfs.dd"))
	if err != nil {
		t.Fatal(err)
	}
	blk := append([]byte(nil), b[146432:146432+indexBlockSize]...)
	if string(blk[:4]) != "INDX" {
		t.Fatal("the sample volume's root index is not where it was")
	}
	return blk
}

// removeEntry deletes the named entry from an index record the way NTFS
// does: the entries after it are moved down over it and the end mark is
// pulled back. The tail of the old data is left where it was, which is how
// names survive in slack. The record is returned protected again.
func removeEntry(t *testing.T, disk []byte, name string) []byte {
	t.Helper()
	le := binary.LittleEndian
	b := append([]byte(nil), disk...)
	if !applyFixups(b) {
		t.Fatal("sample record is torn")
	}
	end := 0x18 + int(le.Uint32(b[0x1C:]))
	pos := 0x18 + int(le.Uint32(b[0x18:]))
	for pos+0x10 <= end {
		length := int(le.Uint16(b[pos+8:]))
		if le.Uint16(b[pos+12:])&2 != 0 {
			break
		}
		if e, _, ok := parseIndexEntry(b[pos:end], false); ok && e.name == name {
			copy(b[pos:], b[pos+length:end])
			le.PutUint32(b[0x1C:], uint32(end-length-0x18))
			return protect(b)
		}
		pos += length
	}
	t.Fatalf("no entry named %q", name)
	return nil
}

// protect puts sector check values back, as a record is stored on disk.
func protect(b []byte) []byte {
	le := binary.LittleEndian
	off, n := int(le.Uint16(b[4:])), int(le.Uint16(b[6:]))
	for i := 1; i < n; i++ {
		end := i*512 - 2
		copy(b[off+2*i:], b[end:end+2])
		copy(b[end:], b[off:off+2])
	}
	return b
}

func names(es []indexEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.name)
	}
	sort.Strings(out)
	return out
}

func TestIndexRecordFromARealVolume(t *testing.T) {
	live, slack, err := parseIndexBlock(rootIndex(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Sixteen entries: the eight metadata files Windows keeps no times for
	// are still listed.
	got := strings.Join(names(live), ",")
	want := "$AttrDef,$BadClus,$Bitmap,$Boot,$Extend,$LogFile,$MFT,$MFTMirr,$RECYCLE.BIN,$Secure,$UpCase,$Volume,.,Folder A,System Volume Information,ones.bin"
	if got != want {
		t.Errorf("live entries\n got %s\nwant %s", got, want)
	}
	if len(slack) != 0 {
		t.Errorf("slack entries in an index nothing was removed from: %v", names(slack))
	}
	for _, e := range live {
		if e.name == "ones.bin" {
			if e.entry != 38 || e.parentEntry != 5 || e.created.UTC().Format(time.RFC3339Nano) != "2018-09-24T07:54:50.5497455Z" || e.isDir() {
				t.Errorf("ones.bin: %+v", e)
			}
		}
		if e.name == "Folder A" && !e.isDir() {
			t.Error("Folder A is not marked as a folder")
		}
	}
}

// What a removal leaves behind depends on where the entry was. Removing one
// from the middle moves the later entries over it and leaves only the tail
// of the last one: nothing readable. Removing the last one writes the end
// marker over its 16-byte header and leaves its name, times and parent.
func TestIndexSlack(t *testing.T) {
	middle := removeEntry(t, rootIndex(t), "Folder A")
	live, slack, err := parseIndexBlock(middle, 0)
	if err != nil || len(live) != 15 || len(slack) != 0 || strings.Contains(strings.Join(names(live), ","), "Folder A") {
		t.Fatalf("after removing a middle entry: %d live, slack %v, err %v", len(live), names(slack), err)
	}
	last := removeEntry(t, rootIndex(t), "System Volume Information")
	live, slack, err = parseIndexBlock(last, 4096)
	if err != nil || len(live) != 15 || len(slack) != 1 {
		t.Fatalf("after removing the last entry: %d live, slack %v, err %v", len(live), names(slack), err)
	}
	e := slack[0]
	if e.name != "System Volume Information" || !e.slack || e.offset < 4096 || e.parentEntry != 5 || !e.isDir() ||
		e.created.UTC().Format(time.RFC3339Nano) != "2018-09-24T07:53:20.0721062Z" {
		t.Errorf("recovered entry: %+v", e)
	}
	if e.sequence != 0 {
		t.Errorf("the header was overwritten, yet a file record is claimed: %d-%d", e.entry, e.sequence)
	}
	// Across a stream: a leftover that is still listed elsewhere in the same
	// index says nothing new and is dropped; the same leftover in two
	// records is reported once.
	var warns []string
	warn := func(f string, a ...any) { warns = append(warns, f) }
	stream := append(append([]byte(nil), middle...), last...)
	if _, slack = readIndexStream(bytes.NewReader(stream), int64(len(stream)), warn); len(slack) != 0 {
		t.Errorf("a leftover copy of a listed entry was reported: %v", names(slack))
	}
	two := removeEntry(t, removeEntry(t, rootIndex(t), "ones.bin"), "System Volume Information")
	stream = append(append([]byte(nil), last...), two...)
	if _, slack = readIndexStream(bytes.NewReader(stream), int64(len(stream)), warn); len(slack) != 1 || slack[0].name != "System Volume Information" {
		t.Errorf("recovered across two records: %v", names(slack))
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
}

func TestIndexFileIsParsedAndDetected(t *testing.T) {
	twice := removeEntry(t, removeEntry(t, rootIndex(t), "ones.bin"), "System Volume Information")
	path := filepath.Join(t.TempDir(), "exported-index")
	if err := os.WriteFile(path, twice, 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, path, nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	var recovered, listed int
	for _, e := range r.events {
		if e.Source != "i30" || e.Category != CatFileSystem || !strings.HasPrefix(e.Ref, "index entry at offset ") && !strings.HasPrefix(e.Ref, "slack entry at offset ") {
			t.Fatalf("event: %+v", e)
		}
		if strings.Trim(e.MACB, ".") == "" {
			t.Errorf("an index time without MACB letters: %+v", e)
		}
		if strings.HasPrefix(e.Type, "$I30-slack ") {
			recovered++
			if e.Path != "System Volume Information" || e.Fields["recovered_from_slack"] != true || e.Fields["file_record_unknown"] != true {
				t.Errorf("recovered: %+v", e)
			}
		} else {
			listed++
		}
	}
	if recovered == 0 || listed == 0 {
		t.Errorf("recovered %d, listed %d", recovered, listed)
	}
	f, _ := os.Open(path)
	defer f.Close()
	if k := detect.Identify(f, int64(len(twice))).Kind; k != detect.NTFSIndex {
		t.Errorf("identified as %q", k)
	}
}

// Carving reads bytes that may be anything: it must not accept noise, and
// must not panic on truncated or mangled records.
func TestIndexCarvingIsStrict(t *testing.T) {
	good := removeEntry(t, rootIndex(t), "Folder A")
	for i := 0; i < len(good); i += 7 {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xFF
		parseIndexBlock(bad, 0)
	}
	for n := 0; n < len(good); n += 97 {
		parseIndexBlock(good[:n], 0)
	}
	noise := make([]byte, indexBlockSize)
	copy(noise, good[:0x40])
	x := uint32(12345)
	for i := 0x58; i < len(noise); i++ {
		x = x*1664525 + 1013904223
		noise[i] = byte(x >> 24)
	}
	binary.LittleEndian.PutUint32(noise[0x1C:], 0x40) // no live entries: all of it is slack
	if _, slack, _ := parseIndexBlock(protect(noise), 0); len(slack) != 0 {
		t.Errorf("%d entries carved out of noise", len(slack))
	}
	// A torn record is reported and still read.
	torn := append([]byte(nil), good...)
	torn[510] ^= 0x55
	live, _, err := parseIndexBlock(torn, 0)
	if err == nil || len(live) == 0 {
		t.Errorf("torn record: %d live, err %v", len(live), err)
	}
}

// The sample volume's own transaction log, written by Windows: it records a
// folder and a file being renamed, and a file being deleted.
func TestLogFileFromARealVolume(t *testing.T) {
	r := run(t, sample(t, "test.ntfs.dd"), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	type op struct{ typ, path string }
	var ops []op
	lsn := map[op]uint64{}
	for _, e := range r.events {
		if e.Source != "logfile" {
			continue
		}
		if e.Category != CatFileSystem || !strings.HasPrefix(e.Ref, "$LogFile in the volume, record at offset ") || !strings.Contains(e.Message, "no clock") {
			t.Fatalf("event: %+v", e)
		}
		o := op{e.Type[:strings.LastIndexByte(e.Type, ' ')], e.Path}
		if _, dup := lsn[o]; !dup {
			ops = append(ops, o)
			lsn[o] = e.Fields["lsn"].(uint64)
		}
	}
	for _, want := range []op{
		{"$LogFile-name-added", "/New folder"},
		{"$LogFile-name-removed", "/New folder"},
		{"$LogFile-name-added", "/Folder A"},
		{"$LogFile-name-added", "/Folder A/Folder B/New Text Document.txt"},
		{"$LogFile-record-created", "/Folder A/Folder B/New Text Document.txt"},
		{"$LogFile-name-removed", "/Folder A/Folder B/New Text Document.txt"},
		{"$LogFile-name-added", "/Folder A/Folder B/Hello world text document.txt"},
		{"$LogFile-name-added", "/deleted.bin"},
		{"$LogFile-name-removed", "/deleted.bin"},
	} {
		if _, ok := lsn[want]; !ok {
			t.Errorf("the log's record of %s %s was not read", want.typ, want.path)
		}
	}
	// Sequence numbers give the order: a rename removes the old name and
	// then adds the new one.
	if a, b := lsn[op{"$LogFile-name-removed", "/New folder"}], lsn[op{"$LogFile-name-added", "/Folder A"}]; a == 0 || a >= b {
		t.Errorf("rename out of order: removed at %d, added at %d", a, b)
	}
	if a, b := lsn[op{"$LogFile-name-added", "/deleted.bin"}], lsn[op{"$LogFile-name-removed", "/deleted.bin"}]; a == 0 || a >= b {
		t.Errorf("deletion out of order: added at %d, removed at %d", a, b)
	}
	// deleted.bin is gone from the directory, and the log still names it.
	for _, e := range r.events {
		if e.Source == "mft" && e.Path == "/deleted.bin" && !strings.Contains(e.Message, "deleted") {
			t.Errorf("deleted.bin is shown as a live file: %s", e.Message)
		}
	}
	note := strings.Join(r.notes, " ")
	if !strings.Contains(note, "operation records read") || !strings.Contains(note, "directory indexes: 0 entries recovered") {
		t.Errorf("notes: %v", r.notes)
	}
}

// The log saved to a file on its own is recognised and gives the same
// operations, with bare names because the directories are not known.
func TestLogFileOnItsOwn(t *testing.T) {
	whole := run(t, sample(t, "test.ntfs.dd"), nil)
	b, err := os.ReadFile(sample(t, "test.ntfs.dd"))
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(b, []byte("RSTR"))
	if at < 0 {
		t.Fatalf("log not found in the sample volume (at %d)", at)
	}
	// The sample's log is one unbroken run of two megabytes.
	path := filepath.Join(t.TempDir(), "saved-log")
	if err := os.WriteFile(path, b[at:at+2<<20], 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, path, nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	count := func(res result) (n int) {
		for _, e := range res.events {
			if e.Source == "logfile" {
				n++
			}
		}
		return n
	}
	if count(r) == 0 || count(r) != count(whole) || len(r.events) != count(r) {
		t.Errorf("standalone log: %d events, in the volume %d", count(r), count(whole))
	}
	found := false
	for _, e := range r.events {
		if e.Path == "Hello world text document.txt" && strings.HasPrefix(e.Type, "$LogFile-name-added") {
			found = true
		}
	}
	if !found {
		t.Error("the renamed file is not in the standalone log's events")
	}
	// Damage does not crash it.
	for i := 0; i < 2<<20; i += 40961 {
		bad := append([]byte(nil), b[at:at+2<<20]...)
		bad[i] ^= 0xFF
		p := filepath.Join(t.TempDir(), "bad")
		os.WriteFile(p, bad, 0o600)
		run(t, p, nil)
	}
}
