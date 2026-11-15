package parsers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/detect"
)

func filetime(s string) uint64 {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return uint64(tm.UnixNano()/100) + 116444736000000000
}

func wide(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func kindOf(data []byte) string {
	return detect.Identify(bytes.NewReader(data), int64(len(data))).Kind
}

// ---------------------------------------------------------- recycle bin ----

func recycleI(version uint64, size uint64, deleted, path string) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint64(b, version)
	binary.LittleEndian.PutUint64(b[8:], size)
	binary.LittleEndian.PutUint64(b[16:], filetime(deleted))
	name := wide(path + "\x00")
	if version == 1 {
		return append(b, append(name, make([]byte, 520-len(name))...)...)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(name)/2))
	return append(b, name...)
}

func TestRecycleBin(t *testing.T) {
	for version, path := range map[uint64]string{1: `C:\Users\dan\Desktop\secret plan.docx`, 2: `D:\données\naïve — report.xlsx`} {
		data := recycleI(version, 123456, "2024-05-06T07:08:09Z", path)
		if k := kindOf(data); k != detect.RecycleI {
			t.Fatalf("v%d identified as %q", version, k)
		}
		r := run(t, write(t, "renamed.bin", data), nil)
		if r.err != nil || len(r.events) != 1 {
			t.Fatalf("v%d: err %v, %d events", version, r.err, len(r.events))
		}
		e := r.events[0]
		if utc(e) != "2024-05-06T07:08:09Z" || e.Path != path || e.Category != CatDeletion || e.MACB != "" ||
			e.Fields["size"] != uint64(123456) || !strings.Contains(e.Message, path) {
			t.Errorf("v%d event: %s %+v", version, utc(e), e)
		}
	}
	// A file that merely starts with the number 2 is not a record.
	for _, not := range [][]byte{
		append(recycleI(2, 1, "2024-05-06T07:08:09Z", "x"), 0, 0), // length does not match
		recycleI(1, 1, "2024-05-06T07:08:09Z", "x")[:500],
		append([]byte{2, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 600)...), // no plausible time
	} {
		if k := kindOf(not); k == detect.RecycleI {
			t.Errorf("%d bytes wrongly identified as a recycle bin record", len(not))
		}
	}
}

// ------------------------------------------------------------------ usn ----

func usnRecord(name string, when string, reason uint32, entry, parent uint64, dir bool) []byte {
	n := wide(name)
	size := (60 + len(n) + 7) &^ 7
	b := make([]byte, size)
	le := binary.LittleEndian
	le.PutUint32(b, uint32(size))
	le.PutUint16(b[4:], 2)
	le.PutUint64(b[8:], entry|uint64(3)<<48)
	le.PutUint64(b[16:], parent|uint64(1)<<48)
	le.PutUint64(b[24:], 0x1000)
	le.PutUint64(b[32:], filetime(when))
	le.PutUint32(b[40:], reason)
	if dir {
		le.PutUint32(b[52:], 0x10)
	} else {
		le.PutUint32(b[52:], 0x20)
	}
	le.PutUint16(b[56:], uint16(len(n)))
	le.PutUint16(b[58:], 60)
	copy(b[60:], n)
	return b
}

func TestUSNJournal(t *testing.T) {
	recs := [][]byte{
		usnRecord("payload.exe", "2024-06-01T10:00:00Z", 0x100, 500, 40, false),
		usnRecord("payload.exe", "2024-06-01T10:00:01Z", 0x80000102, 500, 40, false),
		usnRecord("staging", "2024-06-01T10:00:02Z", 0x100, 501, 5, true),
		usnRecord("payload.exe", "2024-06-01T10:05:00Z", 0x80000200, 500, 40, false),
		usnRecord("données.txt", "2024-06-01T10:06:00Z", 0x2000, 502, 40, false),
	}
	for name, lead := range map[string]int{"no padding": 0, "one sector": 512, "whole first chunk": 4096, "megabytes": 3<<20 + 4096} {
		data := make([]byte, lead)
		for i, r := range recs {
			data = append(data, r...)
			if i == 2 {
				data = append(data, make([]byte, 4096)...) // journals have holes mid-file too
			}
		}
		if k := kindOf(data); k != detect.USN {
			t.Fatalf("%s: identified as %q", name, k)
		}
		r := run(t, write(t, "j.bin", data), nil)
		if r.err != nil || len(r.warns) != 0 || len(r.events) != 5 {
			t.Fatalf("%s: err %v warns %v, %d events", name, r.err, r.warns, len(r.events))
		}
		e := r.events[1]
		if utc(e) != "2024-06-01T10:00:01Z" || e.Path != "payload.exe" || e.Category != CatFileSystem ||
			!strings.Contains(e.Message, "DATA_EXTEND FILE_CREATE CLOSE") || e.Fields["entry"] != uint64(500) ||
			e.Fields["sequence"] != uint64(3) || e.Fields["parent_entry"] != uint64(40) {
			t.Errorf("%s: record 2: %s %q %v", name, utc(e), e.Message, e.Fields)
		}
		if d := r.events[3]; d.Category != CatDeletion || !strings.Contains(d.Message, "FILE_DELETE") {
			t.Errorf("%s: deletion: %q %s", name, d.Message, d.Category)
		}
		if d := r.events[2]; !strings.Contains(d.Message, "directory staging") || d.Fields["is_dir"] != true {
			t.Errorf("%s: directory: %q", name, d.Message)
		}
		if r.events[4].Path != "données.txt" {
			t.Errorf("%s: unicode name: %q", name, r.events[4].Path)
		}
		if want := fmt.Sprintf("USN record at offset %d", lead); r.events[0].Ref != want {
			t.Errorf("%s: ref %q, want %q", name, r.events[0].Ref, want)
		}
	}
	// Damage in the middle is skipped and reported, and parsing carries on.
	data := append(append(append([]byte{}, recs[0]...), bytes.Repeat([]byte{0xEE}, 64)...), recs[3]...)
	r := run(t, write(t, "j.bin", data), nil)
	if len(r.events) != 2 || len(r.warns) != 1 || !strings.Contains(r.warns[0], "64 bytes") {
		t.Errorf("damaged journal: %d events, warns %v", len(r.events), r.warns)
	}
	if k := kindOf(make([]byte, 100000)); k == detect.USN {
		t.Error("a file of zeros identified as a change journal")
	}
}

// ---------------------------------------------------------------- tasks ----

const taskDoc = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>%s</Date>
    <Author>CORP\mallory</Author>
    <URI>\Microsoft\Windows\Updater\Refresh &amp; Sync</URI>
  </RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger><TimeTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\ProgramData\upd.exe</Command><Arguments>-enc SQBFAFgA</Arguments></Exec>
  </Actions>
</Task>`

func TestScheduledTask(t *testing.T) {
	utf16doc := func(s string) []byte { return append([]byte{0xFF, 0xFE}, wide(s)...) }
	// As Windows writes them: UTF-16 with a byte order mark, local time, no zone.
	r := run(t, write(t, "Refresh", utf16doc(fmt.Sprintf(taskDoc, "2024-07-15T12:00:00.1234567"))), nil)
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 1 {
		t.Fatalf("err %v warns %v, %d events", r.err, r.warns, len(r.events))
	}
	e := r.events[0]
	if utc(e) != "2024-07-15T12:00:00.1234567Z" || e.Stamp.ZoneFrom != "assumed" || e.Category != CatPersistence ||
		e.Path != `C:\ProgramData\upd.exe` || e.User != "S-1-5-18" || e.Fields["hidden"] != true || e.Fields["author"] != `CORP\mallory` {
		t.Errorf("task event: %s %s %+v", utc(e), e.Stamp.ZoneFrom, e)
	}
	for _, want := range []string{`\Microsoft\Windows\Updater\Refresh & Sync`, `C:\ProgramData\upd.exe -enc SQBFAFgA`, "LogonTrigger, TimeTrigger"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message lacks %q: %s", want, e.Message)
		}
	}
	// A date with an offset is not an assumption.
	r = run(t, write(t, "t.xml", []byte(fmt.Sprintf(taskDoc, "2024-07-15T12:00:00+01:00"))), nil)
	if len(r.events) != 1 || utc(r.events[0]) != "2024-07-15T11:00:00Z" || r.events[0].Stamp.ZoneFrom != "explicit-offset" {
		t.Errorf("task with offset: %+v", r.events)
	}
	// No registration date: nothing for the timeline, but handed on to be indexed as text.
	noDate := strings.Replace(fmt.Sprintf(taskDoc, "x"), "<Date>x</Date>", "", 1)
	r = run(t, write(t, "t.xml", []byte(noDate)), nil)
	if !errors.Is(r.err, ErrNothingExtracted) || len(r.events) != 0 || len(r.notes) != 1 {
		t.Errorf("task without a date: err %v, %d events, notes %v", r.err, len(r.events), r.notes)
	}
	// Other XML is not mistaken for a task, and broken task XML is an error, not a panic.
	r = run(t, write(t, "o.xml", []byte(`<?xml version="1.0"?><Config><Date>2024-01-01T00:00:00Z</Date></Config>`)), nil)
	if len(r.events) != 0 {
		t.Errorf("unrelated XML produced %d events", len(r.events))
	}
	r = run(t, write(t, "b.xml", []byte(fmt.Sprintf(taskDoc, "2024-07-15T12:00:00")[:400])), nil)
	if r.err == nil || len(r.events) != 0 {
		t.Errorf("truncated task: err %v, %d events", r.err, len(r.events))
	}
}

// ----------------------------------------------------------- jump lists ----

// buildCFB makes a version 3 compound file whose streams all live in the
// mini stream, as the streams of a real jump list do.
func buildCFB(streams map[string][]byte, order []string) []byte {
	const sec = 512
	le := binary.LittleEndian
	var mini []byte
	var miniFAT []uint32
	type ent struct {
		name        string
		start, size uint32
	}
	var ents []ent
	for _, name := range order {
		data := streams[name]
		start := uint32(len(mini) / 64)
		n := (len(data) + 63) / 64
		for i := 0; i < n; i++ {
			next := start + uint32(i) + 1
			if i == n-1 {
				next = 0xFFFFFFFE
			}
			miniFAT = append(miniFAT, next)
		}
		mini = append(mini, append(data, make([]byte, n*64-len(data))...)...)
		ents = append(ents, ent{name, start, uint32(len(data))})
	}
	// Sector 0: FAT. 1: directory. 2: mini FAT. 3..: mini stream.
	miniSectors := (len(mini) + sec - 1) / sec
	dirSectors := (len(ents)+1+3)/4 + 0
	fat := make([]uint32, sec/4)
	for i := range fat {
		fat[i] = 0xFFFFFFFF
	}
	fat[0] = 0xFFFFFFFD
	dirStart := uint32(1)
	for i := 0; i < dirSectors; i++ {
		fat[1+i] = uint32(2 + i)
	}
	fat[dirSectors] = 0xFFFFFFFE
	miniFATAt := uint32(1 + dirSectors)
	fat[miniFATAt] = 0xFFFFFFFE
	miniAt := miniFATAt + 1
	for i := 0; i < miniSectors; i++ {
		fat[int(miniAt)+i] = miniAt + uint32(i) + 1
	}
	fat[int(miniAt)+miniSectors-1] = 0xFFFFFFFE

	hdr := make([]byte, sec)
	copy(hdr, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	le.PutUint16(hdr[24:], 0x3E)
	le.PutUint16(hdr[26:], 3)
	le.PutUint16(hdr[28:], 0xFFFE)
	le.PutUint16(hdr[30:], 9)
	le.PutUint16(hdr[32:], 6)
	le.PutUint32(hdr[44:], 1)
	le.PutUint32(hdr[48:], dirStart)
	le.PutUint32(hdr[56:], 4096)
	le.PutUint32(hdr[60:], miniFATAt)
	le.PutUint32(hdr[64:], 1)
	le.PutUint32(hdr[68:], 0xFFFFFFFE)
	for i := 0; i < 109; i++ {
		le.PutUint32(hdr[76+i*4:], 0xFFFFFFFF)
	}
	le.PutUint32(hdr[76:], 0)

	dirEntry := func(name string, typ byte, start, size uint32) []byte {
		e := make([]byte, 128)
		w := wide(name + "\x00")
		copy(e, w)
		le.PutUint16(e[64:], uint16(len(w)))
		e[66] = typ
		le.PutUint32(e[68:], 0xFFFFFFFF)
		le.PutUint32(e[72:], 0xFFFFFFFF)
		le.PutUint32(e[76:], 0xFFFFFFFF)
		le.PutUint32(e[116:], start)
		le.PutUint32(e[120:], size)
		return e
	}
	dir := dirEntry("Root Entry", 5, miniAt, uint32(len(mini)))
	for _, e := range ents {
		dir = append(dir, dirEntry(e.name, 2, e.start, e.size)...)
	}
	dir = append(dir, make([]byte, dirSectors*sec-len(dir))...)

	out := append([]byte{}, hdr...)
	for _, v := range fat {
		out = le.AppendUint32(out, v)
	}
	out = append(out, dir...)
	mf := make([]byte, sec)
	for i := range mf {
		mf[i] = 0xFF
	}
	for i, v := range miniFAT {
		le.PutUint32(mf[i*4:], v)
	}
	out = append(out, mf...)
	return append(out, append(mini, make([]byte, miniSectors*sec-len(mini))...)...)
}

func destList(version uint32, entries [][3]string) []byte {
	le := binary.LittleEndian
	b := make([]byte, 32)
	le.PutUint32(b, version)
	le.PutUint32(b[4:], uint32(len(entries)))
	fixed := 114
	if version >= 2 {
		fixed = 130
	}
	for i, e := range entries {
		path := wide(e[0])
		x := make([]byte, fixed)
		copy(x[72:], "WORKSTATION7")
		le.PutUint32(x[88:], uint32(i+1))
		le.PutUint64(x[100:], filetime(e[1]))
		le.PutUint32(x[108:], 0xFFFFFFFF)
		if e[2] == "pinned" {
			le.PutUint32(x[108:], 0)
		}
		if version >= 2 {
			le.PutUint32(x[116:], 7)
		}
		le.PutUint16(x[fixed-2:], uint16(len(path)/2))
		b = append(append(b, x...), path...)
		if version >= 2 {
			// A length, then that many bytes of properties: none for the first
			// entry, some for the rest, as real files have.
			extra := make([]byte, i*37)
			b = append(le.AppendUint32(b, uint32(len(extra))), extra...)
		}
	}
	return b
}

func TestAutomaticJumpList(t *testing.T) {
	lnk := buildLnk(filetime("2023-05-01T08:00:00Z"), filetime("2023-05-03T10:00:00Z"), filetime("2023-05-02T09:00:00Z"))
	for _, version := range []uint32{1, 4, 6} {
		entries := [][3]string{
			{`C:\Users\dan\Documents\budget 2024.xlsx`, "2024-02-02T09:30:00Z", ""},
			{`\\fileserver\share\plans — final.docx`, "2024-02-03T16:45:10Z", "pinned"},
		}
		data := buildCFB(map[string][]byte{"DestList": destList(version, entries), "1": lnk, "2": lnk}, []string{"1", "2", "DestList"})
		if k := kindOf(data); k != detect.OLE {
			t.Fatalf("identified as %q", k)
		}
		r := run(t, write(t, "5f7b5f1e01b83767.automaticDestinations-ms", data), nil)
		if r.err != nil || len(r.warns) != 0 {
			t.Fatalf("v%d: err %v warns %v", version, r.err, r.warns)
		}
		var used []Event
		targets := 0
		for _, e := range r.events {
			if e.Category != CatFileOpening {
				t.Errorf("v%d: %s has category %s", version, e.Type, e.Category)
			}
			if e.Type == "jumplist-entry-last-used" {
				used = append(used, e)
			} else if strings.HasPrefix(e.Type, "link-target-") {
				targets++
				if !strings.HasPrefix(e.Ref, "jump list stream ") || e.MACB == "" {
					t.Errorf("v%d: shortcut event ref %q macb %q", version, e.Ref, e.MACB)
				}
			}
		}
		if len(used) != 2 || targets != 6 {
			t.Fatalf("v%d: %d last-used events and %d target times, want 2 and 6", version, len(used), targets)
		}
		if e := used[1]; utc(e) != "2024-02-03T16:45:10Z" || e.Path != entries[1][0] || e.Fields["pinned"] != true ||
			e.Fields["app_id"] != "5f7b5f1e01b83767" || e.Fields["target_host"] != "WORKSTATION7" || e.Ref != "DestList entry 2" || e.MACB != "" {
			t.Errorf("v%d: entry 2: %s %+v", version, utc(e), e)
		}
		if version >= 4 && used[0].Fields["access_count"] != uint32(7) {
			t.Errorf("v4 access count: %v", used[0].Fields["access_count"])
		}
		if used[0].Fields["pinned"] != false {
			t.Error("unpinned entry reported as pinned")
		}
	}
	// A compound file that is not a jump list is handed on, not failed.
	other := buildCFB(map[string][]byte{"WordDocument": bytes.Repeat([]byte("x"), 300)}, []string{"WordDocument"})
	if r := run(t, write(t, "old.doc", other), nil); !errors.Is(r.err, ErrNothingExtracted) {
		t.Errorf("non-jump-list compound file: %v", r.err)
	}
}

func TestCustomJumpList(t *testing.T) {
	lnk := buildLnk(filetime("2023-05-01T08:00:00Z"), 0, filetime("2023-05-02T09:00:00Z"))
	data := make([]byte, 36)
	binary.LittleEndian.PutUint32(data, 2)
	// A category header's class identifier sits between the file header and the first shortcut.
	data = append(data[:20], lnkHeader[4:]...)
	data = append(append(append(data, lnk...), lnkHeader[4:]...), lnk...)
	data = append(data, 0xAB, 0xFB, 0xBF, 0xBA)
	if k := kindOf(data); k != detect.JumpList {
		t.Fatalf("identified as %q", k)
	}
	r := run(t, write(t, "abc.customDestinations-ms", data), nil)
	if r.err != nil || len(r.events) != 4 {
		t.Fatalf("err %v, %d events (two shortcuts with two times each expected), warns %v", r.err, len(r.events), r.warns)
	}
	if !strings.Contains(r.events[0].Message, "jump list abc entry 1") || !strings.HasPrefix(r.events[2].Ref, "shortcut at offset ") {
		t.Errorf("events: %q %q", r.events[0].Message, r.events[2].Ref)
	}
}

// Every truncation and every single-byte corruption of a jump list must be
// survived without a panic or a hang.
func TestDamagedCompoundFiles(t *testing.T) {
	lnk := buildLnk(filetime("2023-05-01T08:00:00Z"), 0, 0)
	good := buildCFB(map[string][]byte{"DestList": destList(4, [][3]string{{`C:\x.txt`, "2024-02-02T09:30:00Z", ""}}), "1": lnk}, []string{"1", "DestList"})
	try := func(data []byte, what string) {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("%s: panic: %v", what, p)
			}
		}()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { recover() }()
			if c, err := openCFB(data); err == nil {
				for name := range c.streams {
					c.stream(name)
				}
				if raw, err := c.stream("DestList"); err == nil {
					parseDestList(raw)
				}
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: did not finish", what)
		}
	}
	for n := 0; n < len(good); n += 37 {
		try(good[:n], fmt.Sprintf("truncated to %d", n))
	}
	for i := 0; i < 1024+512; i++ { // header, allocation table and directory
		for _, v := range []byte{0x00, 0xFF, 0x01} {
			bad := append([]byte{}, good...)
			bad[i] = v
			try(bad, fmt.Sprintf("byte %d set to %#x", i, v))
		}
	}
}

// ------------------------------------------------------- registry keys ----

func TestRegistryKeyClassification(t *testing.T) {
	v := func(pairs ...string) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(pairs); i += 2 {
			m[pairs[i]] = map[string]any{"type": "REG_SZ", "data": pairs[i+1]}
		}
		return m
	}
	cases := []struct {
		hive, path string
		vals       map[string]any
		typ, cat   string
		inMsg      string
	}{
		{"SYSTEM", `\ControlSet001\Services\EvilSvc`, v("ImagePath", `C:\ProgramData\e.exe -k`, "Start", "2"), "service-key-last-write", CatPersistence, `e.exe -k  (start type automatic)`},
		{"SYSTEM", `\ControlSet002\Services\Dnscache`, v("ServiceDll", `%SystemRoot%\System32\dnsrslvr.dll`), "service-key-last-write", CatPersistence, "dnsrslvr.dll"},
		{"SYSTEM", `\ControlSet001\Services\EvilSvc\Parameters`, v("ImagePath", "x"), "", "", ""},
		{"SYSTEM", `\ControlSet001\Services\Tcpip`, v("Description", "no image"), "", "", ""},
		{"SOFTWARE", `\Microsoft\Windows\CurrentVersion\Run`, v("Updater", `C:\Users\Public\u.exe`), "autostart-key-last-write", CatPersistence, `Updater=C:\Users\Public\u.exe`},
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\RunOnce`, v(), "autostart-key-last-write", CatPersistence, "RunOnce"},
		{"SOFTWARE", `\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, v("a", "b"), "autostart-key-last-write", CatPersistence, "a=b"},
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Runtime`, v("a", "b"), "", "", ""},
		{"SYSTEM", `\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C530001230101112345&0`, v("FriendlyName", "SanDisk Ultra USB Device"), "usb-device-key-last-write", CatDevice, "SanDisk Ultra USB Device, serial 4C530001230101112345&0"},
		{"AMCACHE", `\Root\InventoryApplicationFile\evil.exe|1234`, v("LowerCaseLongPath", `c:\temp\evil.exe`, "Publisher", "nobody", "FileId", "0000"+strings.Repeat("a", 40)), "amcache-file-recorded", CatExecution, `c:\temp\evil.exe  (nobody)`},
		// An entry holding only identifiers: the name is in the key's name.
		{"AMCACHE", `\Root\InventoryApplicationFile\tool.exe|1234abcd`, v("ProgramId", "0006"+strings.Repeat("b", 40), "FileId", "0000"+strings.Repeat("a", 40)), "amcache-file-hash-recorded", CatExecution, `by name and hash only: tool.exe`},
		{"AMCACHE", `\Root\InventoryApplicationFile\tool.exe|1234abcd`, v("ProgramId", "0006"+strings.Repeat("b", 40)), "", "", ""},
		{"AMCACHE", `\Root\InventoryApplicationFile`, v(), "", "", ""},
		{"SOFTWARE", `\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Evil\Task`, v("Id", "{guid}"), "scheduled-task-key-last-write", CatPersistence, `\Evil\Task`},
		{"SYSTEM", `\ControlSet001\Control\Lsa`, v("a", "b"), "", "", ""},
		// What an account connected to, typed and ran.
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##fileserver#finance$`, v(), "network-share-key-last-write", CatNetwork, `\\fileserver\finance$`},
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{1a2b}`, v(), "mount-point-key-last-write", CatDevice, "{1a2b}"},
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`, v(), "", "", ""},
		{"NTUSER", `\Software\Microsoft\Terminal Server Client\Servers\10.0.0.5`, v("UsernameHint", `CORP\admin`), "rdp-client-server-key-last-write", CatNetwork, `to 10.0.0.5 (signing in as CORP\admin)`},
		{"NTUSER", `\Software\Microsoft\Terminal Server Client\Default`, v("MRU1", "dc01", "MRU0", "10.0.0.5", "MRU10", "last"), "rdp-client-recent-key-last-write", CatNetwork, "10.0.0.5; dc01; last"},
		{"NTUSER", `\Software\Sysinternals\PsExec`, v("EulaAccepted", "1"), "sysinternals-eula-key-last-write", CatExecution, "Sysinternals PsExec licence accepted"},
		{"NTUSER", `\Software\Sysinternals\PsExec`, v(), "", "", ""},
		{"SOFTWARE", `\Software\Sysinternals\PsExec`, v("EulaAccepted", "1"), "", "", ""},
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`, v("url2", `C:\Temp`, "url1", `\\dc01\c$`), "typed-paths-key-last-write", CatFileOpening, `\\dc01\c$; C:\Temp`},
		{"NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, v("a", `cmd\1`, "b", `powershell -enc AAAA\1`, "MRUList", "ba"), "run-dialog-key-last-write", CatExecution, "powershell -enc AAAA; cmd"},
		{"SOFTWARE", `\Microsoft\Windows NT\CurrentVersion\Winlogon`, v("Userinit", `C:\Windows\system32\userinit.exe,C:\evil.exe`, "Shell", "explorer.exe"), "winlogon-key-last-write", CatPersistence, `userinit.exe,C:\evil.exe; Shell=explorer.exe`},
	}
	for _, c := range cases {
		typ, cat, msg, _, ok := classifyKey(c.hive, strings.ToLower(c.path), c.path, c.vals)
		if ok != (c.typ != "") || typ != c.typ || cat != c.cat || !strings.Contains(msg, c.inMsg) {
			t.Errorf("%s %s: got %q %q %q (special %v), want %q %q with %q", c.hive, c.path, typ, cat, msg, ok, c.typ, c.cat, c.inMsg)
		}
	}
	fields := map[string]any{}
	amcacheFields(fields, v("FileId", "0000"+strings.Repeat("a", 40), "Publisher", "p", "Size", "12"))
	if fields["sha1_first_31mb"] != strings.Repeat("a", 40) || fields["publisher"] != "p" || fields["size"] != "12" {
		t.Errorf("amcache fields: %v", fields)
	}
	// The value-bearing keys are matched in any control set, on any bus.
	for path, want := range map[string]bool{
		`\controlset001\enum\usbstor\disk&ven_x\serial&0\properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066`: true,
		`\controlset003\enum\usb\vid_0781&pid_5581\4c53\properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064`:  true,
		`\controlset001\enum\usbstor\disk&ven_x\serial&0\properties\{83da6326-97a6-4088-9453-a1923f573b29}\0003`: false,
		`\controlset001\enum\usbstor\disk&ven_x\serial&0\properties\{other}\0066`:                                false,
	} {
		if got := reUSBTime.MatchString(path); got != want {
			t.Errorf("usb time key %s: %v", path, got)
		}
	}
	for path, want := range map[string]bool{
		`\controlset001\services\bam\state\usersettings\s-1-5-21-1-2-3-1001`: true,
		`\controlset001\services\bam\usersettings\s-1-5-21-1-2-3-1001`:       true,
		`\controlset001\services\dam\state\usersettings\s-1-5-18`:            true,
		`\controlset001\services\bam\state\usersettings`:                     false,
	} {
		if got := reBAM.MatchString(path); got != want {
			t.Errorf("bam key %s: %v", path, got)
		}
	}
}

// Event names and categories: the ones an intrusion investigation leans on.
func TestEventNamesAndCategories(t *testing.T) {
	for key, want := range map[string]string{
		"Security/4616": CatSecurity,
		"Security/4798": CatAccount,
		"Security/5142": CatNetwork,
		"Microsoft-Windows-TerminalServices-RDPClient/Operational/1024":     CatNetwork,
		"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/131": CatAccount,
		"Microsoft-Windows-WMI-Activity/Operational/5859":                   CatPersistence,
		"Microsoft-Windows-WMI-Activity/Operational/5857":                   CatExecution,
		"Windows PowerShell/400":                                            CatExecution,
		"PowerShellCore/Operational/4104":                                   CatExecution,
		"Microsoft-Windows-WinRM/Operational/91":                            CatAccount,
		"Microsoft-Windows-Windows Defender/Operational/1118":               CatSecurity,
		"Microsoft-Windows-TaskScheduler/Operational/141":                   CatPersistence,
	} {
		i := strings.LastIndexByte(key, '/')
		if got := eventCategory(key[:i], "", key[i+1:]); got != want {
			t.Errorf("%s: category %q, want %q", key, got, want)
		}
		if eventNames[key] == "" {
			t.Errorf("%s has a category and no description", key)
		}
	}
	// Every categorised event is described, so the timeline never shows a
	// category with a bare "Event".
	for key := range eventCategories {
		if eventNames[key] == "" {
			t.Errorf("%s has a category and no description", key)
		}
	}
	// The Application log is shared: 1000 is a crash only from one provider.
	if got := eventCategory("Application", "Application Error", "1000"); got != CatExecution {
		t.Errorf("application crash: category %q", got)
	}
	if got := eventCategory("Application", "SomeProduct", "1000"); got != CatLog {
		t.Errorf("another program's event 1000 was categorised as %q", got)
	}
	if providerEventNames["Application/Application Error/1000"] == "" {
		t.Error("application crash has no description")
	}
}

// A Store app in the BAM key is named by its package, with no backslash.
func TestBAMProgramValues(t *testing.T) {
	when := make([]byte, 24)
	binary.LittleEndian.PutUint64(when, filetime("2024-05-01T12:00:00Z"))
	for _, c := range []struct {
		name string
		data []byte
		want bool
	}{
		{`\Device\HarddiskVolume3\Windows\System32\cmd.exe`, when, true},
		{"Microsoft.WindowsTerminal_8wekyb3d8bbwe", when, true},
		{"Version", []byte{1, 0, 0, 0}, false},
		{"SequenceNumber", []byte{9, 0, 0, 0}, false},
		{"SequenceNumber", when, false},
		{"Some.App_abc", []byte{1, 2, 3}, false},
	} {
		ft, ok := bamProgram(c.name, c.data)
		if ok != c.want || (ok && ft != filetime("2024-05-01T12:00:00Z")) {
			t.Errorf("%s: got %v %d", c.name, ok, ft)
		}
	}
}

// Jump list application names, from the embedded list.
func TestJumpListAppNames(t *testing.T) {
	for id, want := range map[string]string{
		"0A1D19AFE5A80F80": "FileZilla 2.2.32", // as listed
		"0a1d19afe5a80f80": "FileZilla 2.2.32", // any case
		"01b29f0dc90366bb": "AIM 5.9.3857",     // listed without its leading zero
		"1b29f0dc90366bb":  "AIM 5.9.3857",     // and asked for without it
		"ffffffffffffffff": "",                 // unknown
		"not-an-id":        "",                 //
	} {
		if got := appName(id); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
}
