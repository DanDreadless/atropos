package parsers

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// dos packs a time the way shell items store it.
func dos(s string) (date, tm uint16) {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day()), uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
}

// fileItem builds a folder or file shell item with an extension block of the
// given version, as Explorer writes them.
func fileItem(typ byte, short, long string, version uint16, modified, created, accessed string) []byte {
	le := binary.LittleEndian
	b := make([]byte, 14)
	b[2] = typ
	d, tm := dos(modified)
	le.PutUint16(b[8:], d)
	le.PutUint16(b[10:], tm)
	le.PutUint16(b[12:], 0x10)
	b = append(b, append([]byte(short), 0)...)
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	nameAt := map[uint16]int{3: 0x14, 7: 0x26, 8: 0x2A, 9: 0x2E}[version]
	e := make([]byte, nameAt)
	le.PutUint16(e[2:], version)
	copy(e[4:], beef0004)
	d, tm = dos(created)
	le.PutUint16(e[8:], d)
	le.PutUint16(e[10:], tm)
	d, tm = dos(accessed)
	le.PutUint16(e[12:], d)
	le.PutUint16(e[14:], tm)
	if version >= 7 {
		le.PutUint64(e[20:], 0x0005000000001234) // entry 0x1234, sequence 5
	}
	e = append(e, wide(long+"\x00")...)
	e = append(e, 0, 0) // offset of the block, which readers do not need
	le.PutUint16(e, uint16(len(e)))
	b = append(b, e...)
	le.PutUint16(b, uint16(len(b)))
	return b
}

func TestShellItems(t *testing.T) {
	guid := func(typ byte, at int, g [16]byte) []byte {
		b := make([]byte, at+16)
		b[2] = typ
		copy(b[at:], g[:])
		binary.LittleEndian.PutUint16(b, uint16(len(b)))
		return b
	}
	thisPC := [16]byte{0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D}
	vol := append([]byte{0, 0, 0x2F}, append([]byte(`E:\`), make([]byte, 20)...)...)
	binary.LittleEndian.PutUint16(vol, uint16(len(vol)))
	net := append([]byte{0, 0, 0x41, 0, 0x80}, append([]byte(`\\fileserver\finance`), 0, 'M', 'S', 0)...)
	binary.LittleEndian.PutUint16(net, uint16(len(net)))

	// A folder inside a zip: the type byte is leftover memory, the name's
	// length is at 0x54 and the name at 0x5C.
	zipItem := func(typ byte, name string) []byte {
		w := wide(name + "\x00")
		b := make([]byte, 0x5C+len(w)+4)
		b[2], b[3], b[4], b[5] = typ, 0x2E, 0xFC, 0x7F
		copy(b[0x24:], wide("N/A"))
		binary.LittleEndian.PutUint32(b[0x54:], uint32(len(w)/2-1))
		copy(b[0x5C:], w)
		binary.LittleEndian.PutUint16(b, uint16(len(b)))
		return b
	}
	// A folder inside a 7z or tar on Windows 11: the path inside the archive
	// at 0x20, the lengths of its last part and of what precedes it before.
	archItem := func(typ byte, parent, name string) []byte {
		w := wide(parent + name + "\x00")
		b := make([]byte, 0x20+len(w)+6)
		b[2], b[4] = typ, 0x10
		binary.LittleEndian.PutUint32(b[0x18:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint16(b[0x1C:], uint16(len(wide(name))/2))
		binary.LittleEndian.PutUint16(b[0x1E:], uint16(len(wide(parent))/2))
		copy(b[0x20:], w)
		binary.LittleEndian.PutUint16(b, uint16(len(b)))
		return b
	}
	wrapped := make([]byte, 40)
	wrapped[2] = 0x2E
	copy(wrapped[4:], []byte{0x2F, 0x00, 0x10, 0xB7, 0xA6, 0xF5, 0x19, 0x00, 0x2F, 'E', ':', '\\'})
	binary.LittleEndian.PutUint16(wrapped, uint16(len(wrapped)))
	linux := [16]byte{0xD1, 0xA4, 0xB4, 0xB2, 0x54, 0x27, 0x40, 0x41, 0xA2, 0xEB, 0x9A, 0x76, 0xD9, 0xD7, 0xCD, 0xC6}

	cases := []struct {
		name string
		item []byte
		want string
		kind string
	}{
		{"root folder", guid(0x1F, 4, thisPC), "This PC", "root folder"},
		{"unknown root", guid(0x1F, 4, [16]byte{1, 2, 3, 4}), "{04030201-0000-0000-0000-000000000000}", "root folder"},
		{"volume", vol, "E:", "volume"},
		{"network", net, `\\fileserver\finance`, "network location"},
		{"folder, windows 10", fileItem(0x31, "SECRET~1", "Secret plans — très privé", 9, "2024-03-02 10:20:30", "2024-03-01 09:00:00", "2024-03-03 11:00:02"), "Secret plans — très privé", "folder"},
		{"folder, windows 8", fileItem(0x31, "STAGING", "staging", 8, "2024-03-02 10:20:30", "2024-03-01 09:00:00", "2024-03-03 11:00:02"), "staging", "folder"},
		{"folder, vista", fileItem(0x31, "OLDSTU~1", "Old stuff", 7, "2010-01-02 03:04:06", "2009-12-31 23:59:58", "2010-01-02 03:04:06"), "Old stuff", "folder"},
		{"folder, xp", fileItem(0x31, "MYDOCU~1", "My Documents", 3, "2009-07-31 20:23:38", "2007-10-11 12:48:36", "2009-08-04 15:10:30"), "My Documents", "folder"},
		{"file in a zip view", fileItem(0x32, "PAYLOAD.EXE", "payload.exe", 9, "2024-03-02 10:20:30", "2024-03-01 09:00:00", "2024-03-03 11:00:02"), "payload.exe", "file"},
		{"unicode short name", append(fileItem(0x35, "", "x", 9, "2024-03-02 10:20:30", "2024-03-01 09:00:00", "2024-03-03 11:00:02")[:14], wide("données\x00")...), "données", "folder"},
		{"zip folder, type byte looks like a file entry", zipItem(0x32, "payloads"), "payloads", "folder inside an archive"},
		{"zip folder, type byte looks like a network item", zipItem(0x5D, "données"), "données", "folder inside an archive"},
		{"zip folder, type byte zero", zipItem(0x00, "x"), "x", "folder inside an archive"},
		{"archive folder", archItem(0xFA, `data\`, "diagnostics"), "diagnostics", "folder inside an archive"},
		{"archive folder at the top", archItem(0x3A, "", "data"), "data", "folder inside an archive"},
		{"drive wrapped in a device item", wrapped, "E:", "volume"},
		{"linux root", guid(0x1F, 4, linux), "Linux", "root folder"},
		{"unrecognised", []byte{8, 0, 0x99, 0, 1, 2, 3, 4}, "(shell item type 0x99)", "unknown"},
	}
	for _, c := range cases {
		it := parseShellItem(c.item)
		if it.name != c.want || it.kind != c.kind {
			t.Errorf("%s: name %q kind %q, want %q %q", c.name, it.name, it.kind, c.want, c.kind)
		}
	}
	it := parseShellItem(cases[4].item)
	for what, got := range map[string]time.Time{"2024-03-02 10:20:30": it.modified, "2024-03-01 09:00:00": it.created, "2024-03-03 11:00:02": it.accessed} {
		if got.Format("2006-01-02 15:04:05") != what {
			t.Errorf("time: got %s, want %s", got.Format("2006-01-02 15:04:05"), what)
		}
	}
	if it.mftEntry != 0x1234 {
		t.Errorf("file-table entry = %#x", it.mftEntry)
	}
	// Truncated and nonsense items never panic and never claim a time.
	good := cases[4].item
	for n := 0; n <= len(good); n++ {
		parseShellItem(good[:n])
	}
	for i := range good {
		bad := append([]byte{}, good...)
		bad[i] ^= 0xFF
		parseShellItem(bad)
	}
	if _, ok := dosTime(0, 0); ok {
		t.Error("an empty DOS date was accepted")
	}
	if _, ok := dosTime(0x7FFF, 0xFFFF); ok {
		t.Error("an impossible DOS date was accepted")
	}
}

// The tree is walked from a real hive: the public Windows XP sample.
func TestShellbagsFromAHive(t *testing.T) {
	r := run(t, sample(t, "NTUSER.DAT"), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err %v warns %v", r.err, r.warns)
	}
	folders := map[string]Event{}
	var times []Event
	for _, e := range r.events {
		if e.Source != "shellbags" {
			continue
		}
		if e.Category != CatFileOpening {
			t.Errorf("%s: category %s", e.Type, e.Category)
		}
		if e.Type == "shellbag-folder-recorded" {
			if e.MACB != "" || !strings.HasPrefix(e.Path, `Desktop\`) || !strings.HasPrefix(e.Ref, "shellbag key ") {
				t.Errorf("folder event: %+v", e)
			}
			folders[e.Path] = e
		} else {
			times = append(times, e)
		}
	}
	const docs = `Desktop\This PC\C:\Documents and Settings\Administrator\My Documents`
	e, ok := folders[docs]
	if !ok || len(folders) != 5 {
		t.Fatalf("%d folders; the full path of My Documents was not rebuilt: %v", len(folders), folders)
	}
	if utc(e) != "2009-08-04T15:19:16.921875Z" && utc(e)[:19] != "2009-08-04T15:19:16" {
		t.Errorf("key time: %s", utc(e))
	}
	// Every level of the path is a node of its own.
	for _, p := range []string{`Desktop\This PC`, `Desktop\This PC\C:`, `Desktop\This PC\C:\Documents and Settings`} {
		if _, ok := folders[p]; !ok {
			t.Errorf("%s is missing", p)
		}
	}
	got := map[string]string{}
	for _, e := range times {
		if e.Path == docs {
			got[e.MACB] = utc(e)
		}
		if e.Stamp.Caveat == "" || !strings.Contains(e.Stamp.Raw, "DOS date and time") {
			t.Errorf("%s: shell item time carries no caveat or raw value: %+v", e.Type, e.Stamp)
		}
	}
	for macb, want := range map[string]string{"...B": "2007-10-11T12:48:36Z", "M...": "2009-07-31T20:23:38Z", ".A..": "2009-08-04T15:10:30Z"} {
		if got[macb] != want {
			t.Errorf("My Documents %s time = %s, want %s", macb, got[macb], want)
		}
	}
}

func TestSRUM(t *testing.T) {
	r := run(t, sample(t, "SRUDB.dat"), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err %v warns %v", r.err, r.warns)
	}
	count := map[string]int{}
	var usage, net, conn *Event
	for i, e := range r.events {
		count[e.Type]++
		if e.Source != "srum" || e.MACB != "" || e.Stamp.ZoneFrom != "native-utc" || !strings.HasPrefix(e.Ref, "table {") {
			t.Fatalf("event %d: %+v", i, e)
		}
		switch {
		case e.Ref == "table "+srumAppUsage+", AutoIncId 72":
			usage = &r.events[i]
		case e.Ref == "table "+srumNetUsage+", AutoIncId 6":
			net = &r.events[i]
		case e.Ref == "table "+srumNetConnect+", AutoIncId 2":
			conn = &r.events[i]
		}
	}
	// Row counts are those of the tables in the sample database.
	for typ, want := range map[string]int{"srum-application-usage-recorded": 1778, "srum-network-usage-recorded": 255,
		"srum-network-connected": 17, "srum-application-activity-ended": 4038} {
		if count[typ] != want {
			t.Errorf("%s: %d events, want %d", typ, count[typ], want)
		}
	}
	if usage == nil || net == nil || conn == nil {
		t.Fatal("known rows not found")
	}
	if utc(*usage) != "2021-10-07T08:55:00Z" || usage.Category != CatExecution || usage.User != "S-1-5-18" ||
		usage.Fields["foreground_bytes_read"] != uint64(195990016) || usage.Fields["foreground_bytes_written"] != uint64(10457088) ||
		!strings.Contains(usage.Message, "read 195990016 bytes, wrote 10457088 bytes") {
		t.Errorf("application usage row 72: %s %+v", utc(*usage), usage)
	}
	if utc(*net) != "2021-10-07T08:54:00Z" || net.Category != CatNetwork || net.Fields["bytes_sent"] != uint64(4063) || net.Fields["bytes_received"] != uint64(12213) {
		t.Errorf("network usage row 6: %s %+v", utc(*net), net)
	}
	// FILETIME 132780668556499330, a true start time rather than a recording time.
	if utc(*conn) != "2021-10-07T07:54:15.649933Z" || conn.Fields["connected_seconds"] != uint64(3644) {
		t.Errorf("connection row 2: %s %+v", utc(*conn), conn)
	}
	// Names come from the id table, not left as numbers.
	unnamed := 0
	for _, e := range r.events {
		if strings.Contains(e.Path, "(SRUM id") || strings.Contains(e.User, "(SRUM id") {
			unnamed++
		}
	}
	if unnamed > len(r.events)/20 {
		t.Errorf("%d of %d events have an application or user that was not resolved", unnamed, len(r.events))
	}
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "about once an hour") {
		t.Errorf("the meaning of the recording time is not explained: %v", r.notes)
	}
}

func TestSIDString(t *testing.T) {
	sid := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}
	for _, v := range []uint32{1111111111, 2222222222, 3333333333, 1001} {
		sid = binary.LittleEndian.AppendUint32(sid, v)
	}
	if got := sidString(sid); got != "S-1-5-21-1111111111-2222222222-3333333333-1001" {
		t.Errorf("sid: %s", got)
	}
	if got := sidString([]byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}); got != "S-1-5-18" {
		t.Errorf("system sid: %s", got)
	}
	for _, bad := range [][]byte{nil, {1, 5, 0, 0}, {2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}, {1, 9, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}} {
		if got := sidString(bad); got != "" {
			t.Errorf("malformed sid %v gave %q", bad, got)
		}
	}
}

// A damaged ESE database is reported, not fatal, and not silently empty.
func TestDamagedESE(t *testing.T) {
	data := append(bytes.Repeat([]byte{0}, 4), 0xEF, 0xCD, 0xAB, 0x89)
	data = append(data, bytes.Repeat([]byte{0xA5, 0x00, 0xFF, 0x13}, 8000)...)
	r := run(t, write(t, "x.dat", data), nil)
	if r.err == nil && len(r.warns) == 0 && len(r.notes) == 0 {
		t.Error("a damaged ESE database produced nothing and reported nothing")
	}
	if len(r.events) != 0 {
		t.Errorf("%d events from garbage", len(r.events))
	}
}
