package parsers

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func u16(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// attr builds one attribute. A resident one carries content; a non-resident
// one (nonResidentSize of zero or more) states only a size.
func attr(typ uint32, name string, content []byte, nonResidentSize int64) []byte {
	le := binary.LittleEndian
	n := u16(name)
	var a []byte
	if nonResidentSize < 0 {
		a = make([]byte, 24)
		le.PutUint16(a[10:], 24)
		a = append(a, n...)
		for len(a)%8 != 0 {
			a = append(a, 0)
		}
		le.PutUint32(a[16:], uint32(len(content)))
		le.PutUint16(a[20:], uint16(len(a)))
		a = append(a, content...)
	} else {
		a = make([]byte, 64)
		a[8] = 1
		le.PutUint16(a[10:], 64)
		le.PutUint64(a[48:], uint64(nonResidentSize))
		a = append(a, n...)
		for len(a)%8 != 0 {
			a = append(a, 0)
		}
		le.PutUint16(a[32:], uint16(len(a)))
		a = append(a, 0x11, 0x01, 0x10, 0x00) // one run, so the attribute is well formed
	}
	for len(a)%8 != 0 {
		a = append(a, 0)
	}
	le.PutUint32(a[0:], typ)
	le.PutUint32(a[4:], uint32(len(a)))
	a[9] = byte(len(n) / 2)
	return a
}

// fileRecord assembles a 1024-byte file record and applies the update
// sequence the way NTFS does when it writes one.
func fileRecord(entry uint32, flags uint16, attrs ...[]byte) []byte {
	le := binary.LittleEndian
	rec := make([]byte, 1024)
	copy(rec, "FILE")
	le.PutUint16(rec[4:], 0x30) // update sequence offset
	le.PutUint16(rec[6:], 3)    // check value and one entry per sector
	le.PutUint16(rec[0x10:], 1) // sequence number
	le.PutUint16(rec[0x12:], 1) // links
	le.PutUint16(rec[0x14:], 0x38)
	le.PutUint16(rec[0x16:], flags)
	le.PutUint32(rec[0x1C:], 1024)
	le.PutUint32(rec[0x2C:], entry)
	off := 0x38
	for _, a := range attrs {
		off += copy(rec[off:], a)
	}
	le.PutUint32(rec[off:], 0xFFFFFFFF)
	le.PutUint32(rec[0x18:], uint32(off+8))
	le.PutUint16(rec[0x30:], 0xBEEF)
	for i := 1; i <= 2; i++ {
		copy(rec[0x30+i*2:], rec[i*512-2:i*512])
		le.PutUint16(rec[i*512-2:], 0xBEEF)
	}
	return rec
}

const zoneText = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://files.test/landing\r\nHostUrl=https://cdn.test/tool.exe\r\n"

func TestRecordStreams(t *testing.T) {
	rec := fileRecord(40, 1,
		attr(0x80, "", []byte("the file's own content"), -1),
		attr(0x80, "Zone.Identifier", []byte(zoneText), -1),
		attr(0x80, "big", nil, 5<<20),
		attr(0x90, "$I30", []byte("not a data stream"), -1),
	)
	got := recordStreams(rec)
	if len(got) != 2 {
		t.Fatalf("streams: %+v", got)
	}
	z := got["Zone.Identifier"]
	if !z.Resident || z.Size != int64(len(zoneText)) || string(z.Content) != zoneText {
		t.Errorf("zone stream: %+v", z)
	}
	if b := got["big"]; b.Resident || b.Size != 5<<20 || b.Content != nil {
		t.Errorf("non-resident stream: %+v", b)
	}
	// A record whose update sequence does not agree was torn mid-write.
	torn := append([]byte(nil), rec...)
	torn[510] ^= 0xFF
	if recordStreams(torn) != nil {
		t.Error("a torn record was read")
	}
	// Cut short or overwritten anywhere, it must be refused or read safely.
	for n := 0; n < len(rec); n += 7 {
		recordStreams(rec[:n])
		bad := append([]byte(nil), rec...)
		for i := n; i < n+6 && i < len(bad); i++ {
			bad[i] = 0xFF
		}
		recordStreams(bad)
	}
}

func TestParseZone(t *testing.T) {
	z, ok := parseZone([]byte(zoneText))
	if !ok || !z.HasID || z.ID != 3 || z.HostURL != "https://cdn.test/tool.exe" || z.Referrer != "https://files.test/landing" {
		t.Errorf("zone: %+v %v", z, ok)
	}
	if s := z.summary(); s != "marked as from zone 3 (internet): https://cdn.test/tool.exe" {
		t.Errorf("summary: %q", s)
	}
	// UTF-16 with a byte order mark, as some tools write it.
	z, ok = parseZone(append([]byte{0xFF, 0xFE}, u16("[ZoneTransfer]\r\nZoneId=4\r\nLastWriterPackageFamilyName=App_x\r\nAppZoneId=7\r\n")...))
	if !ok || z.ID != 4 || z.Writer != "App_x" || z.Other["AppZoneId"] != "7" {
		t.Errorf("utf-16 zone: %+v %v", z, ok)
	}
	for _, not := range []string{"", "ZoneId=3", "[Other]\nZoneId=3"} {
		if _, ok := parseZone([]byte(not)); ok {
			t.Errorf("%q was taken for a zone mark", not)
		}
	}
	if z, ok := parseZone([]byte("[ZoneTransfer]\nZoneId=banana\n")); !ok || z.HasID || z.zone() != "not stated" {
		t.Errorf("a zone that is not a number: %+v", z)
	}
}

// A stream saved as an item of its own: facts and text, and no event,
// because the stream records no time.
func TestZoneIdentifierFile(t *testing.T) {
	r := run(t, write(t, "tool.exe_Zone.Identifier", []byte(zoneText)), nil)
	if r.err != nil || len(r.events) != 0 {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	if r.facts["zone.id"] != "3 (internet)" || r.facts["zone.host_url"] != "https://cdn.test/tool.exe" || r.facts["zone.referrer_url"] != "https://files.test/landing" {
		t.Errorf("facts: %v", r.facts)
	}
	if !strings.Contains(r.text, "HostUrl=") || len(r.notes) != 1 || !strings.Contains(r.notes[0], "records no time") {
		t.Errorf("text %q notes %q", r.text, r.notes)
	}
}

// A bare file table: the stream rows the library adds are not events, the
// file's own events name its streams, and a zone mark is read out of the record.
func TestMFTStreamsAndZoneMark(t *testing.T) {
	ft := uint64(133500000000000000) // early 2024
	si := make([]byte, 72)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(si[i*8:], ft+uint64(i)*10000000)
	}
	fn := func(name string) []byte {
		b := make([]byte, 66)
		binary.LittleEndian.PutUint64(b[0:], 5|1<<48) // parent: the root
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(b[8+i*8:], ft)
		}
		b[64], b[65] = byte(len(name)), 1
		return append(b, u16(name)...)
	}
	var mft []byte
	mft = append(mft, fileRecord(0, 1, attr(0x10, "", si, -1), attr(0x30, "", fn("tool.exe"), -1),
		attr(0x80, "", []byte("MZ"), -1), attr(0x80, "Zone.Identifier", []byte(zoneText), -1), attr(0x80, "extra", nil, 9000))...)
	mft = append(mft, fileRecord(1, 1, attr(0x10, "", si, -1), attr(0x30, "", fn("plain.txt"), -1), attr(0x80, "", []byte("hi"), -1))...)
	r := run(t, write(t, "$MFT", mft), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	var tool, plain *Event
	for i, e := range r.events {
		if strings.Contains(e.Path, ":") {
			t.Errorf("a stream was emitted as a file event: %s", e.Path)
		}
		switch {
		case strings.HasSuffix(e.Path, "tool.exe") && tool == nil:
			tool = &r.events[i]
		case strings.HasSuffix(e.Path, "plain.txt") && plain == nil:
			plain = &r.events[i]
		}
	}
	if tool == nil || plain == nil {
		t.Fatalf("events: %d, tool %v plain %v", len(r.events), tool != nil, plain != nil)
	}
	streams, _ := tool.Fields["streams"].([]map[string]any)
	if len(streams) != 2 || streams[0]["name"] != "Zone.Identifier" || streams[0]["size"] != int64(len(zoneText)) || streams[1]["name"] != "extra" || streams[1]["size"] != int64(9000) {
		t.Errorf("streams: %+v", tool.Fields["streams"])
	}
	if tool.Fields["zone_id"] != 3 || tool.Fields["zone"] != "internet" || tool.Fields["zone_host_url"] != "https://cdn.test/tool.exe" ||
		tool.Fields["zone_referrer_url"] != "https://files.test/landing" ||
		!strings.Contains(tool.Message, "marked as from zone 3 (internet): https://cdn.test/tool.exe") || !strings.Contains(tool.Message, "streams: Zone.Identifier, extra") {
		t.Errorf("zone mark: %q %+v", tool.Message, tool.Fields)
	}
	if plain.Fields["streams"] != nil || plain.Fields["zone_id"] != nil || strings.Contains(plain.Message, "streams") {
		t.Errorf("a file without streams: %q %+v", plain.Message, plain.Fields)
	}
	if !strings.Contains(strings.Join(r.notes, "\n"), "1 files carry a Zone.Identifier that was read") {
		t.Errorf("notes: %q", r.notes)
	}
}

// The public sample volume was written by Windows and holds one real stream.
func TestNTFSSampleStream(t *testing.T) {
	r := run(t, sample(t, "test.ntfs.dd"), nil)
	found := false
	for _, e := range r.events {
		if e.Source == "mft" && strings.Contains(e.Path, ":") {
			t.Errorf("a stream was emitted as a file event: %s", e.Path)
		}
		if e.Source == "mft" && strings.HasSuffix(e.Path, "Hello world text document.txt") {
			s, _ := e.Fields["streams"].([]map[string]any)
			if len(s) != 1 || s[0]["name"] != "goodbye.txt" || s[0]["size"] != int64(20) {
				t.Errorf("streams: %+v", e.Fields["streams"])
			}
			found = true
		}
	}
	if !found {
		t.Error("the file with a stream was not found")
	}
}

// A file with two names (a hard link) has a $FILE_NAME for each, with its
// own times. The library reports only the first; the second's must still
// reach the timeline, naming the link. Names whose times are those of the
// first (a DOS short name beside its Win32 name) add nothing.
func TestMFTEveryFileNamesTimes(t *testing.T) {
	ft := uint64(133500000000000000)
	sec := uint64(10000000)
	si := make([]byte, 72)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(si[i*8:], ft+uint64(i)*sec)
	}
	fn := func(name string, space byte, parent uint64, at uint64) []byte {
		b := make([]byte, 66)
		binary.LittleEndian.PutUint64(b[0:], parent|1<<48)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(b[8+i*8:], at)
		}
		b[64], b[65] = byte(len(name)), space
		return append(b, u16(name)...)
	}
	link := ft + 500*sec
	var mft []byte
	mft = append(mft, fileRecord(0, 1, attr(0x10, "", si, -1), attr(0x30, "", fn("report.txt", 1, 5, ft), -1),
		attr(0x30, "", fn("copy.txt", 0, 5, link), -1), attr(0x80, "", []byte("x"), -1))...)
	mft = append(mft, fileRecord(1, 1, attr(0x10, "", si, -1), attr(0x30, "", fn("LONGNA~1.TXT", 2, 5, ft), -1),
		attr(0x30, "", fn("long name.txt", 1, 5, ft), -1), attr(0x80, "", []byte("y"), -1))...)
	r := run(t, write(t, "$MFT", mft), nil)
	if r.err != nil {
		t.Fatalf("err=%v", r.err)
	}
	var linked []Event
	for _, e := range r.events {
		if e.Fields["file_name"] != nil {
			linked = append(linked, e)
		}
	}
	if len(linked) != 1 {
		t.Fatalf("want one event for the second name's times, got %d: %+v", len(linked), linked)
	}
	e := linked[0]
	want := int64(link-116444736000000000) * 100
	if e.Stamp.UTC.UnixNano() != want || e.MACB != "MACB" || e.Type != "$FN MACB" || e.Fields["entry"] != int64(0) ||
		e.Fields["file_name"] != "copy.txt" || e.Fields["file_name_namespace"] != "POSIX" || e.Fields["file_name_parent_entry"] != uint64(5) ||
		!strings.Contains(e.Message, `"copy.txt"`) {
		t.Errorf("event: %s %s %d %q %+v", e.Type, e.MACB, e.Stamp.UTC.UnixNano(), e.Message, e.Fields)
	}
	if !strings.Contains(strings.Join(r.notes, "\n"), "1 files have more than one name whose $FILE_NAME times differ") {
		t.Errorf("notes: %q", r.notes)
	}
}

// A name can sit in an extension record that a bare $MFT gives no attribute
// list for. Such a name's times must still reach the timeline; and a file
// whose every name is in an extension record, which the library leaves
// out, must appear too.
func TestMFTNamesInExtensionRecords(t *testing.T) {
	ft := uint64(133500000000000000)
	sec := uint64(10000000)
	si := make([]byte, 72)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(si[i*8:], ft+uint64(i)*sec)
	}
	fn := func(name string, space byte, at uint64) []byte {
		b := make([]byte, 66)
		binary.LittleEndian.PutUint64(b[0:], 5|1<<48)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(b[8+i*8:], at)
		}
		b[64], b[65] = byte(len(name)), space
		return append(b, u16(name)...)
	}
	ext := func(entry, base uint32, attrs ...[]byte) []byte {
		r := fileRecord(entry, 1, attrs...)
		binary.LittleEndian.PutUint64(r[0x20:], uint64(base)|1<<48)
		return r
	}
	var mft []byte
	mft = append(mft, fileRecord(0, 1, attr(0x10, "", si, -1), attr(0x30, "", fn("first.txt", 1, ft), -1), attr(0x80, "", []byte("a"), -1))...)
	mft = append(mft, fileRecord(1, 1, attr(0x10, "", si, -1), attr(0x30, "", fn("linked.txt", 1, ft), -1), attr(0x80, "", []byte("b"), -1))...)
	mft = append(mft, ext(2, 1, attr(0x30, "", fn("other.txt", 0, ft+500*sec), -1))...)
	mft = append(mft, fileRecord(3, 1, attr(0x10, "", si, -1), attr(0x80, "", []byte("cc"), -1))...)
	mft = append(mft, ext(4, 3, attr(0x30, "", fn("orphan.txt", 1, ft+900*sec), -1))...)
	r := run(t, write(t, "$MFT", mft), nil)
	if r.err != nil {
		t.Fatalf("err=%v", r.err)
	}
	ns := func(x uint64) int64 { return int64(x-116444736000000000) * 100 }
	var other, orphanSI, orphanFN bool
	for _, e := range r.events {
		switch {
		case e.Fields["file_name"] == "other.txt":
			other = e.Fields["entry"] == int64(1) && e.Type == "$FN MACB" && e.Stamp.UTC.UnixNano() == ns(ft+500*sec)
		case e.Path == "/orphan.txt" && e.Type == "$SI ...B":
			orphanSI = e.Fields["names_only_in_extension_records"] == true && e.Fields["entry"] == int64(3) && e.Stamp.UTC.UnixNano() == ns(ft)
		case e.Path == "/orphan.txt" && e.Type == "$FN MACB":
			orphanFN = e.Stamp.UTC.UnixNano() == ns(ft+900*sec)
		}
	}
	if !other || !orphanSI || !orphanFN {
		for _, e := range r.events {
			t.Logf("%s %s %d %+v", e.Path, e.Type, e.Stamp.UTC.UnixNano(), e.Fields)
		}
		t.Fatalf("extension name %v, skipped file $SI %v $FN %v", other, orphanSI, orphanFN)
	}
	if !strings.Contains(strings.Join(r.notes, "\n"), "1 files hold all their names in extension records") {
		t.Errorf("notes: %q", r.notes)
	}
}
