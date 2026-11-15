package parsers

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

func npULEB(v uint64) []byte {
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

func npWide(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:], c)
	}
	return out
}

// npTab builds a Windows Notepad tab state file. path "" makes a tab that
// was never saved to a file.
func npTab(path string, filetime uint64, content string) []byte {
	var body bytes.Buffer
	n := uint64(len(utf16.Encode([]rune(content))))
	if path == "" {
		body.Write([]byte{0, 1})
	} else {
		body.WriteByte(1)
		body.Write(npULEB(uint64(len(utf16.Encode([]rune(path))))))
		body.Write(npWide(path))
		body.Write(npULEB(n))
		body.Write([]byte{5, 1})
		body.Write(npULEB(filetime))
		body.Write(make([]byte, 32))
		body.Write([]byte{0, 1})
	}
	body.Write([]byte{0, 0, 1, 0, 0, 3, 0, 0, 1})
	body.Write(npULEB(n))
	body.Write(npWide(content))
	body.WriteByte(1)
	out := append([]byte{'N', 'P', 0}, body.Bytes()...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(body.Bytes()))
}

func TestWindowsNotepad(t *testing.T) {
	// 2024-05-01 12:00:00 UTC as a FILETIME.
	ft := uint64(time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Unix()+11644473600) * 10000000

	// Named like anything at all: identification is by content.
	r := run(t, write(t, "a1b2.bin", npTab(`C:\Users\alice\Desktop\plan.txt`, ft, "meet at the usual place")), nil)
	if r.err != nil || len(r.events) != 1 {
		t.Fatalf("file tab: %v, %d events, notes %v", r.err, len(r.events), r.notes)
	}
	e := r.events[0]
	if utc(e) != "2024-05-01T12:00:00Z" || e.Path != `C:\Users\alice\Desktop\plan.txt` || e.Source != "notepad" || e.Category != CatFileOpening || e.MACB != "M..." {
		t.Errorf("event %+v", e)
	}
	if !strings.Contains(e.Fields["time_meaning"].(string), "not independently confirmed") {
		t.Error("the event does not say its time's meaning is unconfirmed")
	}
	if r.text != "meet at the usual place" {
		t.Errorf("tab text was not indexed: %q", r.text)
	}

	// Never saved: nothing to date it by, so no event, but the text is kept.
	r = run(t, write(t, "x.bin", npTab("", 0, "admin / Winter2024!")), nil)
	if r.err != nil || len(r.events) != 0 || r.text != "admin / Winter2024!" || r.facts["notepad.unsaved_tab"] != "19 characters" {
		t.Errorf("unsaved tab: %v events=%d text=%q facts=%v", r.err, len(r.events), r.text, r.facts)
	}
	if len(r.notes) == 0 || !strings.Contains(r.notes[0], "not on the timeline") {
		t.Errorf("the examiner is not told why nothing is on the timeline: %v", r.notes)
	}

	// A file open with nothing unsaved has no time either.
	r = run(t, write(t, "y.bin", npTab(`D:\todo.txt`, 0, "")), nil)
	if r.err != nil || len(r.events) != 0 || r.facts["notepad.open_file"] != `D:\todo.txt` {
		t.Errorf("saved tab: %v %d %v", r.err, len(r.events), r.facts)
	}

	// Damaged: not recognised as Notepad state at all, so never half-read.
	bad := npTab(`D:\todo.txt`, ft, "abc")
	bad[10] ^= 0xFF
	if k := detect.Identify(bytes.NewReader(bad), int64(len(bad))).Kind; k == detect.WinNotepad {
		t.Error("a state file whose checksum fails was still identified as one")
	}
}

const nppSession = `<?xml version="1.0" encoding="UTF-8"?>
<NotepadPlus>
    <Session activeView="0">
        <mainView activeIndex="1">
            <File firstVisibleLine="0" lang="None (Normal Text)" filename="new 3" backupFilePath="C:\Users\alice\AppData\Roaming\Notepad++\backup\new 3@2024-07-10_131652" originalFileLastModifTimestamp="0" originalFileLastModifTimestampHigh="0" />
            <File firstVisibleLine="0" lang="Shell" filename="C:\tools\run.sh" backupFilePath="" originalFileLastModifTimestamp="2147483648" originalFileLastModifTimestampHigh="31000000" />
            <File firstVisibleLine="0" lang="None (Normal Text)" filename="C:\Users\alice\notes &amp; ideas.txt" backupFilePath="" originalFileLastModifTimestamp="0" originalFileLastModifTimestampHigh="0" />
        </mainView>
        <subView activeIndex="0" />
    </Session>
</NotepadPlus>
`

const nppConfig = `<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <FindHistory nbMaxFindHistoryPath="10" matchWord="no">
        <Path name="C:\Shares\Finance" />
        <Filter name="*.xlsx" />
        <Find name="password" />
        <Find name="iban" />
        <Replace name="REDACTED" />
    </FindHistory>
    <History nbMaxFile="10" inSubMenu="no" customLength="-1">
        <File filename="C:\Users\alice\Desktop\creds.txt" />
    </History>
    <GUIConfigs />
</NotepadPlus>
`

func TestNotepadPlusPlus(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no zone database")
	}
	local := func(c *Context) {
		c.Local = timeutil.LocalContext{Loc: berlin, ZoneFrom: timeutil.ZoneHost, ZoneName: "Europe/Berlin"}
	}
	r := run(t, write(t, "anything.txt", []byte(nppSession)), local)
	if r.err != nil || len(r.events) != 2 {
		t.Fatalf("session: %v, %d events", r.err, len(r.events))
	}
	// The backup's name is local time; Berlin is two hours ahead in July.
	b := r.events[0]
	if b.Type != "notepad++-unsaved-copy-kept" || utc(b) != "2024-07-10T11:16:52Z" || b.Path != "new 3" || b.MACB != "" ||
		b.Stamp.ZoneFrom != timeutil.ZoneHost || !strings.Contains(b.Fields["time_meaning"].(string), "name of the backup file") {
		t.Errorf("backup event %+v at %s", b, utc(b))
	}
	// High and low halves of a FILETIME.
	st, _ := timeutil.FromFiletime(uint64(31000000)<<32 | 2147483648)
	want := st.UTC.Format(time.RFC3339Nano)
	m := r.events[1]
	if m.Type != "file-modified (notepad++ session)" || m.Path != `C:\tools\run.sh` || m.MACB != "M..." || utc(m) != want || m.Source != "notepad++" {
		t.Errorf("modified event %+v at %s, want %s", m, utc(m), want)
	}
	if r.facts["notepad++.open_file"] != `C:\Users\alice\notes & ideas.txt` {
		t.Errorf("an open file with no time is not recorded: %v", r.facts)
	}
	if !strings.Contains(r.text, "run.sh") {
		t.Error("the session is not indexed as text")
	}

	r = run(t, write(t, "c.xml", []byte(nppConfig)), nil)
	if r.err != nil || len(r.events) != 0 {
		t.Fatalf("settings: %v, %d events", r.err, len(r.events))
	}
	for k, v := range map[string]string{
		"notepad++.recent_file": `C:\Users\alice\Desktop\creds.txt`, "notepad++.search_term": "iban", "notepad++.replace_term": "REDACTED",
		"notepad++.search_folder": `C:\Shares\Finance`, "notepad++.search_filter": "*.xlsx",
	} {
		if r.facts[k] != v {
			t.Errorf("fact %s = %q, want %q", k, r.facts[k], v)
		}
	}
	if len(r.notes) == 0 || !strings.Contains(strings.Join(r.notes, " "), "keeps no times") {
		t.Errorf("notes: %v", r.notes)
	}

	// Other XML that merely mentions the editor is left to the ordinary text handling.
	r = run(t, write(t, "o.xml", []byte("<?xml version=\"1.0\"?>\n<Other><NotepadPlus>x</NotepadPlus></Other>\n")), nil)
	if len(r.facts) != 0 && r.facts["notepad++.file"] != "" {
		t.Errorf("unrelated XML was read as Notepad++'s: %v", r.facts)
	}
}
