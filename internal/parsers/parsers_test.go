package parsers

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

type result struct {
	events []Event
	warns  []string
	notes  []string
	facts  map[string]string
	text   string
	err    error
}

// run identifies data by content, picks the parser the pipeline would pick,
// and collects what it emits.
func run(t *testing.T, path string, mod func(*Context)) result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	kind := detect.Identify(f, st.Size()).Kind
	p := For(kind)
	if p == nil {
		p = Generic()
	}
	return runWith(t, p, f, kind, mod)
}

func runWith(t *testing.T, p Parser, f *os.File, kind string, mod func(*Context)) result {
	t.Helper()
	st, _ := f.Stat()
	res := result{facts: map[string]string{}}
	ctx := &Context{
		File: f, Size: st.Size(), Name: filepath.Base(f.Name()), Kind: kind, Local: timeutil.AssumedUTC(),
		ReceivedYear: 2024, ReceivedMonth: 6,
		Emit: func(e Event) error { res.events = append(res.events, e); return nil },
		Fact: func(k, v, _ string) { res.facts[k] = v },
		Warn: func(f string, a ...any) { res.warns = append(res.warns, fmt.Sprintf(f, a...)) },
		Note: func(f string, a ...any) { res.notes = append(res.notes, fmt.Sprintf(f, a...)) },
		Text: func(_ string, _ bool, body string) { res.text = body },
	}
	if mod != nil {
		mod(ctx)
	}
	res.err = p.Parse(ctx)
	return res
}

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func utc(e Event) string { return e.Stamp.UTC.Format(time.RFC3339Nano) }

func sample(t *testing.T, rel ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{"..", "..", "testdata"}, rel...)...)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("sample %s not present; run scripts/fetch-testdata.sh", filepath.Join(rel...))
	}
	return p
}

// --------------------------------------------------------------- text ----

func TestISOLines(t *testing.T) {
	log := "preamble with no time\n" +
		"2024-03-01T10:00:00Z service started\n" +
		"  continuation line\n" +
		"2024-03-01 10:00:05+01:00 with offset\n" +
		"2024-03-01 10:00:06,250 local with comma fraction\n" +
		"[2024-03-01 10:00:07.5] bracketed local\n" +
		"\n" +
		"2024-03-01T10:00:08-0500 offset without colon\n"
	r := run(t, write(t, "app.log", []byte(log)), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	want := []struct{ utc, zone, ref string }{
		{"2024-03-01T10:00:00Z", timeutil.ZoneExplicit, "line 2"},
		{"2024-03-01T09:00:05Z", timeutil.ZoneExplicit, "line 4"},
		{"2024-03-01T10:00:06.25Z", timeutil.ZoneAssumed, "line 5"},
		{"2024-03-01T10:00:07.5Z", timeutil.ZoneAssumed, "line 6"},
		{"2024-03-01T15:00:08Z", timeutil.ZoneExplicit, "line 8"},
	}
	if len(r.events) != len(want) {
		t.Fatalf("got %d events, want %d", len(r.events), len(want))
	}
	for i, w := range want {
		e := r.events[i]
		if utc(e) != w.utc || e.Stamp.ZoneFrom != w.zone || e.Ref != w.ref {
			t.Errorf("event %d: %s %s %s, want %s %s %s", i, utc(e), e.Stamp.ZoneFrom, e.Ref, w.utc, w.zone, w.ref)
		}
	}
	if !strings.Contains(r.events[0].Message, "continuation line") {
		t.Errorf("continuation not joined to its entry: %q", r.events[0].Message)
	}
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "1 lines before the first timestamped entry") {
		t.Errorf("orphan line not reported: %v", r.notes)
	}
}

// Local times are converted with the zone the context supplies, and say so.
func TestLocalTimesUseTheContextZone(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/London")
	r := run(t, write(t, "a.log", []byte("2024-07-15 12:00:00 summer\n2024-01-15 12:00:00 winter\n2024-10-27 01:30:00 repeated hour\n")), func(c *Context) {
		c.Local = timeutil.LocalContext{Loc: loc, ZoneFrom: timeutil.ZoneHost, ZoneName: "Europe/London"}
	})
	if len(r.events) != 3 {
		t.Fatalf("got %d events", len(r.events))
	}
	for i, want := range []string{"2024-07-15T11:00:00Z", "2024-01-15T12:00:00Z", "2024-10-27T00:30:00Z"} {
		if utc(r.events[i]) != want || r.events[i].Stamp.ZoneFrom != timeutil.ZoneHost || r.events[i].Stamp.ZoneName != "Europe/London" {
			t.Errorf("event %d: %s (%s), want %s", i, utc(r.events[i]), r.events[i].Stamp.ZoneFrom, want)
		}
	}
	if r.events[0].Stamp.Raw != "2024-07-15 12:00:00" {
		t.Errorf("raw value not kept as found: %q", r.events[0].Stamp.Raw)
	}
	if r.events[2].Stamp.Caveat == "" || r.events[0].Stamp.Caveat != "" {
		t.Errorf("repeated-hour caveat wrong: %q / %q", r.events[2].Stamp.Caveat, r.events[0].Stamp.Caveat)
	}
}

// Rule: ambiguous date formats are not parsed.
func TestAmbiguousDatesAreNotGuessed(t *testing.T) {
	for _, log := range []string{
		"01/02/2024 10:00:00 logon\n03/04/2024 11:00:00 logoff\n",
		"1.2.24 10:00 something\n2.3.24 11:00 something\n",
		"just some prose\nwith no timestamps at all\n",
	} {
		r := run(t, write(t, "a.log", []byte(log)), nil)
		if len(r.events) != 0 {
			t.Errorf("%q produced %d events", log, len(r.events))
		}
		if !errors.Is(r.err, ErrNothingExtracted) {
			t.Errorf("%q: err = %v, want ErrNothingExtracted so generic handling takes over", log, r.err)
		}
	}
}

func TestAccessLog(t *testing.T) {
	log := `203.0.113.9 - alice [10/Oct/2023:13:55:36 -0700] "GET /admin/login.php?x=1 HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0"
203.0.113.9 - - [10/Oct/2023:13:55:37 +0000] "POST /upload HTTP/1.1" 500 12
`
	r := run(t, write(t, "access.log", []byte(log)), nil)
	if r.err != nil || len(r.events) != 2 {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	e := r.events[0]
	if utc(e) != "2023-10-10T20:55:36Z" || e.Stamp.ZoneFrom != timeutil.ZoneExplicit || e.Stamp.ZoneName != "-07:00" {
		t.Errorf("time: %s %s %s", utc(e), e.Stamp.ZoneFrom, e.Stamp.ZoneName)
	}
	if e.User != "alice" || e.Path != "/admin/login.php?x=1" || e.Fields["status"] != "200" || e.Fields["client"] != "203.0.113.9" {
		t.Errorf("fields: user=%q path=%q %v", e.User, e.Path, e.Fields)
	}
	if r.events[1].User != "" || r.events[1].Path != "/upload" {
		t.Errorf("second line: %+v", r.events[1])
	}
}

func TestW3CIsUTCUnlessTheFileSaysLocal(t *testing.T) {
	iis := "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Date: 2024-02-03 04:05:06\n" +
		"#Fields: date time s-ip cs-method cs-uri-stem cs-username sc-status\n" +
		"2024-02-03 04:05:06 10.0.0.1 GET /index.html - 200\n" +
		"2024-02-03 04:05:07 10.0.0.1 POST /login bob 302\n"
	r := run(t, write(t, "u_ex.log", []byte(iis)), nil)
	if r.err != nil || len(r.events) != 2 {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	if e := r.events[1]; utc(e) != "2024-02-03T04:05:07Z" || e.Stamp.ZoneFrom != timeutil.ZoneNative || e.User != "bob" || e.Path != "/login" || e.Ref != "line 6" {
		t.Errorf("iis event: %s %s %+v", utc(e), e.Stamp.ZoneFrom, e)
	}
	if _, has := r.events[0].Fields["cs-username"]; has {
		t.Error(`"-" placeholder stored as a value`)
	}

	fw := "#Version: 1.5\n#Software: Microsoft Windows Firewall\n#Time Format: Local\n" +
		"#Fields: date time action protocol src-ip dst-ip\n\n" +
		"2024-07-15 12:00:00 DROP TCP 10.0.0.5 10.0.0.9\n"
	r = run(t, write(t, "pfirewall.log", []byte(fw)), nil)
	if len(r.events) != 1 || r.events[0].Stamp.ZoneFrom != timeutil.ZoneAssumed {
		t.Fatalf("firewall log: %d events, zone %v", len(r.events), r.events)
	}
}

func TestSyslogYearIsInferredAndDeclared(t *testing.T) {
	log := "Nov 30 23:59:58 gw sshd[411]: Accepted publickey for root\n" +
		"Dec 31 23:59:59 gw kernel: last of the year\n" +
		"\tcontinued detail\n" +
		"Jan  1 00:00:01 gw cron[9]: first of the year\n" +
		"May  7 08:00:00 gw su: session opened\n"
	// Received June 2024: May is 2024, January 2024, December and November 2023.
	r := run(t, write(t, "messages", []byte(log)), nil)
	if r.err != nil || len(r.events) != 4 {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	for i, want := range []string{"2023-11-30T23:59:58Z", "2023-12-31T23:59:59Z", "2024-01-01T00:00:01Z", "2024-05-07T08:00:00Z"} {
		e := r.events[i]
		if utc(e) != want {
			t.Errorf("event %d: %s, want %s", i, utc(e), want)
		}
		if e.Stamp.ZoneFrom != timeutil.ZoneAssumed {
			t.Errorf("event %d: zone %s, want assumed", i, e.Stamp.ZoneFrom)
		}
		if _, ok := e.Fields["year_inferred"]; !ok {
			t.Errorf("event %d does not declare its inferred year", i)
		}
	}
	if e := r.events[0]; e.Host != "gw" || e.Fields["program"] != "sshd" || e.Fields["pid"] != "411" {
		t.Errorf("syslog fields: %+v", e)
	}
	if !strings.Contains(r.events[1].Message, "continued detail") {
		t.Error("continuation line lost")
	}
	if len(r.notes) == 0 || !strings.Contains(r.notes[0], "inferred") {
		t.Errorf("inference not noted: %v", r.notes)
	}
	// A log whose last entry is later in the year than the receipt month is from the year before.
	r = run(t, write(t, "messages", []byte("Sep  1 10:00:00 h p: a\nSep  2 10:00:00 h p: b\n")), nil)
	if len(r.events) != 2 || utc(r.events[1]) != "2023-09-02T10:00:00Z" {
		t.Errorf("future month not rolled back a year: %v", r.events)
	}
}

func TestJSONShapes(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
		warn       bool
	}{
		{"lines", `{"timestamp":"2024-03-01T10:00:00Z","msg":"a","user":"dan","hostname":"h1"}` + "\n" + `{"timestamp":"2024-03-01T10:00:01.5Z","msg":"b"}` + "\n",
			[]string{"2024-03-01T10:00:00Z", "2024-03-01T10:00:01.5Z"}, false},
		{"array", `[{"@timestamp":"2024-03-01T10:00:00+02:00","message":"a"},{"@timestamp":"2024-03-01T10:00:01Z","message":"b"}]`,
			[]string{"2024-03-01T08:00:00Z", "2024-03-01T10:00:01Z"}, false},
		{"cloudtrail", `{"Records":[{"eventTime":"2024-03-01T10:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","userIdentity":{"arn":"arn:aws:iam::1:user/x"}}]}`,
			[]string{"2024-03-01T10:00:00Z"}, false},
		{"epoch seconds", `{"ts":1700000000,"msg":"a"}` + "\n" + `{"ts":1700000001.25,"msg":"b"}` + "\n", []string{"2023-11-14T22:13:20Z", "2023-11-14T22:13:21.25Z"}, false},
		{"epoch millis", `{"time":1700000000123,"msg":"a"}` + "\n" + `{"time":"1700000000456","msg":"b"}` + "\n", []string{"2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.456Z"}, false},
		{"some untimed", `[{"time":"2024-03-01T10:00:00Z"},{"no_time":true}]`, []string{"2024-03-01T10:00:00Z"}, true},
		{"pretty array", "[\n  {\n    \"time\": \"2024-03-01T10:00:00Z\",\n    \"event\": \"x\"\n  }\n]\n", []string{"2024-03-01T10:00:00Z"}, false},
		{"bom", "\xEF\xBB\xBF" + `{"time":"2024-03-01T10:00:00Z","event":"x"}` + "\n", []string{"2024-03-01T10:00:00Z"}, false},
	}
	for _, c := range cases {
		r := run(t, write(t, "x.json", []byte(c.body)), nil)
		if r.err != nil {
			t.Errorf("%s: %v", c.name, r.err)
			continue
		}
		if len(r.events) != len(c.want) {
			t.Errorf("%s: %d events, want %d", c.name, len(r.events), len(c.want))
			continue
		}
		for i, w := range c.want {
			if utc(r.events[i]) != w {
				t.Errorf("%s: event %d at %s, want %s", c.name, i, utc(r.events[i]), w)
			}
		}
		if (len(r.warns) > 0) != c.warn {
			t.Errorf("%s: warnings = %v", c.name, r.warns)
		}
	}
	r := run(t, write(t, "x.json", []byte(cases[0].body)), nil)
	if e := r.events[0]; e.User != "dan" || e.Host != "h1" || e.Message != "a" || e.Ref != "line 1" {
		t.Errorf("json fields: %+v", e)
	}
	r = run(t, write(t, "x.json", []byte(cases[2].body)), nil)
	if e := r.events[0]; e.User != "arn:aws:iam::1:user/x" || e.Message != "iam.amazonaws.com CreateUser" {
		t.Errorf("cloudtrail: user=%q message=%q", e.User, e.Message)
	}
	// JSON with no time anywhere is handed to generic handling, not dropped.
	r = run(t, write(t, "x.json", []byte(`{"a":1,"b":[1,2,3]}`)), nil)
	if !errors.Is(r.err, ErrNothingExtracted) || len(r.events) != 0 {
		t.Errorf("untimed json: err=%v events=%d", r.err, len(r.events))
	}
}

// The format is chosen from the first 200 lines and the file is then re-read
// from the start. Nothing may be lost or repeated at that seam, whatever the
// file size relative to the read buffers.
func TestLargeLogIsReadExactlyOnce(t *testing.T) {
	for _, n := range []int{1, 199, 200, 201, 5000, 60000} {
		var b bytes.Buffer
		base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "%s entry number %d %s\n", base.Add(time.Duration(i)*time.Second).Format(time.RFC3339), i, strings.Repeat("x", i%97))
		}
		r := run(t, write(t, "big.log", b.Bytes()), nil)
		if r.err != nil || len(r.events) != n {
			t.Fatalf("%d lines: %d events, err=%v", n, len(r.events), r.err)
		}
		for i, e := range r.events {
			if e.Ref != fmt.Sprintf("line %d", i+1) || !strings.Contains(e.Message, fmt.Sprintf("entry number %d ", i)) {
				t.Fatalf("%d lines: event %d is %q at %s", n, i, trunc(e.Message, 60), e.Ref)
			}
		}
	}
}

func TestUTF16Log(t *testing.T) {
	var raw []byte
	raw = append(raw, 0xFF, 0xFE)
	for _, u := range utf16.Encode([]rune("2024-03-01 10:00:00Z Setup started — naïve\r\n2024-03-01 10:00:01Z Setup finished\r\n")) {
		raw = binary.LittleEndian.AppendUint16(raw, u)
	}
	r := run(t, write(t, "setupact.log", raw), nil)
	if r.err != nil || len(r.events) != 2 {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	if !strings.Contains(r.events[0].Message, "naïve") {
		t.Errorf("utf-16 text not decoded: %q", r.events[0].Message)
	}
}

// ------------------------------------------------------------ generic ----

func TestGenericMakesAnythingFindable(t *testing.T) {
	data := append(bytes.Repeat([]byte{0x00, 0x01, 0xFF}, 100), "C:\\Windows\\Temp\\evil-payload.exe"...)
	data = append(data, 0, 1, 2)
	for _, u := range utf16.Encode([]rune("WideStringMarker")) {
		data = binary.LittleEndian.AppendUint16(data, u)
	}
	data = append(data, 0xFF, 0xFE, 0x00)
	r := run(t, write(t, "blob.bin", data), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if !strings.Contains(r.text, "evil-payload.exe") || !strings.Contains(r.text, "WideStringMarker") {
		t.Errorf("strings not extracted: %q", r.text)
	}
	if r.facts["file.entropy"] == "" {
		t.Error("entropy not recorded")
	}
}

func TestPELinkTime(t *testing.T) {
	pe := make([]byte, 0x200)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x80)
	copy(pe[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(pe[0x86:], 5)
	binary.LittleEndian.PutUint32(pe[0x88:], 1700000000)
	r := run(t, write(t, "x.exe", pe), nil)
	if r.err != nil || len(r.events) != 1 {
		t.Fatalf("err=%v events=%d warns=%v", r.err, len(r.events), r.warns)
	}
	e := r.events[0]
	if utc(e) != "2023-11-14T22:13:20Z" || !strings.Contains(e.Type, "unverified") || e.Fields["machine"] != "0x8664" {
		t.Errorf("pe event: %s %q %v", utc(e), e.Type, e.Fields)
	}
	// A truncated executable is reported, not fatal.
	r = run(t, write(t, "x.exe", pe[:0x60]), nil)
	if r.err != nil || len(r.warns) != 1 {
		t.Errorf("truncated pe: err=%v warns=%v", r.err, r.warns)
	}
}

// ------------------------------------------------------------ browser ----

func webkit(s string) int64 {
	tm, _ := time.Parse(time.RFC3339Nano, s)
	return tm.UnixMicro() + 11644473600000000
}

func makeDB(t *testing.T, name string, stmts ...string) string {
	t.Helper()
	// A directory with a space and a percent sign, as real case paths have.
	dir := filepath.Join(t.TempDir(), "case 100% real")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	db.Close()
	return p
}

func TestChromiumHistory(t *testing.T) {
	p := makeDB(t, "History",
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
		`CREATE TABLE downloads(id INTEGER PRIMARY KEY, start_time INTEGER, end_time INTEGER, target_path TEXT, total_bytes INTEGER, tab_url TEXT)`,
		`INSERT INTO urls VALUES (1,'https://example.com/a','Example A',2),(2,'https://evil.test/payload',NULL,1)`,
		fmt.Sprintf(`INSERT INTO visits VALUES (10,1,%d,805306368),(11,2,%d,1),(12,1,0,1)`, webkit("2024-01-17T21:20:00.123456Z"), webkit("2024-01-17T21:21:00Z")),
		fmt.Sprintf(`INSERT INTO downloads VALUES (5,%d,%d,'C:\Users\dan\Downloads\payload.exe',4096,'https://evil.test/payload')`, webkit("2024-01-17T21:21:05Z"), webkit("2024-01-17T21:21:09Z")),
	)
	before, _ := os.ReadFile(p)
	r := run(t, p, nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if len(r.events) != 4 {
		t.Fatalf("got %d events, want 4 (the zero visit time carries no information)", len(r.events))
	}
	e := r.events[0]
	if utc(e) != "2024-01-17T21:20:00.123456Z" || e.Type != "url-visited (link)" || e.Path != "https://example.com/a" || e.Ref != "visits.id 10" ||
		e.Stamp.ZoneFrom != timeutil.ZoneNative || e.Fields["title"] != "Example A" {
		t.Errorf("visit: %s %+v", utc(e), e)
	}
	if d := r.events[3]; d.Type != "download-finished" || utc(d) != "2024-01-17T21:21:09Z" || d.Path != `C:\Users\dan\Downloads\payload.exe` {
		t.Errorf("download: %s %+v", utc(d), d)
	}
	// Rule: evidence is never written to. No journal or lock file may appear either.
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Error("the database file was modified by parsing it")
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("parsing left extra files beside the evidence: %v", entries)
	}
}

// A current Chromium history: referrers, search terms, visits synced from
// another device, addresses whose visits have expired, and download detail.
func TestChromiumHistoryInFull(t *testing.T) {
	at := func(s string) int64 { return webkit(s) }
	p := makeDB(t, "History",
		`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO meta VALUES ('version','70')`,
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, external_referrer_url TEXT, transition INTEGER,
			visit_duration INTEGER, opener_visit INTEGER, originator_cache_guid TEXT, app_id TEXT)`,
		`CREATE TABLE visit_source(id INTEGER PRIMARY KEY, source INTEGER)`,
		`CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT)`,
		`CREATE TABLE content_annotations(visit_id INTEGER PRIMARY KEY, search_terms TEXT, page_language TEXT, password_state INTEGER)`,
		`CREATE TABLE context_annotations(visit_id INTEGER PRIMARY KEY, response_code INTEGER, total_foreground_duration INTEGER)`,
		`CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
			state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, hash BLOB, end_time INTEGER, opened INTEGER, last_access_time INTEGER,
			referrer TEXT, site_url TEXT, tab_url TEXT, tab_referrer_url TEXT, by_ext_id TEXT, by_ext_name TEXT, last_modified TEXT, mime_type TEXT, original_mime_type TEXT)`,
		`CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT)`,
		fmt.Sprintf(`INSERT INTO urls VALUES
			(1,'https://search.test/?q=how+to','how to - Search',1,1,%d,0),
			(2,'https://files.test/landing','Landing',1,0,%d,0),
			(3,'https://other.test/phone','On the phone',1,0,%d,0),
			(4,'https://gone.test/old','Old page',9,0,%d,0),
			(5,'https://never.test/',NULL,0,0,0,1)`,
			at("2024-03-01T10:00:00Z"), at("2024-03-01T10:00:30Z"), at("2024-03-01T08:00:00Z"), at("2023-11-01T09:00:00Z")),
		fmt.Sprintf(`INSERT INTO visits VALUES
			(10,1,%d,0,'',%d,30000000,0,'',''),
			(11,2,%d,10,'https://ext.test/ref',%d,1500,10,'',''),
			(12,3,%d,0,'',0,0,0,'DEVICE-GUID',''),
			(13,2,%d,10,'',%d,0,0,'',''),
			(14,2,%d,0,'',%d,0,0,'','')`,
			at("2024-03-01T10:00:00Z"), 1|0x02000000|0x10000000|0x20000000,
			at("2024-03-01T10:00:30Z"), 0|0x80000000|0x20000000,
			at("2024-03-01T08:00:00Z"),
			at("2024-03-01T10:00:29Z"), 0|0x10000000, // the first hop of a redirect chain
			at("2024-03-01T10:00:31Z"), 3|0x10000000|0x20000000), // a frame inside a page
		`INSERT INTO visit_source VALUES (12,0)`,
		`INSERT INTO keyword_search_terms VALUES (2,1,'How To','how to')`,
		`INSERT INTO content_annotations VALUES (10,'','en',2),(11,'','',1)`,
		`INSERT INTO context_annotations VALUES (10,200,12345678),(11,404,-1)`,
		fmt.Sprintf(`INSERT INTO downloads VALUES
			(5,'C:\Users\dan\Downloads\tool.zip','C:\Users\dan\Downloads\tool.zip',%d,4096,4096,1,6,0,x'',%d,1,%d,
			 'https://files.test/landing','','https://files.test/landing','https://search.test/?q=how+to','','','Mon, 01 Jan 2024 00:00:00 GMT','application/zip','application/octet-stream'),
			(6,'C:\Users\dan\Downloads\half.crdownload','C:\Users\dan\Downloads\half.iso',%d,10,900,4,0,20,x'',0,0,0,'','','https://files.test/landing','','','','','','')`,
			at("2024-03-01T10:01:00Z"), at("2024-03-01T10:01:04Z"), at("2024-03-02T09:00:00Z"), at("2024-03-01T10:05:00Z")),
		`INSERT INTO downloads_url_chains VALUES (5,0,'https://files.test/get?id=1'),(5,1,'https://cdn.test/tool.zip')`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if r.facts["browser.history_schema_version"] != "70" {
		t.Errorf("version fact: %q", r.facts["browser.history_schema_version"])
	}
	by := map[string]Event{}
	types := map[string]int{}
	for _, e := range r.events {
		kind := strings.SplitN(e.Type, " (", 2)[0] // url-visited (typed) is a url-visited
		by[e.Ref+" "+kind] = e
		types[kind]++
	}
	if types["url-visited"] != 5 || types["url-last-visited"] != 1 || types["download-started"] != 2 || types["download-finished"] != 1 || types["download-last-opened"] != 1 {
		t.Fatalf("event types: %v", types)
	}
	v := by["visits.id 10 url-visited"]
	if v.Fields["transition_name"] != "typed" || fmt.Sprint(v.Fields["transition_qualifiers"]) != "[from_address_bar chain_start chain_end]" ||
		v.Fields["search_term"] != "How To" || !strings.Contains(v.Message, "[searched: How To]") || v.Fields["visit_duration_seconds"] != 30.0 ||
		v.Fields["response_code"] != int64(200) || v.Fields["foreground_seconds"] != 12.346 || v.Fields["page_language"] != "en" ||
		v.Fields["url_typed_count"] != int64(1) || v.Fields["synced_from_another_device"] != nil || v.Fields["from_url"] != nil {
		t.Errorf("typed search visit: %q %+v", v.Message, v.Fields)
	}
	// How the page was reached is in the Meaning; the visit carries its own
	// id and its site, for following the chain and grouping by site.
	if v.Type != "url-visited (typed)" || v.Category != CatBrowser || v.Source != "browser" || v.Fields["navigation"] != "user" ||
		v.Fields["visit_id"] != int64(10) || v.Fields["domain"] != "search.test" {
		t.Errorf("typed visit: %s %s %s %+v", v.Type, v.Category, v.Source, v.Fields)
	}
	v = by["visits.id 11 url-visited"]
	if v.Fields["from_url"] != "https://search.test/?q=how+to" || v.Fields["opener_url"] != "https://search.test/?q=how+to" ||
		v.Fields["external_referrer_url"] != "https://ext.test/ref" || fmt.Sprint(v.Fields["transition_qualifiers"]) != "[chain_end server_redirect]" ||
		v.Fields["page_had_password_field"] != true || v.Fields["foreground_seconds"] != nil || v.Fields["visit_duration_seconds"] != 0.002 {
		t.Errorf("referred visit: %+v", v.Fields)
	}
	if v.Type != "url-visited (link, after a redirect)" || v.Category != CatBrowser || v.Fields["from_visit_id"] != int64(10) || v.Fields["opener_visit_id"] != int64(10) {
		t.Errorf("referred visit: %s %s %+v", v.Type, v.Category, v.Fields)
	}
	// A hop in a redirect chain, and a frame inside a page, were loaded by
	// the browser, not chosen: they are evidence of something else.
	for _, ref := range []string{"visits.id 13", "visits.id 14"} {
		a := by[ref+" url-visited"]
		if a.Category != CatBrowserAuto || a.Fields["navigation"] != "automatic" || a.Fields["navigation_reason"] == nil ||
			!strings.HasPrefix(a.Message, "Loaded by the browser") {
			t.Errorf("%s: %s %s %q %+v", ref, a.Type, a.Category, a.Message, a.Fields)
		}
	}
	if by["visits.id 13 url-visited"].Type != "url-visited (redirected through)" || by["visits.id 14 url-visited"].Type != "url-visited (frame)" {
		t.Errorf("automatic loads: %q %q", by["visits.id 13 url-visited"].Type, by["visits.id 14 url-visited"].Type)
	}
	// A visit that sync brought from another device must say so.
	v = by["visits.id 12 url-visited"]
	if v.Fields["synced_from_another_device"] != true || v.Fields["source"] != "synced" || v.Fields["originator_cache_guid"] != "DEVICE-GUID" ||
		!strings.Contains(v.Message, "[synced: recorded on another device]") {
		t.Errorf("synced visit: %q %+v", v.Message, v.Fields)
	}
	// Synced visits are a source of their own, so one chip separates this
	// machine's browsing from other devices'.
	if v.Source != "browser-synced" {
		t.Errorf("synced visit source: %q", v.Source)
	}
	if !strings.Contains(strings.Join(r.notes, "\n"), "1 of 5 visits were brought here by browser sync") {
		t.Errorf("no note about synced visits: %q", r.notes)
	}
	// The address outlived its visit records; the never-visited one says nothing.
	if e := by["urls.id 4 url-last-visited"]; utc(e) != "2023-11-01T09:00:00Z" || e.Path != "https://gone.test/old" {
		t.Errorf("expired address: %s %+v", utc(e), e)
	}
	d := by["downloads.id 5 download-finished"]
	if d.Fields["url"] != "https://cdn.test/tool.zip" || fmt.Sprint(d.Fields["url_chain"]) != "[https://files.test/get?id=1 https://cdn.test/tool.zip]" ||
		d.Fields["danger"] != "dangerous, kept by the user" || d.Fields["state"] != "complete" || d.Fields["opened_from_browser"] != true ||
		d.Fields["mime_type"] != "application/zip" || d.Fields["original_mime_type"] != "application/octet-stream" ||
		d.Fields["tab_referrer_url"] != "https://search.test/?q=how+to" || d.Fields["server_last_modified"] != "Mon, 01 Jan 2024 00:00:00 GMT" ||
		d.Fields["current_path"] != nil || !strings.Contains(d.Message, "from https://cdn.test/tool.zip") || !strings.Contains(d.Message, "the browser's verdict: dangerous, kept by the user") {
		t.Errorf("download: %q %+v", d.Message, d.Fields)
	}
	if o := by["downloads.id 5 download-last-opened"]; utc(o) != "2024-03-02T09:00:00Z" {
		t.Errorf("download opened: %s", utc(o))
	}
	d = by["downloads.id 6 download-started"]
	if d.Fields["state"] != "interrupted" || d.Fields["interrupt_reason"] != "network failed" || d.Fields["received_bytes"] != int64(10) ||
		d.Fields["current_path"] != `C:\Users\dan\Downloads\half.crdownload` || d.Path != `C:\Users\dan\Downloads\half.iso` || !strings.Contains(d.Message, "[interrupted]") {
		t.Errorf("interrupted download: %q %+v", d.Message, d.Fields)
	}
}

func TestFirefoxDownloadsAndReferrers(t *testing.T) {
	p := makeDB(t, "places.sqlite",
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER)`,
		`CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)`,
		`CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER)`,
		`INSERT INTO moz_places VALUES (1,'https://example.org/','Example',2,0,1),(2,'https://example.org/file.zip',NULL,1,0,0)`,
		`INSERT INTO moz_historyvisits VALUES (7,0,1,1700000000000000,2),(8,7,2,1700000005000000,7)`,
		`INSERT INTO moz_anno_attributes VALUES (1,'downloads/destinationFileURI'),(2,'downloads/metaData')`,
		`INSERT INTO moz_annos VALUES (1,2,1,'file:///C:/Users/dan/Downloads/file%20one.zip',1700000005000000),
			(2,2,2,'{"state":1,"endTime":1700000009500,"fileSize":2048}',1700000005000000)`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 4 {
		t.Fatalf("err=%v warns=%v events=%d", r.err, r.warns, len(r.events))
	}
	if v := r.events[1]; v.Fields["from_url"] != "https://example.org/" || v.Fields["visit_type_name"] != "download" {
		t.Errorf("referred visit: %+v", v.Fields)
	}
	if v := r.events[0]; v.Fields["visit_type_name"] != "typed" || v.Fields["url_typed"] != true {
		t.Errorf("typed visit: %+v", v.Fields)
	}
	s, f := r.events[2], r.events[3]
	if s.Type != "download-started" || utc(s) != "2023-11-14T22:13:25Z" || s.Path != "C:/Users/dan/Downloads/file one.zip" ||
		f.Type != "download-finished" || utc(f) != "2023-11-14T22:13:29.5Z" || f.Fields["total_bytes"] != int64(2048) || f.Fields["url"] != "https://example.org/file.zip" {
		t.Errorf("download: %s %+v / %s %+v", utc(s), s, utc(f), f)
	}
}

func TestFirefoxHistory(t *testing.T) {
	p := makeDB(t, "places.sqlite",
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT)`,
		`CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)`,
		`INSERT INTO moz_places VALUES (1,'https://example.org/','Example')`,
		`INSERT INTO moz_historyvisits VALUES (7,1,1700000000123456,1)`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.events) != 1 {
		t.Fatalf("err=%v events=%d", r.err, len(r.events))
	}
	if e := r.events[0]; utc(e) != "2023-11-14T22:13:20.123456Z" || e.Fields["browser"] != "firefox" || e.Ref != "moz_historyvisits.id 7" {
		t.Errorf("visit: %s %+v", utc(e), e)
	}
}

func TestUnknownSQLiteFallsThrough(t *testing.T) {
	p := makeDB(t, "app.db", `CREATE TABLE notes(id INTEGER, body TEXT)`, `INSERT INTO notes VALUES (1,'hello')`)
	r := run(t, p, nil)
	if !errors.Is(r.err, ErrNothingExtracted) {
		t.Errorf("err = %v, want ErrNothingExtracted", r.err)
	}
	if r.facts["sqlite.tables"] != "notes" {
		t.Errorf("tables fact = %q", r.facts["sqlite.tables"])
	}
}

// ---------------------------------------------------------------- lnk ----

// buildLnk assembles a shell link by hand from MS-SHLLINK: header, LinkInfo
// with a local base path, unicode string data and a tracker block.
func buildLnk(created, accessed, written uint64) []byte {
	le := binary.LittleEndian
	b := make([]byte, 76)
	le.PutUint32(b[0:], 0x4C)
	copy(b[4:], []byte{0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46})
	le.PutUint32(b[20:], 0x2|0x4|0x8|0x10|0x20|0x80) // LinkInfo, name, relative path, working dir, arguments, unicode
	le.PutUint32(b[24:], 0x20)
	le.PutUint64(b[28:], created)
	le.PutUint64(b[36:], accessed)
	le.PutUint64(b[44:], written)
	le.PutUint32(b[52:], 123456)

	base := "C:\\Windows\\System32\\cmd.exe\x00"
	vol := make([]byte, 16)
	le.PutUint32(vol[0:], 17)
	le.PutUint32(vol[4:], 3)
	le.PutUint32(vol[8:], 0xDEADBEEF)
	le.PutUint32(vol[12:], 16)
	vol = append(vol, 0) // empty label
	li := make([]byte, 28)
	le.PutUint32(li[4:], 28)                               // header size
	le.PutUint32(li[8:], 1)                                // VolumeIDAndLocalBasePath
	le.PutUint32(li[12:], 28)                              // volume id offset
	le.PutUint32(li[16:], uint32(28+len(vol)))             // local base path offset
	le.PutUint32(li[24:], uint32(28+len(vol)+len(base)-1)) // common path suffix: the terminator of base
	li = append(li, vol...)
	li = append(li, base...)
	le.PutUint32(li[0:], uint32(len(li)))
	b = append(b, li...)

	for _, s := range []string{"Command Prompt", `..\..\Windows\System32\cmd.exe`, `C:\Users\dan`, "/c whoami > out.txt"} {
		u := utf16.Encode([]rune(s))
		b = le.AppendUint16(b, uint16(len(u)))
		for _, c := range u {
			b = le.AppendUint16(b, c)
		}
	}
	tr := make([]byte, 96)
	le.PutUint32(tr[0:], 96)
	le.PutUint32(tr[4:], 0xA0000003)
	le.PutUint32(tr[8:], 88)
	copy(tr[16:], "desktop-abc123")
	copy(tr[58:], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	b = append(b, tr...)
	return le.AppendUint32(b, 0) // terminal block
}

func TestLnk(t *testing.T) {
	ft := func(s string) uint64 {
		tm, _ := time.Parse(time.RFC3339, s)
		return uint64(tm.UnixNano()/100) + 116444736000000000
	}
	data := buildLnk(ft("2023-05-01T08:00:00Z"), ft("2023-05-03T10:00:00Z"), ft("2023-05-02T09:00:00Z"))
	if k := detect.Identify(bytes.NewReader(data), int64(len(data))).Kind; k != detect.LNK {
		t.Fatalf("identified as %q", k)
	}
	r := run(t, write(t, "renamed.dat", data), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	want := map[string]string{
		"link-target-created":  "2023-05-01T08:00:00Z",
		"link-target-modified": "2023-05-02T09:00:00Z",
		"link-target-accessed": "2023-05-03T10:00:00Z",
	}
	if len(r.events) != 3 {
		t.Fatalf("got %d events", len(r.events))
	}
	for _, e := range r.events {
		if utc(e) != want[e.Type] {
			t.Errorf("%s at %s, want %s", e.Type, utc(e), want[e.Type])
		}
		if e.Path != `C:\Windows\System32\cmd.exe` {
			t.Errorf("target = %q", e.Path)
		}
	}
	f := r.events[0].Fields
	for k, v := range map[string]any{
		"description": "Command Prompt", "relative_path": `..\..\Windows\System32\cmd.exe`, "working_dir": `C:\Users\dan`,
		"arguments": "/c whoami > out.txt", "volume_serial": "DEADBEEF", "tracker_machine_id": "desktop-abc123",
		"tracker_mac": "00:11:22:33:44:55", "target_size": uint32(123456),
	} {
		if f[k] != v {
			t.Errorf("field %s = %v, want %v", k, f[k], v)
		}
	}
	if !strings.Contains(r.events[0].Message, "/c whoami") {
		t.Errorf("arguments not in message: %q", r.events[0].Message)
	}
}

// A shortcut with no times and no link information, as a program writes one
// (or as Windows writes one to a target that does not exist): no events, but
// its target, from the shell item list, and its arguments are kept as text,
// which the command checks over file text read. Before, both were lost.
func TestLnkWithoutTimes(t *testing.T) {
	le := binary.LittleEndian
	b := make([]byte, 76)
	le.PutUint32(b[0:], 0x4C)
	copy(b[4:], []byte{0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46})
	le.PutUint32(b[20:], 0x1|0x20|0x80) // item list, arguments, unicode
	ids := pidl(drive('C'))
	b = le.AppendUint16(b, uint16(len(ids)))
	b = append(b, ids...)
	u := utf16.Encode([]rune("-nop -w hidden -enc SQBFAFgA"))
	b = le.AppendUint16(b, uint16(len(u)))
	for _, c := range u {
		b = le.AppendUint16(b, c)
	}
	b = le.AppendUint32(b, 0)
	r := run(t, write(t, "updater.lnk", b), nil)
	if r.err != nil || len(r.events) != 0 || len(r.notes) != 1 || !strings.Contains(r.notes[0], "kept as searchable text") {
		t.Fatalf("err=%v events=%d notes=%q", r.err, len(r.events), r.notes)
	}
	want := "Target: C:\nTarget read from: the shell item list (the shortcut has no link information)\nArguments: -nop -w hidden -enc SQBFAFgA"
	if r.text != want {
		t.Errorf("text %q", r.text)
	}
}

// The target's file-table reference from the last item of the list, and the
// tracking block's identifiers with the time in the file identifier, as
// LECmd shows them (checked against it on 98 real shortcuts).
func TestLnkFileReferenceAndTracker(t *testing.T) {
	le := binary.LittleEndian
	b := make([]byte, 76)
	le.PutUint32(b[0:], 0x4C)
	copy(b[4:], []byte{0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46})
	le.PutUint32(b[20:], 0x1|0x80)
	le.PutUint64(b[28:], 133000000000000000)
	ids := pidl(drive('C'), fileItem(0x32, "UPDATE~1.EXE", "updater.exe", 9, "2024-01-02 03:04:06", "2024-01-02 03:04:06", "2024-01-02 03:04:06"))
	b = le.AppendUint16(b, uint16(len(ids)))
	b = append(b, ids...)
	tr := make([]byte, 96)
	le.PutUint32(tr[0:], 96)
	le.PutUint32(tr[4:], 0xA0000003)
	copy(tr[16:], "ws-7")
	// A version 1 identifier: 2026-11-26 18:55:58.8923771 UTC (as Python's uuid module reads it), node 00:11:22:33:44:55.
	file := []byte{0x7b, 0x1d, 0x89, 0x04, 0xcb, 0xe9, 0xf1, 0x11, 0xb3, 0xd8, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	vol := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x48, 0x89, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	copy(tr[32:], vol)
	copy(tr[48:], file)
	copy(tr[64:], vol)
	copy(tr[80:], file)
	b = append(append(b, tr...), 0, 0, 0, 0)
	ctx, _, _ := collect(timeutil.AssumedUTC())
	n, f, err := parseLnkFields(ctx, b, "Shortcut t.lnk", "shell link header")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for k, v := range map[string]any{
		"target": `C:\updater.exe`, "target_mft_entry": uint64(0x1234), "target_mft_sequence": uint16(5),
		"tracker_volume_id": "04030201-0605-4807-890a-0b0c0d0e0f10", "tracker_file_id": "04891d7b-e9cb-11f1-b3d8-001122334455",
		"tracker_birth_file_id": "04891d7b-e9cb-11f1-b3d8-001122334455", "tracker_mac": "00:11:22:33:44:55",
	} {
		if f[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, f[k], f[k], v)
		}
	}
	if f["tracker_moved"] != nil || f["tracker_file_id_time"] != "2026-11-26 18:55:58.8923771 UTC" || f["tracker_file_id_time_meaning"] == nil {
		t.Errorf("moved %v, time %v", f["tracker_moved"], f["tracker_file_id_time"])
	}
	// Moved: the birth identifier differs. Not version 1: no time.
	tr2 := append([]byte{}, b...)
	at := len(tr2) - 4 - 96
	tr2[at+80] ^= 0xFF
	tr2[at+48+7] = 0x40
	_, f, _ = parseLnkFields(ctx, tr2, "Shortcut t.lnk", "shell link header")
	if f["tracker_moved"] == nil || f["tracker_file_id_time"] != nil {
		t.Errorf("moved %v, time %v", f["tracker_moved"], f["tracker_file_id_time"])
	}
}

// Every truncation of a valid shortcut must be survived: an error or a
// warning is fine, a panic is not.
func TestLnkTruncationNeverPanics(t *testing.T) {
	data := buildLnk(131000000000000000, 0, 0)
	dir := t.TempDir()
	for n := 20; n < len(data); n++ {
		p := filepath.Join(dir, "t.lnk")
		os.WriteFile(p, data[:n], 0o600)
		f, _ := os.Open(p)
		func() {
			defer f.Close()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic at length %d: %v", n, r)
				}
			}()
			runWith(t, lnkParser{}, f, detect.LNK, nil)
		}()
	}
}

// ----------------------------------------------------- sample artefacts ----

// Prefetch output is compared with the expected values published alongside
// the Velocidex parser for the same four files.
func TestPrefetchKnownAnswers(t *testing.T) {
	for file, dir := range map[string]string{
		"CALC.EXE-3FBEF7FD.pf": "Win10", "LIVECOMM.EXE-D546E475.pf": "Win8x",
		"MSMSGS.EXE-2B6052DE.pf": "XPPro", "PING.EXE-B29F6629.pf": "Win7",
	} {
		goldenRaw, err := os.ReadFile(sample(t, "prefetch-golden", file+".golden"))
		if err != nil {
			t.Fatal(err)
		}
		var golden struct {
			Executable    string
			Hash          string
			LastRunTimes  []time.Time
			FilesAccessed []string
			RunCount      uint32
		}
		if err := json.Unmarshal(goldenRaw, &golden); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		r := run(t, sample(t, "prefetch", dir, file), nil)
		if r.err != nil || len(r.warns) != 0 {
			t.Errorf("%s: err=%v warns=%v", file, r.err, r.warns)
			continue
		}
		if len(r.events) != len(golden.LastRunTimes) {
			t.Errorf("%s: %d run times, want %d", file, len(r.events), len(golden.LastRunTimes))
			continue
		}
		for i, e := range r.events {
			if !e.Stamp.UTC.Truncate(time.Second).Equal(golden.LastRunTimes[i]) {
				t.Errorf("%s: run %d at %s, want %s", file, i, utc(e), golden.LastRunTimes[i].Format(time.RFC3339))
			}
			if e.Stamp.ZoneFrom != timeutil.ZoneNative {
				t.Errorf("%s: zone %s", file, e.Stamp.ZoneFrom)
			}
			if e.Fields["executable"] != golden.Executable || e.Fields["run_count"] != golden.RunCount || e.Fields["prefetch_hash"] != golden.Hash {
				t.Errorf("%s: fields %v %v %v", file, e.Fields["executable"], e.Fields["run_count"], e.Fields["prefetch_hash"])
			}
			if e.Fields["files_accessed_count"] != len(golden.FilesAccessed) {
				t.Errorf("%s: %v files accessed, want %d", file, e.Fields["files_accessed_count"], len(golden.FilesAccessed))
			}
		}
	}
}

// Every prefetch sample from every Windows version parses without warnings,
// and the deliberately invalid one is not mistaken for prefetch.
func TestPrefetchAllVersions(t *testing.T) {
	root := sample(t, "prefetch")
	n := 0
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".pf") {
			return nil
		}
		r := run(t, p, nil)
		if filepath.Base(filepath.Dir(p)) == "Bad" {
			for _, e := range r.events {
				if e.Source == "prefetch" {
					t.Errorf("%s: invalid file produced prefetch events", p)
				}
			}
			return nil
		}
		n++
		if r.err != nil || len(r.warns) != 0 || len(r.events) == 0 {
			t.Errorf("%s: err=%v warns=%v events=%d", p, r.err, r.warns, len(r.events))
		}
		return nil
	})
	if n < 50 {
		t.Errorf("only %d prefetch samples found", n)
	}
}

func TestEVTXSample(t *testing.T) {
	r := run(t, sample(t, "Security.evtx"), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	byID := map[string]int{}
	var cleared *Event
	seen := map[any]bool{}
	for i, e := range r.events {
		byID[e.Fields["event_id"].(string)]++
		if e.Stamp.ZoneFrom != timeutil.ZoneNative || e.Host != "TestComputer" || e.Fields["channel"] != "Security" {
			t.Fatalf("event %d: zone=%s host=%q channel=%v", i, e.Stamp.ZoneFrom, e.Host, e.Fields["channel"])
		}
		if seen[e.Fields["record_id"]] {
			t.Fatalf("record %v emitted twice", e.Fields["record_id"])
		}
		seen[e.Fields["record_id"]] = true
		if e.Fields["event_id"] == "1102" && cleared == nil {
			cleared = &r.events[i]
		}
	}
	if len(r.events) != 739 {
		t.Errorf("got %d events, want 739", len(r.events))
	}
	if cleared == nil {
		t.Fatal("no 1102 (audit log cleared) event")
	}
	// Record 31878: the log was cleared by TESTCOMPUTER\test at this instant.
	if utc(*cleared) != "2019-02-06T14:17:53.3172597Z" || !strings.HasPrefix(cleared.Message, "Audit log cleared [Security 1102]") ||
		!strings.Contains(cleared.Message, `"SubjectUserName":"test"`) || cleared.Ref != "record 31878, chunk at offset 4096" {
		t.Errorf("1102: %s %q %s", utc(*cleared), cleared.Message, cleared.Ref)
	}
	for _, id := range []string{"4624", "4648", "4672"} {
		if byID[id] == 0 {
			t.Errorf("no %s events", id)
		}
	}
}

func TestRegistrySample(t *testing.T) {
	r := run(t, sample(t, "NTUSER.DAT"), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if r.facts["hive.kind"] != "NTUSER" {
		t.Errorf("hive kind = %q", r.facts["hive.kind"])
	}
	ua := map[string]Event{}
	paths := map[string]bool{}
	for _, e := range r.events {
		if e.Stamp.ZoneFrom != timeutil.ZoneNative {
			t.Fatalf("zone %s on %s", e.Stamp.ZoneFrom, e.Path)
		}
		switch e.Type {
		case "program-last-run (userassist)":
			ua[e.Path] = e
		case "registry-key-last-write":
			if paths[e.Path] {
				t.Fatalf("key %s emitted twice", e.Path)
			}
			paths[e.Path] = true
		}
	}
	if !paths[`\Software\Microsoft\Windows\CurrentVersion\Run`] && !paths[`\Software\Microsoft\Windows\CurrentVersion\Explorer`] {
		t.Error("expected Explorer keys are missing from the walk")
	}
	// ROT13 decoding: HRZR_EHACVQY:%pfvqy2%\ZFA.yax is UEME_RUNPIDL:%csidl2%\MSN.lnk.
	e, ok := ua[`UEME_RUNPIDL:%csidl2%\MSN.lnk`]
	if !ok {
		t.Fatalf("UserAssist entry not decoded; have %d entries", len(ua))
	}
	if utc(e) != "2009-08-04T15:11:22.8110676Z" || e.Ref != `UserAssist value HRZR_EHACVQY:%pfvqy2%\ZFA.yax` {
		t.Errorf("userassist: %s %q", utc(e), e.Ref)
	}
}

// The public sample hive is from Windows XP and holds real RecentDocs lists.
func TestRegistrySampleRecentDocs(t *testing.T) {
	r := run(t, sample(t, "NTUSER.DAT"), nil)
	var got []string
	for _, e := range r.events {
		if e.Type == "recent-document-latest" {
			got = append(got, fmt.Sprintf("%s|%s|%v|%v", utc(e), e.Path, e.Fields["entry_count"], e.Fields["group"]))
			if e.MACB != "" || e.Category != CatFileOpening {
				t.Errorf("%+v", e)
			}
		}
	}
	sort.Strings(got)
	want := []string{
		// Each key's own last-write time, to 100 ns; dissect.regf gives the same.
		"2009-08-04T15:19:23.62275Z|Not to be seen document.txt|2|.txt",
		"2009-08-04T15:19:23.638375Z|Administrator's Documents|1|Folder",
		"2009-08-04T15:19:23.638375Z|Administrator's Documents|3|<nil>",
	}
	if len(got) != 3 {
		t.Fatalf("recent documents: %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got[i], want[i])
		}
	}
}

func TestNTFSSample(t *testing.T) {
	r := run(t, sample(t, "test.ntfs.dd"), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	found := map[string]bool{}
	for _, e := range r.events {
		if e.Source != "mft" { // the volume's transaction log and index slack are tested on their own
			continue
		}
		found[e.Path] = true
		if e.Stamp.ZoneFrom != timeutil.ZoneNative || !strings.HasPrefix(e.Ref, "MFT entry ") {
			t.Fatalf("%s: zone=%s ref=%q", e.Path, e.Stamp.ZoneFrom, e.Ref)
		}
		if !strings.HasPrefix(e.Type, "$SI ") && !strings.HasPrefix(e.Type, "$FN ") {
			t.Fatalf("unexpected type %q", e.Type)
		}
	}
	for _, p := range []string{"/$MFT", "/$LogFile", "/$Volume"} {
		if !found[p] {
			t.Errorf("%s missing from the file table", p)
		}
	}
	if e := r.events[0]; e.Path != "/$MFT" || utc(e) != "2018-09-24T07:53:17.2748389Z" && utc(e)[:26] != "2018-09-24T07:53:17.274838" {
		t.Errorf("first entry: %s %s", e.Path, utc(e))
	}
}

// Damaged input of every parsed kind must end in an error or a warning the
// examiner can see, never a panic and never a silent success.
func TestCorruptInputIsReportedNotFatal(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xA5, 0x5A, 0x00, 0xFF, 0x13, 0x37}, 3000)
	for name, head := range map[string]string{
		"evtx": "ElfFile\x00", "registry": "regf", "prefetch": "\x11\x00\x00\x00SCCA", "prefetch-compressed": "MAM\x04",
		"sqlite": "SQLite format 3\x00", "ntfs": "\xEB\x52\x90NTFS    ",
	} {
		data := append([]byte(head), garbage...)
		var r result
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: panic: %v", name, p)
				}
			}()
			r = run(t, write(t, name+".bin", data), nil)
		}()
		if r.err == nil && len(r.warns) == 0 && len(r.events) == 0 {
			t.Errorf("%s: corrupt input produced nothing and reported nothing", name)
		}
	}
}

func TestFieldsJSONIsDeterministic(t *testing.T) {
	m := map[string]any{"z": 1, "a": map[string]any{"y": 2, "b": []any{3, "x"}}, "m": "v"}
	want := `{"a":{"b":[3,"x"],"y":2},"m":"v","z":1}`
	for i := 0; i < 50; i++ {
		if got := FieldsJSON(m); got != want {
			t.Fatalf("got %s", got)
		}
	}
	if FieldsJSON(nil) != "{}" {
		t.Error("nil fields")
	}
	if got := Clean("a\x00b\xff"); got != "ab\uFFFD" {
		t.Errorf("Clean = %q", got)
	}
}

// A log saved from another ("Save filtered log file as") has its record
// headers rewritten: numbered from 1, with a time of zero. Each event's own
// TimeCreated and EventRecordID are what Event Viewer and EvtxECmd show.
func TestEvtxSavedFromAnotherLog(t *testing.T) {
	r := run(t, sample(t, "evtx-attack", "Credential_Access__CA_protectedstorage_5145_rpc_masterkey.evtx"), nil)
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 1 {
		t.Fatalf("err=%v warns=%v events=%d", r.err, r.warns, len(r.events))
	}
	e := r.events[0]
	if utc(e) != "2020-07-19T13:06:52.1998558Z" || e.Fields["record_id"] != uint64(886983) || e.Fields["record_number_in_file"] != uint64(1) ||
		e.Ref != "record 886983, chunk at offset 4096" {
		t.Errorf("%s %+v", utc(e), e.Fields)
	}
	if len(r.notes) == 0 || !strings.Contains(r.notes[0], "saved from another one") {
		t.Errorf("notes: %v", r.notes)
	}
}

// The owner of a browser profile is read from the folder the file came
// from, and only from a real profile folder.
func TestProfileUser(t *testing.T) {
	for origin, want := range map[string]string{
		`C:\Users\dan\AppData\Local\Google\Chrome\User Data\Default\History`:                "dan",
		`disk.E01!/Users/Jo Smith/AppData/Roaming/Mozilla/Firefox/Profiles/x/places.sqlite`: "Jo Smith",
		`D:\Documents and Settings\olduser\Local Settings\History`:                          "olduser",
		`upload:Default/History`:               "",
		`C:\Users\Public\Documents\History`:    "",
		`upload:Users/Default/AppData/History`: "",
		`C:\cases\myusers\History`:             "",
	} {
		if got := ProfileUser(origin); got != want {
			t.Errorf("%s: %q, want %q", origin, got, want)
		}
	}
}
