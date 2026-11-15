package analysis

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

func ns(s string) int64 {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t.UnixNano()
}

type builder struct {
	t *testing.T
	s *store.Store
	n int
}

func (b *builder) run(kind, parser string, events ...store.Event) {
	b.t.Helper()
	b.n++
	e := &store.Evidence{SHA256: fmt.Sprintf("%064d", b.n), Name: kind, Origin: "/x/" + kind, BatchID: 1, Kind: kind, DetectReason: "test"}
	if err := b.s.AddEvidence(e); err != nil {
		b.t.Fatal(err)
	}
	run, err := b.s.BeginRun(e.ID, parser, "1", "")
	if err != nil {
		b.t.Fatal(err)
	}
	for _, ev := range events {
		ev.TZSource, ev.TZName = "native-utc", "UTC"
		if err := run.Add(ev); err != nil {
			b.t.Fatal(err)
		}
	}
	if _, err := run.Finish("parsed", ""); err != nil {
		b.t.Fatal(err)
	}
}

// mft makes the $SI events for one file: modified and created at the given
// times, the way the file table parser writes them.
func mft(path string, entry int, modified, created, flags string) []store.Event {
	suffix := ""
	if flags != "" {
		suffix = " [" + flags + "]"
	}
	ref := fmt.Sprintf("MFT entry %d-1", entry)
	return []store.Event{
		{TSUTC: ns(modified), TSType: "$SI M...", MACB: "M...", Source: "mft", Path: path, Message: "$SI M...  " + path + suffix, RecordRef: ref},
		{TSUTC: ns(created), TSType: "$SI .ACB", MACB: ".ACB", Source: "mft", Path: path, Message: "$SI .ACB  " + path + suffix, RecordRef: ref},
	}
}

func shimcache(path, modified string) store.Event {
	return store.Event{TSUTC: ns(modified), TSType: "file-modified (shimcache)", MACB: "M...", Source: "registry", Path: path, Message: "ShimCache: " + path}
}

func amcache(path, recorded, linkDate string) store.Event {
	f, _ := json.Marshal(map[string]any{"link_date": linkDate})
	return store.Event{TSUTC: ns(recorded), TSType: "amcache-file-recorded", Source: "registry", Path: path, Message: "Amcache: " + path, Fields: string(f)}
}

func usn(name string, entry int, when string, reasons ...string) store.Event {
	f, _ := json.Marshal(map[string]any{"reasons": reasons, "entry": entry, "sequence": 1})
	return store.Event{TSUTC: ns(when), TSType: "usn-change", Source: "usn", Path: name, Message: "USN: " + name, Fields: string(f)}
}

func open(t *testing.T) *builder {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "case.db"), "tester")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &builder{t: t, s: s}
}

func kinds(r *Report) map[string][]string {
	out := map[string][]string{}
	for _, f := range r.Findings {
		out[f.Kind] = append(out[f.Kind], f.Path)
	}
	return out
}

func TestTimestompChecks(t *testing.T) {
	b := open(t)
	var files []store.Event
	// Backdated: the file table says 2019, ShimCache saw it modified in 2024.
	files = append(files, mft("/Windows/System32/svch0st.exe", 100, "2019-03-01 10:00:00", "2019-03-01 10:00:00", "SI<FN")...)
	// Untouched: ShimCache and the file table agree to the second.
	files = append(files, mft("/Windows/System32/calc.exe", 101, "2023-05-05 05:05:05", "2023-05-05 05:05:05", "")...)
	// Updated since ShimCache saw it: later, so nothing to report.
	files = append(files, mft("/Program Files/App/app.exe", 102, "2024-08-01 00:00:00", "2022-01-01 00:00:00", "")...)
	// Built in 2024, yet created and modified in 2020.
	files = append(files, mft("/Users/Public/tool.exe", 103, "2020-06-01 12:00:00", "2020-06-01 12:00:00", "")...)
	// Built before it was written: ordinary.
	files = append(files, mft("/Users/Public/old.exe", 104, "2024-02-02 12:00:00", "2024-02-02 12:00:00", "")...)
	// A build "time" after Amcache recorded the file is not a time.
	files = append(files, mft("/Users/Public/repro.exe", 105, "2020-01-01 00:00:00", "2020-01-01 00:00:00", "")...)
	// Created in the journal in 2024; creation time now reads 2018.
	files = append(files, mft("/ProgramData/x/drop.dll", 106, "2018-01-01 00:00:00", "2018-01-01 00:00:00", "")...)
	// Created when the journal says.
	files = append(files, mft("/ProgramData/x/honest.dll", 107, "2024-04-04 04:04:04", "2024-04-04 04:04:04", "")...)
	// Nothing else mentions this one.
	files = append(files, mft("/Windows/notepad.exe", 108, "2021-01-01 00:00:00", "2021-01-01 00:00:00", "")...)
	b.run("mft", "ntfs-mft", files...)

	b.run("windows-registry-hive", "registry",
		shimcache(`C:\Windows\System32\svch0st.exe`, "2024-01-15 09:30:00"),
		shimcache(`SYSVOL\Windows\System32\svch0st.exe`, "2023-12-01 00:00:00"), // an older control set: the later one is reported
		shimcache(`C:\Windows\System32\calc.exe`, "2023-05-05 05:05:05"),
		shimcache(`C:\Program Files\App\app.exe`, "2023-01-01 00:00:00"),
		amcache(`c:\users\public\tool.exe`, "2024-03-10 08:00:00", "03/09/2024 22:11:33"),
		amcache(`c:\users\public\old.exe`, "2024-02-02 12:00:05", "11/20/2021 10:00:00"),
		amcache(`c:\users\public\repro.exe`, "2024-02-02 12:00:05", "07/04/2071 01:02:03"),
		amcache(`c:\users\public\noversion.exe`, "2024-02-02 12:00:05", "1.2.3.4"),
	)
	b.run("usn-journal", "usn-journal",
		usn("drop.dll", 106, "2024-03-10 08:05:00", "FILE_CREATE"),
		usn("drop.dll", 106, "2024-03-10 08:05:01", "BASIC_INFO_CHANGE", "CLOSE"),
		usn("honest.dll", 107, "2024-04-04 04:04:04", "FILE_CREATE", "CLOSE"),
		usn("gone.tmp", 999, "2024-04-04 04:04:04", "FILE_CREATE"),
	)

	// Older copies of creation times: index slack and the transaction log.
	older := func(source, typ, path string, entry int, created string) store.Event {
		f, _ := json.Marshal(map[string]any{"entry": entry, "sequence": 1})
		return store.Event{TSUTC: ns(created), TSType: typ + " MACB", MACB: "MACB", Source: source, Path: path, Message: typ, Fields: string(f)}
	}
	noRecord, _ := json.Marshal(map[string]any{"file_record_unknown": true})
	b.run("ntfs-transaction-log", "ntfs-logfile",
		older("logfile", "$LogFile-record-created", "/Users/Public/tool.exe", 103, "2024-03-09 23:00:00"), // tool.exe really arrived in 2024
		older("logfile", "$LogFile-name-added", "/ProgramData/x/honest.dll", 107, "2024-04-04 04:04:04"),
		older("i30", "$I30-slack", "/Windows/notepad.exe", 108, "2020-12-31 00:00:00"), // an older time than now: nothing wrong
		store.Event{TSUTC: ns("2024-06-06 06:06:06"), TSType: "$I30-slack MACB", MACB: "MACB", Source: "i30", Path: "/Windows/notepad.exe", Message: "x", Fields: string(noRecord)},
	)

	rep, err := Timestomp(b.s)
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(rep)
	want := map[string][]string{
		KindModifiedBeforeShimCache:  {"/Windows/System32/svch0st.exe"},
		KindLinkedAfterFileTimes:     {"/Users/Public/tool.exe"},
		KindCreatedBeforeOlderRecord: {"/Users/Public/tool.exe"},
		KindCreatedBeforeJournal:     {"/ProgramData/x/drop.dll"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", got, want)
	}
	f := rep.Findings[0]
	if f.OtherTime != "2024-01-15 09:30:00.000000" || f.FileTime != "2019-03-01 10:00:00.000000" || !f.AlsoFlagged || len(f.EventIDs) != 2 {
		t.Errorf("shimcache finding: %+v", f)
	}
	if f.Caveat == "" || !strings.Contains(f.Summary, "2024-01-15") {
		t.Errorf("shimcache finding lacks its explanation: %+v", f)
	}
	// The events a finding points at exist and are the ones compared.
	for _, f := range rep.Findings {
		for _, id := range f.EventIDs {
			e, err := b.s.GetEvent(id)
			if err != nil {
				t.Fatalf("%s points at event %d, which does not exist: %v", f.Kind, id, err)
			}
			if e.Source != "mft" && e.Source != "registry" && e.Source != "usn" && e.Source != "logfile" {
				t.Errorf("%s points at an unrelated event: %+v", f.Kind, e)
			}
		}
	}
	if rep.Compared["amcache link dates ignored as implausible"] != 1 || rep.Compared["amcache link dates"] != 2 {
		t.Errorf("link dates compared: %v", rep.Compared)
	}
	if rep.Compared["shimcache entries"] != 4 || rep.Compared["change journal creations"] != 3 {
		t.Errorf("compared: %v", rep.Compared)
	}
	// The same case gives the same report.
	again, _ := Timestomp(b.s)
	a, _ := json.Marshal(rep)
	c, _ := json.Marshal(again)
	if string(a) != string(c) {
		t.Error("two runs over the same case differ")
	}
}

// Artefacts that name different machines are not compared.
func TestTimestompDoesNotCompareAcrossHosts(t *testing.T) {
	b := open(t)
	files := mft("/Windows/System32/a.exe", 5, "2019-01-01 00:00:00", "2019-01-01 00:00:00", "")
	for i := range files {
		files[i].Host = "ALPHA"
	}
	b.run("mft", "ntfs-mft", files...)
	sc := shimcache(`C:\Windows\System32\a.exe`, "2024-01-01 00:00:00")
	sc.Host = "BRAVO"
	b.run("windows-registry-hive", "registry", sc)
	rep, err := Timestomp(b.s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("compared across hosts: %+v", rep.Findings)
	}
}

// Nothing to compare is said plainly, not reported as a clean result.
func TestTimestompSaysWhatWasMissing(t *testing.T) {
	b := open(t)
	rep, err := Timestomp(b.s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || !strings.Contains(strings.Join(rep.Notes, " "), "No file table") {
		t.Errorf("empty case: %+v", rep)
	}
	b.run("mft", "ntfs-mft", mft("/a.exe", 5, "2019-01-01 00:00:00", "2019-01-01 00:00:00", "")...)
	rep, _ = Timestomp(b.s)
	notes := strings.Join(rep.Notes, " ")
	for _, want := range []string{"No ShimCache", "No Amcache", "No change journal"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes do not say %q: %s", want, notes)
		}
	}
}

// A long list is cut, and says so.
func TestTimestompIsBounded(t *testing.T) {
	b := open(t)
	var files, journal []store.Event
	for i := 0; i < MaxPerKind+25; i++ {
		files = append(files, mft(fmt.Sprintf("/d/f%05d.bin", i), 1000+i, "2018-01-01 00:00:00", "2018-01-01 00:00:00", "")...)
		journal = append(journal, usn(fmt.Sprintf("f%05d.bin", i), 1000+i, "2024-01-01 00:00:00", "FILE_CREATE"))
	}
	b.run("mft", "ntfs-mft", files...)
	b.run("usn-journal", "usn-journal", journal...)
	rep, err := Timestomp(b.s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != MaxPerKind || rep.Counts[KindCreatedBeforeJournal] != MaxPerKind+25 || !rep.Truncated[KindCreatedBeforeJournal] {
		t.Errorf("listed %d, counted %d, truncated %v", len(rep.Findings), rep.Counts[KindCreatedBeforeJournal], rep.Truncated)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), fmt.Sprintf("%d found, the first %d listed", MaxPerKind+25, MaxPerKind)) {
		t.Errorf("notes: %v", rep.Notes)
	}
}

func TestNormPath(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Windows\System32\CMD.EXE`:     "windows/system32/cmd.exe",
		`/Windows/System32/cmd.exe`:       "windows/system32/cmd.exe",
		`SYSVOL\Windows\System32\cmd.exe`: "windows/system32/cmd.exe",
		`\??\C:\Windows\System32\cmd.exe`: "windows/system32/cmd.exe",
		`c:\users\a\x.exe`:                "users/a/x.exe",
		``:                                "",
	} {
		if got := normPath(in); got != want {
			t.Errorf("normPath(%q) = %q, want %q", in, got, want)
		}
	}
}
