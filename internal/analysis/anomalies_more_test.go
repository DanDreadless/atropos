package analysis

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/store"
)

// text adds an item that has indexed text and no events.
func (b *builder) text(name, method, body string) int64 {
	b.t.Helper()
	b.n++
	e := &store.Evidence{SHA256: fmt.Sprintf("%064d", b.n), Name: name, Origin: "/x/" + name, BatchID: 1, Kind: "text", DetectReason: "test"}
	if err := b.s.AddEvidence(e); err != nil {
		b.t.Fatal(err)
	}
	if err := b.s.AddText(e.ID, method, false, body); err != nil {
		b.t.Fatal(err)
	}
	return e.ID
}

// Commands in a file that has no times of its own are still found, and
// point at the file rather than at an event.
func TestAnomaliesInAFilesText(t *testing.T) {
	b := open(t)
	history := "cd C:\\Users\\Public\r\nGet-ChildItem\r\n" +
		"vssadmin delete shadows /all /quiet\r\n" +
		"whoami\r\n" +
		"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA\r\n" +
		"vssadmin.exe Delete Shadows /for=C:\r\n"
	id := b.text("ConsoleHost_history.txt", "full text", history)
	b.text("innocent.txt", "full text", "Get-ChildItem\nwhoami\n")
	// Strings pulled out of a program are not a command anyone typed.
	b.text("vssadmin.exe", "strings (ASCII and UTF-16LE, minimum 6 characters)", "vssadmin delete shadows /all\n")
	b.run("evtx", "evtx", ev("log", "evtx", "", "nothing of note", nil))

	rep, err := Anomalies(b.s)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Texts != 2 || rep.Counts[AnomCommandText] != 3 || len(rep.Findings) != 3 {
		t.Fatalf("texts %d, counts %v, findings %+v", rep.Texts, rep.Counts, rep.Findings)
	}
	by := map[string]Anomaly{}
	for _, f := range rep.Findings {
		by[f.Subject] = f
		if f.Kind != AnomCommandText || f.EvidenceID != id || f.Evidence != "ConsoleHost_history.txt" || f.Events != 0 || len(f.EventIDs) != 0 || f.EventIDs == nil || f.First != "" {
			t.Errorf("finding: %+v", f)
		}
	}
	sh := by["Shadow copies or backups deleted"]
	if !strings.Contains(sh.Detail, "2 place(s) in ConsoleHost_history.txt, at line 3, 6: vssadmin delete shadows /all /quiet") {
		t.Errorf("detail: %q", sh.Detail)
	}
	if enc := by["PowerShell run with an encoded command"]; !strings.Contains(enc.Detail, "at line 5: powershell -nop -w hidden -enc") {
		t.Errorf("detail: %q", enc.Detail)
	}
	// There is no event to tag, and tagging says so by adding nothing.
	if n, err := TagAnomalies(b.s, rep); err != nil || n != 0 {
		t.Errorf("tagging text findings: %d %v", n, err)
	}
	var out bytes.Buffer
	if err := WriteAnomaliesText(&out, rep); err != nil || !strings.Contains(out.String(), "in the text of evidence") {
		t.Errorf("text report: %v\n%s", err, out.String())
	}
}

// A program the file system marks as from the internet, which another
// artefact shows running; and a download the browser flagged.
func TestAnomaliesFromTheInternet(t *testing.T) {
	b := open(t)
	b.run("mft", "mft",
		ev("file-system", "mft", `/Users/alice/Documents/tool.exe`, "$SI", map[string]any{"zone_id": 3, "zone_host_url": "https://cdn.test/tool.exe"}),
		ev("file-system", "mft", `/Users/alice/Documents/tool.exe`, "$SI again", map[string]any{"zone_id": 3, "zone_host_url": "https://cdn.test/tool.exe"}),
		// Marked, but nothing shows it running.
		ev("file-system", "mft", `/Users/alice/Documents/unused.exe`, "$SI", map[string]any{"zone_id": 3}),
		// Ran, but came from the intranet.
		ev("file-system", "mft", `/Program Files/App/app.exe`, "$SI", map[string]any{"zone_id": 1}),
		// A document from the internet is not a program.
		ev("file-system", "mft", `/Users/alice/Documents/report.pdf`, "$SI", map[string]any{"zone_id": 3}),
	)
	b.run("prefetch", "prefetch",
		ev("execution", "prefetch", `\VOLUME{01d9}\USERS\ALICE\DOCUMENTS\TOOL.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\PROGRAM FILES\APP\APP.EXE`, "ran", nil),
	)
	b.run("registry", "registry", ev("execution", "registry", `C:\Users\alice\Documents\tool.exe`, "ShimCache entry", nil))
	dl := func(code int, name, path string) store.Event {
		e := ev("browser", "browser", path, "Download finished", map[string]any{"danger_code": code, "danger": name, "url": "https://cdn.test/x"})
		e.TSType = "download-finished"
		return e
	}
	b.run("sqlite", "sqlite",
		dl(0, "not dangerous", `C:\Users\alice\Downloads\fine.zip`),
		dl(6, "dangerous, kept by the user", `C:\Users\alice\Downloads\keygen.zip`),
		dl(15, "scanned: safe", `C:\Users\alice\Downloads\scanned.zip`),
	)

	rep, err := Anomalies(b.s)
	if err != nil {
		t.Fatal(err)
	}
	got := anomalies(rep)
	if len(got[AnomRunFromInternet]) != 1 || got[AnomRunFromInternet][0] != `/Users/alice/Documents/tool.exe` {
		t.Errorf("run and from the internet: %q", got[AnomRunFromInternet])
	}
	if len(got[AnomDangerousDownload]) != 1 || got[AnomDangerousDownload][0] != `C:\Users\alice\Downloads\keygen.zip` {
		t.Errorf("dangerous download: %q", got[AnomDangerousDownload])
	}
	for _, f := range rep.Findings {
		switch f.Kind {
		case AnomRunFromInternet:
			// The file-table event and both artefacts that show it running.
			if f.Events != 3 || strings.Join(f.Sources, ",") != "mft,prefetch,registry" || f.Detail != "fetched from https://cdn.test/tool.exe" {
				t.Errorf("finding: %+v", f)
			}
		case AnomDangerousDownload:
			if !strings.Contains(f.Detail, "dangerous, kept by the user; from https://cdn.test/x") {
				t.Errorf("finding: %+v", f)
			}
		}
	}
	if n, err := TagAnomalies(b.s, rep); err != nil || n == 0 {
		t.Errorf("tagging: %d %v", n, err)
	}
	if rows, _ := b.s.Search(store.Query{Text: "tag:anomaly-run-and-from-the-internet"}); len(rows) != 3 {
		t.Errorf("the kind tag finds %d events, want 3", len(rows))
	}
}

// Defender's own records, outside the event log, are brought to the surface
// like its event-log detections: one finding per threat, however many
// records name it.
func TestAnomaliesDefenderRecords(t *testing.T) {
	b := open(t)
	det := func(typ, name string) store.Event {
		e := ev("security", "defender", `C:\Users\a\Downloads\tool.exe`, "detected", map[string]any{"threat_name": name})
		e.TSType = typ
		return e
	}
	other := ev("log", "defender", "", "[RTP] Setting something", nil)
	other.TSType = "logged"
	b.run("defender", "defender-detection",
		det("defender-detection", "Trojan:Win32/Test.A"),
		det("defender-detection (mplog)", "Trojan:Win32/Test.A"),
		det("defender-remediation", "Trojan:Win32/Test.A"),
		det("defender-detection", "PUA:Win32/Other"),
		other,
	)
	rep, err := Anomalies(b.s)
	if err != nil {
		t.Fatal(err)
	}
	got := anomalies(rep)[AnomProtection]
	if len(got) != 2 || rep.Counts[AnomProtection] != 2 {
		t.Fatalf("findings %v, counts %v", got, rep.Counts)
	}
	for _, f := range rep.Findings {
		if f.Subject == "Defender detection: Trojan:Win32/Test.A" && f.Events != 2 {
			t.Errorf("events on the finding: %d", f.Events)
		}
	}
}

// An extension loaded from a folder is surfaced; one from the store is not.
func TestAnomaliesSideloadedExtension(t *testing.T) {
	b := open(t)
	ext := func(loc int, name string) store.Event {
		e := ev("browser", "browser", `C:\Temp\ext`, "Browser extension installed: "+name, map[string]any{"location": loc, "name": name, "location_name": "how"})
		e.TSType = "browser-extension-installed"
		return e
	}
	b.run("browser", "text-log", ext(4, "Helper"), ext(1, "Store thing"), ext(8, "Flag thing"), ext(5, "Component"))
	rep, err := Anomalies(b.s)
	if err != nil {
		t.Fatal(err)
	}
	got := anomalies(rep)[AnomSideloadedExtension]
	if len(got) != 2 || rep.Counts[AnomSideloadedExtension] != 2 {
		t.Fatalf("findings %v, counts %v", got, rep.Counts)
	}
}

// A WMI consumer that runs a command is surfaced, with its binding; the one Windows ships is not.
func TestAnomaliesWMISubscription(t *testing.T) {
	b := open(t)
	rec := func(fields map[string]any) store.Event {
		e := ev("persistence", "wmi", "", "WMI record", fields)
		e.TSType = "wmi-subscription-record-written (inferred)"
		return e
	}
	b.run("wmi", "wmi-repository",
		rec(map[string]any{"class": "CommandLineEventConsumer", "name": "Updater"}),
		rec(map[string]any{"class": "__FilterToConsumerBinding", "consumer_class": "CommandLineEventConsumer", "consumer": "Updater"}),
		rec(map[string]any{"class": "NTEventLogEventConsumer", "name": "SCM Event Log Consumer"}),
		rec(map[string]any{"class": "__FilterToConsumerBinding", "consumer_class": "NTEventLogEventConsumer", "consumer": "SCM Event Log Consumer"}),
		rec(map[string]any{"class": "__EventFilter", "name": "SCM Event Log Filter"}),
	)
	rep, err := Anomalies(b.s)
	if err != nil {
		t.Fatal(err)
	}
	got := anomalies(rep)[AnomWMISubscription]
	if len(got) != 1 || got[0] != "CommandLineEventConsumer Updater" || rep.Counts[AnomWMISubscription] != 1 {
		t.Fatalf("findings %v, counts %v", got, rep.Counts)
	}
}
