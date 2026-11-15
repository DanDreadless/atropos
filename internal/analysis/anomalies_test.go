package analysis

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/store"
)

func ev(category, source, path, message string, fields map[string]any) store.Event {
	f := "{}"
	if fields != nil {
		b, _ := json.Marshal(fields)
		f = string(b)
	}
	return store.Event{TSUTC: ns("2024-05-01 10:00:00"), TSType: "t", Category: category, Source: source, Path: path, Message: message, Fields: f}
}

func anomalies(r *AnomalyReport) map[string][]string {
	out := map[string][]string{}
	for _, f := range r.Findings {
		out[f.Kind] = append(out[f.Kind], f.Subject)
	}
	return out
}

func TestAnomalies(t *testing.T) {
	b := open(t)
	b.run("prefetch", "prefetch",
		// Out of place.
		ev("execution", "prefetch", `\VOLUME{01d9}\USERS\ALICE\APPDATA\LOCAL\TEMP\UPD.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\USERS\PUBLIC\SVCHOST.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\USERS\ALICE\DOWNLOADS\SETUP.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\PROGRAMDATA\SCVHOST.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\WINDOWS\SYSTEM32\SVCH0ST.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\TOOLS\MIMIKATZ.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\TEMP\A.EXE`, "ran", nil),
		// Where they belong.
		ev("execution", "prefetch", `\VOLUME{01d9}\WINDOWS\SYSTEM32\SVCHOST.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\WINDOWS\EXPLORER.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\PROGRAM FILES\APP\APP.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\PROGRAMDATA\VENDOR\AGENT\AGENT.EXE`, "ran", nil),
		ev("execution", "prefetch", `\VOLUME{01d9}\WINDOWS\SYSTEM32\TASKHOSTW.EXE`, "ran", nil),
	)
	b.run("registry", "registry",
		// The same file seen by a second artefact joins the first finding.
		ev("execution", "registry", `C:\Users\Public\svchost.exe`, "ShimCache entry", nil),
		// A known-folder form says nothing about the folder.
		ev("execution", "registry", `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe`, "UserAssist", nil),
	)
	b.run("mft", "mft",
		ev("file-system", "mft", `/Users/Public/Documents/invoice.pdf.exe`, "$SI", nil),
		ev("file-system", "mft", `/Users/Public/Documents/invoice.pdf.exe`, "$SI again", nil),
		ev("file-system", "mft", `/Windows/Fonts/a.dll`, "$SI", nil),
		ev("file-system", "mft", "/Users/alice/Desktop/report\u202efdp.exe", "$SI", nil),
		// Present in Temp but never seen running: installers fill Temp.
		ev("file-system", "mft", `/Users/alice/AppData/Local/Temp/is-ABC/setup.exe`, "$SI", nil),
		ev("file-system", "mft", `/Windows/WinSxS/amd64_x/svchost.exe`, "$SI", nil),
		ev("file-opening", "lnk", `C:\Users\alice\Documents\report.pdf.lnk`, "opened", nil),
	)
	b.run("evtx", "evtx",
		ev("execution", "evtx", "", "process created", map[string]any{"event_id": 4688, "channel": "Security",
			"event": map[string]any{"CommandLine": `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA`}}),
		ev("execution", "evtx", "", "process created", map[string]any{"event_id": 4688, "channel": "Security",
			"event": map[string]any{"CommandLine": `vssadmin.exe delete shadows /all /quiet`}}),
		ev("execution", "evtx", "", "process created", map[string]any{"event_id": 4688, "channel": "Security",
			"event": map[string]any{"CommandLine": `powershell.exe -File C:\Scripts\backup.ps1`}}),
		ev("security", "evtx", "", "log cleared", map[string]any{"event_id": 1102, "channel": "Security"}),
		ev("security", "evtx", "", "threat", map[string]any{"event_id": 1116, "channel": "Microsoft-Windows-Windows Defender/Operational"}),
		ev("persistence", "evtx", "", "service installed", map[string]any{"event_id": 7045, "channel": "System",
			"event": map[string]any{"ImagePath": `C:\Users\bob\AppData\Local\Temp\svc.exe -k`}}),
		ev("persistence", "evtx", "", "service installed", map[string]any{"event_id": 7045, "channel": "System",
			"event": map[string]any{"ImagePath": `C:\Program Files\Vendor\svc.exe`}}),
	)

	rep, err := Anomalies(b.s)
	if err != nil {
		t.Fatal(err)
	}
	got := anomalies(rep)
	want := map[string][]string{
		AnomSystemNameElsewhere: {`\VOLUME{01d9}\USERS\PUBLIC\SVCHOST.EXE`},
		AnomLookAlikeName:       {`\VOLUME{01d9}\PROGRAMDATA\SCVHOST.EXE`, `\VOLUME{01d9}\WINDOWS\SYSTEM32\SVCH0ST.EXE`},
		AnomDeceptiveName:       {`/Users/Public/Documents/invoice.pdf.exe`, "/Users/alice/Desktop/report\u202efdp.exe"},
		AnomLogCleared:          {"Security event 1102"},
		AnomProtection:          {"Defender detection (event 1116)"},
		AnomCommand:             {"PowerShell run with an encoded command", "PowerShell run with a hidden window", "Shadow copies or backups deleted"},
		AnomPersistence:         {`c:/users/bob/appdata/local/temp/svc.exe`},
		AnomRunStaging:          {`\VOLUME{01d9}\USERS\PUBLIC\SVCHOST.EXE`, `\VOLUME{01d9}\PROGRAMDATA\SCVHOST.EXE`},
		AnomRunTemp:             {`\VOLUME{01d9}\USERS\ALICE\APPDATA\LOCAL\TEMP\UPD.EXE`, `\VOLUME{01d9}\TEMP\A.EXE`},
		AnomTool:                {`\VOLUME{01d9}\TOOLS\MIMIKATZ.EXE`},
		AnomFileStaging:         {`/Users/Public/Documents/invoice.pdf.exe`, `/Windows/Fonts/a.dll`},
		AnomRunDownloads:        {`\VOLUME{01d9}\USERS\ALICE\DOWNLOADS\SETUP.EXE`},
	}
	for kind, subjects := range want {
		have := map[string]bool{}
		for _, s := range got[kind] {
			have[s] = true
		}
		for _, s := range subjects {
			if !have[s] {
				t.Errorf("%s: missing %q; got %q", kind, s, got[kind])
			}
		}
		if len(got[kind]) != len(subjects) {
			t.Errorf("%s: want %d findings, got %q", kind, len(subjects), got[kind])
		}
	}
	for kind := range got {
		if _, ok := want[kind]; !ok {
			t.Errorf("unexpected kind %s: %q", kind, got[kind])
		}
	}
	// The same file seen by prefetch and by ShimCache, written two ways, is one finding.
	for _, f := range rep.Findings {
		if f.Kind == AnomSystemNameElsewhere && (f.Events != 2 || strings.Join(f.Sources, ",") != "prefetch,registry") {
			t.Errorf("one file seen by two artefacts: %+v", f)
		}
	}
	// Two events for one file are one finding.
	for _, f := range rep.Findings {
		if f.Kind == AnomDeceptiveName && strings.HasSuffix(f.Subject, "invoice.pdf.exe") && (f.Events != 2 || len(f.EventIDs) != 2) {
			t.Errorf("events for one file were not gathered: %+v", f)
		}
	}

	var out bytes.Buffer
	if err := WriteAnomaliesText(&out, rep); err != nil || !strings.Contains(out.String(), "Event log cleared (1)") {
		t.Errorf("text report: %v\n%s", err, out.String())
	}

	// Tagging marks every listed event once, and a second pass adds nothing.
	n, err := TagAnomalies(b.s, rep)
	if err != nil || n == 0 {
		t.Fatalf("tagging: %d %v", n, err)
	}
	rows, err := b.s.Search(store.Query{Text: "tag:anomaly"})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[int64]bool{}
	for _, f := range rep.Findings {
		for _, id := range f.EventIDs {
			ids[id] = true
		}
	}
	if len(rows) != len(ids) {
		t.Errorf("tag:anomaly finds %d events, the report lists %d", len(rows), len(ids))
	}
	rows, _ = b.s.Search(store.Query{Text: "tag:anomaly-log-cleared"})
	if len(rows) != 1 {
		t.Errorf("the kind tag finds %d events, want 1", len(rows))
	}
	if again, err := TagAnomalies(b.s, rep); err != nil || again != 0 {
		t.Errorf("tagging twice added %d more (%v)", again, err)
	}
}

func TestLookAlike(t *testing.T) {
	for name, want := range map[string]string{
		"scvhost": "svchost", "svch0st": "svchost", "svchosts": "svchost", "lsasss": "lsass", "lsas": "",
		"exp1orer": "explorer", "svchost": "", "taskhostw": "", "notepad": "", "service": "", "chrome": "", "chrom": "chrome",
	} {
		if got := lookAlike(name); got != want {
			t.Errorf("lookAlike(%q) = %q, want %q", name, got, want)
		}
	}
}
