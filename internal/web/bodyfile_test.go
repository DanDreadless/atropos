package web

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

func TestBodyfileExport(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "case.db"), "tester")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := func(v string) int64 {
		tm, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatal(err)
		}
		return tm.UnixNano()
	}
	add := func(n int, events ...store.Event) {
		e := &store.Evidence{SHA256: fmt.Sprintf("%064d", n), Name: "x", Origin: "/x", BatchID: 1, Kind: "x", DetectReason: "test"}
		if err := s.AddEvidence(e); err != nil {
			t.Fatal(err)
		}
		run, err := s.BeginRun(e.ID, "p", "1", "")
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range events {
			ev.TZSource, ev.TZName = "native-utc", "UTC"
			if err := run.Add(ev); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := run.Finish("parsed", ""); err != nil {
			t.Fatal(err)
		}
	}
	const ref = "MFT entry 40-2"
	fields := `{"entry":40,"is_dir":false,"sequence":2,"size":4096}`
	add(1,
		// One file's $SI times, as three moments; its $FN times as one.
		store.Event{TSUTC: at("2024-01-10T09:00:00Z"), TSType: "$SI ...B", MACB: "...B", Source: "mft", Path: "/Users/a/evil|tool.exe", RecordRef: ref, Fields: fields},
		store.Event{TSUTC: at("2024-01-11T10:00:00.7Z"), TSType: "$SI M.C.", MACB: "M.C.", Source: "mft", Path: "/Users/a/evil|tool.exe", RecordRef: ref, Fields: fields},
		store.Event{TSUTC: at("2024-01-12T11:00:00Z"), TSType: "$SI .A..", MACB: ".A..", Source: "mft", Path: "/Users/a/evil|tool.exe", RecordRef: ref, Fields: fields},
		store.Event{TSUTC: at("2024-01-10T09:00:01Z"), TSType: "$FN MACB", MACB: "MACB", Source: "mft", Path: "/Users/a/evil|tool.exe", RecordRef: ref, Fields: fields},
		store.Event{TSUTC: at("2024-01-09T08:00:00Z"), TSType: "$SI MACB", MACB: "MACB", Source: "mft", Path: "/Users/a", RecordRef: "MFT entry 39-1", Fields: `{"is_dir":true,"size":0}`},
	)
	add(2,
		// A registry key's last write is a real modified time; a log record is not a file time.
		store.Event{TSUTC: at("2024-01-13T12:00:00Z"), TSType: "registry-key-last-write", MACB: "M...", Source: "registry", Path: `\Software\Run`, RecordRef: "key node at offset 0x20"},
		store.Event{TSUTC: at("2024-01-13T12:00:05Z"), TSType: "event 4624", MACB: "....", Source: "evtx", Path: "", RecordRef: "record 9"},
		store.Event{TSUTC: at("2024-01-13T12:00:06Z"), TSType: "url-visited", Source: "browser", Path: "https://x.test/", RecordRef: "visits.id 1"},
	)

	var out bytes.Buffer
	res, err := ExportWith(s, store.Query{}, "bodyfile", &out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 6 || res.Lines != 4 || res.LeftOut != 2 {
		t.Errorf("result: %+v", res)
	}
	sec := func(v string) int64 { return at(v) / 1e9 }
	want := []string{
		fmt.Sprintf("0|/Users/a|39-1|d/drwxrwxrwx|0|0|0|%[1]d|%[1]d|%[1]d|%[1]d", sec("2024-01-09T08:00:00Z")),
		// atime, mtime, ctime, crtime; the separator in the name made harmless; sub-seconds dropped.
		fmt.Sprintf("0|/Users/a/evil%%7Ctool.exe|40-2|r/rrwxrwxrwx|0|0|4096|%d|%d|%d|%d",
			sec("2024-01-12T11:00:00Z"), sec("2024-01-11T10:00:00Z"), sec("2024-01-11T10:00:00Z"), sec("2024-01-10T09:00:00Z")),
		fmt.Sprintf("0|/Users/a/evil%%7Ctool.exe ($FILE_NAME)|40-2|r/rrwxrwxrwx|0|0|4096|%[1]d|%[1]d|%[1]d|%[1]d", sec("2024-01-10T09:00:01Z")),
		fmt.Sprintf(`0|\Software\Run (registry: registry-key-last-write)|0|0|0|0|0|0|%d|0|0`, sec("2024-01-13T12:00:00Z")),
	}
	got := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("%d lines:\n%s", len(got), out.String())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got %s\nwant %s", i, got[i], want[i])
		}
		if strings.Count(got[i], "|") != 10 {
			t.Errorf("line %d has %d separators", i, strings.Count(got[i], "|"))
		}
	}
	// The other formats are unchanged and still count every event.
	out.Reset()
	if res, err := ExportWith(s, store.Query{}, "jsonl", &out); err != nil || res.Events != 8 || res.LeftOut != 0 {
		t.Errorf("jsonl: %+v %v", res, err)
	}
}

func TestBodyfileOverHTTP(t *testing.T) {
	h := seeded(t)
	code, hdr, body := h.do("GET", "/api/export?format=bodyfile", nil, nil)
	if code != 200 || !strings.Contains(hdr.Get("Content-Disposition"), ".body") {
		t.Fatalf("bodyfile: %d %v", code, hdr)
	}
	// The seeded case is log lines: none is a file time, so nothing is written.
	if len(body) != 0 {
		t.Errorf("log records were written as file times:\n%s", body)
	}
	rows, _ := h.s.ListAudit(5)
	found := false
	for _, a := range rows {
		if d := string(a.Details); a.Action == "export" && strings.Contains(d, `"left_out_no_file_time"`) && strings.Contains(d, `"format":"bodyfile"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("the export's audit entry does not say what was left out: %+v", rows)
	}
	if code, _, _ := h.do("GET", "/api/export?format=nonsense", nil, nil); code != 400 {
		t.Errorf("unknown format: %d", code)
	}
}
