// Command seedcase writes a small case whose artefacts contradict each other
// about three files' times, so the browser check can look at the Analysis tab
// with findings in it. The events are written straight into the store: there
// are no files behind them, so this case is for looking at, not for verifying.
//
//	go run ./scripts/uicheck/seedcase DIR
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: seedcase DIR")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		panic(err)
	}
	s, err := store.Open(filepath.Join(dir, "case.db"), "uicheck")
	if err != nil {
		panic(err)
	}
	defer s.Close()
	n := 0
	run := func(kind, parser string, events ...store.Event) {
		n++
		e := &store.Evidence{SHA256: fmt.Sprintf("%064d", n), Name: kind, Origin: "seed:" + kind, BatchID: 1, Kind: kind, DetectReason: "seeded for the browser check"}
		if err := s.AddEvidence(e); err != nil {
			panic(err)
		}
		r, err := s.BeginRun(e.ID, parser, "seed", "")
		if err != nil {
			panic(err)
		}
		for _, ev := range events {
			ev.TZSource, ev.TZName, ev.Host = "native-utc", "UTC", "WKSTN-07"
			if err := r.Add(ev); err != nil {
				panic(err)
			}
		}
		if _, err := r.Finish("parsed", ""); err != nil {
			panic(err)
		}
	}
	mft := func(path string, entry int, modified, created, flags string) []store.Event {
		suffix := ""
		if flags != "" {
			suffix = " [" + flags + "]"
		}
		ref := fmt.Sprintf("MFT entry %d-1", entry)
		return []store.Event{
			{TSUTC: ns(modified), TSType: "$SI M...", MACB: "M...", Category: "file-system", Source: "mft", Path: path, Message: "$SI M...  " + path + suffix, RecordRef: ref},
			{TSUTC: ns(created), TSType: "$SI .ACB", MACB: ".ACB", Category: "file-system", Source: "mft", Path: path, Message: "$SI .ACB  " + path + suffix, RecordRef: ref},
		}
	}
	fields := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }

	var files []store.Event
	files = append(files, mft("/Windows/System32/svch0st.exe", 100, "2019-03-01 10:00:00", "2019-03-01 10:00:00", "SI<FN")...)
	files = append(files, mft("/Users/Public/tool.exe", 103, "2020-06-01 12:00:00", "2020-06-01 12:00:00", "")...)
	files = append(files, mft("/ProgramData/x/drop.dll", 106, "2018-01-01 00:00:00", "2018-01-01 00:00:00", "")...)
	files = append(files, mft("/Windows/System32/calc.exe", 101, "2023-05-05 05:05:05", "2023-05-05 05:05:05", "")...)
	run("mft", "ntfs-mft", files...)
	run("windows-registry-hive", "registry",
		store.Event{TSUTC: ns("2024-01-15 09:30:00"), TSType: "file-modified (shimcache)", MACB: "M...", Category: "execution", Source: "registry",
			Path: `C:\Windows\System32\svch0st.exe`, Message: `ShimCache: C:\Windows\System32\svch0st.exe`},
		store.Event{TSUTC: ns("2023-05-05 05:05:05"), TSType: "file-modified (shimcache)", MACB: "M...", Category: "execution", Source: "registry",
			Path: `C:\Windows\System32\calc.exe`, Message: `ShimCache: C:\Windows\System32\calc.exe`},
		store.Event{TSUTC: ns("2024-03-10 08:00:00"), TSType: "amcache-file-recorded", Category: "execution", Source: "registry",
			Path: `c:\users\public\tool.exe`, Message: `Amcache: file recorded: c:\users\public\tool.exe`, Fields: fields(map[string]any{"link_date": "03/09/2024 22:11:33"})},
	)
	run("usn-journal", "usn-journal",
		store.Event{TSUTC: ns("2024-03-10 08:05:00"), TSType: "usn-change", Category: "file-system", Source: "usn", Path: "drop.dll",
			Message: "USN: created drop.dll  FILE_CREATE", Fields: fields(map[string]any{"reasons": []string{"FILE_CREATE"}, "entry": 106, "sequence": 1})},
	)
}
