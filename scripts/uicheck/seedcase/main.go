// Command seedcase writes a small case whose artefacts contradict each other
// about three files' times, so the browser check can look at the Analysis tab
// with findings in it, and holds a command history with a command of a kind
// attackers use, for the finding in a file's text. The events are written straight into the store: there
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
	// The registry hive (evidence 2) names the host, as a SYSTEM hive does.
	if err := s.AddFact(2, "host.name", "WKSTN-07", "seeded: ComputerName"); err != nil {
		panic(err)
	}
	// A browser history, as the sqlite parser reads one: a typed search, the
	// page reached from it, a hop in a redirect chain, a visit synced from
	// another device, and a download (judged safe, so the Analysis counts
	// above are unchanged).
	visit := func(at, typ, cat, src, u, domain string, f map[string]any) store.Event {
		f["url"], f["domain"], f["browser"] = u, domain, "chromium"
		return store.Event{TSUTC: ns(at), TSType: typ, Category: cat, Source: src, Path: u, User: "dan", Message: "Visited " + u, Fields: fields(f),
			RecordRef: fmt.Sprintf("visits.id %v", f["visit_id"])}
	}
	run("sqlite-database", "sqlite",
		visit("2024-03-10 09:00:00", "url-visited (typed)", "browser", "browser", "https://search.test/?q=how+to", "search.test",
			map[string]any{"visit_id": 1, "title": "how to - Search", "search_term": "how to", "transition_name": "typed", "navigation": "user",
				"transition_qualifiers": []string{"from_address_bar", "chain_start", "chain_end"}, "visit_duration_seconds": 30.5, "response_code": 200,
				"url_visit_count": 2, "url_typed_count": 1, "user_from": "the profile folder the file was taken from (inferred from its path)"}),
		visit("2024-03-10 09:00:29", "url-visited (redirected through)", "browser-automatic", "browser", "https://go.search.test/r?u=files", "go.search.test",
			map[string]any{"visit_id": 2, "from_visit_id": 1, "from_url": "https://search.test/?q=how+to", "navigation": "automatic",
				"navigation_reason": "a hop in a redirect chain, not the page that was shown", "transition_qualifiers": []string{"chain_start"}}),
		visit("2024-03-10 09:00:30", "url-visited (link, after a redirect)", "browser", "browser", "https://files.test/landing", "files.test",
			map[string]any{"visit_id": 3, "from_visit_id": 1, "from_url": "https://search.test/?q=how+to", "title": "Landing", "navigation": "user",
				"transition_qualifiers": []string{"server_redirect", "chain_end"}}),
		visit("2024-03-10 07:00:00", "url-visited (link)", "browser", "browser-synced", "https://www.search.test/news", "www.search.test",
			map[string]any{"visit_id": 4, "synced_from_another_device": true, "navigation": "user", "title": "News"}),
		store.Event{TSUTC: ns("2024-03-10 09:01:00"), TSType: "download-finished", Category: "browser", Source: "browser", User: "dan",
			Path: `C:\Users\dan\Downloads\report.pdf`, Message: `Download finished: C:\Users\dan\Downloads\report.pdf`, RecordRef: "downloads.id 5",
			Fields: fields(map[string]any{"browser": "chromium", "target_path": `C:\Users\dan\Downloads\report.pdf`, "url": "https://cdn.files.test/report.pdf",
				"domain": "cdn.files.test", "url_chain": []string{"https://files.test/get?id=1", "https://cdn.files.test/report.pdf"},
				"tab_url": "https://files.test/landing", "state": "complete", "danger": "not dangerous", "danger_code": 0,
				"received_bytes": 4096, "total_bytes": 4096, "mime_type": "application/pdf", "opened_from_browser": true})},
	)
	// A Defender detection record, as the defender-detection parser reads
	// one: a macro document quarantined, found in two places.
	run("defender-detection-history", "defender-detection",
		store.Event{TSUTC: ns("2024-03-10 09:02:00"), TSType: "defender-detection", Category: "security", Source: "defender", User: `WKSTN-07\dan`,
			Path: `C:\Users\dan\Documents\invoice.docm`, RecordRef: "detection {5A1B2C3D-0000-4000-8000-000000000001}",
			Message: `Defender detected TrojanDownloader:O97M/Seed.A in file C:\Users\dan\Documents\invoice.docm and 1 more (severity severe; status now quarantined)`,
			Fields: fields(map[string]any{"detection_id": "{5A1B2C3D-0000-4000-8000-000000000001}", "threat_name": "TrojanDownloader:O97M/Seed.A",
				"severity": "severe", "severity_id": 5, "category": "trojan downloader", "category_id": 4, "threat_status": "quarantined", "threat_status_id": 3,
				"detection_source": "real-time", "execution_status": "not executing", "process": `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
				"user": `WKSTN-07\dan`, "initial_detection_time": "2024-03-10T09:02:00Z", "file": `C:\Users\dan\Documents\invoice.docm`,
				"sha256": "0000000000000000000000000000000000000000000000000000000000000abc",
				"resources": []map[string]any{
					{"type": "file", "location": `C:\Users\dan\Documents\invoice.docm`, "ThreatTrackingSha256": "0000000000000000000000000000000000000000000000000000000000000abc", "ThreatTrackingSize": 48213},
					{"type": "containerfile", "location": `C:\Users\dan\Downloads\invoices.zip`},
				}})},
	)
	// A PowerShell command history: text with no times of its own, indexed
	// in full, whose third line is a command of a kind attackers use.
	hist := &store.Evidence{SHA256: fmt.Sprintf("%064d", n+1), Name: "ConsoleHost_history.txt", Origin: "seed:text", BatchID: 1, Kind: "text", DetectReason: "seeded for the browser check"}
	if err := s.AddEvidence(hist); err != nil {
		panic(err)
	}
	if err := s.AddText(hist.ID, "full text", false, "Get-ChildItem C:\\Users\\Public\ncd C:\\Users\\Public\n"+
		"powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\nexit\n"); err != nil {
		panic(err)
	}
}
