package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// Every event says which MACB time it is, if any, and what it is evidence
// of. A time that is not a file-system style time is never given a letter.
func TestMACBAndCategory(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range []string{CatExecution, CatFileOpening, CatFileSystem, CatBrowser, CatAccount, CatNetwork, CatPersistence, CatDevice, CatRegistry, CatSecurity, CatDeletion, CatLog} {
		valid[c] = true
	}
	check := func(name string, evs []Event) {
		t.Helper()
		if len(evs) == 0 {
			t.Errorf("%s: no events", name)
		}
		for _, e := range evs {
			if !valid[e.Category] {
				t.Errorf("%s: %q has category %q", name, e.Type, e.Category)
				return
			}
			if e.MACB == "" {
				continue
			}
			if len(e.MACB) != 4 || e.MACB == "...." {
				t.Errorf("%s: malformed MACB %q", name, e.MACB)
				return
			}
			for i, ch := range "MACB" {
				if e.MACB[i] != '.' && rune(e.MACB[i]) != ch {
					t.Errorf("%s: MACB %q has a letter in the wrong place", name, e.MACB)
					return
				}
			}
		}
	}

	ft := func(s string) uint64 {
		tm, _ := time.Parse(time.RFC3339, s)
		return uint64(tm.UnixNano()/100) + 116444736000000000
	}
	lnk := run(t, write(t, "a.lnk", buildLnk(ft("2023-05-01T08:00:00Z"), ft("2023-05-03T10:00:00Z"), ft("2023-05-02T09:00:00Z"))), nil)
	check("lnk", lnk.events)
	for _, e := range lnk.events {
		want := map[string]string{"link-target-created": "...B", "link-target-modified": "M...", "link-target-accessed": ".A.."}[e.Type]
		if e.MACB != want || e.Category != CatFileOpening {
			t.Errorf("lnk %s: MACB %q category %q", e.Type, e.MACB, e.Category)
		}
	}

	logs := run(t, write(t, "a.log", []byte("2024-03-01T10:00:00Z x\n")), nil)
	check("text", logs.events)
	if e := logs.events[0]; e.MACB != "" || e.Category != CatLog {
		t.Errorf("a log line is not a file time: MACB %q category %q", e.MACB, e.Category)
	}
	web := run(t, write(t, "access.log", []byte(`1.2.3.4 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1`+"\n")), nil)
	if len(web.events) != 1 || web.events[0].Category != CatNetwork {
		t.Errorf("http request: %+v", web.events)
	}

	p := filepath.Join("..", "..", "testdata")
	if !exists(filepath.Join(p, "Security.evtx")) {
		t.Skip("no sample artefacts; run scripts/fetch-testdata.sh")
	}
	mft := run(t, filepath.Join(p, "test.ntfs.dd"), nil)
	check("mft", mft.events)
	for _, e := range mft.events {
		if e.Category != CatFileSystem || !strings.HasSuffix(e.Type, " "+e.MACB) {
			t.Fatalf("mft: type %q with MACB %q category %q", e.Type, e.MACB, e.Category)
		}
	}
	reg := run(t, filepath.Join(p, "NTUSER.DAT"), nil)
	check("registry", reg.events)
	for _, e := range reg.events {
		switch e.Type {
		case "registry-key-last-write":
			if e.MACB != "M..." || e.Category != CatRegistry {
				t.Fatalf("key write: %q %q", e.MACB, e.Category)
			}
		case "program-last-run (userassist)":
			if e.MACB != "" || e.Category != CatExecution {
				t.Fatalf("userassist: %q %q", e.MACB, e.Category)
			}
		}
	}
	evt := run(t, filepath.Join(p, "Security.evtx"), nil)
	check("evtx", evt.events)
	got := map[string]string{}
	for _, e := range evt.events {
		got[e.Fields["event_id"].(string)] = e.Category
		if e.MACB != "" {
			t.Fatalf("event log record given MACB %q", e.MACB)
		}
	}
	for id, want := range map[string]string{"4624": CatAccount, "4648": CatAccount, "4672": CatAccount, "1102": CatSecurity} {
		if got[id] != want {
			t.Errorf("event %s: category %q, want %q", id, got[id], want)
		}
	}
	pf := run(t, filepath.Join(p, "prefetch", "Win10", "CALC.EXE-3FBEF7FD.pf"), nil)
	check("prefetch", pf.events)
	if pf.events[0].Category != CatExecution {
		t.Errorf("prefetch category %q", pf.events[0].Category)
	}
}
