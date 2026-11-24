package parsers

import (
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/artw"
)

// The test-data writers in artw must give what Windows' own files give:
// these read their output back with the real parsers.

func TestArtwHive(t *testing.T) {
	t0 := time.Date(2026, 3, 2, 9, 0, 0, 123456700, time.UTC)
	root := &artw.Key{Name: "ROOT", Written: t0}
	root.Path(`Environment`, t0).Values = []artw.Value{artw.SZ("TEMP", `%USERPROFILE%\AppData\Local\Temp`)}
	tsc := `Software\Microsoft\Terminal Server Client`
	srv := root.Path(tsc+`\Servers\SRV-FILE01`, t0.Add(time.Hour))
	srv.Values = []artw.Value{artw.SZ("UsernameHint", `CORP\alice`), artw.Value{Name: "CertHash", Type: artw.RegBinary, Data: []byte{1, 2, 3, 4, 5, 6}}}
	root.Path(tsc+`\Default`, t0.Add(2*time.Hour)).Values = []artw.Value{artw.SZ("MRU0", "SRV-FILE01"), artw.SZ("MRU1", "10.0.0.9")}
	root.Path(`Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##SRV-FILE01#Finance`, t0.Add(3*time.Hour)).Values = []artw.Value{artw.DWORD("BaseClass", 0)}
	root.Path(`Software\Ünïcode`, t0)
	hive, err := artw.Hive(root, `\??\C:\Users\alice\ntuser.dat`, t0)
	if err != nil {
		t.Fatal(err)
	}
	r := run(t, write(t, "NTUSER.DAT", hive), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err %v warns %v", r.err, r.warns)
	}
	if r.facts["hive.kind"] != "NTUSER" {
		t.Errorf("hive kind %q", r.facts["hive.kind"])
	}
	want := map[string]struct{ at, path, msg string }{
		"rdp-client-server-key-last-write": {"2026-03-02T10:00:00.1234567Z", "SRV-FILE01", `Remote Desktop connection from this account to SRV-FILE01 (signing in as CORP\alice)`},
		"rdp-client-recent-key-last-write": {"2026-03-02T11:00:00.1234567Z", "", "Remote Desktop recent connections list written: SRV-FILE01; 10.0.0.9"},
		"network-share-key-last-write":     {"2026-03-02T12:00:00.1234567Z", `\\SRV-FILE01\Finance`, `Network share used by this account: \\SRV-FILE01\Finance`},
	}
	got := map[string]bool{}
	keys := map[string]bool{}
	for _, e := range r.events {
		keys[e.Path] = true
		w, ok := want[e.Type]
		if !ok {
			continue
		}
		got[e.Type] = true
		if utc(e) != w.at || (w.path != "" && e.Path != w.path) || e.Message != w.msg {
			t.Errorf("%s: %s %q %q", e.Type, utc(e), e.Path, e.Message)
		}
	}
	for typ := range want {
		if !got[typ] {
			t.Errorf("no %s event", typ)
		}
	}
	if !keys[`\Software\Ünïcode`] {
		t.Errorf("key with a UTF-16 name not read back; keys %v", keys)
	}
}

func TestArtwJumpList(t *testing.T) {
	t1 := time.Date(2026, 3, 2, 9, 30, 0, 0, time.UTC)
	data := artw.JumpList([]artw.JumpEntry{
		{Path: `C:\Users\alice\Documents\notes.txt`, LastUsed: t1, Count: 2, Machine: "WS-ALICE"},
		{Path: `\\SRV-FILE01\Finance\Q3 results.xlsx`, LastUsed: t1.Add(time.Minute), Count: 1, Machine: "SRV-FILE01"},
	})
	r := run(t, write(t, "6e855c85de07bc6a.automaticDestinations-ms", data), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err %v warns %v", r.err, r.warns)
	}
	var used, unc int
	for _, e := range r.events {
		switch {
		case e.Type == "jumplist-entry-last-used":
			used++
			if e.Path == `\\SRV-FILE01\Finance\Q3 results.xlsx` {
				if utc(e) != "2026-03-02T09:31:00Z" || e.Fields["target_host"] != "SRV-FILE01" || e.Fields["application"] == nil {
					t.Errorf("share entry: %s %+v", utc(e), e.Fields)
				}
			}
		case e.Path == `\\SRV-FILE01\Finance\Q3 results.xlsx`:
			unc++
			if e.Fields["network_share"] != `\\SRV-FILE01\Finance` {
				t.Errorf("shortcut share %v", e.Fields["network_share"])
			}
		case e.Path != `C:\Users\alice\Documents\notes.txt`:
			t.Errorf("unexpected %s %q", e.Type, e.Path)
		}
	}
	if used != 2 || unc != 3 {
		t.Errorf("%d entries, %d shortcut times on the share; want 2 and 3", used, unc)
	}
}
