package ingest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/artw"
	"github.com/DanDreadless/atropos/internal/store"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

// A SOFTWARE hive's network history is in local time. Added with its SYSTEM
// hive in one submission (SOFTWARE named first, so the order is the
// ingester's), the networks take the host's zone from the SYSTEM hive;
// added alone, the zone is assumed and says so.
func TestNetworkHistoryTakesZoneFromSystemHive(t *testing.T) {
	t0 := time.Date(2024, 7, 20, 9, 0, 0, 0, time.UTC)
	sys := &artw.Key{Name: "ROOT", Written: t0}
	sys.Path(`Select`, t0).Values = []artw.Value{artw.DWORD("Current", 1)}
	sys.Path(`ControlSet001\Control\ComputerName\ComputerName`, t0).Values = []artw.Value{artw.SZ("ComputerName", "LAPTOP-7")}
	sys.Path(`ControlSet001\Control\TimeZoneInformation`, t0).Values = []artw.Value{artw.SZ("TimeZoneKeyName", "GMT Standard Time")}
	sysHive, err := artw.Hive(sys, `\REGISTRY\MACHINE\SYSTEM`, t0)
	if err != nil {
		t.Fatal(err)
	}
	wide := func(s string) []byte {
		u := utf16.Encode([]rune(s + "\x00"))
		b := make([]byte, 2*len(u))
		for i, c := range u {
			binary.LittleEndian.PutUint16(b[2*i:], c)
		}
		return b
	}
	st := func(y, mo, d, h, mi, s int) []byte {
		b := make([]byte, 16)
		for i, n := range []int{y, mo, 0, d, h, mi, s, 0} {
			binary.LittleEndian.PutUint16(b[i*2:], uint16(n))
		}
		return b
	}
	sw := &artw.Key{Name: "ROOT", Written: t0}
	sw.Path(`Classes`, t0) // with Microsoft, what marks a SOFTWARE hive
	sw.Path(`Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{11111111-2222-3333-4444-555555555555}`, t0).Values = []artw.Value{
		{Name: "ProfileName", Type: 1, Data: wide("Hotel Guest")},
		artw.DWORD("NameType", 71),
		{Name: "DateCreated", Type: 3, Data: st(2024, 7, 14, 21, 5, 9)}, // 20:05:09 UTC in British Summer Time
	}
	swHive, err := artw.Hive(sw, `\REGISTRY\MACHINE\SOFTWARE`, t0)
	if err != nil {
		t.Fatal(err)
	}

	first := func(t *testing.T, c *testCase) store.EventRow {
		t.Helper()
		rows, err := c.s.Search(store.Query{Text: "Hotel Guest"})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.TSType == "network-first-connected" {
				return r
			}
		}
		t.Fatalf("no network-first-connected event among %d", len(rows))
		return store.EventRow{}
	}
	add := func(t *testing.T, c *testCase, files map[string][]byte) {
		t.Helper()
		dir := t.TempDir()
		batch, _ := c.s.NextBatch()
		var evs []*store.Evidence
		for _, name := range []string{"SOFTWARE", "SYSTEM"} {
			b, ok := files[name]
			if !ok {
				continue
			}
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			e, err := c.in.IntakePath(batch, p)
			if err != nil {
				t.Fatal(err)
			}
			evs = append(evs, e)
		}
		c.in.Process(evs)
	}

	t.Run("with its SYSTEM hive", func(t *testing.T) {
		c := newCase(t)
		add(t, c, map[string][]byte{"SOFTWARE": swHive, "SYSTEM": sysHive})
		r := first(t, c)
		if got := time.Unix(0, r.TSUTC).UTC().Format(time.RFC3339); got != "2024-07-14T20:05:09Z" || r.TZSource != timeutil.ZoneHost || r.TZName != "Europe/London" {
			t.Errorf("%s, zone %q %q", got, r.TZSource, r.TZName)
		}
	})
	t.Run("alone", func(t *testing.T) {
		c := newCase(t)
		add(t, c, map[string][]byte{"SOFTWARE": swHive})
		r := first(t, c)
		if got := time.Unix(0, r.TSUTC).UTC().Format(time.RFC3339); got != "2024-07-14T21:05:09Z" || r.TZSource != timeutil.ZoneAssumed {
			t.Errorf("%s, zone %q %q", got, r.TZSource, r.TZName)
		}
	})
}
