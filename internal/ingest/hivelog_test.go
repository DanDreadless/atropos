package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copySample puts a public test hive or log in a temporary folder under a
// name that says nothing: logs are matched by content.
func copySample(t *testing.T, dir, name string, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata", "hivelog"}, rel...)...))
	if err != nil {
		t.Skip("registry log samples not present; run scripts/fetch-testdata.sh")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A dirty hive is read with its transaction logs applied, in this process
// or a worker; the logs record what they are.
func TestHiveWithItsLogs(t *testing.T) {
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			dir := t.TempDir()
			hive := copySample(t, dir, "one.bin", "regipy", "UsrClass.dat")
			l1 := copySample(t, dir, "two.bin", "regipy", "UsrClass.dat.LOG1")
			l2 := copySample(t, dir, "three.bin", "regipy", "UsrClass.dat.LOG2")
			stranger := copySample(t, dir, "four.bin", "regipy", "SYSTEM_B.LOG1")
			c.ingest(t, l2, hive, stranger, l1)
			h := c.byName(t, "one.bin")
			if h.Kind != "windows-registry-hive" || h.Status != "parsed" || !strings.Contains(h.Notes, "transaction logs were applied") ||
				!strings.Contains(h.Notes, "sequence 287 to 290") || !strings.Contains(h.Notes, "sequence 291 to 300") {
				t.Fatalf("hive: kind %s status %s notes %s", h.Kind, h.Status, h.Notes)
			}
			for _, n := range []string{"two.bin", "three.bin", "four.bin"} {
				l := c.byName(t, n)
				if l.Kind != "windows-registry-log" || l.Status != "parsed" || l.EventCount != 0 || !strings.Contains(l.Notes, "transaction log of the hive") {
					t.Errorf("%s: kind %s status %s events %d notes %s", n, l.Kind, l.Status, l.EventCount, l.Notes)
				}
			}
			if got := c.fact("registry.transaction_logs_applied"); !strings.Contains(got, c.byName(t, "two.bin").SHA256) || !strings.Contains(got, c.byName(t, "three.bin").SHA256) || strings.Contains(got, c.byName(t, "four.bin").SHA256) {
				t.Errorf("logs applied: %s", got)
			}
			c.verifyOK(t)
		})
	}
}

// A dirty hive alone says what is missing; when its logs are added later
// it is parsed again with them, and gains what they held.
func TestHiveThenItsLogs(t *testing.T) {
	c := newCase(t)
	dir := t.TempDir()
	hive := copySample(t, dir, "hive.bin", "regipy", "transactions_NTUSER.DAT")
	c.ingest(t, hive)
	h := c.byName(t, "hive.bin")
	if h.Status != "partial" || !strings.Contains(h.Notes, "not fully written") || !strings.Contains(h.Notes, "not in the case") {
		t.Fatalf("hive alone: status %s notes %s", h.Status, h.Notes)
	}
	before := h.EventCount
	c.ingest(t, copySample(t, dir, "a.bin", "regipy", "transactions_ntuser.dat.log1"), copySample(t, dir, "b.bin", "regipy", "transactions_ntuser.dat.log2"))
	h = c.byName(t, "hive.bin")
	if h.Status != "parsed" || !strings.Contains(h.Notes, "sequence 566 to 588") || !strings.Contains(h.Notes, "older than the hive") {
		t.Fatalf("after the logs: status %s notes %s", h.Status, h.Notes)
	}
	if h.EventCount <= before {
		t.Errorf("the recovered hive gave %d events, no more than the %d of the hive alone", h.EventCount, before)
	}
	// The first run is kept beside the new one.
	runs := 0
	c.s.RawWriter().QueryRow(`SELECT count(*) FROM runs WHERE evidence_id = ?`, h.ID).Scan(&runs)
	if runs != 2 {
		t.Errorf("%d runs of the hive, want 2", runs)
	}
	c.verifyOK(t)
}
