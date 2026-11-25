package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/store"
)

// The same file collected from two hosts links them, with no time; a file
// collected from one host does not.
func TestCollectedFileLinksHosts(t *testing.T) {
	dir := t.TempDir()
	tool := append([]byte("MZ"), []byte(strings.Repeat("tool ", 200))...)
	files := map[string][]byte{
		"WS-A/svcupd.exe":    tool,
		"WS-A/only-here.ps1": []byte("Write-Output 'only on WS-A'\r\n"),
		"SRV-B/pd64.exe":     tool,
	}
	for p, b := range files {
		p = filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := newCase(t)
	add := func(host string) {
		t.Helper()
		hst, err := c.s.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
		batch, _ := c.s.NextBatch()
		if err := c.s.AssignBatch(batch, &hst.ID, ""); err != nil {
			t.Fatal(err)
		}
		paths, _ := filepath.Glob(filepath.Join(dir, host, "*"))
		var evs []*store.Evidence
		for _, f := range paths {
			e, err := c.in.IntakePath(batch, f)
			if err != nil {
				t.Fatal(err)
			}
			evs = append(evs, e)
		}
		c.in.Process(evs)
	}
	add("WS-A")
	add("SRV-B")
	rep, err := analysis.Connections(c.s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Connections) != 1 {
		t.Fatalf("%d connections: %+v", len(rep.Connections), rep.Connections)
	}
	cn := rep.Connections[0]
	r := strings.Join(cn.Reasons, " | ")
	if cn.Kind != "file" || !cn.Undated || cn.Start != 0 || cn.NoTime != "the file was collected from both, and that gives no time" ||
		!strings.Contains(r, "svcupd.exe)") || !strings.Contains(r, "pd64.exe)") || !strings.Contains(r, "renamed") {
		t.Errorf("%s -> %s %+v: %s", cn.From, cn.To, cn, r)
	}
	if len(rep.Edges) != 1 || rep.Edges[0].First != 0 {
		t.Errorf("edges: %+v", rep.Edges)
	}
}
