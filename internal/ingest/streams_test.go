package ingest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/store"
)

// A file taken in from an NTFS volume brings its alternate data streams with
// it, each sealed as an item of its own under the file, and the mark of the
// web among them is read.
func TestStreamsOfAFileAreTakenIn(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("alternate data streams can only be read through Windows")
	}
	c := newCase(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "tool one.bin")
	if err := os.WriteFile(p, []byte("the file's own content, which is not a known format"), 0o600); err != nil {
		t.Fatal(err)
	}
	zone := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://files.test/landing\r\nHostUrl=https://cdn.test/tool.bin\r\n"
	if err := os.WriteFile(p+":Zone.Identifier", []byte(zone), 0o600); err != nil {
		t.Skipf("this volume does not hold streams: %v", err)
	}
	if err := os.WriteFile(p+":second", []byte("another stream"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain.txt")
	os.WriteFile(plain, []byte("nothing attached"), 0o600)

	batch, _ := c.s.NextBatch()
	var top []*store.Evidence
	for _, f := range []string{p, plain} {
		e, err := c.in.IntakePath(batch, f)
		if err != nil {
			t.Fatal(err)
		}
		top = append(top, e)
		streams, errs := c.in.IntakeStreams(batch, f, e)
		if len(errs) != 0 {
			t.Fatalf("%s: %v", f, errs)
		}
		top = append(top, streams...)
	}
	c.in.Process(top)

	if n := len(c.evidence(t)); n != 4 {
		t.Fatalf("%d items in the case, want the two files and two streams", n)
	}
	parent := c.byName(t, "tool one.bin")
	z := c.byName(t, "tool one.bin:Zone.Identifier")
	if z.ParentID == nil || *z.ParentID != parent.ID || z.Size != int64(len(zone)) || !strings.HasSuffix(z.Origin, `tool one.bin:Zone.Identifier`) {
		t.Errorf("zone stream: %+v", z)
	}
	if z.Status != "parsed" || !strings.Contains(z.Notes, "marked as from zone 3 (internet): https://cdn.test/tool.bin") {
		t.Errorf("zone stream: %s, %q", z.Status, z.Notes)
	}
	facts, _ := c.s.Facts("zone.host_url")
	if len(facts) != 1 || facts[0].Value != "https://cdn.test/tool.bin" {
		t.Errorf("host url fact: %+v", facts)
	}
	if s := c.byName(t, "tool one.bin:second"); s.Size != 14 || s.ParentID == nil {
		t.Errorf("second stream: %+v", s)
	}
	// The source keeps its streams: reading them changed nothing.
	if b, err := os.ReadFile(p + ":Zone.Identifier"); err != nil || string(b) != zone {
		t.Errorf("the source stream changed: %v", err)
	}
}
