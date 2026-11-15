package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A differencing VHD and its parent, added under names that say nothing:
// the image is browsed through its parent, found by its identifier.
func TestDifferencingVHDInACase(t *testing.T) {
	dir := t.TempDir()
	cp := func(src, dst string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vdisk", src))
		if err != nil {
			t.Skip("virtual disk samples not present; run scripts/fetch-testdata.sh")
		}
		p := filepath.Join(dir, dst)
		os.WriteFile(p, b, 0o600)
		return p
	}
	c := newCase(t)
	c.ingest(t, cp("ntfs-differential.vhd", "child.bin"))
	child := c.byName(t, "child.bin")
	if child.Kind != "vhd-image" {
		t.Fatalf("kind %s", child.Kind)
	}
	if _, _, err := c.in.Browse(&child, "/"); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Errorf("without its parent: %v", err)
	}
	c.ingest(t, cp("ntfs-parent.vhd", "other.bin"))
	describe, entries, err := c.in.Browse(&child, "/")
	if err != nil || len(entries) == 0 || !strings.Contains(describe, "differencing VHD") {
		t.Fatalf("with its parent: %q, %d entries, %v", describe, len(entries), err)
	}
}
