package ingest

import (
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
)

// e01Files writes a disc as a three-segment E01 image. The files are named
// so that their names say nothing of their order: segments are matched by
// what is inside them.
func e01Files(t *testing.T) []string {
	t.Helper()
	iso, err := os.ReadFile(testISO(t))
	if err != nil {
		t.Fatal(err)
	}
	// Room after the disc, as a real image has, so that it fills several segments.
	iso = append(iso, make([]byte, 6*32768)...)
	dir := t.TempDir()
	var out []string
	for i, seg := range imagetest.E01(iso, imagetest.E01Options{Segments: 3, Compress: true}) {
		p := filepath.Join(dir, []string{"zulu.bin", "alpha.bin", "mike.bin"}[i])
		if err := os.WriteFile(p, seg, 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func (c *testCase) fact(key string) string {
	v, _ := c.s.LatestFact(key)
	return v
}

// A split E01 image is verified against its stored hash, browsed and
// extracted from like any other image, in this process or a worker.
func TestE01ImageVerifiedBrowsedAndExtracted(t *testing.T) {
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			files := e01Files(t)
			c.ingest(t, files...)
			first := c.byName(t, "zulu.bin")
			if first.Kind != "ewf-image" || first.Status != "parsed" || !strings.Contains(first.Notes, "verified:") || !strings.Contains(first.Notes, "3 segment file") {
				t.Fatalf("first segment: kind %s, status %s, notes %s", first.Kind, first.Status, first.Notes)
			}
			if c.fact("ewf.verified") != "yes" || c.fact("ewf.segments") != "3" || c.fact("ewf.acquisition.case_number") != "CASE-7" ||
				c.fact("ewf.computed_md5") == "" || c.fact("ewf.computed_md5") != c.fact("ewf.stored_md5") {
				t.Errorf("facts: verified %q segments %q case %q", c.fact("ewf.verified"), c.fact("ewf.segments"), c.fact("ewf.acquisition.case_number"))
			}
			if first.EventCount != 1 {
				t.Errorf("%d events from the first segment, want the acquisition", first.EventCount)
			}
			if other := c.byName(t, "mike.bin"); other.Status != "parsed" || !strings.Contains(other.Notes, "segment 3 of an E01 image") {
				t.Errorf("another segment: status %s, notes %s", other.Status, other.Notes)
			}
			describe, _, err := c.in.Browse(&first, "/")
			if err != nil || !strings.Contains(describe, "ISO 9660") || !strings.Contains(describe, "E01 image of 3 segments") {
				t.Fatalf("describe %q, %v", describe, err)
			}
			if got := listNames(t, c, &first, "/"); got != "SUB/ APP.LOG README.TXT" {
				t.Errorf("root: %s", got)
			}
			// Any segment leads to the same image.
			last := c.byName(t, "mike.bin")
			if got := listNames(t, c, &last, "/SUB"); got != "BLOB.BIN DEEP.LOG" {
				t.Errorf("sub, by the last segment: %s", got)
			}
			kids, err := c.in.Extract(&first, []string{"/APP.LOG"}, false)
			if err != nil || len(kids) != 1 {
				t.Fatalf("extract: %d children, %v", len(kids), err)
			}
			if app := c.byName(t, "APP.LOG"); app.Status != "parsed" || app.EventCount != 2 || !strings.HasSuffix(app.Origin, "zulu.bin!/APP.LOG") {
				t.Errorf("extracted file: %+v", app)
			}
			c.verifyOK(t)
		})
	}
}

// An incomplete set says what is missing, and is verified once it is whole.
func TestE01ImageIncompleteThenComplete(t *testing.T) {
	c := newCase(t)
	files := e01Files(t)
	c.ingest(t, files[0], files[1])
	first := c.byName(t, "zulu.bin")
	if first.Status != "partial" || !strings.Contains(first.Notes, "incomplete") || !strings.Contains(first.Notes, "after segment 2") {
		t.Fatalf("incomplete set: status %s, notes %s", first.Status, first.Notes)
	}
	if _, _, err := c.in.Browse(&first, "/"); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("browsing an incomplete image: %v", err)
	}
	if c.fact("ewf.verified") != "" {
		t.Error("an incomplete image was given a verification result")
	}
	// The last segment arriving is enough: the waiting image is parsed again.
	c.ingest(t, files[2])
	if first = c.byName(t, "zulu.bin"); first.Status != "parsed" || c.fact("ewf.verified") != "yes" {
		t.Errorf("after the last segment arrived: status %s, notes %s, verified %q", first.Status, first.Notes, c.fact("ewf.verified"))
	}
}

// An image that no longer has the hash it was made with is said to be so.
func TestE01ImageThatFailsVerification(t *testing.T) {
	c := newCase(t)
	iso, _ := os.ReadFile(testISO(t))
	seg := imagetest.E01(iso, imagetest.E01Options{})[0]
	// Change one byte of the stored hash: the media reads cleanly, and is not what was acquired.
	i := strings.Index(string(seg), "hash\x00")
	if i < 0 {
		t.Fatal("no hash section in the test image")
	}
	clone := append([]byte(nil), seg...)
	clone[i+76] ^= 0x01
	// Keep the section's own checksum sound, so that only the hash differs.
	fixE01Hash(clone[i+76 : i+76+36])
	p := filepath.Join(t.TempDir(), "tampered.E01")
	os.WriteFile(p, clone, 0o600)
	c.ingest(t, p)
	e := c.byName(t, "tampered.E01")
	if e.Status != "partial" || !strings.Contains(e.Notes, "NOT VERIFIED") || c.fact("ewf.verified") != "NO" {
		t.Errorf("status %s, verified %q, notes %s", e.Status, c.fact("ewf.verified"), e.Notes)
	}
}

func fixE01Hash(h []byte) {
	binary.LittleEndian.PutUint32(h[32:], adler32.Checksum(h[:32]))
}
