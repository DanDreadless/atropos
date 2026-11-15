package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
	"github.com/DanDreadless/atropos/internal/store"
)

func testISO(t *testing.T) string {
	t.Helper()
	img := imagetest.ISO(
		map[string][]byte{
			"APP.LOG":    []byte("2024-03-01T10:00:00Z service started on the disc\n2024-03-01T10:00:05Z second line\n"),
			"README.TXT": []byte("plain notes mentioning zebrafish\n"),
		},
		map[string][]byte{
			"DEEP.LOG": []byte("2024-04-01T00:00:00Z from a folder on the disc\n"),
			"BLOB.BIN": randomBytes(9, 3000),
		},
		[]string{"APP.LOG", "README.TXT", "DEEP.LOG", "BLOB.BIN"})
	p := filepath.Join(t.TempDir(), "disc.iso")
	if err := os.WriteFile(p, img, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func listNames(t *testing.T, c *testCase, e *store.Evidence, dir string) string {
	t.Helper()
	_, entries, err := c.in.Browse(e, dir)
	if err != nil {
		t.Fatalf("browse %s: %v", dir, err)
	}
	var out []string
	for _, x := range entries {
		n := x.Name
		if x.IsDir {
			n += "/"
		}
		out = append(out, n)
	}
	return strings.Join(out, " ")
}

// An image is stored and hashed like any evidence, is not unpacked on
// arrival, and can then be browsed and have chosen files put on the
// timeline as child evidence. The same holds in a worker process.
func TestBrowseAndExtractFromAnImage(t *testing.T) {
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			iso := testISO(t)
			c.ingest(t, iso)
			img := c.byName(t, "disc.iso")
			if img.Kind != "iso-image" || img.Status != "generic" || !strings.Contains(img.Notes, "open it under Files") {
				t.Fatalf("image: kind %s, status %s, notes %s", img.Kind, img.Status, img.Notes)
			}
			if n := len(c.evidence(t)); n != 1 {
				t.Fatalf("%d evidence items after adding an image; it must not be unpacked on arrival", n)
			}
			describe, _, err := c.in.Browse(&img, "/")
			if err != nil || !strings.Contains(describe, "ISO 9660") || !strings.Contains(describe, "ATROPOS_TEST") {
				t.Fatalf("describe %q, %v", describe, err)
			}
			if got := listNames(t, c, &img, "/"); got != "SUB/ APP.LOG README.TXT" {
				t.Errorf("root: %s", got)
			}
			if got := listNames(t, c, &img, "/SUB"); got != "BLOB.BIN DEEP.LOG" {
				t.Errorf("sub: %s", got)
			}
			if _, _, err := c.in.Browse(&img, "/NOPE"); err == nil {
				t.Error("browsing a missing folder succeeded")
			}
			if _, _, err := c.in.Browse(&img, "/SUB/../.."); err == nil {
				t.Error("a path with .. was accepted")
			}

			// One file, then a whole folder.
			kids, err := c.in.Extract(&img, []string{"/APP.LOG"}, false)
			if err != nil || len(kids) != 1 {
				t.Fatalf("extract file: %d children, %v", len(kids), err)
			}
			app := c.byName(t, "APP.LOG")
			if app.ParentID == nil || *app.ParentID != img.ID || app.BatchID != img.BatchID || app.Depth != 1 ||
				!strings.HasSuffix(app.Origin, "disc.iso!/APP.LOG") || app.Status != "parsed" || app.EventCount != 2 || app.Size != 82 {
				t.Errorf("extracted file: %+v", app)
			}
			if _, err := c.in.Extract(&img, []string{"/SUB", "/README.TXT", "/MISSING.TXT"}, false); err != nil {
				t.Fatalf("extract folder: %v", err)
			}
			if deep := c.byName(t, "DEEP.LOG"); deep.Status != "parsed" || deep.EventCount != 1 || !strings.HasSuffix(deep.Origin, "!/SUB/DEEP.LOG") {
				t.Errorf("file from a folder: %+v", deep)
			}
			if n := len(c.evidence(t)); n != 5 {
				t.Errorf("%d evidence items, want the image and four files", n)
			}
			if !strings.Contains(c.in.LastExtract(), "MISSING.TXT") {
				t.Errorf("a path that was not found is not reported: %s", c.in.LastExtract())
			}
			// The same file asked for again is a duplicate, not a second copy.
			c.in.Extract(&img, []string{"/APP.LOG"}, false)
			var dups int
			for _, e := range c.evidence(t) {
				if e.Name == "APP.LOG" && e.DuplicateOf != nil {
					dups++
				}
			}
			if dups != 1 {
				t.Errorf("%d duplicates of APP.LOG, want 1", dups)
			}
			rows, _ := c.s.Search(store.Query{Text: "disc"})
			if len(rows) != 2 {
				t.Errorf("%d events from the disc on the timeline", len(rows))
			}
			if hits, _ := c.s.SearchText("zebrafish", 5); len(hits) != 2 { // the image itself, and the file copied out of it
				t.Errorf("text of an extracted file not indexed: %v", hits)
			}
			// Nothing is left in the work directory, and the image is untouched.
			if left, _ := os.ReadDir(filepath.Join(c.dir, "work")); len(left) != 0 {
				t.Errorf("%d temporary files left behind", len(left))
			}
			audit, _ := c.s.ListAudit(1000)
			n := 0
			for _, a := range audit {
				if a.Action == "image.extract" {
					n++
				}
			}
			if n != 3 {
				t.Errorf("%d extractions audited, want 3", n)
			}
			// Evidence that is not an image has nothing to browse.
			if _, _, err := c.in.Browse(&app, "/"); err == nil {
				t.Error("browsed a log file")
			}
			c.verifyOK(t)
		})
	}
}

// The standard Windows artefacts are found by path inside an NTFS volume,
// including the volume's own file table.
func TestStandardArtefactsFromAVolume(t *testing.T) {
	vol := filepath.Join("..", "..", "testdata", "test.ntfs.dd")
	if !fileExists(vol) {
		t.Skip("no sample NTFS volume; run scripts/fetch-testdata.sh")
	}
	c := newCase(t)
	c.isolate(t, "atropos-worker")
	c.ingest(t, vol)
	img := c.byName(t, "test.ntfs.dd")
	root := listNames(t, c, &img, "/")
	if !strings.Contains(root, "$MFT") || !strings.Contains(root, "$Extend/") {
		t.Fatalf("root: %s", root)
	}
	kids, err := c.in.Extract(&img, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var mft *store.Evidence
	for _, k := range kids {
		if k.Name == "$MFT" {
			mft = k
		}
	}
	if mft == nil {
		t.Fatalf("$MFT was not among the %d standard artefacts found", len(kids))
	}
	got := c.byName(t, "$MFT")
	if got.Kind != "ntfs-mft" || got.Status != "parsed" || got.EventCount == 0 || got.Size != 262144 {
		t.Errorf("extracted $MFT: %s %s %d events, %d bytes", got.Kind, got.Status, got.EventCount, got.Size)
	}
	c.verifyOK(t)
}

func TestTriagePatterns(t *testing.T) {
	pats := [][]string{}
	for _, p := range triagePatterns {
		pats = append(pats, strings.Split(strings.ToLower(p), "/"))
	}
	match := func(p string) (bool, bool) {
		segs := strings.Split(strings.ToLower(p), "/")
		full, partial := false, false
		for _, pat := range pats {
			f, pp := matchTriage(pat, segs)
			full, partial = full || f, partial || pp
		}
		return full, partial
	}
	for _, want := range []string{
		"$MFT", "$Extend/$UsnJrnl:$J", "Windows/System32/config/SYSTEM", "WINDOWS/system32/CONFIG/software",
		"Windows/System32/winevt/Logs/Security.evtx", "Windows/Prefetch/CMD.EXE-1234ABCD.pf",
		"Users/dan/NTUSER.DAT", "Users/dan/AppData/Local/Microsoft/Windows/UsrClass.dat",
		// A hive's transaction logs hold its newest changes, and are applied to it.
		"Windows/System32/config/SYSTEM.LOG1", "Windows/System32/config/SOFTWARE.LOG2", "Users/dan/ntuser.dat.LOG1",
		"Users/dan/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2", "Windows/AppCompat/Programs/Amcache.hve.LOG1",
		"Users/dan/AppData/Roaming/Microsoft/Windows/Recent/report.docx.lnk",
		"Users/dan/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/abc.automaticDestinations-ms",
		"Users/dan/AppData/Local/Google/Chrome/User Data/Default/History",
		"Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag", "$Recycle.Bin/S-1-5-21-1/$IABC123.txt",
		"Users/dan/Documents/PowerShell_transcript.WS-1.aBcD1234.20240117212000.txt",
		"ProgramData/Microsoft/Windows Defender/Support/MPLog-20240101-120000.log",
		"ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/05/8CC4BE3D-8D3F-4952-9953-F24EB6638A37",
	} {
		if full, _ := match(want); !full {
			t.Errorf("%s is not matched", want)
		}
	}
	for _, not := range []string{
		"Windows/System32/config/SYSTEM.sav", "Windows/System32/cmd.exe", "Users/dan/Documents/NTUSER.DAT",
		"Users/dan/Desktop/x.lnk", "Users/dan/Documents/notes.txt", "$Recycle.Bin/S-1-5-21-1/$RABC123.txt", "Program Files/x/History", "$MFTMirr",
	} {
		if full, _ := match(not); full {
			t.Errorf("%s is matched and should not be", not)
		}
	}
	// Directories on the way to an artefact are walked; others are not.
	for dir, want := range map[string]bool{"Windows": true, "Windows/System32": true, "Users/dan/AppData": true,
		"Program Files": false, "Windows/WinSxS": false, "Users/dan/Pictures": false, "Users/dan/Documents": true, "Users/dan/Documents/Work": false} {
		if _, partial := match(dir); partial != want {
			t.Errorf("walking into %s: %v, want %v", dir, partial, want)
		}
	}
}

// A USB stick imaged as a disk: its FAT volume's entries go on the timeline
// when it is added, deleted ones included, and its files can be browsed and
// copied out. The same in a worker process.
func TestFATImageOnTheTimeline(t *testing.T) {
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			p := filepath.Join(t.TempDir(), "stick.dd")
			if err := os.WriteFile(p, imagetest.MBR(imagetest.FAT16(), 0x0E), 0o600); err != nil {
				t.Fatal(err)
			}
			c.ingest(t, p)
			img := c.byName(t, "stick.dd")
			if img.Kind != "disk-image" || img.Status != "parsed" || img.EventCount != 10 || img.Parser != "disk-image" {
				t.Fatalf("image: kind %s, status %s, %d events, parser %s, notes %s", img.Kind, img.Status, img.EventCount, img.Parser, img.Notes)
			}
			if rows, _ := c.s.Search(store.Query{Text: "secret plan.txt"}); len(rows) != 3 {
				t.Errorf("%d events for the deleted file", len(rows))
			}
			// As the user guide says to search for them.
			if rows, _ := c.s.Search(store.Query{Text: "source:fat deleted"}); len(rows) != 3 {
				t.Errorf("source:fat deleted finds %d events", len(rows))
			}
			if got := listNames(t, c, &img, "/p1"); got != "DCIM/ Report final.docx" {
				t.Errorf("p1: %s", got)
			}
			if _, err := c.in.Extract(&img, []string{"/p1/DCIM/img_0001.jpg"}, false); err != nil {
				t.Fatal(err)
			}
			if j := c.byName(t, "img_0001.jpg"); j.Size != 12 || !strings.HasSuffix(j.Origin, "stick.dd!/p1/DCIM/img_0001.jpg") {
				t.Errorf("copied out: %+v", j)
			}
			c.verifyOK(t)
		})
	}
}

// A Linux volume imaged on its own: names and inode times on the timeline
// when it is added, and its files browsable, in a worker as in process.
func TestExtImageOnTheTimeline(t *testing.T) {
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			p := filepath.Join(t.TempDir(), "linux.img")
			if err := os.WriteFile(p, imagetest.Ext4(), 0o600); err != nil {
				t.Fatal(err)
			}
			c.ingest(t, p)
			img := c.byName(t, "linux.img")
			if img.Kind != "ext-volume-image" || img.Status != "parsed" || img.Parser != "disk-image" || img.EventCount == 0 {
				t.Fatalf("image: kind %s, status %s, %d events, parser %s, notes %s", img.Kind, img.Status, img.EventCount, img.Parser, img.Notes)
			}
			if rows, _ := c.s.Search(store.Query{Text: "category:deletion source:ext"}); len(rows) != 1 {
				t.Errorf("%d deletion events", len(rows))
			}
			if got := listNames(t, c, &img, "/"); got != "docs/ big.bin link tree.dat" {
				t.Errorf("root: %s", got)
			}
			if _, err := c.in.Extract(&img, []string{"/docs/report.txt"}, false); err != nil {
				t.Fatal(err)
			}
			if r := c.byName(t, "report.txt"); r.Size != 5000 {
				t.Errorf("copied out: %+v", r)
			}
			c.verifyOK(t)
		})
	}
}

// A file is copied out of a shadow copy like any other, and its origin
// says which copy it came from.
func TestExtractFromAShadowCopy(t *testing.T) {
	sample := filepath.Join("..", "..", "testdata", "vss", "vss.raw")
	if _, err := os.Stat(sample); err != nil {
		t.Skip("no sample volume with shadow copies")
	}
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			c.ingest(t, sample)
			img := c.byName(t, "vss.raw")
			if got := listNames(t, c, &img, "/<shadow copy 1>"); strings.Contains(got, "vss1") || !strings.Contains(got, "passwords.txt") {
				t.Errorf("copy 1: %s", got)
			}
			if _, err := c.in.Extract(&img, []string{"/<shadow copy 2>/vss1"}, false); err != nil {
				t.Fatal(err)
			}
			v := c.byName(t, "vss1")
			if v.Size != 7 || !strings.HasSuffix(v.Origin, "vss.raw!/<shadow copy 2>/vss1") {
				t.Errorf("copied out: %+v", v)
			}
			c.verifyOK(t)
		})
	}
}
