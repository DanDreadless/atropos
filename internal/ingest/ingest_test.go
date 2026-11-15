package ingest

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
	"github.com/DanDreadless/atropos/internal/vault"
)

type testCase struct {
	dir string
	s   *store.Store
	in  *Ingester
}

func newCase(t *testing.T) *testCase {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "case one") // a space, as real paths have
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "case.db"), "tester")
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		// Vault files are read-only; make them removable so the temp dir can go.
		filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error { os.Chmod(p, 0o700); return nil })
	})
	return &testCase{dir: dir, s: s, in: &Ingester{S: s, V: v}}
}

// ingest submits the files as one batch and processes it.
func (c *testCase) ingest(t *testing.T, paths ...string) int64 {
	t.Helper()
	batch, err := c.s.NextBatch()
	if err != nil {
		t.Fatal(err)
	}
	var top []*store.Evidence
	for _, p := range paths {
		e, err := c.in.IntakePath(batch, p)
		if err != nil {
			t.Fatalf("intake %s: %v", p, err)
		}
		top = append(top, e)
	}
	c.in.Process(top)
	return batch
}

func (c *testCase) evidence(t *testing.T) []store.Evidence {
	t.Helper()
	list, err := c.s.ListEvidence()
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func (c *testCase) byName(t *testing.T, name string) store.Evidence {
	t.Helper()
	for _, e := range c.evidence(t) {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no evidence named %s", name)
	return store.Evidence{}
}

func (c *testCase) verifyOK(t *testing.T) Report {
	t.Helper()
	rep, err := c.in.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("verify failed on an untouched case: %+v", rep)
	}
	return rep
}

func zipOf(t *testing.T, files map[string][]byte, order ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, name := range order {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(files[name])
	}
	zw.Close()
	return b.Bytes()
}

func gzipOf(name string, data []byte) []byte {
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	gw.Name = name
	gw.Write(data)
	gw.Close()
	return b.Bytes()
}

func tarOf(files map[string][]byte, order ...string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, name := range order {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(files[name])), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
		tw.Write(files[name])
	}
	tw.Close()
	return b.Bytes()
}

func randomBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// corpus writes a mixed set of inputs: every awkward thing an examiner might
// drop in. It is deterministic, so two calls produce identical content.
func corpus(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "submitted")
	os.MkdirAll(filepath.Join(dir, "sub"), 0o700)
	iso := []byte("2024-03-01T10:00:00Z service started\n2024-03-01T10:00:05+01:00 second line\n")
	files := map[string][]byte{
		"app.log":       iso,
		"local.log":     []byte("2024-07-15 12:00:00 local time entry\n2024-07-15 12:00:01 another\n"),
		"events.jsonl":  []byte(`{"timestamp":"2024-03-01T10:00:00Z","msg":"a"}` + "\n" + `{"timestamp":"2024-03-01T10:00:01Z","msg":"b"}` + "\n"),
		"notes.txt":     []byte("these are free-form notes mentioning mimikatz and nothing with a timestamp\n"),
		"ambiguous.log": []byte("01/02/2024 10:00:00 logon\n03/04/2024 11:00:00 logoff\n"),
		"empty.bin":     {},
		"random.bin":    randomBytes(1, 20000),
		"corrupt.evtx":  append([]byte("ElfFile\x00"), randomBytes(2, 9000)...),
		"corrupt.dat":   append([]byte("regf"), randomBytes(3, 9000)...),
		"corrupt.pf":    append([]byte("\x11\x00\x00\x00SCCA"), randomBytes(4, 9000)...),
		"corrupt.zip":   append([]byte("PK\x03\x04"), randomBytes(5, 500)...),
		"corrupt.gz":    append([]byte{0x1f, 0x8b, 0x08}, randomBytes(6, 500)...),
		"copy-of-app":   iso, // identical content under another name
	}
	inner := zipOf(t, map[string][]byte{"deep/inner.log": []byte("2024-05-05T05:05:05Z from the innermost archive\n"), "deep/empty": {}}, "deep/inner.log", "deep/empty")
	files["bundle.zip"] = zipOf(t, map[string][]byte{
		"logs/a.log":   []byte("2024-04-01T00:00:00Z inside the zip\n"),
		"logs/b.gz":    gzipOf("b.log", []byte("2024-04-02T00:00:00Z inside a gzip inside the zip\n")),
		"nested.zip":   inner,
		"unknown.blob": randomBytes(7, 3000),
	}, "logs/a.log", "logs/b.gz", "nested.zip", "unknown.blob")
	files["sub/archive.tar"] = tarOf(map[string][]byte{"var/log/x.log": []byte("2024-06-01T00:00:00Z inside the tar\n")}, "var/log/x.log")
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func corpusPaths(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// Rule: throw anything at it. Every submitted file, and every member of every
// container, ends as an evidence row with a sealed outcome. Nothing is
// skipped, nothing is left queued, and failures are visible.
func TestNothingIsRejectedOrDropped(t *testing.T) {
	c := newCase(t)
	dir := corpus(t)
	paths := corpusPaths(t, dir)
	c.ingest(t, paths...)

	list := c.evidence(t)
	names := map[string]store.Evidence{}
	for _, e := range list {
		names[e.Name] = e
		switch e.Status {
		case "parsed", "generic", "partial", "no-content", "failed", "unpacked", "duplicate":
		default:
			t.Errorf("%s: left in status %q", e.Origin, e.Status)
		}
		if len(e.SHA256) != 64 || len(e.SHA1) != 40 || len(e.MD5) != 32 {
			t.Errorf("%s: hashes missing", e.Origin)
		}
		if e.Kind == "" || e.DetectReason == "" {
			t.Errorf("%s: not identified", e.Origin)
		}
	}
	for _, p := range paths {
		if _, ok := names[filepath.Base(p)]; !ok {
			t.Errorf("submitted file %s has no evidence row", p)
		}
	}
	// Container members, to the bottom of the nesting.
	for _, member := range []string{"a.log", "b.gz", "b.log", "nested.zip", "inner.log", "unknown.blob", "x.log", "empty"} {
		if _, ok := names[member]; !ok {
			t.Errorf("container member %s was not registered", member)
		}
	}
	want := map[string]struct {
		status string
		events int64
	}{
		"app.log": {"parsed", 2}, "events.jsonl": {"parsed", 2}, "local.log": {"parsed", 2},
		"notes.txt": {"generic", 0}, "ambiguous.log": {"generic", 0}, "empty.bin": {"generic", 0}, "random.bin": {"generic", 0},
		"bundle.zip": {"unpacked", 0}, "archive.tar": {"unpacked", 0}, "nested.zip": {"unpacked", 0}, "b.gz": {"unpacked", 0},
		"a.log": {"parsed", 1}, "b.log": {"parsed", 1}, "inner.log": {"parsed", 1}, "x.log": {"parsed", 1},
		"copy-of-app": {"duplicate", 0},
	}
	for name, w := range want {
		e := names[name]
		if e.Status != w.status || e.EventCount != w.events {
			t.Errorf("%s: %s with %d events (%s), want %s with %d", name, e.Status, e.EventCount, e.Notes, w.status, w.events)
		}
	}
	// Damaged files: visible status and a note saying what went wrong.
	for _, name := range []string{"corrupt.evtx", "corrupt.dat", "corrupt.pf", "corrupt.zip", "corrupt.gz"} {
		e := names[name]
		if e.Notes == "" {
			t.Errorf("%s: status %q with no note explaining it", name, e.Status)
		}
		if e.Status == "parsed" {
			t.Errorf("%s: reported as cleanly parsed", name)
		}
	}
	if e := names["inner.log"]; e.Depth != 2 || !strings.HasSuffix(e.Origin, "bundle.zip!/nested.zip!/deep/inner.log") || e.ParentID == nil {
		t.Errorf("nested member provenance: depth=%d origin=%q parent=%v", e.Depth, e.Origin, e.ParentID)
	}
	if e := names["copy-of-app"]; e.DuplicateOf == nil || *e.DuplicateOf != names["app.log"].ID {
		t.Errorf("duplicate not linked to the first copy: %v", e.DuplicateOf)
	}
	// Files with no dedicated parser are still findable by their text.
	hits, err := c.s.SearchText("mimikatz", 10)
	if err != nil || len(hits) != 1 || hits[0].Name != "notes.txt" {
		t.Errorf("text search: %v %v", hits, err)
	}
	if hits, _ := c.s.SearchText("logoff", 10); len(hits) != 1 {
		t.Errorf("unparsed log is not text-searchable: %v", hits)
	}
	rows, _ := c.s.Search(store.Query{Text: "innermost"})
	if len(rows) != 1 {
		t.Errorf("event from the innermost archive not on the timeline")
	}
	c.verifyOK(t)
}

// Rule: every event traces back to its evidence, run, parser version and a
// location inside the source file.
func TestEveryEventTracesBack(t *testing.T) {
	c := newCase(t)
	c.ingest(t, corpusPaths(t, corpus(t))...)
	n := 0
	err := c.s.Stream(store.Query{}, func(e store.EventRow) error {
		n++
		if e.EvidenceID == 0 || e.RunID == 0 || e.RecordRef == "" || e.TSRaw == "" || e.TZSource == "" || e.TZName == "" {
			t.Errorf("event %d lacks provenance: %+v", e.ID, e)
		}
		ev, err := c.s.GetEvidence(e.EvidenceID)
		if err != nil || ev.Parser == "" || ev.SHA256 == "" {
			t.Errorf("event %d: evidence %d not resolvable (%v)", e.ID, e.EvidenceID, err)
		}
		return nil
	})
	if err != nil || n == 0 {
		t.Fatalf("stream: n=%d err=%v", n, err)
	}
	var missing int
	c.s.RawWriter().QueryRow(`SELECT count(*) FROM runs WHERE parser_version = '' OR tool_version = ''`).Scan(&missing)
	if missing != 0 {
		t.Errorf("%d runs record no parser or tool version", missing)
	}
}

func (c *testCase) signature(t *testing.T) []string {
	t.Helper()
	rows, err := c.s.RawWriter().Query(`SELECT e.sha256, r.parser, rr.status, rr.event_count, rr.event_digest, rr.notes
		FROM runs r JOIN run_results rr ON rr.run_id = r.id JOIN evidence e ON e.id = r.evidence_id ORDER BY r.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sha, parser, status, digest, notes string
		var n int64
		rows.Scan(&sha, &parser, &status, &n, &digest, &notes)
		out = append(out, fmt.Sprintf("%s %s %s %d %s %s", sha[:12], parser, status, n, digest, notes))
	}
	return out
}

// Rule: stay deterministic. The same input into two fresh cases gives the
// same runs with the same event digests.
func TestSameInputGivesSameDigests(t *testing.T) {
	inputs := corpusPaths(t, corpus(t))
	for _, rel := range []string{"Security.evtx", "NTUSER.DAT", "test.ntfs.dd", filepath.Join("prefetch", "Win10", "CALC.EXE-3FBEF7FD.pf")} {
		if p := filepath.Join("..", "..", "testdata", rel); fileExists(p) {
			inputs = append(inputs, p)
		}
	}
	a, b := newCase(t), newCase(t)
	a.ingest(t, inputs...)
	time.Sleep(20 * time.Millisecond)
	b.ingest(t, inputs...)
	sa, sb := a.signature(t), b.signature(t)
	if len(sa) == 0 || len(sa) != len(sb) {
		t.Fatalf("run counts differ: %d and %d", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Errorf("run %d differs:\n  %s\n  %s", i+1, sa[i], sb[i])
		}
	}
	// A third ingest of the same files into the first case is a new batch of
	// duplicates; it adds no events and leaves earlier digests valid.
	before, _ := a.s.Summarise(store.Query{}, 1)
	a.ingest(t, inputs...)
	after, _ := a.s.Summarise(store.Query{}, 1)
	if before.Count != after.Count {
		t.Errorf("re-submitting identical files changed the timeline from %d to %d events", before.Count, after.Count)
	}
	a.verifyOK(t)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Rule: never write to evidence. The submitted originals are byte-identical
// and keep their modification times; the vault copy matches and is read-only.
func TestOriginalsAreUntouchedAndVaultIsReadOnly(t *testing.T) {
	c := newCase(t)
	dir := corpus(t)
	paths := corpusPaths(t, dir)
	type state struct {
		sha string
		mod time.Time
	}
	before := map[string]state{}
	for _, p := range paths {
		info, _ := os.Stat(p)
		before[p] = state{fileSHA(t, p), info.ModTime()}
	}
	c.ingest(t, paths...)
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if fileSHA(t, p) != before[p].sha || !info.ModTime().Equal(before[p].mod) {
			t.Errorf("%s was altered by ingestion", p)
		}
	}
	for _, e := range c.evidence(t) {
		vp := c.in.V.Path(e.SHA256)
		if fileSHA(t, vp) != e.SHA256 {
			t.Errorf("vault copy of %s does not match its recorded hash", e.Name)
		}
		if f, err := os.OpenFile(vp, os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Errorf("vault copy of %s can be opened for writing", e.Name)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(c.dir, "work")); len(left) != 0 {
		t.Errorf("%d temporary intake files left behind", len(left))
	}
}

// Rule: tampering with a vault file is caught by verify.
func TestVerifyDetectsVaultTampering(t *testing.T) {
	for name, tamper := range map[string]func(string){
		"one byte changed": func(p string) {
			b, _ := os.ReadFile(p)
			b[0] ^= 0xFF
			os.WriteFile(p, b, 0o600)
		},
		"byte appended": func(p string) {
			f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			f.Write([]byte{0})
			f.Close()
		},
		"file removed": func(p string) { os.Remove(p) },
	} {
		t.Run(name, func(t *testing.T) {
			c := newCase(t)
			c.ingest(t, corpusPaths(t, corpus(t))...)
			c.verifyOK(t)
			e := c.byName(t, "app.log")
			vp := c.in.V.Path(e.SHA256)
			if err := os.Chmod(vp, 0o600); err != nil {
				t.Fatal(err)
			}
			tamper(vp)
			rep, err := c.in.Verify()
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK || len(rep.EvidenceBad) != 1 || !strings.Contains(rep.EvidenceBad[0], e.SHA256) {
				t.Errorf("tampering not reported: %+v", rep)
			}
			if len(rep.RunsBad) != 0 || rep.AuditBrokenAt != 0 {
				t.Errorf("unrelated checks failed: %+v", rep)
			}
		})
	}
}

// Rule: tampering with the database is caught by verify even after the
// triggers that normally prevent it have been removed.
func TestVerifyDetectsDatabaseTampering(t *testing.T) {
	for name, stmt := range map[string]string{
		"event edited":    `UPDATE events SET message = 'benign' WHERE id = (SELECT min(id) FROM events)`,
		"event removed":   `DELETE FROM events WHERE id = (SELECT max(id) FROM events)`,
		"audit edited":    `UPDATE audit SET details = '{}' WHERE id = 3`,
		"audit removed":   `DELETE FROM audit WHERE id = 3`,
		"digest replaced": `UPDATE run_results SET event_digest = 'feed' WHERE event_count > 0`,
		// The next two leave every remaining run consistent with its own
		// result row. Only the audit log's record of the seal exposes them.
		"run emptied and resealed": `UPDATE run_results SET event_count = 0, event_digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
				WHERE run_id = (SELECT max(run_id) FROM events);
			DELETE FROM events WHERE run_id = (SELECT max(run_id) FROM events)`,
		"whole run removed": `DELETE FROM events WHERE run_id = (SELECT max(run_id) FROM events);
			DELETE FROM run_results WHERE run_id = (SELECT max(run_id) FROM run_results WHERE event_count > 0)`,
		"result row planted": `INSERT INTO runs(evidence_id,parser,parser_version,tool_version,started_utc,zone_context) VALUES (1,'text-log','1','0.1.0',0,'');
			INSERT INTO run_results(run_id,status,event_count,event_digest,notes,finished_utc)
				SELECT max(id),'parsed',0,'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','',0 FROM runs`,
	} {
		t.Run(name, func(t *testing.T) {
			c := newCase(t)
			c.ingest(t, corpusPaths(t, corpus(t))...)
			c.verifyOK(t)
			w := c.s.RawWriter()
			// Appending is always allowed, so a planted row needs no triggers removed.
			if _, err := w.Exec(stmt); err == nil && !strings.HasPrefix(stmt, "INSERT") {
				t.Fatal("the database accepted the change with its triggers in place")
			}
			for _, table := range []string{"events", "audit", "run_results"} {
				w.Exec(`DROP TRIGGER ` + table + `_no_update`)
				w.Exec(`DROP TRIGGER ` + table + `_no_delete`)
			}
			if _, err := w.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			rep, err := c.in.Verify()
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Errorf("tampering not reported: %+v", rep)
			}
		})
	}
}

// Everything done to a case is in the audit log, and the log verifies.
func TestActionsAreAudited(t *testing.T) {
	c := newCase(t)
	c.ingest(t, corpusPaths(t, corpus(t))...)
	c.verifyOK(t)
	rows, err := c.s.ListAudit(10000)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, r := range rows {
		count[r.Action]++
		if r.Actor != "tester" {
			t.Errorf("audit %d: actor %q", r.ID, r.Actor)
		}
	}
	n := len(c.evidence(t))
	if count["evidence.intake"] != n {
		t.Errorf("%d intake entries for %d evidence items", count["evidence.intake"], n)
	}
	if count["case.create"] != 1 || count["case.verify"] != 1 || count["container.unpack"] < 4 || count["parse.complete"] == 0 {
		t.Errorf("audit actions: %v", count)
	}
	var runs int
	c.s.RawWriter().QueryRow(`SELECT count(*) FROM runs`).Scan(&runs)
	if count["parse.complete"]+count["container.unpack"] != runs {
		t.Errorf("%d runs but %d audited", runs, count["parse.complete"]+count["container.unpack"])
	}
}

// Zone provenance: the host's own registry beats the examiner's statement,
// which beats an assumption, and a fact never leaks from one batch to another.
func TestZoneProvenanceAndBatchIsolation(t *testing.T) {
	dir := t.TempDir()
	logPath := func(name string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("2024-07-15 12:00:00 "+name+" local entry\n"), 0o600)
		return p
	}
	hivePath := filepath.Join(dir, "SYSTEM")
	os.WriteFile(hivePath, []byte("stand-in for a SYSTEM hive"), 0o600)

	first := func(c *testCase, text string) store.EventRow {
		t.Helper()
		rows, err := c.s.Search(store.Query{Text: text})
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: %d events (%v)", text, len(rows), err)
		}
		return rows[0]
	}
	at := func(e store.EventRow) string { return time.Unix(0, e.TSUTC).UTC().Format(time.RFC3339) }

	c := newCase(t)
	// Batch 1: nothing establishes a zone. UTC is assumed and flagged.
	c.ingest(t, logPath("one.log"))
	if e := first(c, "one.log"); e.TZSource != "assumed" || at(e) != "2024-07-15T12:00:00Z" {
		t.Errorf("no zone known: %s %s", e.TZSource, at(e))
	}

	// Batch 2: the batch's own hive names the zone.
	batch, _ := c.s.NextBatch()
	hive, err := c.in.IntakePath(batch, hivePath)
	if err != nil {
		t.Fatal(err)
	}
	c.s.AddFact(hive.ID, "host.timezone", "America/New_York", "test")
	c.s.AddFact(hive.ID, "host.name", "NYC-PC", "test")
	two, _ := c.in.IntakePath(batch, logPath("two.log"))
	c.in.Process([]*store.Evidence{two})
	if e := first(c, "two.log"); e.TZSource != "host-registry" || e.TZName != "America/New_York" || at(e) != "2024-07-15T16:00:00Z" || e.Host != "NYC-PC" {
		t.Errorf("host zone: %s %s %s host=%q", e.TZSource, e.TZName, at(e), e.Host)
	}
	if ev := c.byName(t, "two.log"); ev.ZoneCtx != "host-registry: America/New_York" {
		t.Errorf("run zone context = %q", ev.ZoneCtx)
	}

	// Batch 3: a different submission must not inherit batch 2's host or zone.
	c.ingest(t, logPath("three.log"))
	if e := first(c, "three.log"); e.TZSource != "assumed" || e.Host != "" {
		t.Errorf("batch 2 facts leaked into batch 3: %s host=%q", e.TZSource, e.Host)
	}

	// Batch 4: the examiner states a zone. It applies, and says who decided.
	loc, _ := time.LoadLocation("Europe/London")
	c.in.ExaminerZone, c.in.ExaminerZoneName = loc, "Europe/London"
	c.ingest(t, logPath("four.log"))
	if e := first(c, "four.log"); e.TZSource != "examiner-set" || e.TZName != "Europe/London" || at(e) != "2024-07-15T11:00:00Z" {
		t.Errorf("examiner zone: %s %s %s", e.TZSource, e.TZName, at(e))
	}

	// Batch 5: evidence outranks the examiner's statement.
	batch, _ = c.s.NextBatch()
	hive2, _ := c.in.IntakePath(batch, hivePath)
	c.s.AddFact(hive2.ID, "host.timezone", "Asia/Tokyo", "test")
	five, _ := c.in.IntakePath(batch, logPath("five.log"))
	c.in.Process([]*store.Evidence{five})
	if e := first(c, "five.log"); e.TZSource != "host-registry" || at(e) != "2024-07-15T03:00:00Z" {
		t.Errorf("host zone should outrank the examiner's: %s %s", e.TZSource, at(e))
	}

	// Batch 6: two hosts with different zones in one batch. Neither is
	// picked; the examiner's statement applies and the conflict is recorded.
	batch, _ = c.s.NextBatch()
	six, _ := c.in.IntakePath(batch, logPath("six.log"))
	c.s.AddFact(six.ID, "host.timezone", "Asia/Tokyo", "test")
	c.s.AddFact(six.ID, "host.timezone", "America/New_York", "test")
	c.in.Process([]*store.Evidence{six})
	if e := first(c, "six.log"); e.TZSource != "examiner-set" {
		t.Errorf("conflicting host zones: %s", e.TZSource)
	}
	if ev := c.byName(t, "six.log"); !strings.Contains(ev.ZoneCtx, "several host zones") {
		t.Errorf("conflict not recorded: %q", ev.ZoneCtx)
	}

	// Explicit offsets and UTC-by-definition values are never re-interpreted.
	p := filepath.Join(dir, "explicit.log")
	os.WriteFile(p, []byte("2024-07-15T12:00:00+09:00 explicit entry\n"), 0o600)
	c.ingest(t, p)
	if e := first(c, "explicit"); e.TZSource != "explicit-offset" || at(e) != "2024-07-15T03:00:00Z" {
		t.Errorf("explicit offset: %s %s", e.TZSource, at(e))
	}
	facets, _ := c.s.Facets()
	if facets["tz_source"]["assumed"] != 2 {
		t.Errorf("facets = %v", facets["tz_source"])
	}
	c.verifyOK(t)
}

// A local time that falls in a daylight-saving change is stored with a
// caveat the examiner can see and search for.
func TestDaylightSavingCaveatReachesTheEvent(t *testing.T) {
	c := newCase(t)
	loc, _ := time.LoadLocation("Europe/London")
	c.in.ExaminerZone, c.in.ExaminerZoneName = loc, "Europe/London"
	p := filepath.Join(t.TempDir(), "dst.log")
	os.WriteFile(p, []byte("2024-10-27 01:30:00 in the repeated hour\n2024-10-27 03:00:00 after it\n"), 0o600)
	c.ingest(t, p)
	rows, _ := c.s.Search(store.Query{})
	if len(rows) != 2 {
		t.Fatalf("%d events", len(rows))
	}
	e, _ := c.s.GetEvent(rows[0].ID)
	if !strings.Contains(string(e.Fields), "_time_caveat") || !strings.Contains(string(e.Fields), "occurs twice") {
		t.Errorf("no caveat stored: %s", e.Fields)
	}
	e, _ = c.s.GetEvent(rows[1].ID)
	if strings.Contains(string(e.Fields), "_time_caveat") {
		t.Errorf("caveat on an unambiguous time: %s", e.Fields)
	}
}

// A re-parse is a new run. The earlier run and its events stay, both verify,
// and the timeline shows only the newest.
func TestReparseAppendsARun(t *testing.T) {
	c := newCase(t)
	dir := corpus(t)
	c.ingest(t, filepath.Join(dir, "app.log"), filepath.Join(dir, "notes.txt"))
	before, _ := c.s.Summarise(store.Query{}, 1)
	for _, name := range []string{"app.log", "notes.txt"} {
		e := c.byName(t, name)
		c.in.Process([]*store.Evidence{&e})
	}
	after, _ := c.s.Summarise(store.Query{}, 1)
	if before.Count != after.Count {
		t.Errorf("timeline went from %d to %d events after an identical re-parse", before.Count, after.Count)
	}
	var runs, events int
	c.s.RawWriter().QueryRow(`SELECT count(*) FROM runs WHERE evidence_id = ?`, c.byName(t, "app.log").ID).Scan(&runs)
	c.s.RawWriter().QueryRow(`SELECT count(*) FROM events`).Scan(&events)
	if runs != 2 || events != 4 {
		t.Errorf("runs=%d events=%d, want 2 and 4: earlier runs must be kept", runs, events)
	}
	if e := c.byName(t, "notes.txt"); e.Status != "generic" {
		t.Errorf("re-parsed generic file: status %q (%s)", e.Status, e.Notes)
	}
	if hits, _ := c.s.SearchText("mimikatz", 10); len(hits) != 1 {
		t.Errorf("text index after re-parse: %d hits", len(hits))
	}
	rep := c.verifyOK(t)
	// app.log: two text-log runs. notes.txt: text-log then generic, twice.
	if rep.RunsChecked != 6 {
		t.Errorf("verify checked %d runs, want all 6", rep.RunsChecked)
	}
}

// Archive bombs and runaway nesting stop at a limit and say so.
func TestNestingLimit(t *testing.T) {
	data := []byte("2024-01-01T00:00:00Z at the very bottom\n")
	for i := 0; i < maxDepth+2; i++ {
		data = gzipOf(fmt.Sprintf("level%d", i), data)
	}
	p := filepath.Join(t.TempDir(), "deep.gz")
	os.WriteFile(p, data, 0o600)
	c := newCase(t)
	c.ingest(t, p)
	limited := false
	for _, e := range c.evidence(t) {
		if e.Depth > maxDepth {
			t.Errorf("%s unpacked at depth %d, beyond the limit", e.Name, e.Depth)
		}
		if strings.Contains(e.Notes, "nesting limit") {
			limited = true
			if e.Status != "partial" {
				t.Errorf("limit reached but status is %q", e.Status)
			}
		}
	}
	if !limited {
		t.Error("the nesting limit was not reported on any item")
	}
	c.verifyOK(t)
}

// The test binary doubles as the worker process, so isolation is tested with
// the real protocol and no separate build.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "atropos-worker":
			os.Exit(RunWorker(os.Stdin, os.Stdout))
		case "atropos-hang":
			time.Sleep(time.Hour)
		case "atropos-crash":
			fmt.Fprintln(os.Stderr, "fatal error: out of memory\ngoroutine 1 [running]:")
			os.Exit(3)
		case "atropos-garbage":
			fmt.Println(`{"t":"event","e":{"Message":"before the fault","TSUTC":1700000000000000000}}`)
			fmt.Println(`{"t":"eve`)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func (c *testCase) isolate(t *testing.T, mode string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c.in.WorkerExe, c.in.WorkerArgs = exe, []string{mode}
}

// Parsing in a worker process must give exactly what parsing in-process
// gives: the same runs, statuses, notes and event digests.
func TestIsolatedParsingMatchesInProcess(t *testing.T) {
	inputs := corpusPaths(t, corpus(t))
	for _, rel := range []string{"Security.evtx", "NTUSER.DAT", "test.ntfs.dd", filepath.Join("prefetch", "Win10", "CALC.EXE-3FBEF7FD.pf")} {
		if p := filepath.Join("..", "..", "testdata", rel); fileExists(p) {
			inputs = append(inputs, p)
		}
	}
	a, b := newCase(t), newCase(t)
	b.isolate(t, "atropos-worker")
	loc, _ := time.LoadLocation("Europe/London")
	for _, c := range []*testCase{a, b} {
		c.in.ExaminerZone, c.in.ExaminerZoneName = loc, "Europe/London"
		c.ingest(t, inputs...)
	}
	sa, sb := a.signature(t), b.signature(t)
	if len(sa) == 0 || len(sa) != len(sb) {
		t.Fatalf("run counts differ: %d in-process, %d isolated", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Errorf("run %d differs:\n  in-process %s\n  isolated   %s", i+1, sa[i], sb[i])
		}
	}
	// Facts and extracted text cross the process boundary too.
	for _, q := range []string{`SELECT count(*) FROM facts`, `SELECT count(*) FROM evidence_text`, `SELECT coalesce(sum(length(body)),0) FROM evidence_text`} {
		var x, y int64
		a.s.RawWriter().QueryRow(q).Scan(&x)
		b.s.RawWriter().QueryRow(q).Scan(&y)
		if x != y || x == 0 {
			t.Errorf("%s: %d in-process, %d isolated", q, x, y)
		}
	}
	b.verifyOK(t)
}

// A parser that hangs, dies or emits nonsense fails that one file, visibly,
// and nothing else: later files still parse and the case still verifies.
func TestWorkerFaultsAreContained(t *testing.T) {
	for mode, want := range map[string]string{
		"atropos-hang":    "time limit",
		"atropos-crash":   "ended unexpectedly",
		"atropos-garbage": "ended unexpectedly",
	} {
		t.Run(mode, func(t *testing.T) {
			c := newCase(t)
			c.isolate(t, mode)
			c.in.ParseTimeout = 400 * time.Millisecond
			dir := corpus(t)
			start := time.Now()
			c.ingest(t, filepath.Join(dir, "app.log"))
			if d := time.Since(start); d > 20*time.Second {
				t.Errorf("a faulty parser held the pipeline for %s", d)
			}
			e := c.byName(t, "app.log")
			if e.Status == "parsed" || e.Status == "processing" || e.Status == "queued" {
				t.Errorf("status %q after a parser fault", e.Status)
			}
			if !strings.Contains(e.Notes, want) {
				t.Errorf("notes do not explain the fault (want %q): %s", want, e.Notes)
			}
			if mode == "atropos-crash" && !strings.Contains(e.Notes, "out of memory") {
				t.Errorf("the worker's own error is not passed on: %s", e.Notes)
			}
			if mode == "atropos-garbage" && e.Status != "partial" {
				t.Errorf("events received before the fault should be kept as a partial run; status %q, %d events", e.Status, e.EventCount)
			}
			// The same case recovers as soon as the parser behaves.
			c.isolate(t, "atropos-worker")
			c.in.ParseTimeout = time.Minute
			c.in.Process([]*store.Evidence{&e})
			if e := c.byName(t, "app.log"); e.Status != "parsed" || e.EventCount != 2 {
				t.Errorf("re-parse after the fault: %s with %d events (%s)", e.Status, e.EventCount, e.Notes)
			}
			c.verifyOK(t)
		})
	}
}

// An archive that expands without end stops at the submission's allowance.
func TestUnpackSizeLimit(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "bomb.gz")
	os.WriteFile(big, gzipOf("zeros", make([]byte, 5<<20)), 0o600)
	files := map[string][]byte{"a.log": bytes.Repeat([]byte("2024-01-01T00:00:00Z line\n"), 30), "b.log": bytes.Repeat([]byte("2024-01-02T00:00:00Z line\n"), 30), "c.log": []byte("2024-01-03T00:00:00Z line\n")}
	many := filepath.Join(dir, "many.zip")
	os.WriteFile(many, zipOf(t, files, "a.log", "b.log", "c.log"), 0o600)

	c := newCase(t)
	c.in.MaxUnpack = 1000
	c.ingest(t, big)
	e := c.byName(t, "bomb.gz")
	if e.Status != "partial" || !strings.Contains(e.Notes, "larger than the remaining unpack allowance") {
		t.Errorf("bomb: %s: %s", e.Status, e.Notes)
	}
	if child := c.byName(t, "zeros"); child.Size > 1001 {
		t.Errorf("%d bytes were written for a member limited to 1000", child.Size)
	}

	c.ingest(t, many) // a new submission gets a fresh allowance
	e = c.byName(t, "many.zip")
	if e.Status != "partial" || !strings.Contains(e.Notes, "remaining members not unpacked") {
		t.Errorf("many: %s: %s", e.Status, e.Notes)
	}
	if got := c.byName(t, "a.log"); got.Status != "parsed" {
		t.Errorf("member within the allowance: %s", got.Status)
	}
	for _, ev := range c.evidence(t) {
		if ev.Name == "c.log" {
			t.Error("a member beyond the allowance was unpacked")
		}
	}
	c.verifyOK(t)
}
