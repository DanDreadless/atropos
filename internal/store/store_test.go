package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "case.db"), "tester")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seed puts at least one row in every append-only table and returns the ids
// of the event and annotation it made.
func seed(t *testing.T, s *Store) (eventID, annotationID int64) {
	t.Helper()
	e := &Evidence{SHA256: strings.Repeat("a", 64), SHA1: "s1", MD5: "m5", Size: 3, Name: "a.log", Origin: "/x/a.log", BatchID: 1, Kind: "text", DetectReason: "test"}
	if err := s.AddEvidence(e); err != nil {
		t.Fatal(err)
	}
	run, err := s.BeginRun(e.ID, "text-log", "1", "assumed: UTC")
	if err != nil {
		t.Fatal(err)
	}
	for i, msg := range []string{"alpha powershell.exe started", "beta logon by dan", "gamma $MFT touched"} {
		if err := run.Add(Event{TSUTC: int64(1700000000+i) * 1e9, TSType: "logged", TSRaw: "raw", TZSource: "native-utc", TZName: "UTC",
			MACB: []string{"M...", ".A..", "MACB"}[i], Category: []string{"execution", "account", "file-system"}[i],
			Source: "log", Host: "HOST1", User: "dan", Path: `C:\x`, Message: msg, RecordRef: "line 1"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := run.Finish("parsed", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddText(e.ID, "full text", false, "some body text"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddFact(e.ID, "host.name", "HOST1", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.w.QueryRow(`SELECT min(id) FROM events`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	annotationID, err = s.Annotate(eventID, "tag", "suspicious", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup("Seed group", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDetails("", map[string]string{"case_reference": "SEED/1"}); err != nil {
		t.Fatal(err)
	}
	// A host, and the submission assigned to it and then to no host.
	h, err := s.AddHost("SEED-PC")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignBatch(e.BatchID, &h.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignBatch(e.BatchID, nil, "seeded from nowhere"); err != nil {
		t.Fatal(err)
	}
	// Excluded and included again: the item stays in view.
	if err := s.SetExcluded(e.ID, true, "seed"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetExcluded(e.ID, false, ""); err != nil {
		t.Fatal(err)
	}
	return eventID, annotationID
}

// Rule: evidence, events, runs, facts, annotations and audit rows are never
// updated or deleted. The database itself refuses.
func TestAppendOnlyTablesRejectUpdateAndDelete(t *testing.T) {
	s := open(t)
	seed(t, s)
	col := map[string]string{
		"details": "value", "case_meta": "value", "evidence": "name", "runs": "parser", "run_results": "status", "events": "message",
		"evidence_text": "body", "facts": "value", "annotations": "body", "groups": "name", "audit": "details", "exclusions": "reason", "run_stats": "source", "run_stats_done": "version", "hosts": "name", "batch_hosts": "source",
	}
	for _, table := range appendOnlyTables {
		var n int
		if err := s.w.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n == 0 {
			t.Fatalf("%s: no rows to test against (n=%d, err=%v)", table, n, err)
		}
		c, ok := col[table]
		if !ok {
			t.Fatalf("%s: append-only table has no column listed in this test", table)
		}
		if _, err := s.w.Exec(`UPDATE ` + table + ` SET ` + c + ` = 'tampered'`); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("UPDATE %s: want append-only refusal, got %v", table, err)
		}
		if _, err := s.w.Exec(`DELETE FROM ` + table); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("DELETE %s: want append-only refusal, got %v", table, err)
		}
		var after int
		s.w.QueryRow(`SELECT count(*) FROM ` + table).Scan(&after)
		if after != n {
			t.Errorf("%s: row count changed from %d to %d", table, n, after)
		}
	}
	// INSERT OR REPLACE is a delete followed by an insert; it must not get round the rule.
	for _, stmt := range []string{
		`INSERT OR REPLACE INTO case_meta(key,value) VALUES ('created_by','mallory')`,
		`REPLACE INTO audit(id,ts_utc,actor,action,target,details,prev_hash,hash) VALUES (1,0,'mallory','x','x','{}','','')`,
		`INSERT OR REPLACE INTO run_results(run_id,status,event_count,event_digest,notes,finished_utc) VALUES (1,'parsed',0,'','',0)`,
	} {
		if _, err := s.w.Exec(stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: want append-only refusal, got %v", stmt[:40], err)
		}
	}
	var v string
	s.w.QueryRow(`SELECT value FROM case_meta WHERE key='created_by'`).Scan(&v)
	if v != "tester" {
		t.Errorf("case_meta was rewritten to %q", v)
	}
}

// Every table that holds case data must be in the append-only list. A table
// added later without triggers would be a silent hole.
func TestEveryDataTableIsProtected(t *testing.T) {
	s := open(t)
	protected := map[string]bool{"current_runs": true} // the one rebuildable index
	for _, t := range appendOnlyTables {
		protected[t] = true
	}
	rows, err := s.w.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%_fts%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		if !protected[name] {
			t.Errorf("table %s is neither append-only nor the declared mutable index", name)
		}
	}
}

// dropTriggers simulates someone with write access to the file removing the
// database-level protection, which is why integrity rests on hashes.
func dropTriggers(t *testing.T, s *Store) {
	t.Helper()
	for _, table := range appendOnlyTables {
		for _, op := range []string{"update", "delete"} {
			if _, err := s.w.Exec(`DROP TRIGGER ` + table + `_no_` + op); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestVerifyAuditDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]string{
		"edited details": `UPDATE audit SET details = '{"edited":true}' WHERE id = 2`,
		"edited actor":   `UPDATE audit SET actor = 'mallory' WHERE id = 2`,
		"edited time":    `UPDATE audit SET ts_utc = ts_utc + 1 WHERE id = 2`,
		"removed entry":  `DELETE FROM audit WHERE id = 2`,
		"rehashed entry": `UPDATE audit SET details = '{}', hash = 'deadbeef' WHERE id = 2`,
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			for i := 0; i < 4; i++ {
				if err := s.Audit("test.action", "case", map[string]any{"i": i}); err != nil {
					t.Fatal(err)
				}
			}
			n, head, broken, err := s.VerifyAudit()
			if err != nil || broken != 0 || n != 5 || len(head) != 64 {
				t.Fatalf("clean chain: n=%d head=%q broken=%d err=%v", n, head, broken, err)
			}
			dropTriggers(t, s)
			if _, err := s.w.Exec(tamper); err != nil {
				t.Fatal(err)
			}
			_, _, broken, err = s.VerifyAudit()
			if err != nil {
				t.Fatal(err)
			}
			if broken == 0 {
				t.Error("tampering was not detected")
			}
		})
	}
}

func TestVerifyRunsDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]string{
		"edited message":   `UPDATE events SET message = 'nothing to see' WHERE id = (SELECT min(id) FROM events)`,
		"shifted time":     `UPDATE events SET ts_utc = ts_utc + 1 WHERE id = (SELECT min(id) FROM events)`,
		"changed zone tag": `UPDATE events SET tz_source = 'native-utc', tz_name='x' WHERE id = (SELECT max(id) FROM events)`,
		"removed event":    `DELETE FROM events WHERE id = (SELECT max(id) FROM events)`,
		"added event": `INSERT INTO events(run_id,evidence_id,ts_utc,ts_type,ts_raw,tz_source,tz_name,macb,category,source,host,user,path,message,fields,record_ref)
			SELECT run_id,evidence_id,ts_utc,ts_type,ts_raw,tz_source,tz_name,macb,category,source,host,user,path,'planted',fields,record_ref FROM events LIMIT 1`,
		"changed macb":              `UPDATE events SET macb = 'MACB' WHERE id = (SELECT min(id) FROM events)`,
		"changed category":          `UPDATE events SET category = 'log' WHERE id = (SELECT min(id) FROM events)`,
		"moved text between fields": `UPDATE events SET path = path || substr(message,1,1), message = substr(message,2) WHERE id = (SELECT min(id) FROM events)`,
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			seed(t, s)
			checked, bad, err := s.VerifyRuns()
			if err != nil || checked != 1 || len(bad) != 0 {
				t.Fatalf("clean run: checked=%d bad=%v err=%v", checked, bad, err)
			}
			dropTriggers(t, s)
			if _, err := s.w.Exec(tamper); err != nil {
				t.Fatal(err)
			}
			_, bad, err = s.VerifyRuns()
			if err != nil {
				t.Fatal(err)
			}
			if len(bad) != 1 {
				t.Errorf("tampering was not detected (bad=%v)", bad)
			}
		})
	}
}

func TestAnnotationsAreRetractedNotRemoved(t *testing.T) {
	s := open(t)
	eventID, tagID := seed(t, s)
	if _, err := s.Annotate(eventID, "retract", "", nil); err == nil {
		t.Error("a retraction with no target was accepted")
	}
	if _, err := s.Annotate(eventID, "delete", "x", nil); err == nil {
		t.Error("an unknown annotation kind was accepted")
	}
	rows, err := s.Search(Query{Text: "tag:suspicious"})
	if err != nil || len(rows) != 1 || len(rows[0].Tags) != 1 {
		t.Fatalf("tag search before retraction: %v %v", rows, err)
	}
	if _, err := s.Annotate(eventID, "retract", "added in error", &tagID); err != nil {
		t.Fatal(err)
	}
	notes, err := s.Annotations(eventID)
	if err != nil || len(notes) != 2 {
		t.Fatalf("want the tag and its retraction both kept, got %d (%v)", len(notes), err)
	}
	if !notes[0].Retracted {
		t.Error("tag is not marked retracted")
	}
	rows, _ = s.Search(Query{Text: "tag:suspicious"})
	if len(rows) != 0 {
		t.Error("retracted tag still matches a tag search")
	}
	if n, _, broken, _ := s.VerifyAudit(); broken != 0 || n < 3 {
		t.Errorf("annotations were not audited: n=%d broken=%d", n, broken)
	}
}

func TestSearchSyntax(t *testing.T) {
	s := open(t)
	seed(t, s)
	cases := []struct {
		q    string
		want int
	}{
		{"", 3},
		{"powersh", 1},             // prefix match
		{`"powersh"`, 0},           // quoted is exact
		{`"powershell.exe"`, 1},    // punctuation inside a term
		{"logon dan", 1},           // terms are ANDed
		{"-alpha", 2},              // exclusion
		{"host:host1", 3},          // field filter, case-insensitive
		{"host:other", 0},          //
		{"-host:host1", 0},         //
		{"source:log user:dan", 3}, //
		{"tz:native-utc", 3},       //
		{"type:logged gamma", 1},   //
		{"$MFT", 1},                // $ is a token character
		{"evidence:1", 3},          //
		{"evidence:2", 0},          //
		{"id:1,3", 2},              // exactly these events, as an analysis finding links to them
		{"id:2", 1},                //
		{"-id:2", 2},               //
		{"id:1,3 gamma", 1},        //
		{"tag:suspicious", 1},
		{"category:execution", 1},  //
		{"-category:execution", 2}, //
		{"macb:m", 2},              // any event whose time is a modification time
		{"macb:a", 2},              //
		{"macb:mb", 1},             // both letters
		{"macb:B", 1},              //
		{"-macb:m", 1},             //
		{"macb:x", 0},              // not a MACB letter: treated as a search term
		{"group:nosuch", 0},        //      //
		{"-tag:suspicious", 2},     //
		{`") OR 1=1 --`, 0},        // hostile input is one literal phrase: no error, no injection
		{`"unterminated`, 0},       //
		{"NEAR( AND OR NOT *", 0},  // FTS operators are treated as plain words
	}
	for _, c := range cases {
		rows, err := s.Search(Query{Text: c.q})
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		if len(rows) != c.want {
			t.Errorf("%q: %d events, want %d", c.q, len(rows), c.want)
		}
	}
}

func TestSearchPagingAndSummary(t *testing.T) {
	s := open(t)
	seed(t, s)
	var seen []int64
	q := Query{Limit: 2}
	for {
		rows, err := s.Search(q)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			seen = append(seen, r.ID)
		}
		q.AfterTS, q.AfterID = rows[len(rows)-1].TSUTC, rows[len(rows)-1].ID
	}
	if len(seen) != 3 || seen[0] >= seen[1] || seen[1] >= seen[2] {
		t.Errorf("paging returned %v", seen)
	}
	desc, _ := s.Search(Query{Desc: true, Limit: 1})
	if len(desc) != 1 || desc[0].ID != seen[2] {
		t.Errorf("descending order returned %v", desc)
	}
	sum, err := s.Summarise(Query{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, b := range sum.Bars {
		total += b.Count
		if b.Index < 0 || b.Index >= 10 {
			t.Errorf("bar index %d outside the requested 10 buckets", b.Index)
		}
	}
	if sum.Count != 3 || total != 3 || sum.MinTS != 1700000000*1e9 || sum.MaxTS != 1700000002*1e9 {
		t.Errorf("summary = %+v", sum)
	}
	if empty, err := s.Summarise(Query{Text: "nomatch"}, 10); err != nil || empty.Count != 0 || empty.Bars == nil {
		t.Errorf("empty summary = %+v err=%v", empty, err)
	}
}

// A new run supersedes the old one on the timeline, and the old run's events
// stay in the database and stay verifiable.
func TestReparseSupersedesWithoutRemoving(t *testing.T) {
	s := open(t)
	seed(t, s)
	run, err := s.BeginRun(1, "text-log", "2", "examiner-set: Europe/London")
	if err != nil {
		t.Fatal(err)
	}
	run.Add(Event{TSUTC: 1700000100 * 1e9, TSType: "logged", Source: "log", Message: "only event of the second run"})
	if _, err := run.Finish("parsed", ""); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.Search(Query{})
	if len(rows) != 1 || rows[0].Message != "only event of the second run" {
		t.Errorf("timeline shows %d events, want only the new run's", len(rows))
	}
	var all int
	s.w.QueryRow(`SELECT count(*) FROM events`).Scan(&all)
	if all != 4 {
		t.Errorf("events stored = %d, want 4 (both runs kept)", all)
	}
	if checked, bad, _ := s.VerifyRuns(); checked != 2 || len(bad) != 0 {
		t.Errorf("verify after re-parse: checked=%d bad=%v", checked, bad)
	}
	// Text is indexed once per evidence item; a second attempt is refused, not duplicated.
	if err := s.AddText(1, "full text", false, "again"); err == nil {
		t.Error("second AddText for the same evidence succeeded")
	}
	hits, err := s.SearchText("body", 10)
	if err != nil || len(hits) != 1 {
		t.Errorf("text search: %v %v", hits, err)
	}
}

func TestReopenKeepsCaseAndChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := Open(path, "first")
	if err != nil {
		t.Fatal(err)
	}
	s.Audit("x", "case", nil)
	s.Close()
	s, err = Open(path, "second")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	meta, _ := s.Meta()
	if meta["created_by"] != "first" {
		t.Errorf("created_by = %q after reopening", meta["created_by"])
	}
	s.Audit("y", "case", nil)
	if n, _, broken, err := s.VerifyAudit(); n != 3 || broken != 0 || err != nil {
		t.Errorf("chain after reopen: n=%d broken=%d err=%v", n, broken, err)
	}
}

// A run cut off by a crash is sealed on the next start: its events are kept
// and digested, its status says what happened, and the case still verifies.
func TestInterruptedRunsAreSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := Open(path, "tester")
	if err != nil {
		t.Fatal(err)
	}
	e := &Evidence{SHA256: strings.Repeat("b", 64), Name: "big.evtx", Origin: "/x", BatchID: 1, Kind: "windows-event-log", DetectReason: "test"}
	s.AddEvidence(e)
	run, _ := s.BeginRun(e.ID, "evtx", "1", "")
	for i := 0; i < batchSize+10; i++ { // one batch reaches the database, ten events do not
		run.Add(Event{TSUTC: int64(1700000000+i) * 1e9, TSType: "event-logged", Source: "evtx", Message: "m"})
	}
	empty, _ := s.BeginRun(e.ID, "evtx", "1", "")
	_ = empty
	s.Close() // the process dies here: neither run is ever finished

	s, err = Open(path, "tester")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, _ := s.ListEvidence()
	if list[0].Status != "processing" {
		t.Fatalf("before sealing, status is %q", list[0].Status)
	}
	sealed, err := s.SealInterrupted()
	if err != nil || len(sealed) != 2 {
		t.Fatalf("sealed %v, err %v", sealed, err)
	}
	again, _ := s.SealInterrupted()
	if len(again) != 0 {
		t.Errorf("a second pass sealed %v", again)
	}
	var status string
	var n int64
	s.w.QueryRow(`SELECT status, event_count FROM run_results WHERE run_id = ?`, sealed[0]).Scan(&status, &n)
	if status != "interrupted" || n != batchSize {
		t.Errorf("first run sealed as %q with %d events, want interrupted with %d", status, n, batchSize)
	}
	list, _ = s.ListEvidence()
	if list[0].Status != "interrupted" || !strings.Contains(list[0].Notes, "parse this item again") {
		t.Errorf("evidence shows %q: %s", list[0].Status, list[0].Notes)
	}
	if checked, bad, _ := s.VerifyRuns(); checked != 2 || len(bad) != 0 {
		t.Errorf("verify runs: %d checked, bad %v", checked, bad)
	}
	if un, miss, _ := s.VerifyRunsAudited(); len(un) != 0 || len(miss) != 0 {
		t.Errorf("sealed runs not vouched for by the audit log: %v %v", un, miss)
	}
	if _, _, broken, _ := s.VerifyAudit(); broken != 0 {
		t.Errorf("audit chain broken at %d", broken)
	}
}

// Case directories are named by people. Characters that mean something in a
// URI must not change which file is opened.
func TestAwkwardCasePaths(t *testing.T) {
	for _, name := range []string{"Case #4", "50% done", "a&b=c", "Op Nightjar (R v Smith)", "données été", "x;y"} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "case.db")
		s, err := Open(path, "tester")
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		seed(t, s)
		rows, err := s.Search(Query{})
		if err != nil || len(rows) != 3 {
			t.Errorf("%q: read back %d events (%v)", name, len(rows), err)
		}
		s.Close()
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Errorf("%q: the database is not where it was asked for (%v)", name, err)
		}
		entries, _ := os.ReadDir(filepath.Dir(dir))
		if len(entries) != 1 {
			t.Errorf("%q: stray files created beside the case directory: %v", name, entries)
		}
	}
}
