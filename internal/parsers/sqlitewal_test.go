package parsers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveDB makes a database in WAL mode the way a running browser leaves it:
// the first statements checkpointed into the database file, the rest only
// in the log. It returns copies of the database and its log, taken while
// the database is still open.
func liveDB(t *testing.T, name string, base, later []string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, s := range base {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	for _, s := range later {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	out := t.TempDir()
	copyFile := func(from, to string) {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dbCopy, walCopy := filepath.Join(out, name), filepath.Join(out, name+"-wal")
	copyFile(p, dbCopy)
	copyFile(p+"-wal", walCopy)
	db.Close()
	return dbCopy, walCopy
}

func historyDB(t *testing.T, name string, n int) (string, string) {
	base := []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
		fmt.Sprintf(`INSERT INTO urls VALUES (1,'https://old.example/','Old',1)`),
		fmt.Sprintf(`INSERT INTO visits VALUES (1,1,%d,1)`, webkit("2024-01-01T00:00:00Z")),
	}
	var later []string
	for i := 0; i < n; i++ {
		later = append(later,
			fmt.Sprintf(`INSERT INTO urls VALUES (%d,'https://new.example/%d','New %d',1)`, i+2, i, i),
			fmt.Sprintf(`INSERT INTO visits VALUES (%d,%d,%d,1)`, i+2, i+2, webkit("2024-02-01T00:00:00Z")+int64(i)))
	}
	return historyDBWith(t, name, base, later)
}

func historyDBWith(t *testing.T, name string, base, later []string) (string, string) {
	return liveDB(t, name, base, later)
}

func TestWALAppliedToItsDatabase(t *testing.T) {
	db, wal := historyDB(t, "History", 40)
	if k := run(t, wal, nil); k.err != nil || k.facts["sqlite_wal.commits"] != "80" {
		t.Errorf("the log on its own: %v %v", k.err, k.facts)
	}
	// Without its log: only what was checkpointed, and a note saying so.
	alone := run(t, db, nil)
	if len(alone.events) != 1 || !strings.Contains(strings.Join(alone.notes, " "), "no log in the case fits it") {
		t.Fatalf("without the log: %d events, notes %v", len(alone.events), alone.notes)
	}
	before, _ := os.ReadFile(db)
	work := t.TempDir()
	with := run(t, db, func(c *Context) { c.Segments = []string{wal}; c.WorkDir = work })
	if with.err != nil || len(with.warns) > 0 || len(with.events) != 41 {
		t.Fatalf("with the log: %v %v, %d events", with.err, with.warns, len(with.events))
	}
	if !strings.Contains(strings.Join(with.notes, " "), "80 committed transactions") || with.facts["sqlite.wal_applied"] != "History-wal" {
		t.Errorf("notes %v facts %v", with.notes, with.facts)
	}
	if after, _ := os.ReadFile(db); string(after) != string(before) {
		t.Error("the evidence was changed")
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Errorf("the working copy was left behind: %v", left)
	}
}

// Logs are paired with databases by their pages, not their names: a
// browser profile holds several databases with the same page size.
func TestWALNotAppliedToAnotherDatabase(t *testing.T) {
	hist, histWAL := historyDB(t, "History", 30)
	cookies, cookiesWAL := liveDB(t, "Cookies",
		[]string{`CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, has_expires INTEGER, is_persistent INTEGER, priority INTEGER, encrypted_value BLOB, samesite INTEGER, source_scheme INTEGER)`},
		func() []string {
			var s []string
			for i := 0; i < 30; i++ {
				s = append(s, fmt.Sprintf(`INSERT INTO cookies VALUES (%d,'site%d.test','c','SECRETVALUE','/',0,1,1,%d,1,1,1,x'00',0,2)`,
					webkit("2024-03-01T00:00:00Z")+int64(i), i, webkit("2024-03-02T00:00:00Z")))
			}
			return s
		}())
	// The history database offered only the cookie log: nothing applied.
	r := run(t, hist, func(c *Context) { c.Segments = []string{cookiesWAL}; c.WorkDir = t.TempDir() })
	if len(r.events) != 1 || r.facts["sqlite.wal_applied"] != "" {
		t.Errorf("a cookie log was applied to a history database: %d events %v", len(r.events), r.facts)
	}
	// Offered both, each database takes its own.
	r = run(t, hist, func(c *Context) { c.Segments = []string{cookiesWAL, histWAL}; c.WorkDir = t.TempDir() })
	if len(r.events) != 31 || r.facts["sqlite.wal_applied"] != "History-wal" {
		t.Errorf("history: %d events %v %v", len(r.events), r.facts, r.notes)
	}
	r = run(t, cookies, func(c *Context) { c.Segments = []string{histWAL, cookiesWAL}; c.WorkDir = t.TempDir() })
	if r.facts["sqlite.wal_applied"] != "Cookies-wal" || len(r.events) == 0 {
		t.Errorf("cookies: %d events %v %v", len(r.events), r.facts, r.notes)
	}
	for _, e := range r.events {
		if strings.Contains(fmt.Sprint(e), "SECRETVALUE") {
			t.Fatal("a cookie value reached the output")
		}
	}
}

// Only whole transactions count, and a damaged frame ends the log there.
func TestWALDamaged(t *testing.T) {
	db, wal := historyDB(t, "History", 40)
	b, _ := os.ReadFile(wal)
	frame := int64(24 + 4096)
	cut := filepath.Join(t.TempDir(), "cut-wal")
	os.WriteFile(cut, b[:32+frame*21+100], 0o600) // part of the way into frame 22
	r := run(t, db, func(c *Context) { c.Segments = []string{cut}; c.WorkDir = t.TempDir() })
	if r.err != nil || len(r.events) <= 1 || len(r.events) >= 41 {
		t.Errorf("cut log: %v, %d events", r.err, len(r.events))
	}
	bad := append([]byte(nil), b...)
	bad[32+frame*5+24+100] ^= 0xFF // a page byte in frame 6: its checksum fails
	badp := filepath.Join(t.TempDir(), "bad-wal")
	os.WriteFile(badp, bad, 0o600)
	w, err := readWAL(mustOpen(t, badp), int64(len(bad)))
	if err != nil || w.frames != 5 {
		t.Errorf("a frame with a bad checksum must end the log: %v %+v", err, w)
	}
	junk := filepath.Join(t.TempDir(), "junk-wal")
	os.WriteFile(junk, append(append([]byte(nil), b[:32]...), make([]byte, 50000)...), 0o600)
	r = run(t, db, func(c *Context) { c.Segments = []string{junk}; c.WorkDir = t.TempDir() })
	if r.err != nil || len(r.events) != 1 {
		t.Errorf("a log with no valid frames: %v, %d events", r.err, len(r.events))
	}
}

func mustOpen(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
