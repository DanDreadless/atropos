package ingest

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
	"github.com/DanDreadless/atropos/internal/store"

	_ "modernc.org/sqlite"
)

// liveHistory copies a Chromium-style history database and its write-ahead
// log while the database is open: one visit checkpointed, n only in the log.
func liveHistory(t *testing.T, n int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "History")
	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	wk := func(tm time.Time) int64 { return tm.UnixMicro() + 11644473600000000 }
	base := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	stmts := []string{
		`CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)`,
		`CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)`,
		`INSERT INTO urls VALUES (1,'https://old.example/','Old',1)`,
		fmt.Sprintf(`INSERT INTO visits VALUES (1,1,%d,1)`, wk(base.Add(-time.Hour))),
		`PRAGMA wal_checkpoint(TRUNCATE)`,
	}
	for i := 0; i < n; i++ {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO urls VALUES (%d,'https://new.example/%d','New',1)`, i+2, i),
			fmt.Sprintf(`INSERT INTO visits VALUES (%d,%d,%d,1)`, i+2, i+2, wk(base.Add(time.Duration(i)*time.Second))))
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	out := t.TempDir()
	for _, f := range []string{"History", "History-wal"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(out, f), b, 0o600)
	}
	db.Close()
	return filepath.Join(out, "History"), filepath.Join(out, "History-wal")
}

func TestDatabaseWithItsWriteAheadLog(t *testing.T) {
	for _, mode := range []string{"in-process", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			db, wal := liveHistory(t, 25)
			// Together in one submission.
			c := newCase(t)
			if mode == "isolated" {
				c.isolate(t, "atropos-worker")
			}
			c.ingest(t, db, wal)
			h := c.byName(t, "History")
			if h.EventCount != 26 || !strings.Contains(h.Notes, "write-ahead log") || !strings.Contains(h.Notes, "applied") {
				t.Errorf("together: %d events, notes %s", h.EventCount, h.Notes)
			}
			if w := c.byName(t, "History-wal"); w.Kind != "sqlite-wal" || w.Parser != "sqlite-wal" {
				t.Errorf("the log: %+v", w)
			}
			if left, _ := os.ReadDir(filepath.Join(c.dir, "work")); len(left) != 0 {
				t.Errorf("working copies left behind: %d", len(left))
			}
			c.verifyOK(t)

			// The database first, its log in a later submission.
			c2 := newCase(t)
			if mode == "isolated" {
				c2.isolate(t, "atropos-worker")
			}
			c2.ingest(t, db)
			if h := c2.byName(t, "History"); h.EventCount != 1 {
				t.Fatalf("alone: %d events", h.EventCount)
			}
			c2.ingest(t, wal)
			if h := c2.byName(t, "History"); h.EventCount != 26 {
				t.Errorf("after the log arrived: %d events, notes %s", h.EventCount, h.Notes)
			}
			c2.verifyOK(t)
		})
	}
}

// A OneDrive log added before its keystore is read again, decrypted, when
// the keystore arrives.
func TestOneDriveLogThenKeystore(t *testing.T) {
	log, ks := imagetest.OneDriveLog(bytes.Repeat([]byte{3}, 32), "Plans for the merger.docx")
	dir := t.TempDir()
	lp, kp := filepath.Join(dir, "SyncEngine.odl"), filepath.Join(dir, "general.keystore")
	os.WriteFile(lp, log, 0o600)
	os.WriteFile(kp, ks, 0o600)
	c := newCase(t)
	c.ingest(t, lp)
	if rows, _ := c.s.Search(store.Query{Text: "merger"}); len(rows) != 0 {
		t.Fatal("decrypted without a key")
	}
	c.ingest(t, kp)
	if rows, _ := c.s.Search(store.Query{Text: "merger"}); len(rows) != 1 {
		t.Errorf("not decrypted once the keystore arrived: %d", len(rows))
	}
	if k := c.byName(t, "general.keystore"); k.Kind != "onedrive-keystore" {
		t.Errorf("keystore kind %s", k.Kind)
	}
	c.verifyOK(t)
}
