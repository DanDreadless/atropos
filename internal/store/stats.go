package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Per-run summaries, so that counts over the whole case do not read every
// event. A sealed run never changes, so its events are counted once, by
// source, category, zone provenance and hour, into run_stats. A search made
// only of filters on those columns and on the evidence item (source:, tz:,
// category:, evidence:, from:, submission:, item:, kind:) is then counted
// from the summaries: the chips, the totals and the chart. Anything else
// (words, a time range, a group, tags, host, user) reads the events as
// before.
//
// The chart drawn from summaries is exact: its bars are whole numbers of
// hours, starting on an hour, so every hour's events fall in one bar.
//
// Both tables are append-only. A change to how the summaries are made gets a
// new statsVersion; rows of other versions are ignored and the runs are
// counted again.

const statsVersion = 2 // 2: counted by host too

const hourNS = int64(3600) * 1e9

const statsSchema = `
CREATE TABLE IF NOT EXISTS run_stats (
  run_id      INTEGER NOT NULL REFERENCES runs(id),
  evidence_id INTEGER NOT NULL,
  source      TEXT NOT NULL,
  category    TEXT NOT NULL,
  tz_source   TEXT NOT NULL,
  host        TEXT NOT NULL DEFAULT '',
  hour        INTEGER NOT NULL,     -- floor(ts_utc / one hour)
  n           INTEGER NOT NULL,
  min_ts      INTEGER NOT NULL,
  max_ts      INTEGER NOT NULL,
  version     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS run_stats_run ON run_stats(run_id, version);
CREATE TABLE IF NOT EXISTS run_stats_done (
  run_id  INTEGER NOT NULL REFERENCES runs(id),
  version INTEGER NOT NULL,
  PRIMARY KEY (run_id, version)
);
`

// Indexes that let a search on one source or category read only its events,
// and a zoomed chart count without reading the events.
// Built in the background (BuildDerived) because on a large existing case
// they take a while.
var derivedIndexes = []string{
	// Filters compare without regard to case (source:MFT is source:mft),
	// so the indexes do too: an index of exact values cannot serve them.
	`CREATE INDEX IF NOT EXISTS events_source_nc ON events(source COLLATE NOCASE, ts_utc, id)`,
	`CREATE INDEX IF NOT EXISTS events_category_nc ON events(category COLLATE NOCASE, ts_utc, id)`,
	`CREATE INDEX IF NOT EXISTS events_tz_nc ON events(tz_source COLLATE NOCASE, ts_utc, id)`,
	// One run's events in time order: an item's timeline without a sort.
	`CREATE INDEX IF NOT EXISTS events_run_ts ON events(run_id, ts_utc, id)`,
	// Made by a build of the same day that compared exactly; never used.
	`DROP INDEX IF EXISTS events_source_ts`,
	`DROP INDEX IF EXISTS events_category_ts`,
	// Time and run together: a zoomed chart is counted from this index
	// alone, without reading each event to learn its run.
	`CREATE INDEX IF NOT EXISTS events_ts_run ON events(ts_utc, run_id)`,
}

// statsFrom reads run summaries as if they were events (alias e, with the
// same column names), for the current, not excluded runs.
var statsFrom = fmt.Sprintf(` FROM run_stats e JOIN current_runs c ON c.run_id = e.run_id AND c.evidence_id%s AND e.version = %d `, notExcluded, statsVersion)

// computeStats summarises one sealed run.
func (s *Store) computeStats(runID int64) error {
	tx, err := s.w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var done int
	if err := tx.QueryRow(`SELECT count(*) FROM run_stats_done WHERE run_id = ? AND version = ?`, runID, statsVersion).Scan(&done); err != nil || done > 0 {
		return err
	}
	hour := fmt.Sprintf(`CASE WHEN ts_utc >= 0 THEN ts_utc / %d ELSE (ts_utc + 1) / %d - 1 END`, hourNS, hourNS)
	if _, err := tx.Exec(`INSERT INTO run_stats(run_id,evidence_id,source,category,tz_source,host,hour,n,min_ts,max_ts,version)
		SELECT run_id, evidence_id, source, category, tz_source, host, `+hour+`, count(*), min(ts_utc), max(ts_utc), ?
		FROM events WHERE run_id = ? GROUP BY evidence_id, source, category, tz_source, host, `+hour, statsVersion, runID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO run_stats_done(run_id, version) VALUES (?, ?)`, runID, statsVersion); err != nil {
		return err
	}
	return tx.Commit()
}

// BuildDerived builds what a case made by an earlier version lacks: the
// source and category indexes, and the summaries of sealed runs. It is safe
// to run while the case is in use; until it is done, searches read the
// events as before. It stops early when ctx is cancelled.
func (s *Store) BuildDerived(ctx context.Context) error {
	indexes := func() string {
		var names string
		s.r.QueryRow(`SELECT COALESCE(group_concat(name), '') FROM (SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name)`).Scan(&names)
		return names
	}
	before := indexes()
	for _, ix := range derivedIndexes {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := s.w.ExecContext(ctx, ix); err != nil {
			return err
		}
	}
	changed := indexes() != before
	rows, err := s.r.Query(`SELECT r.run_id FROM run_results r
		WHERE NOT EXISTS (SELECT 1 FROM run_stats_done d WHERE d.run_id = r.run_id AND d.version = ?) ORDER BY r.run_id`, statsVersion)
	if err != nil {
		return err
	}
	var todo []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, id)
	}
	rows.Close()
	for _, id := range todo {
		if ctx.Err() != nil {
			return nil
		}
		if err := s.computeStats(id); err != nil {
			return fmt.Errorf("summarising run %d: %w", id, err)
		}
	}
	if err := s.buildObservables(ctx); err != nil {
		return err
	}
	if len(todo) > 0 || changed {
		// Let the query planner learn the new indexes' selectivity.
		if _, err := s.w.ExecContext(ctx, `ANALYZE`); err != nil {
			return err
		}
	}
	return nil
}

// statsReady says whether every current run has its summary. A run still
// being written, or one from before summaries existed, means no.
func (s *Store) statsReady() bool {
	var missing int
	err := s.r.QueryRow(`SELECT count(*) FROM current_runs c
		WHERE NOT EXISTS (SELECT 1 FROM run_stats_done d WHERE d.run_id = c.run_id AND d.version = ?)`, statsVersion).Scan(&missing)
	return err == nil && missing == 0
}

// statsKeys are the filters a run summary can answer: its own columns, and
// those that pick evidence items.
var statsKeys = map[string]bool{
	"source": true, "tz": true, "category": true, "host": true,
	"evidence": true, "from": true, "submission": true, "item": true, "kind": true,
}

// byStats says whether q can be counted from run summaries.
func (s *Store) byStats(q Query) bool {
	if s.noStats || q.From != 0 || q.To != 0 || q.Group != "" {
		return false
	}
	for _, t := range splitTerms(q.Text) {
		t = strings.TrimPrefix(t, "-")
		k, v, ok := strings.Cut(t, ":")
		k, v = strings.ToLower(k), strings.Trim(v, `"`)
		if !ok || strings.HasPrefix(t, `"`) || !statsKeys[k] || v == "" {
			return false
		}
		// These take an item number; anything else is searched as words.
		if k == "evidence" || k == "from" || k == "submission" {
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return false
			}
		}
	}
	return s.statsReady()
}

// sparse says whether so few events match q that the list is best read by
// the filter's own index and sorted, rather than by walking the timeline in
// time order until enough match. Walking costs about limit x total / matches
// rows; sorting costs about the matches. Only searches the run summaries can
// count are judged; for the rest the database's planner decides.
func (s *Store) sparse(q Query) bool {
	limit := int64(q.Limit)
	if limit <= 0 {
		limit = 500
	}
	plain := Query{Text: q.Text, EvidenceID: q.EvidenceID}
	if !s.byStats(plain) || (strings.TrimSpace(q.Text) == "" && q.EvidenceID == 0) {
		return false
	}
	c := plain.compile()
	var matches, total int64
	if err := s.r.QueryRow(`SELECT COALESCE(sum(e.n), 0)`+statsFrom+c.sql(), c.args...).Scan(&matches); err != nil {
		return false
	}
	if err := s.r.QueryRow(`SELECT COALESCE(sum(e.n), 0)` + statsFrom).Scan(&total); err != nil {
		return false
	}
	return matches*matches < 4*limit*total
}
