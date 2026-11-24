// Package store is the case database: an append-only SQLite file holding the
// evidence register, the normalised event timeline, extracted text, facts,
// examiner annotations and the hash-chained audit log.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ToolVersion is recorded with every parse run and in the audit log.
const ToolVersion = "0.2.0"

type Store struct {
	w     *sql.DB // single writer
	r     *sql.DB // readers
	mu    sync.Mutex
	Actor string
	// noStats makes every count read the events, for tests that compare
	// the two ways of counting.
	noStats bool
}

func dsn(path string, ro bool) string {
	// The path is escaped because it is part of a URI: a case directory
	// named "Case #4" or "50% done" would otherwise be cut short or misread.
	d := "file:" + url.PathEscape(path) + "?_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)&_pragma=recursive_triggers(1)"
	if ro {
		d += "&_pragma=query_only(1)"
	} else {
		// Take the write lock when a transaction begins, not at its first
		// write, so a read-then-append (the audit chain) cannot be interleaved.
		d += "&_txlock=immediate"
	}
	return d
}

// Open opens or creates the case database at path.
func Open(path, actor string) (*Store, error) {
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if _, err := w.Exec(schema); err != nil {
		w.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	// Added on 23 November 2026 without a new storage format: a case made
	// earlier gains the tables when opened, and holds no rows in them.
	if _, err := w.Exec(exclusionsSchema + statsSchema + hostsSchema + observablesSchema); err != nil {
		w.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	// run_stats gained a host column (summaries version 2); a table made
	// earlier gets it, and its version 1 rows are simply not used.
	var hasHost int
	w.QueryRow(`SELECT count(*) FROM pragma_table_info('run_stats') WHERE name = 'host'`).Scan(&hasHost)
	if hasHost == 0 {
		if _, err := w.Exec(`ALTER TABLE run_stats ADD COLUMN host TEXT NOT NULL DEFAULT ''`); err != nil {
			w.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	for _, t := range immutabilityTriggers() {
		if _, err := w.Exec(t); err != nil {
			w.Close()
			return nil, fmt.Errorf("triggers: %w", err)
		}
	}
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	s := &Store{w: w, r: r, Actor: actor}
	var n int
	if err := w.QueryRow(`SELECT count(*) FROM case_meta`).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		now := time.Now().UTC()
		if _, err := w.Exec(`INSERT INTO case_meta(key,value) VALUES ('created_utc',?),('created_by',?),('tool_version',?),('schema_version',?)`,
			now.Format(time.RFC3339Nano), actor, ToolVersion, SchemaVersion); err != nil {
			return nil, err
		}
		if err := s.Audit("case.create", path, map[string]any{"tool_version": ToolVersion}); err != nil {
			return nil, err
		}
	}
	var have string
	w.QueryRow(`SELECT value FROM case_meta WHERE key='schema_version'`).Scan(&have)
	if have != SchemaVersion {
		s.Close()
		if have == "" {
			have = "1"
		}
		return nil, fmt.Errorf("this case uses storage format %s and this version of Atropos uses format %s; it cannot be opened without invalidating its digests. Open it with the version that made it, or ingest the original evidence into a new case", have, SchemaVersion)
	}
	return s, nil
}

func (s *Store) Close() error {
	s.r.Close()
	return s.w.Close()
}

// ---------------------------------------------------------------- audit ----

func auditHash(prev string, id, ts int64, actor, action, target, details string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%d\n%d\n", prev, id, ts)
	for _, f := range []string{actor, action, target, details} {
		fmt.Fprintf(h, "%d:%s\n", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Audit appends an entry to the hash-chained audit log.
func (s *Store) Audit(action, target string, details any) error {
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var prev string
	var last int64
	err = tx.QueryRow(`SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&last, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	id := last + 1
	ts := time.Now().UTC().UnixNano()
	h := auditHash(prev, id, ts, s.Actor, action, target, string(b))
	if _, err := tx.Exec(`INSERT INTO audit(id,ts_utc,actor,action,target,details,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)`,
		id, ts, s.Actor, action, target, string(b), prev, h); err != nil {
		return err
	}
	return tx.Commit()
}

type AuditRow struct {
	ID      int64           `json:"id"`
	TS      int64           `json:"ts_utc,string"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Details json.RawMessage `json:"details"`
	Prev    string          `json:"prev_hash"`
	Hash    string          `json:"hash"`
}

func (s *Store) ListAudit(limit int) ([]AuditRow, error) {
	rows, err := s.r.Query(`SELECT id,ts_utc,actor,action,target,details,prev_hash,hash FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		var d string
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Target, &d, &a.Prev, &a.Hash); err != nil {
			return nil, err
		}
		a.Details = json.RawMessage(d)
		out = append(out, a)
	}
	return out, rows.Err()
}

// VerifyAudit walks the whole chain. It returns the number of entries, the
// head hash and the id of the first broken entry (0 if intact).
func (s *Store) VerifyAudit() (n int64, head string, brokenAt int64, err error) {
	rows, err := s.r.Query(`SELECT id,ts_utc,actor,action,target,details,prev_hash,hash FROM audit ORDER BY id`)
	if err != nil {
		return 0, "", 0, err
	}
	defer rows.Close()
	prev := ""
	var expectID int64 = 1
	for rows.Next() {
		var id, ts int64
		var actor, action, target, details, ph, h string
		if err := rows.Scan(&id, &ts, &actor, &action, &target, &details, &ph, &h); err != nil {
			return n, head, 0, err
		}
		if brokenAt == 0 && (id != expectID || ph != prev || auditHash(prev, id, ts, actor, action, target, details) != h) {
			brokenAt = id
		}
		prev, head = h, h
		expectID = id + 1
		n++
	}
	return n, head, brokenAt, rows.Err()
}

// ------------------------------------------------------------- evidence ----

type Evidence struct {
	ID           int64  `json:"id"`
	SHA256       string `json:"sha256"`
	SHA1         string `json:"sha1"`
	MD5          string `json:"md5"`
	Size         int64  `json:"size"`
	Name         string `json:"name"`
	Origin       string `json:"origin"`
	ParentID     *int64 `json:"parent_id"`
	BatchID      int64  `json:"batch_id"`
	Depth        int    `json:"depth"`
	Kind         string `json:"kind"`
	DetectReason string `json:"detect_reason"`
	DuplicateOf  *int64 `json:"duplicate_of"`
	ReceivedUTC  int64  `json:"received_utc,string"`
	ReceivedBy   string `json:"received_by"`

	// Joined from the current run, when listing.
	Status string `json:"status"`
	Parser string `json:"parser"`
	// ParserVersion is the version of the parser that made the run shown.
	ParserVersion string `json:"parser_version"`
	// Stale is set, when listing for the interface, to why this build of
	// Atropos would read the item differently from the run shown. It is
	// worked out from the parsers in the running program, not stored.
	Stale      string `json:"stale,omitempty"`
	EventCount int64  `json:"event_count"`
	Notes      string `json:"notes"`
	ZoneCtx    string `json:"zone_context"`
	// Excluded is set when the item, or the item it came out of
	// (ExcludedBy), has been excluded from the case's view.
	Excluded      bool   `json:"excluded,omitempty"`
	ExcludedBy    int64  `json:"excluded_by,omitempty"`
	ExcludeReason string `json:"exclude_reason,omitempty"`
	// Assigned is where its submission came from: a host, or no host and a
	// stated source; nil when the submission was never assigned.
	Assigned *Assignment `json:"assigned,omitempty"`
}

func (s *Store) AddEvidence(e *Evidence) error {
	e.ReceivedUTC = time.Now().UTC().UnixNano()
	e.ReceivedBy = s.Actor
	res, err := s.w.Exec(`INSERT INTO evidence(sha256,sha1,md5,size,name,origin,parent_id,batch_id,depth,kind,detect_reason,duplicate_of,received_utc,received_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.SHA256, e.SHA1, e.MD5, e.Size, e.Name, e.Origin, e.ParentID, e.BatchID, e.Depth, e.Kind, e.DetectReason, e.DuplicateOf, e.ReceivedUTC, e.ReceivedBy)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// FirstBySHA returns the earliest evidence row with this content hash.
func (s *Store) FirstBySHA(sha string) (int64, bool) {
	var id int64
	err := s.w.QueryRow(`SELECT id FROM evidence WHERE sha256=? AND duplicate_of IS NULL ORDER BY id LIMIT 1`, sha).Scan(&id)
	return id, err == nil
}

func (s *Store) GetEvidence(id int64) (*Evidence, error) {
	list, err := s.listEvidence(`WHERE e.id = ?`, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, sql.ErrNoRows
	}
	return &list[0], nil
}

func (s *Store) ListEvidence() ([]Evidence, error) { return s.listEvidence(``) }

func (s *Store) listEvidence(where string, args ...any) ([]Evidence, error) {
	rows, err := s.r.Query(`SELECT e.id,e.sha256,e.sha1,e.md5,e.size,e.name,e.origin,e.parent_id,e.batch_id,e.depth,e.kind,e.detect_reason,e.duplicate_of,e.received_utc,e.received_by,
		COALESCE(rr.status, CASE WHEN e.duplicate_of IS NOT NULL THEN 'duplicate' WHEN r.id IS NULL THEN 'queued' ELSE 'processing' END),
		COALESCE(r.parser,''), COALESCE(r.parser_version,''), COALESCE(rr.event_count,0), COALESCE(rr.notes,''), COALESCE(r.zone_context,'')
		FROM evidence e
		LEFT JOIN current_runs c ON c.evidence_id = e.id
		LEFT JOIN runs r ON r.id = c.run_id
		LEFT JOIN run_results rr ON rr.run_id = r.id `+where+` ORDER BY e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Evidence{}
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.SHA256, &e.SHA1, &e.MD5, &e.Size, &e.Name, &e.Origin, &e.ParentID, &e.BatchID, &e.Depth, &e.Kind, &e.DetectReason, &e.DuplicateOf, &e.ReceivedUTC, &e.ReceivedBy,
			&e.Status, &e.Parser, &e.ParserVersion, &e.EventCount, &e.Notes, &e.ZoneCtx); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := s.markHosts(out); err != nil {
		return nil, err
	}
	return out, s.markExcluded(out)
}

// ----------------------------------------------------------------- runs ----

// Event is one normalised timeline entry produced by a parser.
type Event struct {
	TSUTC     int64
	TSType    string
	TSRaw     string
	TZSource  string
	TZName    string
	MACB      string // "M...", ".A..", "..C.", "...B", a combination, or "...."
	Category  string
	Source    string
	Host      string
	User      string
	Path      string
	Message   string
	Fields    string // JSON object
	RecordRef string
}

// canonical feeds the event to a digest. Every field is length-prefixed, so
// no two different events (or sequences of events) share an encoding however
// their text is arranged.
func (e *Event) canonical(h hash.Hash) {
	fmt.Fprintf(h, "%d\n", e.TSUTC)
	for _, f := range []string{e.TSType, e.TSRaw, e.TZSource, e.TZName, e.MACB, e.Category, e.Source, e.Host, e.User, e.Path, e.Message, e.Fields, e.RecordRef} {
		fmt.Fprintf(h, "%d:%s\n", len(f), f)
	}
}

// Run is one parse of one evidence item. Events are buffered and written in
// batches; a running SHA-256 over them becomes the run's event digest.
type Run struct {
	s          *Store
	ID         int64
	EvidenceID int64
	buf        []Event
	count      int64
	digest     hash.Hash
}

const batchSize = 4000

func (s *Store) BeginRun(evidenceID int64, parser, parserVersion, zoneCtx string) (*Run, error) {
	res, err := s.w.Exec(`INSERT INTO runs(evidence_id,parser,parser_version,tool_version,started_utc,zone_context) VALUES (?,?,?,?,?,?)`,
		evidenceID, parser, parserVersion, ToolVersion, time.Now().UTC().UnixNano(), zoneCtx)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if _, err := s.w.Exec(`INSERT INTO current_runs(evidence_id,run_id) VALUES (?,?)
		ON CONFLICT(evidence_id) DO UPDATE SET run_id=excluded.run_id`, evidenceID, id); err != nil {
		return nil, err
	}
	return &Run{s: s, ID: id, EvidenceID: evidenceID, digest: sha256.New()}, nil
}

func (r *Run) Add(e Event) error {
	if e.Fields == "" {
		e.Fields = "{}"
	}
	if e.MACB == "" {
		e.MACB = "...."
	}
	r.buf = append(r.buf, e)
	if len(r.buf) >= batchSize {
		return r.flush()
	}
	return nil
}

func (r *Run) Count() int64 { return r.count + int64(len(r.buf)) }

func (r *Run) flush() error {
	if len(r.buf) == 0 {
		return nil
	}
	tx, err := r.s.w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins, err := tx.Prepare(`INSERT INTO events(run_id,evidence_id,ts_utc,ts_type,ts_raw,tz_source,tz_name,macb,category,source,host,user,path,message,fields,record_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	fts, err := tx.Prepare(`INSERT INTO events_fts(rowid,message,path,host,user,fields,source,ts_type) VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer fts.Close()
	for i := range r.buf {
		e := &r.buf[i]
		res, err := ins.Exec(r.ID, r.EvidenceID, e.TSUTC, e.TSType, e.TSRaw, e.TZSource, e.TZName, e.MACB, e.Category, e.Source, e.Host, e.User, e.Path, e.Message, e.Fields, e.RecordRef)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		if _, err := fts.Exec(id, e.Message, e.Path, e.Host, e.User, e.Fields, e.Source, e.TSType); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for i := range r.buf {
		r.buf[i].canonical(r.digest)
	}
	r.count += int64(len(r.buf))
	r.buf = r.buf[:0]
	return nil
}

// Finish seals the run: flushes events and records status and event digest.
func (r *Run) Finish(status, notes string) (digest string, err error) {
	if err := r.flush(); err != nil {
		return "", err
	}
	digest = hex.EncodeToString(r.digest.Sum(nil))
	_, err = r.s.w.Exec(`INSERT INTO run_results(run_id,status,event_count,event_digest,notes,finished_utc) VALUES (?,?,?,?,?,?)`,
		r.ID, status, r.count, digest, notes, time.Now().UTC().UnixNano())
	if err != nil {
		return digest, err
	}
	// The run is sealed: count it once for the chips, totals and chart, and
	// take out what its events involve, for the links between hosts.
	if err := r.s.computeStats(r.ID); err != nil {
		return digest, err
	}
	return digest, r.s.computeObservables(r.ID)
}

// VerifyRuns recomputes each sealed run's event digest from the stored rows.
func (s *Store) VerifyRuns() (checked int, bad []int64, err error) {
	rows, err := s.r.Query(`SELECT run_id, event_count, event_digest FROM run_results ORDER BY run_id`)
	if err != nil {
		return 0, nil, err
	}
	type rr struct {
		id, n  int64
		digest string
	}
	var all []rr
	for rows.Next() {
		var x rr
		if err := rows.Scan(&x.id, &x.n, &x.digest); err != nil {
			rows.Close()
			return 0, nil, err
		}
		all = append(all, x)
	}
	rows.Close()
	for _, x := range all {
		h := sha256.New()
		var n int64
		er, err := s.r.Query(`SELECT ts_utc,ts_type,ts_raw,tz_source,tz_name,macb,category,source,host,user,path,message,fields,record_ref FROM events WHERE run_id=? ORDER BY id`, x.id)
		if err != nil {
			return checked, bad, err
		}
		for er.Next() {
			var e Event
			if err := er.Scan(&e.TSUTC, &e.TSType, &e.TSRaw, &e.TZSource, &e.TZName, &e.MACB, &e.Category, &e.Source, &e.Host, &e.User, &e.Path, &e.Message, &e.Fields, &e.RecordRef); err != nil {
				er.Close()
				return checked, bad, err
			}
			e.canonical(h)
			n++
		}
		er.Close()
		if n != x.n || hex.EncodeToString(h.Sum(nil)) != x.digest {
			bad = append(bad, x.id)
		}
		checked++
	}
	return checked, bad, nil
}

// SealInterrupted closes parse runs that were begun and never sealed, which
// is what a crash, a kill or a power cut leaves behind. Whatever events such
// a run had stored are kept and digested, the run is marked "interrupted",
// and the fact is audited. It must only be called by the process holding the
// case lock, when nothing is being parsed. It returns the runs it sealed.
func (s *Store) SealInterrupted() ([]int64, error) {
	rows, err := s.w.Query(`SELECT r.id, r.evidence_id FROM runs r LEFT JOIN run_results rr ON rr.run_id = r.id WHERE rr.run_id IS NULL ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	type open struct{ run, evidence int64 }
	var list []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.run, &o.evidence); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var sealed []int64
	for _, o := range list {
		h := sha256.New()
		var n int64
		er, err := s.w.Query(`SELECT ts_utc,ts_type,ts_raw,tz_source,tz_name,macb,category,source,host,user,path,message,fields,record_ref FROM events WHERE run_id=? ORDER BY id`, o.run)
		if err != nil {
			return sealed, err
		}
		for er.Next() {
			var e Event
			if err := er.Scan(&e.TSUTC, &e.TSType, &e.TSRaw, &e.TZSource, &e.TZName, &e.MACB, &e.Category, &e.Source, &e.Host, &e.User, &e.Path, &e.Message, &e.Fields, &e.RecordRef); err != nil {
				er.Close()
				return sealed, err
			}
			e.canonical(h)
			n++
		}
		er.Close()
		digest := hex.EncodeToString(h.Sum(nil))
		const note = "Atropos stopped before this parse finished. The events it had stored are kept, but the result is incomplete: parse this item again."
		if _, err := s.w.Exec(`INSERT INTO run_results(run_id,status,event_count,event_digest,notes,finished_utc) VALUES (?,?,?,?,?,?)`,
			o.run, "interrupted", n, digest, note, time.Now().UTC().UnixNano()); err != nil {
			return sealed, err
		}
		if err := s.Audit("parse.interrupted", fmt.Sprintf("evidence:%d", o.evidence), map[string]any{
			"run": o.run, "status": "interrupted", "events": n, "event_digest": digest,
		}); err != nil {
			return sealed, err
		}
		sealed = append(sealed, o.run)
	}
	return sealed, nil
}

// VerifyRunsAudited compares the sealed runs with what the audit log recorded
// when each was sealed. A run's own digest only proves its events match its
// result row; someone able to rewrite both, or to remove a run entirely,
// would pass that check. The audit chain is the independent witness.
//
// unaudited lists sealed runs with no audit entry agreeing on digest, status
// and event count. missing lists runs the audit log sealed that are no longer
// in the database.
func (s *Store) VerifyRunsAudited() (unaudited, missing []int64, err error) {
	type sealed struct {
		digest, status string
		events         int64
	}
	audited := map[int64]sealed{}
	var order []int64
	rows, err := s.r.Query(`SELECT details FROM audit WHERE action IN ('parse.complete','container.unpack','parse.interrupted') ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, nil, err
		}
		var d struct {
			Run    int64  `json:"run"`
			Digest string `json:"event_digest"`
			Status string `json:"status"`
			Events int64  `json:"events"`
		}
		if json.Unmarshal([]byte(raw), &d) != nil || d.Run == 0 {
			continue // an unreadable entry is a broken chain, reported by VerifyAudit
		}
		if _, dup := audited[d.Run]; !dup {
			order = append(order, d.Run)
		}
		audited[d.Run] = sealed{d.Digest, d.Status, d.Events}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	present := map[int64]bool{}
	rows, err = s.r.Query(`SELECT run_id, event_digest, status, event_count FROM run_results ORDER BY run_id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var got sealed
		if err := rows.Scan(&id, &got.digest, &got.status, &got.events); err != nil {
			return nil, nil, err
		}
		present[id] = true
		if want, ok := audited[id]; !ok || want != got {
			unaudited = append(unaudited, id)
		}
	}
	for _, id := range order {
		if !present[id] {
			missing = append(missing, id)
		}
	}
	return unaudited, missing, rows.Err()
}

// ------------------------------------------------------- text and facts ----

func (s *Store) AddText(evidenceID int64, method string, truncated bool, body string) error {
	tx, err := s.w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO evidence_text(evidence_id,method,truncated,body) VALUES (?,?,?,?)`, evidenceID, method, truncated, body); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO evidence_text_fts(rowid,body) VALUES (?,?)`, evidenceID, body); err != nil {
		return err
	}
	return tx.Commit()
}

type Fact struct {
	ID         int64  `json:"id"`
	EvidenceID int64  `json:"evidence_id"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	Detail     string `json:"detail"`
	NotedUTC   int64  `json:"noted_utc,string"`
}

func (s *Store) AddFact(evidenceID int64, key, value, detail string) error {
	_, err := s.w.Exec(`INSERT INTO facts(evidence_id,key,value,detail,noted_utc) VALUES (?,?,?,?,?)`,
		evidenceID, key, value, detail, time.Now().UTC().UnixNano())
	return err
}

// NextBatch allocates a batch number for a group of files submitted together.
func (s *Store) NextBatch() (int64, error) {
	var n int64
	err := s.w.QueryRow(`SELECT COALESCE(MAX(batch_id),0)+1 FROM evidence`).Scan(&n)
	return n, err
}

// BatchFacts returns the distinct values of a fact established by evidence in
// one batch (for example the host time zone read from that batch's SYSTEM hive).
func (s *Store) BatchFacts(batchID int64, key string) ([]string, error) {
	rows, err := s.w.Query(`SELECT DISTINCT f.value FROM facts f JOIN evidence e ON e.id=f.evidence_id WHERE e.batch_id=? AND f.key=? ORDER BY f.value`, batchID, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestFact returns the most recently recorded value of a fact.
func (s *Store) LatestFact(key string) (string, bool) {
	var v string
	err := s.w.QueryRow(`SELECT value FROM facts WHERE key=? ORDER BY id DESC LIMIT 1`, key).Scan(&v)
	return v, err == nil
}

func (s *Store) Facts(key string) ([]Fact, error) {
	q := `SELECT id,evidence_id,key,value,detail,noted_utc FROM facts`
	var args []any
	if key != "" {
		q += ` WHERE key=?`
		args = append(args, key)
	}
	// The writer handle is used so facts written moments ago by the same
	// ingest batch are always visible.
	rows, err := s.w.Query(q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Fact{}
	for rows.Next() {
		var f Fact
		if err := rows.Scan(&f.ID, &f.EvidenceID, &f.Key, &f.Value, &f.Detail, &f.NotedUTC); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------- annotations ----

type Annotation struct {
	ID        int64  `json:"id"`
	EventID   int64  `json:"event_id"`
	Kind      string `json:"kind"`
	Body      string `json:"body"`
	RefersTo  *int64 `json:"refers_to"`
	Actor     string `json:"actor"`
	MadeUTC   int64  `json:"made_utc,string"`
	Retracted bool   `json:"retracted"`
}

// Annotate appends an examiner note. Notes live in their own layer and never
// alter evidence or events; a note is withdrawn by appending a retraction.
func (s *Store) Annotate(eventID int64, kind, body string, refersTo *int64) (int64, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind != "tag" && kind != "comment" && kind != "retract" {
		// Group membership is written in bulk by AddToGroup, which audits once.
		return 0, fmt.Errorf("unknown annotation kind %q", kind)
	}
	if kind == "retract" && refersTo == nil {
		return 0, errors.New("a retraction must refer to an annotation")
	}
	res, err := s.w.Exec(`INSERT INTO annotations(event_id,kind,body,refers_to,actor,made_utc) VALUES (?,?,?,?,?,?)`,
		eventID, kind, strings.TrimSpace(body), refersTo, s.Actor, time.Now().UTC().UnixNano())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, s.Audit("annotation."+kind, fmt.Sprintf("event:%d", eventID), map[string]any{"annotation_id": id, "body": body, "refers_to": refersTo})
}

func (s *Store) Annotations(eventID int64) ([]Annotation, error) {
	rows, err := s.r.Query(`SELECT a.id,a.event_id,a.kind,a.body,a.refers_to,a.actor,a.made_utc,
		EXISTS(SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id)
		FROM annotations a WHERE a.event_id=? ORDER BY a.id`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Annotation{}
	for rows.Next() {
		var a Annotation
		if err := rows.Scan(&a.ID, &a.EventID, &a.Kind, &a.Body, &a.RefersTo, &a.Actor, &a.MadeUTC, &a.Retracted); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Meta returns the case metadata.
func (s *Store) Meta() (map[string]string, error) {
	rows, err := s.r.Query(`SELECT key,value FROM case_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

// RawWriter exposes the writer handle for tests that prove immutability.
func (s *Store) RawWriter() *sql.DB { return s.w }
