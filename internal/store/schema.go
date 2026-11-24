package store

// The schema enforces write-once semantics in the database itself.
//
// Evidence, parse runs, run results, events, extracted text, facts,
// annotations and the audit log are append-only: triggers abort any UPDATE or
// DELETE. Corrections are made by appending (a new parse run supersedes an old
// one; an annotation is retracted by a later annotation), never by rewriting.
//
// Triggers stop the application and casual edits. They cannot stop someone
// with write access to the file from removing the triggers first, which is why
// integrity does not rest on them alone: every evidence file is hashed, every
// run records a digest of the events it produced, and every audit entry is
// chained to the one before it. `verify` recomputes all three.
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS case_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS evidence (
  id            INTEGER PRIMARY KEY,
  sha256        TEXT NOT NULL,
  sha1          TEXT NOT NULL,
  md5           TEXT NOT NULL,
  size          INTEGER NOT NULL,
  name          TEXT NOT NULL,      -- file name as submitted
  origin        TEXT NOT NULL,      -- submitted path, or path inside its container
  parent_id     INTEGER REFERENCES evidence(id),
  batch_id      INTEGER NOT NULL,   -- files submitted together share a batch
  depth         INTEGER NOT NULL DEFAULT 0,
  kind          TEXT NOT NULL,      -- detected artefact type
  detect_reason TEXT NOT NULL,      -- why it was identified as that type
  duplicate_of  INTEGER REFERENCES evidence(id),
  received_utc  INTEGER NOT NULL,   -- unix nanoseconds
  received_by   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_sha ON evidence(sha256);

CREATE TABLE IF NOT EXISTS runs (
  id             INTEGER PRIMARY KEY,
  evidence_id    INTEGER NOT NULL REFERENCES evidence(id),
  parser         TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  tool_version   TEXT NOT NULL,
  started_utc    INTEGER NOT NULL,
  zone_context   TEXT NOT NULL      -- zone applied to zoneless local times in this run
);

CREATE TABLE IF NOT EXISTS run_results (
  run_id       INTEGER PRIMARY KEY REFERENCES runs(id),
  status       TEXT NOT NULL,       -- parsed | generic | partial | failed
  event_count  INTEGER NOT NULL,
  event_digest TEXT NOT NULL,       -- SHA-256 over the run's events in order
  notes        TEXT NOT NULL,
  finished_utc INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY,
  run_id      INTEGER NOT NULL REFERENCES runs(id),
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  ts_utc      INTEGER NOT NULL,     -- unix nanoseconds, always UTC
  ts_type     TEXT NOT NULL,        -- what the timestamp means
  ts_raw      TEXT NOT NULL,        -- the value as found in the source
  tz_source   TEXT NOT NULL,        -- native-utc | explicit-offset | host-registry | assumed
  tz_name     TEXT NOT NULL,
  macb        TEXT NOT NULL,        -- which of Modified/Accessed/Changed/Born this time is; "...." if none
  category    TEXT NOT NULL,        -- what the event is evidence of, e.g. execution, account
  source      TEXT NOT NULL,        -- artefact family, e.g. evtx, registry, mft
  host        TEXT NOT NULL,
  user        TEXT NOT NULL,
  path        TEXT NOT NULL,
  message     TEXT NOT NULL,
  fields      TEXT NOT NULL,        -- JSON object of parsed fields
  record_ref  TEXT NOT NULL         -- where in the source file this came from
);
CREATE INDEX IF NOT EXISTS events_ts  ON events(ts_utc, id);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id, id);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  message, path, host, user, fields, source, ts_type,
  content='events', content_rowid='id', tokenize="unicode61 tokenchars '_$'"
);

CREATE TABLE IF NOT EXISTS evidence_text (
  evidence_id INTEGER PRIMARY KEY REFERENCES evidence(id),
  method      TEXT NOT NULL,
  truncated   INTEGER NOT NULL,
  body        TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS evidence_text_fts USING fts5(
  body, content='evidence_text', content_rowid='evidence_id', tokenize="unicode61 tokenchars '_$'"
);

CREATE TABLE IF NOT EXISTS facts (
  id          INTEGER PRIMARY KEY,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  key         TEXT NOT NULL,        -- e.g. host.name, host.timezone
  value       TEXT NOT NULL,
  detail      TEXT NOT NULL,
  noted_utc   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS annotations (
  id        INTEGER PRIMARY KEY,
  event_id  INTEGER NOT NULL REFERENCES events(id),
  kind      TEXT NOT NULL,          -- tag | comment | group | retract
  body      TEXT NOT NULL,
  refers_to INTEGER REFERENCES annotations(id),
  actor     TEXT NOT NULL,
  made_utc  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS annotations_event ON annotations(event_id);
CREATE INDEX IF NOT EXISTS annotations_kind ON annotations(kind, body);

-- Named timelines the examiner builds from the main one. Membership is an
-- annotation of kind 'group' whose body is the group's name, so adding and
-- removing events never touches an event. A group is archived by appending a
-- row that points at it.
CREATE TABLE IF NOT EXISTS groups (
  id       INTEGER PRIMARY KEY,
  name     TEXT NOT NULL,
  note     TEXT NOT NULL,
  archives INTEGER REFERENCES groups(id),
  actor    TEXT NOT NULL,
  made_utc INTEGER NOT NULL
);

-- What the examiner states about the case (host '') and about each host, for
-- the report. A new value is a new row; the latest row for a field is the
-- current one, and an empty value withdraws it.
CREATE TABLE IF NOT EXISTS details (
  id       INTEGER PRIMARY KEY,
  host     TEXT NOT NULL,
  field    TEXT NOT NULL,
  value    TEXT NOT NULL,
  actor    TEXT NOT NULL,
  made_utc INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
  id        INTEGER PRIMARY KEY,
  ts_utc    INTEGER NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT NOT NULL,
  details   TEXT NOT NULL,          -- JSON
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);

-- Derived index: which run is the current one for each evidence item. It is
-- rebuildable from runs and holds no evidence, so it is the one mutable table.
CREATE TABLE IF NOT EXISTS current_runs (
  evidence_id INTEGER PRIMARY KEY,
  run_id      INTEGER NOT NULL
) WITHOUT ROWID;
`

var appendOnlyTables = []string{
	"case_meta", "evidence", "runs", "run_results", "events", "evidence_text",
	"facts", "annotations", "groups", "details", "audit", "exclusions",
	"run_stats", "run_stats_done", "hosts", "batch_hosts", "observables", "observables_done",
}

// SchemaVersion is recorded in a new case and checked when one is opened.
// It changes whenever stored rows or digests would no longer be understood.
const SchemaVersion = "2"

func immutabilityTriggers() []string {
	var out []string
	for _, t := range appendOnlyTables {
		out = append(out,
			`CREATE TRIGGER IF NOT EXISTS `+t+`_no_update BEFORE UPDATE ON `+t+
				` BEGIN SELECT RAISE(ABORT, 'immutable: `+t+` is append-only'); END;`,
			`CREATE TRIGGER IF NOT EXISTS `+t+`_no_delete BEFORE DELETE ON `+t+
				` BEGIN SELECT RAISE(ABORT, 'immutable: `+t+` is append-only'); END;`,
		)
	}
	return out
}
