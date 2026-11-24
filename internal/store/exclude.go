package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Excluding an item takes it out of the case's view without removing
// anything: the file stays in the vault, its runs and events stay stored and
// verifiable, and the decision is a row in the append-only exclusions table
// (with the examiner's reason) and an audit entry. The latest row for an item
// says whether it is excluded; including it again is another row. An
// excluded item takes everything that came out of it (the files copied out
// of an image, an archive's members) with it.
//
// Events of excluded items are left out wherever events are read for the
// examiner (eventFrom), and their text is left out of text searches and the
// checks over file text. Verify still checks every run.

const exclusionsSchema = `
CREATE TABLE IF NOT EXISTS exclusions (
  id          INTEGER PRIMARY KEY,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  action      TEXT NOT NULL CHECK (action IN ('exclude', 'include')),
  reason      TEXT NOT NULL,
  actor       TEXT NOT NULL,
  made_utc    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS exclusions_evidence ON exclusions(evidence_id, id);

-- Every item now out of the case's view: those whose latest row excludes
-- them, and everything that came out of them, at any depth.
CREATE VIEW IF NOT EXISTS excluded_evidence AS
WITH RECURSIVE tree(evidence_id) AS (
  SELECT x.evidence_id FROM exclusions x
    WHERE x.action = 'exclude' AND x.id = (SELECT max(y.id) FROM exclusions y WHERE y.evidence_id = x.evidence_id)
  UNION
  SELECT e.id FROM evidence e JOIN tree t ON e.parent_id = t.evidence_id
)
SELECT evidence_id FROM tree;
`

// notExcluded is a condition on an evidence id column.
const notExcluded = ` NOT IN (SELECT evidence_id FROM excluded_evidence)`

// SetExcluded excludes an item from the case's view, or includes it again.
// A reason is required to exclude.
func (s *Store) SetExcluded(evidenceID int64, exclude bool, reason string) error {
	reason = strings.TrimSpace(reason)
	if exclude && reason == "" {
		return errors.New("say why the item is being excluded: the reason is kept in the case")
	}
	e, err := s.GetEvidence(evidenceID)
	if err != nil {
		return fmt.Errorf("no such evidence item")
	}
	if e.Excluded && e.ExcludedBy != e.ID {
		return fmt.Errorf("this item is excluded with #%d, which it came out of; include that item instead", e.ExcludedBy)
	}
	if exclude == (e.Excluded && e.ExcludedBy == e.ID) {
		return nil // already so
	}
	action := "include"
	if exclude {
		action = "exclude"
	}
	if _, err := s.w.Exec(`INSERT INTO exclusions(evidence_id,action,reason,actor,made_utc) VALUES (?,?,?,?,?)`,
		evidenceID, action, reason, s.Actor, time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	return s.Audit("evidence."+action, fmt.Sprintf("evidence:%d", evidenceID), map[string]any{"reason": reason})
}

// markExcluded fills in each listed item's exclusion: its own, or the one of
// the item it came out of.
func (s *Store) markExcluded(list []Evidence) error {
	rows, err := s.r.Query(`SELECT evidence_id, action, reason FROM exclusions ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	own := map[int64]string{} // excluded item -> reason
	for rows.Next() {
		var id int64
		var action, reason string
		if err := rows.Scan(&id, &action, &reason); err != nil {
			return err
		}
		if action == "exclude" {
			own[id] = reason
		} else {
			delete(own, id)
		}
	}
	if err := rows.Err(); err != nil || len(own) == 0 {
		return err
	}
	parent := map[int64]*int64{}
	for i := range list {
		parent[list[i].ID] = list[i].ParentID
	}
	// A listing of one item does not hold its parents: read them.
	lookup := func(id int64) (*int64, bool) {
		if p, ok := parent[id]; ok {
			return p, true
		}
		var p *int64
		if err := s.r.QueryRow(`SELECT parent_id FROM evidence WHERE id = ?`, id).Scan(&p); err != nil {
			return nil, false
		}
		parent[id] = p
		return p, true
	}
	for i := range list {
		id := list[i].ID
		for depth := 0; depth < 64; depth++ {
			if reason, ok := own[id]; ok {
				list[i].Excluded, list[i].ExcludedBy, list[i].ExcludeReason = true, id, reason
				break
			}
			p, ok := lookup(id)
			if !ok || p == nil {
				break
			}
			id = *p
		}
	}
	return nil
}
