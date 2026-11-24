package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// A group is a named timeline the examiner builds out of the main one: pick
// the events that tell one part of the story ("Malware", "Exfiltration") and
// view, export or report on just those. Groups live entirely in the notes
// layer. Membership is an annotation, removal is a retraction, and no event
// is ever changed by being picked.

type Group struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Note    string `json:"note"`
	Actor   string `json:"actor"`
	MadeUTC int64  `json:"made_utc,string"`
	Count   int64  `json:"count"` // events on the current timeline in this group
}

const maxGroupName = 60

func cleanGroupName(name string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "", errors.New("a group needs a name")
	}
	if len([]rune(name)) > maxGroupName {
		return "", fmt.Errorf("group names are limited to %d characters", maxGroupName)
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '"' {
			return "", errors.New(`group names cannot contain control characters or double quotes`)
		}
	}
	return name, nil
}

const openGroups = `FROM groups g WHERE g.archives IS NULL AND NOT EXISTS (SELECT 1 FROM groups x WHERE x.archives = g.id)`

// Groups lists the groups that have not been archived, oldest first.
func (s *Store) Groups() ([]Group, error) {
	rows, err := s.r.Query(`SELECT g.id, g.name, g.note, g.actor, g.made_utc,
		(SELECT count(DISTINCT a.event_id) FROM annotations a
			JOIN events e ON e.id = a.event_id JOIN current_runs c ON c.run_id = e.run_id AND c.evidence_id` + notExcluded + `
			WHERE a.kind='group' AND a.body = g.name COLLATE NOCASE
			AND NOT EXISTS (SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id)) ` + openGroups + ` ORDER BY g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Note, &g.Actor, &g.MadeUTC, &g.Count); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupByID returns an open group.
func (s *Store) GroupByID(id int64) (*Group, error) {
	var g Group
	err := s.w.QueryRow(`SELECT g.id, g.name, g.note, g.actor, g.made_utc `+openGroups+` AND g.id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Note, &g.Actor, &g.MadeUTC)
	if err != nil {
		return nil, errors.New("no such group")
	}
	return &g, nil
}

// CreateGroup adds a named group. Names are unique among open groups,
// ignoring case.
func (s *Store) CreateGroup(name, note string) (*Group, error) {
	name, err := cleanGroupName(name)
	if err != nil {
		return nil, err
	}
	var n int
	if err := s.w.QueryRow(`SELECT count(*) `+openGroups+` AND g.name = ? COLLATE NOCASE`, name).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, fmt.Errorf("there is already a group called %q", name)
	}
	g := &Group{Name: name, Note: strings.TrimSpace(note), Actor: s.Actor, MadeUTC: time.Now().UTC().UnixNano()}
	res, err := s.w.Exec(`INSERT INTO groups(name,note,archives,actor,made_utc) VALUES (?,?,NULL,?,?)`, g.Name, g.Note, g.Actor, g.MadeUTC)
	if err != nil {
		return nil, err
	}
	g.ID, _ = res.LastInsertId()
	return g, s.Audit("group.create", "group:"+g.Name, map[string]any{"group_id": g.ID, "note": g.Note})
}

// ArchiveGroup hides a group from the list. Nothing is removed: the group,
// its memberships and this action all stay in the case and the audit log.
// Creating a group with the same name later brings its events back.
func (s *Store) ArchiveGroup(id int64) error {
	g, err := s.GroupByID(id)
	if err != nil {
		return err
	}
	if _, err := s.w.Exec(`INSERT INTO groups(name,note,archives,actor,made_utc) VALUES (?,?,?,?,?)`,
		g.Name, "archived", g.ID, s.Actor, time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	return s.Audit("group.archive", "group:"+g.Name, map[string]any{"group_id": g.ID})
}

func auditIDs(ids []int64) any {
	if len(ids) > 200 {
		return fmt.Sprintf("%d events; too many to list here, see the annotations table", len(ids))
	}
	return ids
}

// AddToGroup puts events in a group. Events already in it, and ids that are
// not events, are skipped. It returns how many were added. The whole call is
// one transaction and one audit entry.
func (s *Store) AddToGroup(name string, ids []int64, how string) (int64, error) {
	tx, err := s.w.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	ins, err := tx.Prepare(`INSERT INTO annotations(event_id,kind,body,refers_to,actor,made_utc)
		SELECT ?, 'group', ?, NULL, ?, ? WHERE EXISTS (SELECT 1 FROM events WHERE id = ?)
		AND NOT EXISTS (SELECT 1 FROM annotations a WHERE a.event_id = ? AND a.kind='group' AND a.body = ? COLLATE NOCASE
			AND NOT EXISTS (SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id))`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()
	now := time.Now().UTC().UnixNano()
	var added int64
	for _, id := range ids {
		res, err := ins.Exec(id, name, s.Actor, now, id, id, name)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		added += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, s.Audit("group.add", "group:"+name, map[string]any{"added": added, "requested": len(ids), "events": auditIDs(ids), "how": how})
}

// RemoveFromGroup takes events out of a group by retracting their membership.
func (s *Store) RemoveFromGroup(name string, ids []int64) (int64, error) {
	tx, err := s.w.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	ins, err := tx.Prepare(`INSERT INTO annotations(event_id,kind,body,refers_to,actor,made_utc)
		SELECT a.event_id, 'retract', '', a.id, ?, ? FROM annotations a
		WHERE a.event_id = ? AND a.kind='group' AND a.body = ? COLLATE NOCASE
		AND NOT EXISTS (SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id)`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()
	now := time.Now().UTC().UnixNano()
	var removed int64
	for _, id := range ids {
		res, err := ins.Exec(s.Actor, now, id, name)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return removed, s.Audit("group.remove", "group:"+name, map[string]any{"removed": removed, "requested": len(ids), "events": auditIDs(ids)})
}

// MatchingIDs returns the ids of events matching q, in time order, stopping
// with an error if there are more than max. It is how "add everything this
// search shows" is turned into a list.
func (s *Store) MatchingIDs(q Query, max int) ([]int64, error) {
	c := q.compile()
	rows, err := s.r.Query(`SELECT e.id`+eventFrom+c.sql()+` ORDER BY e.ts_utc, e.id LIMIT ?`, append(c.args, max+1)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if len(ids) > max {
		return nil, fmt.Errorf("this search matches more than %d events; narrow it before adding everything to a group", max)
	}
	return ids, rows.Err()
}

// TagEvents gives events a tag. Events that already carry it, and ids that
// are not events, are skipped. It returns how many were tagged. The whole
// call is one transaction and one audit entry.
func (s *Store) TagEvents(tag string, ids []int64, how string) (int64, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" || len(tag) > 100 {
		return 0, errors.New("a tag needs between 1 and 100 characters")
	}
	tx, err := s.w.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	ins, err := tx.Prepare(`INSERT INTO annotations(event_id,kind,body,refers_to,actor,made_utc)
		SELECT ?, 'tag', ?, NULL, ?, ? WHERE EXISTS (SELECT 1 FROM events WHERE id = ?)
		AND NOT EXISTS (SELECT 1 FROM annotations a WHERE a.event_id = ? AND a.kind='tag' AND a.body = ? COLLATE NOCASE
			AND NOT EXISTS (SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id))`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()
	now := time.Now().UTC().UnixNano()
	var added int64
	for _, id := range ids {
		res, err := ins.Exec(id, tag, s.Actor, now, id, id, tag)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		added += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, s.Audit("tag.add", "tag:"+tag, map[string]any{"added": added, "requested": len(ids), "events": auditIDs(ids), "how": how})
}
