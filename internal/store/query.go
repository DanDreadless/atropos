package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Query describes a timeline search. All times are unix nanoseconds UTC.
type Query struct {
	Text       string // free text plus key:value filters
	From, To   int64  // 0 = unbounded
	EvidenceID int64
	Group      string // show only events in this named group
	AfterTS    int64  // keyset cursor
	AfterID    int64
	Limit      int
	Desc       bool
}

type EventRow struct {
	ID         int64           `json:"id"`
	RunID      int64           `json:"run_id"`
	EvidenceID int64           `json:"evidence_id"`
	TSUTC      int64           `json:"ts_utc,string"`
	TSType     string          `json:"ts_type"`
	TSRaw      string          `json:"ts_raw"`
	TZSource   string          `json:"tz_source"`
	TZName     string          `json:"tz_name"`
	MACB       string          `json:"macb"`
	Category   string          `json:"category"`
	Source     string          `json:"source"`
	Host       string          `json:"host"`
	User       string          `json:"user"`
	Path       string          `json:"path"`
	Message    string          `json:"message"`
	Fields     json.RawMessage `json:"fields,omitempty"`
	RecordRef  string          `json:"record_ref"`
	Tags       []string        `json:"tags,omitempty"`
	Groups     []string        `json:"groups,omitempty"`
}

// filterKeys are the key:value prefixes understood in the search box.
var filterKeys = map[string]string{
	"source": "e.source", "host": "e.host", "user": "e.user",
	"type": "e.ts_type", "tz": "e.tz_source", "category": "e.category",
}

// memberSQL matches events carrying a live annotation of one kind and body.
// It is written as a list of event ids so that the database can start from
// the annotations, which are few, rather than test every event.
const memberSQL = `e.id IN (SELECT a.event_id FROM annotations a WHERE a.kind=? AND a.body=? COLLATE NOCASE
	AND NOT EXISTS (SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id))`

// descendantsSQL matches events of one evidence item and of every item that
// was unpacked or copied out of it, at any depth.
const descendantsSQL = `c.evidence_id IN (WITH RECURSIVE d(id) AS (SELECT ? UNION SELECT x.id FROM evidence x JOIN d ON x.parent_id = d.id) SELECT id FROM d)`

type compiled struct {
	where []string
	args  []any
}

func splitTerms(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case unicode.IsSpace(r) && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func hasAlnum(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// ftsPhrase turns a user term into a safe FTS5 phrase. Unquoted terms match
// as a prefix so "powersh" finds "powershell".
func ftsPhrase(term string) (string, bool) {
	exact := strings.HasPrefix(term, `"`) && strings.HasSuffix(term, `"`) && len(term) >= 2
	term = strings.Trim(term, `"`)
	if !hasAlnum(term) {
		return "", false
	}
	p := `"` + strings.ReplaceAll(term, `"`, `""`) + `"`
	if !exact {
		p += "*"
	}
	return p, true
}

func (q *Query) compile() compiled {
	var c compiled
	var pos []string
	// Several values of one field (source:mft source:evtx) are alternatives,
	// as picking two chips in one row means: either. They are gathered here
	// and written as one condition where the first of them stands. Values
	// excluded with "-" each apply.
	alts := map[string][]any{}
	for _, t := range splitTerms(q.Text) {
		if strings.HasPrefix(t, "-") || strings.HasPrefix(t, `"`) {
			continue
		}
		if i := strings.IndexByte(t, ':'); i > 0 {
			key, val := strings.ToLower(t[:i]), strings.Trim(t[i+1:], `"`)
			if _, ok := filterKeys[key]; ok && val != "" {
				alts[key] = append(alts[key], val)
			}
		}
	}
	for _, t := range splitTerms(q.Text) {
		neg := false
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			neg = true
			t = t[1:]
		}
		if i := strings.IndexByte(t, ':'); i > 0 && !strings.HasPrefix(t, `"`) {
			key, val := strings.ToLower(t[:i]), strings.Trim(t[i+1:], `"`)
			if col, ok := filterKeys[key]; ok && val != "" {
				if neg {
					c.where = append(c.where, col+" <> ? COLLATE NOCASE")
					c.args = append(c.args, val)
					continue
				}
				vals, first := alts[key]
				if !first {
					continue // already written with the first of its alternatives
				}
				delete(alts, key)
				conds := make([]string, len(vals))
				for i := range vals {
					conds[i] = col + " = ? COLLATE NOCASE"
				}
				c.where = append(c.where, "("+strings.Join(conds, " OR ")+")")
				c.args = append(c.args, vals...)
				continue
			}
			if (key == "tag" || key == "group") && val != "" {
				not := ""
				if neg {
					not = "NOT "
				}
				c.where = append(c.where, not+memberSQL)
				c.args = append(c.args, key, val)
				continue
			}
			// macb:m matches any event whose time is a modification time;
			// macb:mb needs both letters.
			if key == "macb" && val != "" {
				ok := true
				var conds []string
				for _, ch := range strings.ToUpper(val) {
					if i := strings.IndexRune("MACB", ch); i >= 0 {
						conds = append(conds, fmt.Sprintf("substr(e.macb,%d,1) = '%c'", i+1, ch))
					} else {
						ok = false
					}
				}
				if ok {
					cond := "(" + strings.Join(conds, " AND ") + ")"
					if neg {
						cond = "NOT " + cond
					}
					c.where = append(c.where, cond)
					continue
				}
			}
			// id:12,15,19 shows exactly those events, which is how a finding
			// from an analysis points back at the timeline.
			if key == "id" && val != "" {
				parts := strings.Split(val, ",")
				ids := make([]any, 0, len(parts))
				for _, p := range parts {
					if n, err := strconv.ParseInt(p, 10, 64); err == nil && len(ids) < 200 {
						ids = append(ids, n)
					}
				}
				if len(ids) == len(parts) {
					cond := "e.id IN (?" + strings.Repeat(",?", len(ids)-1) + ")"
					if neg {
						cond = "NOT " + cond
					}
					c.where = append(c.where, cond)
					c.args = append(c.args, ids...)
					continue
				}
			}
			not := ""
			if neg {
				not = "NOT "
			}
			if key == "evidence" {
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					c.where = append(c.where, not+"c.evidence_id = ?")
					c.args = append(c.args, n)
					continue
				}
			}
			// from:12 is evidence item 12 and everything that came out of it:
			// the files copied out of an image, the members of an archive,
			// and whatever those in turn held.
			if key == "from" {
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					c.where = append(c.where, not+descendantsSQL)
					c.args = append(c.args, n)
					continue
				}
			}
			// submission:3 is everything added together in the third submission.
			if key == "submission" {
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					c.where = append(c.where, not+"c.evidence_id IN (SELECT id FROM evidence WHERE batch_id = ?)")
					c.args = append(c.args, n)
					continue
				}
			}
			// domain:example.com is browser events for that site and its
			// subdomains (www.example.com); visit:12 is the browser's own
			// visit number, for following a visit to the one it came from
			// (with evidence:, since each history file numbers its own).
			// Both read only browser events, through the source index.
			if (key == "domain" || key == "visit") && val != "" {
				browserOnly := `(e.source = 'browser' COLLATE NOCASE OR e.source = 'browser-synced' COLLATE NOCASE)`
				if key == "domain" {
					v := strings.TrimPrefix(strings.ToLower(val), "www.")
					like := "%." + strings.NewReplacer(`!`, `!!`, `%`, `!%`, `_`, `!_`).Replace(v)
					c.where = append(c.where, not+"("+browserOnly+` AND (json_extract(e.fields,'$.domain') = ? OR json_extract(e.fields,'$.domain') LIKE ? ESCAPE '!'))`)
					c.args = append(c.args, v, like)
					continue
				}
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					c.where = append(c.where, not+"("+browserOnly+` AND json_extract(e.fields,'$.visit_id') = ?)`)
					c.args = append(c.args, n)
					continue
				}
			}
			// item:NTUSER.DAT is every item of that name, as the timeline's
			// Item column shows it: all the hives of that name, wherever they
			// came from. item:"a name with spaces" for a name with spaces.
			if key == "item" && val != "" {
				c.where = append(c.where, not+"c.evidence_id IN (SELECT id FROM evidence WHERE name = ? COLLATE NOCASE)")
				c.args = append(c.args, val)
				continue
			}
			// kind:windows-registry-hive is every item of one kind, as the
			// Evidence tab names it, wherever it came from.
			if key == "kind" && val != "" {
				c.where = append(c.where, not+"c.evidence_id IN (SELECT id FROM evidence WHERE kind = ? COLLATE NOCASE)")
				c.args = append(c.args, val)
				continue
			}
			// file:ntuser matches events from items whose name, or whose path
			// (including the path inside an image or archive), contains the text.
			if key == "file" && val != "" {
				// "!" escapes the two characters LIKE treats as wildcards; a backslash is common in paths and is left alone.
				like := "%" + strings.NewReplacer(`!`, `!!`, `%`, `!%`, `_`, `!_`).Replace(val) + "%"
				c.where = append(c.where, not+`c.evidence_id IN (SELECT id FROM evidence WHERE name LIKE ? ESCAPE '!' OR origin LIKE ? ESCAPE '!')`)
				c.args = append(c.args, like, like)
				continue
			}
		}
		p, ok := ftsPhrase(t)
		if !ok {
			continue
		}
		if neg {
			c.where = append(c.where, "e.id NOT IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
			c.args = append(c.args, p)
		} else {
			pos = append(pos, p)
		}
	}
	if len(pos) > 0 {
		c.where = append(c.where, "e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
		c.args = append(c.args, strings.Join(pos, " AND "))
	}
	if q.From != 0 {
		c.where = append(c.where, "e.ts_utc >= ?")
		c.args = append(c.args, q.From)
	}
	if q.To != 0 {
		c.where = append(c.where, "e.ts_utc <= ?")
		c.args = append(c.args, q.To)
	}
	if q.EvidenceID != 0 {
		c.where = append(c.where, "c.evidence_id = ?")
		c.args = append(c.args, q.EvidenceID)
	}
	if q.Group != "" {
		c.where = append(c.where, memberSQL)
		c.args = append(c.args, "group", q.Group)
	}
	return c
}

// eventFrom is how every reading of the timeline starts: the current run of
// each item, leaving out items excluded from the case's view.
const eventFrom = ` FROM events e JOIN current_runs c ON c.run_id = e.run_id AND c.evidence_id` + notExcluded + ` `

func (c compiled) sql() string {
	if len(c.where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(c.where, " AND ")
}

const eventCols = `e.id,e.run_id,e.evidence_id,e.ts_utc,e.ts_type,e.ts_raw,e.tz_source,e.tz_name,e.macb,e.category,e.source,e.host,e.user,e.path,e.message,e.fields,e.record_ref`

func scanEvent(sc interface{ Scan(...any) error }, withFields bool) (EventRow, error) {
	var e EventRow
	var f string
	err := sc.Scan(&e.ID, &e.RunID, &e.EvidenceID, &e.TSUTC, &e.TSType, &e.TSRaw, &e.TZSource, &e.TZName, &e.MACB, &e.Category, &e.Source, &e.Host, &e.User, &e.Path, &e.Message, &f, &e.RecordRef)
	if withFields {
		e.Fields = json.RawMessage(f)
	}
	return e, err
}

// Search returns one page of events in time order.
func (s *Store) Search(q Query) ([]EventRow, error) {
	c := q.compile()
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 200
	}
	order := " ORDER BY e.ts_utc, e.id"
	if q.Desc {
		order = " ORDER BY e.ts_utc DESC, e.id DESC"
	}
	if s.sparse(q) {
		// Few events match: find them by the filter's index and sort them,
		// rather than walk the whole timeline in time order looking for them.
		// The unary + stops the time index being used for the order.
		order = strings.NewReplacer("e.ts_utc", "+e.ts_utc", "e.id", "+e.id").Replace(order)
	}
	if q.AfterID != 0 {
		if q.Desc {
			c.where = append(c.where, "(e.ts_utc, e.id) < (?, ?)")
		} else {
			c.where = append(c.where, "(e.ts_utc, e.id) > (?, ?)")
		}
		c.args = append(c.args, q.AfterTS, q.AfterID)
	}
	rows, err := s.r.Query(`SELECT `+eventCols+eventFrom+c.sql()+order+` LIMIT ?`, append(c.args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventRow{}
	ids := []any{}
	for rows.Next() {
		e, err := scanEvent(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		ids = append(ids, e.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		tr, err := s.r.Query(`SELECT a.event_id, a.kind, a.body FROM annotations a WHERE a.kind IN ('tag','group') AND a.event_id IN (`+placeholders(len(ids))+`)
			AND NOT EXISTS (SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id) ORDER BY a.id`, ids...)
		if err != nil {
			return nil, err
		}
		defer tr.Close()
		tags, groups := map[int64][]string{}, map[int64][]string{}
		for tr.Next() {
			var id int64
			var kind, b string
			if err := tr.Scan(&id, &kind, &b); err != nil {
				return nil, err
			}
			if kind == "group" {
				groups[id] = append(groups[id], b)
			} else {
				tags[id] = append(tags[id], b)
			}
		}
		for i := range out {
			out[i].Tags, out[i].Groups = tags[out[i].ID], groups[out[i].ID]
		}
	}
	return out, nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

type Summary struct {
	Count  int64 `json:"count"`
	MinTS  int64 `json:"min_ts,string"`
	MaxTS  int64 `json:"max_ts,string"`
	Bucket int64 `json:"bucket_ns,string"`
	Start  int64 `json:"start_ts,string"`
	// Buckets is the number of bars the span takes, at most the number
	// asked for: fewer when the bars were widened to whole hours.
	Buckets int64 `json:"buckets"`
	Bars    []Bar `json:"bars"`
}

type Bar struct {
	Index int64 `json:"i"`
	Count int64 `json:"n"`
}

// Summarise returns the match count, time span and a histogram for a query.
func (s *Store) Summarise(q Query, buckets int) (Summary, error) {
	c := q.compile()
	stats := s.byStats(q)
	var sum Summary
	var mn, mx *int64
	var err error
	if stats {
		err = s.r.QueryRow(`SELECT COALESCE(sum(e.n), 0), min(e.min_ts), max(e.max_ts)`+statsFrom+c.sql(), c.args...).Scan(&sum.Count, &mn, &mx)
	} else {
		err = s.r.QueryRow(`SELECT count(*), min(e.ts_utc), max(e.ts_utc)`+eventFrom+c.sql(), c.args...).Scan(&sum.Count, &mn, &mx)
	}
	if err != nil {
		return sum, err
	}
	sum.Bars = []Bar{}
	if sum.Count == 0 || mn == nil {
		return sum, nil
	}
	sum.MinTS, sum.MaxTS = *mn, *mx
	if buckets <= 0 {
		buckets = 120
	}
	span := sum.MaxTS - sum.MinTS
	sum.Bucket = span/int64(buckets) + 1
	sum.Start = sum.MinTS
	var rows *sql.Rows
	if stats && sum.Bucket >= hourNS {
		// From the hourly summaries: bars of whole hours, starting on an
		// hour, so each hour's events fall in exactly one bar.
		// The start moves back to its hour, so the width is worked out from
		// there: the bars must still cover the span in the number asked.
		sum.Start = floorDiv(sum.MinTS, hourNS) * hourNS
		sum.Bucket = (sum.MaxTS-sum.Start)/int64(buckets) + 1
		sum.Bucket = (sum.Bucket + hourNS - 1) / hourNS * hourNS
		args := append([]any{sum.Start, sum.Bucket}, c.args...)
		rows, err = s.r.Query(`SELECT (e.hour * `+fmt.Sprint(hourNS)+` - ?) / ? AS b, sum(e.n)`+statsFrom+c.sql()+` GROUP BY b ORDER BY b`, args...)
	} else {
		args := append([]any{sum.Start, sum.Bucket}, c.args...)
		rows, err = s.r.Query(`SELECT (e.ts_utc - ?) / ? AS b, count(*)`+eventFrom+c.sql()+` GROUP BY b ORDER BY b`, args...)
	}
	sum.Buckets = (sum.MaxTS-sum.Start)/sum.Bucket + 1
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	for rows.Next() {
		var b Bar
		if err := rows.Scan(&b.Index, &b.Count); err != nil {
			return sum, err
		}
		sum.Bars = append(sum.Bars, b)
	}
	return sum, rows.Err()
}

func (s *Store) GetEvent(id int64) (*EventRow, error) {
	e, err := scanEvent(s.r.QueryRow(`SELECT `+eventCols+` FROM events e WHERE e.id=?`, id), true)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Facets returns event counts by artefact source and by zone provenance for
// the current timeline.
func (s *Store) Facets() (map[string]map[string]int64, error) { return s.FacetsFor(Query{}) }

// FacetsFor counts the events matching q by source, zone provenance and
// category: the numbers on the timeline's chips, for what is being looked at.
// FacetsFor counts the events matching q by source, zone provenance and
// category, for the chips under the search box. Each group is counted with
// its own filters left out (source counts ignore source:, and so on), as
// faceted searches do: the other choices in a group stay visible while one
// is chosen, and every count still follows the rest of the search.
// Groups whose search comes out the same share one pass.
func (s *Store) FacetsFor(q Query) (map[string]map[string]int64, error) {
	out := map[string]map[string]int64{"source": {}, "tz_source": {}, "category": {}, "host": {}}
	groups := []struct{ key, col string }{{"source", "source"}, {"tz", "tz_source"}, {"category", "category"}, {"host", "host"}}
	byText := map[string][]string{} // search text -> output groups counted with it
	var order []string
	for _, g := range groups {
		var keep []string
		for _, t := range splitTerms(q.Text) {
			k, _, ok := strings.Cut(strings.TrimPrefix(t, "-"), ":")
			if ok && strings.EqualFold(k, g.key) {
				continue
			}
			keep = append(keep, t)
		}
		text := strings.Join(keep, " ")
		if _, seen := byText[text]; !seen {
			order = append(order, text)
		}
		byText[text] = append(byText[text], g.col)
	}
	for _, text := range order {
		qq := q
		qq.Text = text
		c := qq.compile()
		where := ""
		if len(c.where) > 0 {
			where = " WHERE " + strings.Join(c.where, " AND ")
		}
		var rows *sql.Rows
		var err error
		if s.byStats(qq) {
			rows, err = s.r.Query(`SELECT e.source, e.tz_source, e.category, e.host, sum(e.n)`+statsFrom+where+` GROUP BY 1, 2, 3, 4`, c.args...)
		} else {
			rows, err = s.r.Query(`SELECT e.source, e.tz_source, e.category, e.host, count(*)`+eventFrom+where+` GROUP BY 1, 2, 3, 4`, c.args...)
		}
		if err != nil {
			return nil, err
		}
		want := map[string]bool{}
		for _, col := range byText[text] {
			want[col] = true
		}
		for rows.Next() {
			var src, tz, cat, host string
			var n int64
			if err := rows.Scan(&src, &tz, &cat, &host, &n); err != nil {
				rows.Close()
				return nil, err
			}
			if want["source"] {
				out["source"][src] += n
			}
			if want["tz_source"] {
				out["tz_source"][tz] += n
			}
			if want["category"] {
				out["category"][cat] += n
			}
			// Events with no host have no chip: there is nothing to filter on.
			if want["host"] && host != "" {
				out["host"][host] += n
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

type TextHit struct {
	EvidenceID int64  `json:"evidence_id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Snippet    string `json:"snippet"`
}

// SearchText searches the text extracted from files that have no dedicated
// parser, so unrecognised artefacts remain findable.
func (s *Store) SearchText(text string, limit int) ([]TextHit, error) {
	var pos []string
	for _, t := range splitTerms(text) {
		if strings.HasPrefix(t, "-") || (strings.Contains(t, ":") && !strings.HasPrefix(t, `"`)) {
			continue
		}
		if p, ok := ftsPhrase(t); ok {
			pos = append(pos, p)
		}
	}
	out := []TextHit{}
	if len(pos) == 0 {
		return out, nil
	}
	rows, err := s.r.Query(`SELECT f.rowid, ev.name, ev.kind, snippet(evidence_text_fts, 0, '[', ']', ' … ', 16)
		FROM evidence_text_fts f JOIN evidence ev ON ev.id = f.rowid
		WHERE evidence_text_fts MATCH ? AND ev.id`+notExcluded+` LIMIT ?`, strings.Join(pos, " AND "), limit)
	if err != nil {
		return nil, fmt.Errorf("text search: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h TextHit
		if err := rows.Scan(&h.EvidenceID, &h.Name, &h.Kind, &h.Snippet); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Stream calls fn for every event matching q in time order, for export.
// StreamFullText calls fn with the indexed text of every item that was
// indexed as text in full (logs, scripts, transcripts, command histories),
// leaving out strings pulled from binary files.
func (s *Store) StreamFullText(fn func(evidenceID int64, name, origin, body string) error) error {
	rows, err := s.r.Query(`SELECT t.evidence_id, e.name, e.origin, t.body FROM evidence_text t JOIN evidence e ON e.id = t.evidence_id
		WHERE t.method = 'full text' AND e.duplicate_of IS NULL AND e.id` + notExcluded + ` ORDER BY t.evidence_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name, origin, body string
		if err := rows.Scan(&id, &name, &origin, &body); err != nil {
			return err
		}
		if err := fn(id, name, origin, body); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) Stream(q Query, fn func(EventRow) error) error {
	c := q.compile()
	rows, err := s.r.Query(`SELECT `+eventCols+eventFrom+c.sql()+` ORDER BY e.ts_utc, e.id`, c.args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEvent(rows, true)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// RunRow is one parse run with its sealed result, for the case report.
type RunRow struct {
	ID            int64  `json:"id"`
	EvidenceID    int64  `json:"evidence_id"`
	Parser        string `json:"parser"`
	ParserVersion string `json:"parser_version"`
	ToolVersion   string `json:"tool_version"`
	StartedUTC    int64  `json:"started_utc,string"`
	ZoneContext   string `json:"zone_context"`
	Status        string `json:"status"` // "unsealed" if the run never finished
	EventCount    int64  `json:"event_count"`
	EventDigest   string `json:"event_digest"`
	Notes         string `json:"notes"`
	Current       bool   `json:"current"` // the run shown on the timeline for its evidence
}

// ListRuns returns every parse run, including ones a later run superseded.
func (s *Store) ListRuns() ([]RunRow, error) {
	rows, err := s.r.Query(`SELECT r.id, r.evidence_id, r.parser, r.parser_version, r.tool_version, r.started_utc, r.zone_context,
		COALESCE(rr.status,'unsealed'), COALESCE(rr.event_count,0), COALESCE(rr.event_digest,''), COALESCE(rr.notes,''),
		EXISTS(SELECT 1 FROM current_runs c WHERE c.run_id = r.id)
		FROM runs r LEFT JOIN run_results rr ON rr.run_id = r.id ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunRow{}
	for rows.Next() {
		var r RunRow
		if err := rows.Scan(&r.ID, &r.EvidenceID, &r.Parser, &r.ParserVersion, &r.ToolVersion, &r.StartedUTC, &r.ZoneContext,
			&r.Status, &r.EventCount, &r.EventDigest, &r.Notes, &r.Current); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NoteRow is an examiner annotation together with the event it is about.
type NoteRow struct {
	Annotation
	EventTS      int64  `json:"event_ts_utc,string"`
	EventMessage string `json:"event_message"`
	EvidenceID   int64  `json:"evidence_id"`
}

// AllAnnotations returns every tag and comment, withdrawn ones included, with
// the event each refers to. Retraction entries themselves are folded into the
// Retracted flag.
func (s *Store) AllAnnotations() ([]NoteRow, error) {
	rows, err := s.r.Query(`SELECT a.id,a.event_id,a.kind,a.body,a.refers_to,a.actor,a.made_utc,
		EXISTS(SELECT 1 FROM annotations x WHERE x.kind='retract' AND x.refers_to=a.id),
		e.ts_utc, e.message, e.evidence_id
		FROM annotations a JOIN events e ON e.id = a.event_id WHERE a.kind <> 'retract' ORDER BY e.ts_utc, a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NoteRow{}
	for rows.Next() {
		var n NoteRow
		if err := rows.Scan(&n.ID, &n.EventID, &n.Kind, &n.Body, &n.RefersTo, &n.Actor, &n.MadeUTC, &n.Retracted,
			&n.EventTS, &n.EventMessage, &n.EvidenceID); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AuditAscending returns the audit log oldest first, up to limit entries
// (0 for all), and the total number of entries.
func (s *Store) AuditAscending(limit int) ([]AuditRow, int64, error) {
	var total int64
	if err := s.r.QueryRow(`SELECT count(*) FROM audit`).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id,ts_utc,actor,action,target,details,prev_hash,hash FROM audit ORDER BY id`
	args := []any{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.r.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var a AuditRow
		var d string
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Target, &d, &a.Prev, &a.Hash); err != nil {
			return nil, 0, err
		}
		a.Details = json.RawMessage(d)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// JournalFolder is where a change-journal record's parent folder is, as the
// file table in the same submission records it.
type JournalFolder struct {
	Path       string `json:"path"`
	EvidenceID int64  `json:"evidence_id"`
	Note       string `json:"note"`
}

// JournalParent looks up the folder a change-journal record names by its
// file-table entry and sequence number, among the file-table events of the
// same submission. It is worked out when asked for and stored nowhere: an
// event's content depends only on its own evidence.
func (s *Store) JournalParent(e *EventRow) (*JournalFolder, error) {
	if e.Source != "usn" {
		return nil, nil
	}
	var f struct {
		Entry    *int64 `json:"parent_entry"`
		Sequence *int64 `json:"parent_sequence"`
	}
	if json.Unmarshal(e.Fields, &f) != nil || f.Entry == nil || f.Sequence == nil {
		return nil, nil
	}
	var out JournalFolder
	err := s.r.QueryRow(`SELECT e.path, e.evidence_id`+eventFrom+`JOIN evidence v ON v.id = e.evidence_id
		WHERE e.source = 'mft' AND v.batch_id = (SELECT batch_id FROM evidence WHERE id = ?)
		AND json_extract(e.fields, '$.entry') = ? AND json_extract(e.fields, '$.sequence') = ?
		ORDER BY e.id LIMIT 1`, e.EvidenceID, *f.Entry, *f.Sequence).Scan(&out.Path, &out.EvidenceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out.Note = "the folder's path as the file table records it now; it may have been renamed or moved since the journal record was written"
	return &out, nil
}

// floorDiv divides rounding towards minus infinity, for times before 1970.
func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}
