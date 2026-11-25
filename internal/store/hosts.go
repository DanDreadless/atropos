package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Hosts are the computers a case is about. The examiner describes them (the
// Details tab) before adding evidence, and each submission is assigned to one
// of them, or stated to come from no host with a description of where it came
// from (a packet capture, firewall or cloud logs, a phone export). Both are
// append-only: a host is a row, an assignment is a row, and reassigning a
// submission appends a new one; the latest per submission is the one in force.
// Every change is audited.

const hostsSchema = `
CREATE TABLE IF NOT EXISTS hosts (
  id       INTEGER PRIMARY KEY,
  name     TEXT NOT NULL,
  actor    TEXT NOT NULL,
  made_utc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS batch_hosts (
  id       INTEGER PRIMARY KEY,
  batch_id INTEGER NOT NULL,
  host_id  INTEGER REFERENCES hosts(id),  -- NULL: not from a host
  source   TEXT NOT NULL,                 -- where it came from, when not from a host
  actor    TEXT NOT NULL,
  made_utc INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS batch_hosts_batch ON batch_hosts(batch_id, id);
`

// Host is a computer described in the case.
type Host struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Assignment says where a submission came from: a host, or no host and a
// stated source.
type Assignment struct {
	HostID   *int64 `json:"host_id"`
	HostName string `json:"host,omitempty"`
	Source   string `json:"source,omitempty"`
}

// validHostName refuses what cannot be a host's name in the case.
func validHostName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("give the host a name")
	}
	if len(name) > 255 || strings.ContainsAny(name, "\x00\r\n") {
		return "", errors.New("a host name is at most 255 characters on one line")
	}
	return name, nil
}

// AddHost records a host, or returns the one of that name (names are the
// same host however they are capitalised).
func (s *Store) AddHost(name string) (Host, error) {
	name, err := validHostName(name)
	if err != nil {
		return Host{}, err
	}
	if h, ok := s.hostByName(name); ok {
		return h, nil
	}
	res, err := s.w.Exec(`INSERT INTO hosts(name, actor, made_utc) VALUES (?,?,?)`, name, s.Actor, time.Now().UTC().UnixNano())
	if err != nil {
		return Host{}, err
	}
	id, _ := res.LastInsertId()
	if err := s.Audit("host.add", fmt.Sprintf("host:%d", id), map[string]any{"name": name}); err != nil {
		return Host{}, err
	}
	return Host{ID: id, Name: name}, nil
}

func (s *Store) hostByName(name string) (Host, bool) {
	var h Host
	err := s.w.QueryRow(`SELECT id, name FROM hosts WHERE name = ? COLLATE NOCASE ORDER BY id LIMIT 1`, strings.TrimSpace(name)).Scan(&h.ID, &h.Name)
	return h, err == nil
}

// Hosts lists the hosts described, in the order they were added.
func (s *Store) Hosts() ([]Host, error) {
	rows, err := s.r.Query(`SELECT id, name FROM hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Host{}
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.Name); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// AssignBatch states where a submission came from: hostID, or, with hostID
// nil, no host and source saying where. The latest statement is in force.
func (s *Store) AssignBatch(batch int64, hostID *int64, source string) error {
	source = strings.TrimSpace(source)
	details := map[string]any{"batch": batch}
	if hostID != nil {
		var name string
		if err := s.w.QueryRow(`SELECT name FROM hosts WHERE id = ?`, *hostID).Scan(&name); err != nil {
			return fmt.Errorf("no host %d in this case", *hostID)
		}
		source = ""
		details["host_id"], details["host"] = *hostID, name
	} else {
		if source == "" {
			return errors.New("evidence that is not from a host needs a description of where it came from")
		}
		if len(source) > 4000 {
			return errors.New("the description of where the evidence came from is at most 4,000 characters")
		}
		details["not_from_a_host"] = source
	}
	if _, err := s.w.Exec(`INSERT INTO batch_hosts(batch_id, host_id, source, actor, made_utc) VALUES (?,?,?,?,?)`,
		batch, hostID, source, s.Actor, time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	return s.Audit("submission.assigned", fmt.Sprintf("batch:%d", batch), details)
}

// BatchAssignment is the assignment in force for a submission; nil when none
// was made (cases made before hosts existed, and the command line without
// --host).
func (s *Store) BatchAssignment(batch int64) (*Assignment, error) {
	var a Assignment
	var hostID sql.NullInt64
	var name sql.NullString
	err := s.w.QueryRow(`SELECT b.host_id, h.name, b.source FROM batch_hosts b LEFT JOIN hosts h ON h.id = b.host_id
		WHERE b.batch_id = ? ORDER BY b.id DESC LIMIT 1`, batch).Scan(&hostID, &name, &a.Source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if hostID.Valid {
		id := hostID.Int64
		a.HostID, a.HostName = &id, name.String
	}
	return &a, nil
}

// markHosts fills in each listed item's assignment, from its submission's.
func (s *Store) markHosts(list []Evidence) error {
	rows, err := s.r.Query(`SELECT b.batch_id, b.host_id, COALESCE(h.name,''), b.source FROM batch_hosts b LEFT JOIN hosts h ON h.id = b.host_id
		WHERE b.id IN (SELECT max(id) FROM batch_hosts GROUP BY batch_id)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	by := map[int64]Assignment{}
	for rows.Next() {
		var batch int64
		var hostID sql.NullInt64
		var a Assignment
		if err := rows.Scan(&batch, &hostID, &a.HostName, &a.Source); err != nil {
			return err
		}
		if hostID.Valid {
			id := hostID.Int64
			a.HostID = &id
		}
		by[batch] = a
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range list {
		if a, ok := by[list[i].BatchID]; ok {
			a := a
			list[i].Assigned = &a
		}
	}
	return nil
}

// HostTimeZone is the zone stated for a host on the Details tab, if it is a
// zone name Atropos can load ("Europe/London"); otherwise "".
func (s *Store) HostTimeZone(host string) string {
	d, err := s.currentDetails()
	if err != nil {
		return ""
	}
	for name, fields := range d {
		if name != "" && strings.EqualFold(name, host) {
			if z, ok := fields["time_zone"]; ok && z.Value != "" {
				if _, err := time.LoadLocation(strings.TrimSpace(z.Value)); err == nil {
					return strings.TrimSpace(z.Value)
				}
			}
		}
	}
	return ""
}

// HostIdentity is how a host may be named in another host's evidence: its
// name and other stated names, its stated addresses, and how far its clock
// was from true time.
type HostIdentity struct {
	Name  string   `json:"name"`
	Names []string `json:"names"` // upper case, the name first
	IPs   []string `json:"ips"`   // canonical form
	// Clock is how far the host's clock was ahead of true time (behind
	// when negative); ClockStated says whether a usable value was given,
	// and ClockText is what was written.
	Clock       time.Duration `json:"clock_ns,string"`
	ClockStated bool          `json:"clock_stated"`
	ClockText   string        `json:"clock_text,omitempty"`
	// Unread lists stated values that could not be used, for a note.
	Unread []string `json:"unread,omitempty"`
	// HiveIPs and HiveNames are the addresses and full names the host's own
	// SYSTEM hive records (Services\Tcpip): evidence, not statements, so they
	// are kept apart from what was stated.
	HiveIPs   []HiveFact `json:"hive_ips,omitempty"`
	HiveNames []HiveFact `json:"hive_names,omitempty"`
}

// HiveFact is a value a host's SYSTEM hive records, with where.
type HiveFact struct {
	Value      string `json:"value"`
	Detail     string `json:"detail"`
	EvidenceID int64  `json:"evidence_id"`
}

func sameHostName(a, b string) bool {
	short := func(s string) string { s, _, _ = strings.Cut(strings.TrimSpace(s), "."); return s }
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && (strings.EqualFold(a, b) || strings.EqualFold(short(a), short(b)))
}

// hiveFacts gives, by host id, what SYSTEM hives of the host's evidence
// record about its names and addresses. A hive belongs to the host its
// submission is assigned to, or, when the submission is not assigned, the
// host it names. A hive naming another computer than the one its submission
// is assigned to is not used, and the host gets a note saying so.
func (s *Store) hiveFacts(hs []Host) (ips, names map[int64][]HiveFact, notes map[int64][]string, err error) {
	ips, names, notes = map[int64][]HiveFact{}, map[int64][]HiveFact{}, map[int64][]string{}
	assigned := map[int64]*int64{}
	rows, err := s.w.Query(`SELECT b.batch_id, b.host_id FROM batch_hosts b WHERE b.id IN (SELECT max(id) FROM batch_hosts GROUP BY batch_id)`)
	if err != nil {
		return nil, nil, nil, err
	}
	for rows.Next() {
		var batch int64
		var id sql.NullInt64
		if err := rows.Scan(&batch, &id); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		if id.Valid {
			v := id.Int64
			assigned[batch] = &v
		} else {
			assigned[batch] = nil
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	rows, err = s.w.Query(`SELECT e.id, e.batch_id, f.key, f.value, f.detail FROM facts f JOIN evidence e ON e.id = f.evidence_id
		WHERE f.key IN ('host.name','host.dns_name','host.ip_address') ORDER BY e.id, f.id`)
	if err != nil {
		return nil, nil, nil, err
	}
	type ev struct {
		batch        int64
		name         string
		dns, ip      []HiveFact
		seenDNS, ip4 map[string]bool
	}
	var order []int64
	evs := map[int64]*ev{}
	for rows.Next() {
		var id, batch int64
		var k, v, d string
		if err := rows.Scan(&id, &batch, &k, &v, &d); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		e := evs[id]
		if e == nil {
			e = &ev{batch: batch, seenDNS: map[string]bool{}, ip4: map[string]bool{}}
			evs[id] = e
			order = append(order, id)
		}
		switch k {
		case "host.name":
			e.name = v
		case "host.dns_name":
			if !e.seenDNS[v] { // a run read again gives its facts again
				e.seenDNS[v] = true
				e.dns = append(e.dns, HiveFact{v, d, id})
			}
		case "host.ip_address":
			if ip, ok := normIP(v); ok && !e.ip4[ip] {
				e.ip4[ip] = true
				e.ip = append(e.ip, HiveFact{ip, d, id})
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	noted := map[string]bool{}
	for _, id := range order {
		e := evs[id]
		if len(e.dns) == 0 && len(e.ip) == 0 {
			continue
		}
		var host *Host
		if a, ok := assigned[e.batch]; ok {
			if a == nil {
				continue // stated to be from no host
			}
			for i := range hs {
				if hs[i].ID == *a {
					host = &hs[i]
				}
			}
			if host != nil && e.name != "" && !sameHostName(e.name, host.Name) {
				msg := fmt.Sprintf("a SYSTEM hive in its evidence (item %d) names the computer %s, so the addresses it records are not used", id, e.name)
				if !noted[msg] {
					noted[msg] = true
					notes[host.ID] = append(notes[host.ID], msg)
				}
				continue
			}
		} else {
			for i := range hs {
				if sameHostName(e.name, hs[i].Name) {
					host = &hs[i]
					break
				}
			}
		}
		if host == nil {
			continue
		}
		names[host.ID] = append(names[host.ID], e.dns...)
		ips[host.ID] = append(ips[host.ID], e.ip...)
	}
	return ips, names, notes, nil
}

// HostIdentities lists every host of the case with what is stated about how
// it may be named and its clock.
func (s *Store) HostIdentities() ([]HostIdentity, error) {
	hs, err := s.Hosts()
	if err != nil {
		return nil, err
	}
	d, err := s.currentDetails()
	if err != nil {
		return nil, err
	}
	hiveIPs, hiveNames, hiveNotes, err := s.hiveFacts(hs)
	if err != nil {
		return nil, err
	}
	var out []HostIdentity
	for _, h := range hs {
		id := HostIdentity{Name: h.Name, Names: []string{strings.ToUpper(h.Name)}}
		var fields map[string]Detail
		for name, f := range d {
			if name != "" && strings.EqualFold(name, h.Name) {
				fields = f
			}
		}
		split := func(v string) []string {
			return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t' })
		}
		for _, n := range split(fields["other_names"].Value) {
			n = strings.ToUpper(strings.Trim(n, `\ `))
			if n != "" && !contains(id.Names, n) {
				id.Names = append(id.Names, n)
			}
		}
		for _, v := range split(fields["ip_addresses"].Value) {
			v = strings.TrimSuffix(strings.TrimSpace(v), ".")
			if i := strings.IndexByte(v, '/'); i > 0 {
				v = v[:i] // an address written with its prefix length
			}
			if ip, ok := normIP(v); ok {
				if !contains(id.IPs, ip) {
					id.IPs = append(id.IPs, ip)
				}
			} else if v != "" {
				id.Unread = append(id.Unread, fmt.Sprintf("%q in its IP addresses is not an address", v))
			}
		}
		if t := strings.TrimSpace(fields["clock_offset"].Value); t != "" {
			id.ClockText = t
			if c, ok := ParseClockOffset(t); ok {
				id.Clock, id.ClockStated = c, true
			} else {
				id.Unread = append(id.Unread, fmt.Sprintf("its clock difference %q was not understood; write it as, for example, 3 minutes ahead or -90s", t))
			}
		}
		id.Unread = append(id.Unread, hiveNotes[h.ID]...)
		seen := map[string]bool{}
		for _, f := range hiveIPs[h.ID] {
			if !seen[f.Value] {
				seen[f.Value] = true
				id.HiveIPs = append(id.HiveIPs, f)
			}
		}
		for _, f := range hiveNames[h.ID] {
			if !seen["n"+f.Value] {
				seen["n"+f.Value] = true
				id.HiveNames = append(id.HiveNames, f)
			}
		}
		out = append(out, id)
	}
	return out, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ParseClockOffset reads a stated clock difference: how far a clock was
// ahead of true time, negative when behind. It accepts "3 minutes ahead",
// "90 seconds behind", "1 min 30 s slow", "+3m", "-1m30s", "-00:01:30",
// "1h2m fast", and "0", "none", "correct" or "accurate" for none. A number
// with no unit, or a value with no sign or direction other than zero, is
// refused: which way the clock was out cannot be guessed.
func ParseClockOffset(s string) (time.Duration, bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "0", "none", "correct", "accurate", "nil", "no difference", "0s":
		return 0, true
	}
	sign := 0
	for _, w := range []string{"ahead", "fast"} {
		if strings.Contains(t, w) {
			sign = 1
			t = strings.ReplaceAll(t, w, " ")
		}
	}
	for _, w := range []string{"behind", "slow"} {
		if strings.Contains(t, w) {
			if sign != 0 {
				return 0, false
			}
			sign = -1
			t = strings.ReplaceAll(t, w, " ")
		}
	}
	t = strings.TrimSpace(t)
	switch {
	case strings.HasPrefix(t, "+"):
		if sign == -1 {
			return 0, false
		}
		sign, t = 1, strings.TrimSpace(t[1:])
	case strings.HasPrefix(t, "-"):
		if sign == 1 {
			return 0, false
		}
		sign, t = -1, strings.TrimSpace(t[1:])
	}
	var d time.Duration
	if parts := strings.Split(t, ":"); len(parts) == 3 {
		var h, m, sec int
		if _, err := fmt.Sscanf(t, "%d:%d:%d", &h, &m, &sec); err != nil || m > 59 || sec > 59 || h < 0 || m < 0 || sec < 0 {
			return 0, false
		}
		d = time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
	} else {
		r := strings.NewReplacer(" and ", " ", ",", " ")
		t = r.Replace(t)
		units := []struct {
			words []string
			u     string
		}{
			{[]string{"hours", "hour", "hrs", "hr"}, "h"},
			{[]string{"minutes", "minute", "mins", "min"}, "m"},
			{[]string{"seconds", "second", "secs", "sec"}, "s"},
			{[]string{"milliseconds", "millisecond"}, "ms"},
		}
		fs := strings.Fields(t)
		var b strings.Builder
		for _, f := range fs {
			unit := f
			for _, u := range units {
				for _, w := range u.words {
					if strings.HasSuffix(f, w) {
						unit = strings.TrimSuffix(f, w) + u.u
						goto done
					}
				}
			}
		done:
			b.WriteString(unit)
		}
		var err error
		if d, err = time.ParseDuration(b.String()); err != nil {
			return 0, false
		}
	}
	if d == 0 {
		return 0, true
	}
	if sign == 0 {
		return 0, false
	}
	return time.Duration(sign) * d, true
}
