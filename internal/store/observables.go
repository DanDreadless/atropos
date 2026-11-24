package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Observables are who and what an event involves, taken out of its fields
// once so that links between hosts can be found without reading every event:
// the address a Remote Desktop session came from, the computer a client
// connected to, the account used. Like the run summaries they are derived
// from a sealed run, never change, and are rebuilt under a new version when
// how they are taken changes.
//
// So far only Remote Desktop is read (act "rdp-out" on the computer
// connecting, "rdp-in" on the computer connected to); SMB, PsExec, WinRM,
// devices and hashes are to follow (the plan, H.2).

const observablesVersion = 1

const observablesSchema = `
CREATE TABLE IF NOT EXISTS observables (
  event_id    INTEGER NOT NULL,
  run_id      INTEGER NOT NULL REFERENCES runs(id),
  evidence_id INTEGER NOT NULL,
  ts_utc      INTEGER NOT NULL,
  host        TEXT NOT NULL,      -- the event's host
  act         TEXT NOT NULL,      -- what the event shows: rdp-out, rdp-in
  what        TEXT NOT NULL,      -- the event, briefly: "RDP client connecting (1024)"
  kind        TEXT NOT NULL,      -- ip, host, account
  value       TEXT NOT NULL,
  role        TEXT NOT NULL,      -- source, target, subject
  version     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS observables_run ON observables(run_id, version);
CREATE INDEX IF NOT EXISTS observables_act ON observables(act, version);
CREATE TABLE IF NOT EXISTS observables_done (
  run_id  INTEGER NOT NULL REFERENCES runs(id),
  version INTEGER NOT NULL,
  PRIMARY KEY (run_id, version)
);
`

// Observable is one thing an event involves.
type Observable struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Role  string `json:"role"`
}

// ObservedEvent is an event with what it involves.
type ObservedEvent struct {
	EventID    int64        `json:"event_id"`
	EvidenceID int64        `json:"evidence_id"`
	TSUTC      int64        `json:"ts_utc,string"`
	Host       string       `json:"host"`
	Act        string       `json:"act"`
	What       string       `json:"what"`
	Items      []Observable `json:"items"`
}

// Channels read for Remote Desktop.
const (
	chSecurity = "Security"
	chRDPCli   = "Microsoft-Windows-TerminalServices-RDPClient/Operational"
	chRCM      = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
	chLSM      = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
	chCoreTS   = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
)

// computeObservables takes the observables out of one sealed run.
func (s *Store) computeObservables(runID int64) error {
	var done int
	if err := s.w.QueryRow(`SELECT count(*) FROM observables_done WHERE run_id = ? AND version = ?`, runID, observablesVersion).Scan(&done); err != nil || done > 0 {
		return err
	}
	// Only event-log records of the channels read; the category narrows
	// them before any JSON is looked at.
	rows, err := s.r.Query(`SELECT id, evidence_id, ts_utc, host, fields FROM events
		WHERE run_id = ? AND source = 'evtx' AND category IN ('account', 'network')
		AND json_extract(fields, '$.channel') IN (?,?,?,?,?)`, runID, chSecurity, chRDPCli, chRCM, chLSM, chCoreTS)
	if err != nil {
		return err
	}
	var found []ObservedEvent
	for rows.Next() {
		var oe ObservedEvent
		var fields string
		if err := rows.Scan(&oe.EventID, &oe.EvidenceID, &oe.TSUTC, &oe.Host, &fields); err != nil {
			rows.Close()
			return err
		}
		if observeEvent(&oe, fields) {
			found = append(found, oe)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := s.w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins, err := tx.Prepare(`INSERT INTO observables(event_id,run_id,evidence_id,ts_utc,host,act,what,kind,value,role,version) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, oe := range found {
		for _, it := range oe.Items {
			if _, err := ins.Exec(oe.EventID, runID, oe.EvidenceID, oe.TSUTC, oe.Host, oe.Act, oe.What, it.Kind, it.Value, it.Role, observablesVersion); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`INSERT INTO observables_done(run_id, version) VALUES (?, ?)`, runID, observablesVersion); err != nil {
		return err
	}
	return tx.Commit()
}

// observeEvent reads what one event-log record involves. It reports false
// for a record that shows nothing read here.
func observeEvent(oe *ObservedEvent, fieldsJSON string) bool {
	var f struct {
		Channel string `json:"channel"`
		EventID string `json:"event_id"`
		Event   struct {
			EventData map[string]any `json:"EventData"`
			UserData  map[string]any `json:"UserData"`
		} `json:"event"`
	}
	if json.Unmarshal([]byte(fieldsJSON), &f) != nil {
		return false
	}
	d := f.Event.EventData
	if d == nil {
		// Terminal Services events keep their values one level down, in
		// UserData/EventXML.
		for _, v := range f.Event.UserData {
			if m, ok := v.(map[string]any); ok {
				d = m
				break
			}
		}
	}
	get := func(k string) string { return clean(fieldString(d[k])) }
	add := func(kind, value, role string) {
		if value != "" {
			oe.Items = append(oe.Items, Observable{kind, value, role})
		}
	}
	// target: a computer named as typed, which may be an address.
	target := func(v string) {
		if ip, ok := normIP(v); ok {
			add("ip", ip, "target")
		} else if h := normHostName(v); h != "" {
			add("host", h, "target")
		}
	}
	source := func(v string) {
		if ip, ok := normIP(v); ok {
			add("ip", ip, "source")
		}
	}
	account := func(domain, user, role string) {
		if user == "" {
			return
		}
		if domain != "" && !strings.Contains(user, `\`) {
			user = domain + `\` + user
		}
		add("account", user, role)
	}
	switch f.Channel + "/" + f.EventID {
	case chSecurity + "/4624":
		switch get("LogonType") {
		case "10", "12": // remote interactive; cached remote interactive
		default:
			return false
		}
		oe.Act, oe.What = "rdp-in", "Remote Desktop logon (Security 4624, type "+get("LogonType")+")"
		source(get("IpAddress"))
		if h := normHostName(get("WorkstationName")); h != "" {
			add("host", h, "source")
		}
		account(get("TargetDomainName"), get("TargetUserName"), "target")
	case chSecurity + "/4778":
		oe.Act, oe.What = "rdp-in", "Session reconnected (Security 4778)"
		source(get("ClientAddress"))
		if h := normHostName(get("ClientName")); h != "" {
			add("host", h, "source")
		}
		account(get("AccountDomain"), get("AccountName"), "target")
	case chSecurity + "/4648":
		ti := get("TargetInfo")
		if !strings.HasPrefix(strings.ToUpper(ti), "TERMSRV/") {
			return false
		}
		oe.Act, oe.What = "rdp-out", "Explicit credentials for Remote Desktop (Security 4648)"
		t := get("TargetServerName")
		if t == "" || t == "localhost" {
			t = ti[len("TERMSRV/"):]
		}
		target(t)
		account(get("TargetDomainName"), get("TargetUserName"), "target")
		account(get("SubjectDomainName"), get("SubjectUserName"), "subject")
	case chRCM + "/1149":
		oe.Act, oe.What = "rdp-in", "Remote Desktop authentication succeeded (1149)"
		source(get("Param3"))
		account(get("Param2"), get("Param1"), "target")
	case chLSM + "/21", chLSM + "/22", chLSM + "/25":
		ip, ok := normIP(get("Address"))
		if !ok {
			return false // "LOCAL": a session at the console
		}
		names := map[string]string{"21": "Remote Desktop session logon (21)", "22": "Remote Desktop shell started (22)", "25": "Remote Desktop session reconnected (25)"}
		oe.Act, oe.What = "rdp-in", names[f.EventID]
		add("ip", ip, "source")
		account("", get("User"), "target")
	case chCoreTS + "/131":
		oe.Act, oe.What = "rdp-in", "Remote Desktop connection accepted (RdpCoreTS 131)"
		v := get("ClientIP")
		if ap, err := netip.ParseAddrPort(v); err == nil {
			v = ap.Addr().String()
		} else if i := strings.LastIndex(v, ":"); i > 0 && strings.Count(v, ":") == 1 {
			v = v[:i]
		}
		source(v)
	case chRDPCli + "/1024":
		oe.Act, oe.What = "rdp-out", "Remote Desktop client connecting (1024)"
		target(get("Value"))
	case chRDPCli + "/1102":
		oe.Act, oe.What = "rdp-out", "Remote Desktop client connected (1102)"
		target(get("Value"))
	default:
		return false
	}
	return len(oe.Items) > 0
}

func fieldString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprint(x)
	default:
		return fmt.Sprint(x)
	}
}

func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	return s
}

// normIP gives an address in canonical form (an IPv4 address mapped into
// IPv6 as plain IPv4); false for anything else.
func normIP(s string) (string, bool) {
	s = strings.Trim(strings.TrimSpace(s), "[]")
	if i := strings.IndexByte(s, '%'); i > 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.IsUnspecified() {
		return "", false
	}
	return a.Unmap().String(), true
}

// normHostName is a computer name in upper case, without a leading "\\".
func normHostName(s string) string {
	s = strings.ToUpper(strings.TrimLeft(strings.TrimSpace(s), `\`))
	if s == "" || s == "-" || s == "LOCALHOST" || strings.ContainsAny(s, " \t/") {
		return ""
	}
	return s
}

// ObservedEvents lists the observed events of the current, included runs
// with one of the acts given, in time order. ok is false while some run has
// not been read yet (BuildDerived is still working).
func (s *Store) ObservedEvents(acts ...string) (out []ObservedEvent, ok bool, err error) {
	var missing int
	if err := s.r.QueryRow(`SELECT count(*) FROM current_runs c
		WHERE NOT EXISTS (SELECT 1 FROM observables_done d WHERE d.run_id = c.run_id AND d.version = ?)`, observablesVersion).Scan(&missing); err != nil {
		return nil, false, err
	}
	if len(acts) == 0 {
		return nil, missing == 0, nil
	}
	q := `SELECT o.event_id, o.evidence_id, o.ts_utc, o.host, o.act, o.what, o.kind, o.value, o.role
		FROM observables o JOIN current_runs c ON c.run_id = o.run_id AND c.evidence_id` + notExcluded + `
		WHERE o.version = ? AND o.act IN (?` + strings.Repeat(",?", len(acts)-1) + `)
		ORDER BY o.ts_utc, o.event_id, o.rowid`
	args := []any{observablesVersion}
	for _, a := range acts {
		args = append(args, a)
	}
	rows, err := s.r.Query(q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var cur *ObservedEvent
	for rows.Next() {
		var oe ObservedEvent
		var it Observable
		if err := rows.Scan(&oe.EventID, &oe.EvidenceID, &oe.TSUTC, &oe.Host, &oe.Act, &oe.What, &it.Kind, &it.Value, &it.Role); err != nil {
			return nil, false, err
		}
		if cur == nil || cur.EventID != oe.EventID {
			out = append(out, oe)
			cur = &out[len(out)-1]
		}
		cur.Items = append(cur.Items, it)
	}
	return out, missing == 0, rows.Err()
}

// buildObservables reads every sealed run not yet read (BuildDerived).
func (s *Store) buildObservables(ctx context.Context) error {
	rows, err := s.r.Query(`SELECT r.run_id FROM run_results r
		WHERE NOT EXISTS (SELECT 1 FROM observables_done d WHERE d.run_id = r.run_id AND d.version = ?) ORDER BY r.run_id`, observablesVersion)
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
		if err := s.computeObservables(id); err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("reading observables of run %d: %w", id, err)
		}
	}
	return nil
}
