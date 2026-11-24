package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Observables are who and what an event involves, taken out of its fields
// once so that links between hosts can be found without reading every event:
// the address a Remote Desktop session came from, the computer a client
// connected to, the account used. Like the run summaries they are derived
// from a sealed run, never change, and are rebuilt under a new version when
// how they are taken changes.
//
// An act names the kind of connection and which end recorded it: "rdp-out"
// on the computer connecting, "rdp-in" on the computer connected to; "smb-"
// for a file share, "exec-" for a program started remotely (PsExec, a
// service or task created over the network, WinRM, WMI); "logon-in" for a
// network logon, which only supports the others. Devices and hashes are to
// follow (the plan, H.2).
//
// "rdp-named" and "smb-named" are the connecting computer's registry
// naming a computer it connected to (the Remote Desktop server lists,
// MountPoints2). Their time is the key's last write, not a connection's, so
// they support a connection and are never paired by time.
//
// A record of remote execution at the target that names no source (a
// service installed, a task created, a program WMI started) carries a "via"
// item saying how it was started: service, task, wmi or winrm. The analysis
// ties it to a network logon by time, and by account where it names one.

const observablesVersion = 4

const observablesSchema = `
CREATE TABLE IF NOT EXISTS observables (
  event_id    INTEGER NOT NULL,
  run_id      INTEGER NOT NULL REFERENCES runs(id),
  evidence_id INTEGER NOT NULL,
  ts_utc      INTEGER NOT NULL,
  host        TEXT NOT NULL,      -- the event's host
  act         TEXT NOT NULL,      -- what the event shows: rdp-out, rdp-in, smb-in, exec-out, logon-in...
  what        TEXT NOT NULL,      -- the event, briefly: "RDP client connecting (1024)"
  kind        TEXT NOT NULL,      -- ip, host, account, share, file, service, task, program, via
  value       TEXT NOT NULL,
  role        TEXT NOT NULL,      -- source, target, subject, object
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

// Channels read.
const (
	chSystem   = "System"
	chSysmon   = "Microsoft-Windows-Sysmon/Operational"
	chSecurity = "Security"
	chRDPCli   = "Microsoft-Windows-TerminalServices-RDPClient/Operational"
	chRCM      = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
	chLSM      = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
	chCoreTS   = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
	chWinRM    = "Microsoft-Windows-WinRM/Operational"
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
		WHERE run_id = ? AND source = 'evtx' AND category IN ('account', 'network', 'execution', 'persistence')
		AND json_extract(fields, '$.channel') IN (?,?,?,?,?,?,?,?)`, runID, chSecurity, chRDPCli, chRCM, chLSM, chCoreTS, chSystem, chSysmon, chWinRM)
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
	// The connecting computer's own records outside its logs: the
	// registry's Remote Desktop server lists and MountPoints2, and jump
	// list entries on a share.
	rows, err = s.r.Query(`SELECT id, evidence_id, ts_utc, host, ts_type, path, fields FROM events
		WHERE run_id = ? AND source IN ('registry', 'jumplist') AND ts_type IN (?,?,?,?)`,
		runID, "rdp-client-server-key-last-write", "rdp-client-recent-key-last-write", "network-share-key-last-write", "jumplist-entry-last-used")
	if err != nil {
		return err
	}
	for rows.Next() {
		var oe ObservedEvent
		var typ, path, fields string
		if err := rows.Scan(&oe.EventID, &oe.EvidenceID, &oe.TSUTC, &oe.Host, &typ, &path, &fields); err != nil {
			rows.Close()
			return err
		}
		if observeArtefact(&oe, typ, path, fields) {
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
		case "3":
			// A network logon: by itself it says only that something
			// authenticated from there, so it supports the other acts.
			// Computer accounts, anonymous logons and the host itself are
			// left out: they are constant and say nothing of a person.
			ip, ok := normIP(get("IpAddress"))
			user := get("TargetUserName")
			if !ok || isLoopbackIP(ip) || user == "" || strings.HasSuffix(user, "$") || strings.EqualFold(user, "ANONYMOUS LOGON") {
				return false
			}
			oe.Act, oe.What = "logon-in", "Network logon (Security 4624, type 3)"
			add("ip", ip, "source")
			if h := normHostName(get("WorkstationName")); h != "" {
				add("host", h, "source")
			}
			account(get("TargetDomainName"), user, "target")
			return true
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
		svc, rest, _ := strings.Cut(get("TargetInfo"), "/")
		switch strings.ToUpper(svc) {
		case "TERMSRV":
			oe.Act, oe.What = "rdp-out", "Explicit credentials for Remote Desktop (Security 4648)"
		case "CIFS":
			oe.Act, oe.What = "smb-out", "Explicit credentials for a file share (Security 4648)"
		case "WSMAN":
			oe.Act, oe.What = "exec-out", "Explicit credentials for remote management (WinRM, Security 4648)"
		case "HTTP":
			// HTTP is any web server; only the remote management clients
			// make it remote management.
			switch baseName(get("ProcessName")) {
			case "powershell.exe", "pwsh.exe", "powershell_ise.exe", "winrs.exe", "wsmprovhost.exe":
				oe.Act, oe.What = "exec-out", "Explicit credentials for remote management (WinRM, Security 4648)"
			default:
				return false
			}
		case "RPCSS":
			// The remote activation of WMI and DCOM: wmic /node: and
			// Invoke-WmiMethod -ComputerName with a user named.
			oe.Act, oe.What = "exec-out", "Explicit credentials for remote WMI or DCOM (RPCSS, Security 4648)"
		default:
			return false
		}
		t := get("TargetServerName")
		if t == "" || strings.EqualFold(t, "localhost") {
			t = rest
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
	case chSecurity + "/5140", chSecurity + "/5145":
		if !observeShare(oe, f.EventID, get, add, account) {
			return false
		}
	case chSystem + "/7045", chSecurity + "/4697":
		// A service installed. The record has no source: the analysis
		// ties it to a network logon or share access near it in time.
		name := get("ServiceName")
		if name == "" {
			return false
		}
		oe.Act = "exec-in"
		if f.EventID == "7045" {
			oe.What = "Service installed: " + name + " (System 7045)"
			add("program", get("ImagePath"), "object")
		} else {
			oe.What = "Service installed: " + name + " (Security 4697)"
			add("program", get("ServiceFileName"), "object")
			account(get("SubjectDomainName"), get("SubjectUserName"), "target")
		}
		add("service", name, "object")
		add("via", "service", "object")
	case chSecurity + "/4698", chSecurity + "/4702":
		// A scheduled task created or changed. Like a service it records
		// no source, and tasks are made locally all the time, so only those
		// by a person's account are read; the analysis ties them to a
		// network logon by the same account.
		name, user := get("TaskName"), get("SubjectUserName")
		if name == "" || !personAccount(user) {
			return false
		}
		content := get("TaskContent")
		oe.Act, oe.What = "exec-in", "Scheduled task created: "+name+" (Security 4698)"
		if f.EventID == "4702" {
			content = get("TaskContentNew")
			oe.What = "Scheduled task changed: " + name + " (Security 4702)"
		}
		add("task", name, "object")
		add("program", taskCommand(content), "object")
		account(get("SubjectDomainName"), user, "target")
		add("via", "task", "object")
	case chWinRM + "/6":
		// The client: "Creating WSMan Session. The connection string is:
		// dc01/wsman?PSVersion=5.1".
		conn := get("connection")
		if conn == "" {
			for _, v := range d {
				if s := fieldString(v); strings.Contains(strings.ToLower(s), "wsman") {
					conn = s
					break
				}
			}
		}
		t := wsmanHost(conn)
		if t == "" {
			return false
		}
		oe.Act, oe.What = "exec-out", "Remote management session to "+t+" (WinRM 6)"
		target(t)
	case chWinRM + "/91":
		// The server: a shell created. The record often carries nothing
		// readable (its shell id fails to decode), so it is tied by time.
		oe.Act, oe.What = "exec-in", "Remote management shell created (WinRM 91)"
		add("via", "winrm", "object")
	case chSecurity + "/4688", chSysmon + "/1":
		image, parent, user := get("NewProcessName"), get("ParentProcessName"), ""
		if f.EventID == "1" {
			image, parent, user = get("Image"), get("ParentImage"), get("User")
		} else {
			// The new process's own account (Windows 10 on) before the
			// creator's, which for a program WMI starts is the computer.
			for _, p := range [][2]string{{"TargetDomainName", "TargetUserName"}, {"SubjectDomainName", "SubjectUserName"}} {
				if u := get(p[1]); u != "" && !strings.HasSuffix(u, "$") {
					user = u
					if d := get(p[0]); d != "" {
						user = d + `\` + u
					}
					break
				}
			}
		}
		if !observeCommand(oe, image, parent, get("CommandLine"), user, add) {
			return false
		}
	default:
		return false
	}
	return len(oe.Items) > 0
}

// observeShare reads Security 5140 (a share connected to) and 5145 (an
// object on it checked). Shares every domain member reads (SYSVOL, NETLOGON,
// print$), computer accounts and the host itself are left out. On IPC$ only
// the named pipes of remote execution count: the service and task managers,
// and pipes named as PsExec and its imitators name them.
func observeShare(oe *ObservedEvent, eid string, get func(string) string, add func(string, string, string), account func(string, string, string)) bool {
	ip, ok := normIP(get("IpAddress"))
	user := get("SubjectUserName")
	if !ok || isLoopbackIP(ip) || strings.HasSuffix(user, "$") {
		return false
	}
	share := get("ShareName")
	if i := strings.LastIndexByte(share, '\\'); i >= 0 {
		share = share[i+1:]
	}
	shareU := strings.ToUpper(share)
	rel := get("RelativeTargetName")
	relL := strings.ToLower(rel)
	switch {
	case shareU == "" || shareU == "SYSVOL" || shareU == "NETLOGON" || shareU == "PRINT$":
		return false
	case shareU == "IPC$":
		if eid != "5145" {
			return false
		}
		switch {
		case relL == "svcctl":
			oe.Act, oe.What = "exec-in", "Service manager reached over the network (svcctl, Security 5145)"
		case relL == "atsvc":
			oe.Act, oe.What = "exec-in", "Task Scheduler reached over the network (atsvc, Security 5145)"
		case strings.HasSuffix(relL, "-stdin") || strings.HasSuffix(relL, "-stdout") || strings.HasSuffix(relL, "-stderr") ||
			strings.HasPrefix(relL, "psexesvc") || strings.HasPrefix(relL, "remcom") || strings.HasPrefix(relL, "paexec"):
			oe.Act, oe.What = "exec-in", "Pipe named as PsExec names them: "+rel+" (Security 5145)"
		default:
			return false
		}
	case eid == "5145" && isProgram(relL) && writes(get("AccessMask")):
		// A program written to ADMIN$ (the Windows folder) is how PsExec
		// and its kind deliver their service; elsewhere it is a file copy,
		// named so it stands out.
		oe.Act, oe.What = "smb-in", "Program written to "+share+": "+rel+" (Security 5145)"
		if shareU == "ADMIN$" {
			oe.Act = "exec-in"
		}
		add("program", rel, "object")
	case eid == "5140":
		oe.Act, oe.What = "smb-in", "Share connected: "+share+" (Security 5140)"
	default:
		oe.Act, oe.What = "smb-in", "Share object checked: "+share+`\`+rel+" (Security 5145)"
	}
	add("ip", ip, "source")
	account(get("SubjectDomainName"), user, "target")
	add("share", share, "object")
	return true
}

func isProgram(name string) bool {
	for _, ext := range []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sys"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// writes reports whether an access mask asks to write data or append to a
// file (WriteData 0x2, AppendData 0x4).
func writes(mask string) bool {
	m, err := strconv.ParseUint(strings.TrimSpace(mask), 0, 64)
	return err == nil && m&0x6 != 0
}

// observeCommand reads a process created (Security 4688 with its command
// line, Sysmon 1). At the computer connecting: a command that names another
// computer, as PsExec and its kind, sc, at and schtasks do with \\name,
// wmic with /node:, winrs with -r:, schtasks with /s and PowerShell's
// remoting commands with -ComputerName, is remote execution; any other
// command naming \\name or \\name\share (net use, copy, a program run from a
// share) is the share. At the computer connected to: the PsExec service, the
// PowerShell remoting and winrs hosts starting, and programs that WMI or
// those hosts start, are remote execution with no source.
func observeCommand(oe *ObservedEvent, image, parent, cmd, user string, add func(string, string, string)) bool {
	base, pbase := baseName(image), baseName(parent)
	switch {
	case base == "psexesvc.exe":
		oe.Act, oe.What = "exec-in", "PsExec service started (PSEXESVC.exe)"
		add("via", "service", "object")
	case base == "wsmprovhost.exe":
		oe.Act, oe.What = "exec-in", "PowerShell remoting session started (wsmprovhost.exe)"
		add("via", "winrm", "object")
	case base == "winrshost.exe":
		oe.Act, oe.What = "exec-in", "Remote shell host started (winrshost.exe)"
		add("via", "winrm", "object")
	case pbase == "wsmprovhost.exe" || pbase == "winrshost.exe":
		oe.Act, oe.What = "exec-in", "Program started over remote management: "+base+" (by "+pbase+")"
		add("via", "winrm", "object")
	case pbase == "wmiprvse.exe":
		// WMI starts programs for local software all the time; only those
		// run as a person's account are read, and the analysis wants a
		// network logon by that account.
		if !personAccount(user) {
			return false
		}
		oe.Act, oe.What = "exec-in", "Program started by WMI: "+base+" (by WmiPrvSE.exe)"
		add("via", "wmi", "object")
	default:
		return observeCommandOut(oe, image, base, cmd, user, add)
	}
	if personAccount(user) {
		add("account", user, "target")
	}
	add("program", image, "object")
	return true
}

func observeCommandOut(oe *ObservedEvent, image, base, cmd, user string, add func(string, string, string)) bool {
	prog := base
	if prog == "" {
		prog = "a program"
	}
	target, how := remoteArg(base, cmd)
	if target != "" {
		oe.Act, oe.What = "exec-out", how+" "+target+": "+prog
	} else {
		for _, s := range []string{image, cmd} {
			if t := uncHosts(s); len(t) > 0 {
				target = t[0]
				break
			}
		}
		if target == "" {
			return false
		}
		switch base {
		case "psexec.exe", "psexec64.exe", "paexec.exe", "paexec64.exe", "remcom.exe", "sc.exe", "at.exe", "schtasks.exe", "wmic.exe", "winrs.exe":
			oe.Act, oe.What = "exec-out", `Program run against \\`+target+": "+prog
		default:
			oe.Act, oe.What = "smb-out", `Command naming \\`+target+": "+prog
		}
	}
	if ip, ok := normIP(target); ok {
		add("ip", ip, "target")
	} else {
		add("host", target, "target")
	}
	if u := credentialArg(cmd); u != "" {
		add("account", u, "target")
	}
	add("account", user, "subject")
	add("program", image, "object")
	return true
}

// remoteArg is the computer a remote management command names other than as
// \\name, and how it is named: wmic /node:name, winrs -r:name, schtasks
// /s name, and PowerShell's remoting and WMI commands with -ComputerName
// name (or Enter-PSSession name).
func remoteArg(base, cmd string) (target, how string) {
	f := strings.Fields(cmd)
	tok := func(i int) string { return strings.Trim(f[i], `"'`) }
	pick := func(v string) string {
		v = strings.Trim(v, `"'`)
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i] // the first of several
		}
		v = strings.Trim(v, `"'`)
		if v == "" || v == "." || strings.ContainsAny(v, "$@({*%") {
			return "" // a variable, a list in a file, the local computer
		}
		if ip, ok := normIP(v); ok {
			if isLoopbackIP(ip) {
				return ""
			}
			return ip
		}
		return normHostName(v)
	}
	switch base {
	case "wmic.exe":
		for i := range f {
			if t := tok(i); len(t) > 6 && strings.EqualFold(t[:6], "/node:") {
				return pick(t[6:]), "WMI command against"
			}
		}
	case "winrs.exe":
		for i := range f {
			t := tok(i)
			lt := strings.ToLower(t)
			for _, p := range []string{"-r:", "/r:", "-remote:", "/remote:"} {
				if strings.HasPrefix(lt, p) {
					return pick(wsmanHost(t[len(p):])), "Remote shell against"
				}
			}
		}
	case "schtasks.exe":
		for i := 0; i+1 < len(f); i++ {
			if strings.EqualFold(tok(i), "/s") {
				return pick(strings.TrimLeft(tok(i+1), `\`)), "Scheduled task command against"
			}
		}
	case "powershell.exe", "pwsh.exe", "powershell_ise.exe":
		lc := strings.ToLower(cmd)
		remote := false
		for _, c := range []string{"invoke-command", "enter-pssession", "new-pssession", "invoke-wmimethod", "invoke-cimmethod", "new-cimsession"} {
			if strings.Contains(lc, c) {
				remote = true
			}
		}
		if !remote {
			return "", ""
		}
		for i := 0; i+1 < len(f); i++ {
			lt := strings.ToLower(tok(i))
			switch {
			case lt == "-computername" || lt == "-cn":
				return pick(tok(i + 1)), "PowerShell remoting to"
			case strings.HasPrefix(lt, "-computername:"):
				return pick(tok(i)[len("-computername:"):]), "PowerShell remoting to"
			case lt == "enter-pssession" && !strings.HasPrefix(tok(i+1), "-"):
				return pick(tok(i + 1)), "PowerShell remoting to"
			}
		}
	}
	return "", ""
}

// wsmanHost is the computer of a WinRM connection string: "dc01/wsman?...",
// "http://10.0.0.5:5985/wsman", "https://[fe80::1]:5986/wsman".
func wsmanHost(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			s = s[1:i]
		}
	} else if strings.Count(s, ":") == 1 {
		s = s[:strings.IndexByte(s, ':')]
	}
	if ip, ok := normIP(s); ok {
		if isLoopbackIP(ip) {
			return ""
		}
		return ip
	}
	return normHostName(s)
}

// taskCommand is the first program a task's XML runs (<Command>).
func taskCommand(xml string) string {
	_, rest, ok := strings.Cut(xml, "<Command>")
	if !ok {
		return ""
	}
	cmd, _, _ := strings.Cut(rest, "</Command>")
	return strings.TrimSpace(cmd)
}

// personAccount reports whether an account is a person's rather than the
// computer's or a service's own.
func personAccount(user string) bool {
	if user == "" || strings.HasSuffix(user, "$") {
		return false
	}
	u := user
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	switch strings.ToUpper(u) {
	case "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "LOCALSYSTEM", "-":
		return false
	}
	return true
}

// baseName is a path's last element in lower case.
func baseName(p string) string {
	p = strings.ToLower(strings.Trim(p, `" `))
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// uncHosts lists the computers a command line names as \\name, in order,
// leaving out the local computer and device paths (\\?\, \\.\).
func uncHosts(s string) []string {
	var out []string
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '\\' || s[i+1] != '\\' {
			continue
		}
		if i > 0 && !strings.ContainsRune(" \t\"'=>:(,", rune(s[i-1])) {
			continue
		}
		j := i + 2
		for j < len(s) && !strings.ContainsRune("\\/\"' ,;|&<>\t", rune(s[j])) {
			j++
		}
		name := s[i+2 : j]
		i = j
		if ip, ok := normIP(name); ok {
			if !isLoopbackIP(ip) {
				out = append(out, ip)
			}
			continue
		}
		if name == "" || name == "?" || name == "." || strings.ContainsAny(name, "*%$") {
			continue
		}
		if h := normHostName(name); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// credentialArg is the account a command gives to connect as: PsExec's
// -u name, net use's /user:name or /u:name.
func credentialArg(cmd string) string {
	f := strings.Fields(cmd)
	for i, a := range f {
		la := strings.ToLower(a)
		switch {
		case la == "-u" && i+1 < len(f):
			return strings.Trim(f[i+1], `"`)
		case strings.HasPrefix(la, "/user:"):
			return strings.Trim(a[6:], `"`)
		case strings.HasPrefix(la, "/u:"):
			return strings.Trim(a[3:], `"`)
		}
	}
	return ""
}

// isLoopbackIP: the host itself.
func isLoopbackIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsLoopback()
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

// observeArtefact reads what a registry key or jump list entry involves. A
// jump list entry on \\computer\share is a file opened there, at the time
// it gives ("smb-out"). The registry's Remote Desktop server list and recent
// list and its MountPoints2 shares name computers this account connected to,
// but their times are only when the key was last written ("rdp-named",
// "smb-named"): they support a connection, never time one.
func observeArtefact(oe *ObservedEvent, typ, path, fieldsJSON string) bool {
	var f struct {
		Application string `json:"application"`
		Values      map[string]struct {
			Data string `json:"data"`
		} `json:"values"`
	}
	_ = json.Unmarshal([]byte(fieldsJSON), &f)
	add := func(kind, value, role string) {
		if value != "" {
			oe.Items = append(oe.Items, Observable{kind, value, role})
		}
	}
	server := func(v string) bool {
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") {
			if i := strings.IndexByte(v, ']'); i > 0 {
				v = v[1:i]
			}
		} else if strings.Count(v, ":") == 1 {
			v, _, _ = strings.Cut(v, ":") // a port
		}
		if ip, ok := normIP(v); ok {
			if isLoopbackIP(ip) {
				return false
			}
			add("ip", ip, "target")
			return true
		}
		if h := normHostName(v); h != "" && !strings.ContainsAny(h, `\*%$`) {
			add("host", h, "target")
			return true
		}
		return false
	}
	// share is \\computer\share of a path, and the computer.
	share := func(p string) (string, string) {
		if !strings.HasPrefix(p, `\\`) {
			return "", ""
		}
		hs := uncHosts(p)
		if len(hs) == 0 {
			return "", ""
		}
		parts := strings.SplitN(p[2:], `\`, 3)
		if len(parts) < 2 || parts[1] == "" {
			return "", ""
		}
		h := hs[0]
		if i := strings.IndexByte(h, '@'); i > 0 {
			h = h[:i] // WebDAV: name@SSL, name@port
		}
		return `\\` + parts[0] + `\` + parts[1], h
	}
	switch typ {
	case "rdp-client-server-key-last-write":
		if !server(path) {
			return false
		}
		oe.Act, oe.What = "rdp-named", "Remote Desktop server in this account's list: "+path+" (registry, Terminal Server Client\\Servers)"
		if hint := clean(f.Values["UsernameHint"].Data); hint != "" {
			add("account", hint, "target")
			oe.What += ", signing in as " + hint
		}
	case "rdp-client-recent-key-last-write":
		var names []string
		for i := 0; i < 10; i++ {
			v := clean(f.Values[fmt.Sprintf("MRU%d", i)].Data)
			if v != "" && server(v) {
				names = append(names, v)
			}
		}
		if len(names) == 0 {
			return false
		}
		add("via", "recent-list", "object")
		oe.Act, oe.What = "rdp-named", "Remote Desktop recent connections list: "+strings.Join(names, ", ")+" (registry, Terminal Server Client\\Default)"
	case "network-share-key-last-write":
		sh, h := share(path)
		if sh == "" {
			return false
		}
		add(map[bool]string{true: "ip", false: "host"}[isIPText(h)], h, "target")
		add("share", sh, "object")
		oe.Act, oe.What = "smb-named", "Network share in this account's MountPoints2: "+sh+" (registry)"
	case "jumplist-entry-last-used":
		sh, h := share(path)
		if sh == "" {
			return false
		}
		add(map[bool]string{true: "ip", false: "host"}[isIPText(h)], h, "target")
		add("share", sh, "object")
		add("file", path, "object")
		app := f.Application
		if app == "" {
			app = "an application"
		}
		oe.Act, oe.What = "smb-out", "File on a share opened (jump list of "+app+"): "+path
	default:
		return false
	}
	return true
}

func isIPText(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
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
