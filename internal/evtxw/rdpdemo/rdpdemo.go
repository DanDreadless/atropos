// Package rdpdemo writes a made-up set of Windows event logs from three
// hosts that connect to each other by Remote Desktop: for trying the
// Connections view (scripts/mkrdp) and for the tests. No real machine,
// person or network is described: the domain is corp.example, and the
// addresses are private or documentation ranges.
//
// The story, in true time (UTC) on 20 November 2026:
//
//	08:55  203.0.113.45 -> SRV-FILE01  svc_backup  (the target's side only)
//	09:14  WS-ALICE -> SRV-FILE01      alice       (both ends)
//	09:41  SRV-FILE01 -> DC01          svc_backup  (both ends)
//	10:05  WS-ALICE -> 10.9.9.9        alice       (the source's side only)
//	10:30  WS-ALICE -> DC01            alice       (the target's side only)
//
// WS-ALICE's clock is three minutes fast.
package rdpdemo

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/evtxw"
)

// Host is one of the made-up hosts, as it would be described.
type Host struct {
	Name, IP, OtherName, Clock string
}

// Hosts are the three hosts, with what to state for each.
var Hosts = []Host{
	{"WS-ALICE", "10.1.1.20", "WS-ALICE.corp.example", "3 minutes ahead"},
	{"SRV-FILE01", "10.1.1.50", "SRV-FILE01.corp.example", ""},
	{"DC01", "10.1.1.10", "DC01.corp.example", ""},
}

type host struct {
	name, ip string
	clock    time.Duration // how far its clock is ahead of true time
	logs     map[string][]evtxw.Record
}

const domain = "CORP"

var day = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

func at(hhmmss string) time.Time {
	t, err := time.Parse("15:04:05", hhmmss)
	if err != nil {
		panic(err)
	}
	return day.Add(time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute + time.Duration(t.Second())*time.Second)
}

const (
	chSecurity = "Security"
	chClient   = "Microsoft-Windows-TerminalServices-RDPClient/Operational"
	chRCM      = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
	chLSM      = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
	chCore     = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
)

var providers = map[string][2]string{
	chSecurity: {"Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}"},
	chClient:   {"Microsoft-Windows-TerminalServices-ClientActiveXCore", "{28AA95BB-D444-4719-A36F-40462168127E}"},
	chRCM:      {"Microsoft-Windows-TerminalServices-RemoteConnectionManager", "{C76BAA63-AE81-421C-B425-340B4B24157F}"},
	chLSM:      {"Microsoft-Windows-TerminalServices-LocalSessionManager", "{5D896912-022D-40AA-A3A8-4FA5515C76D7}"},
	chCore:     {"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", "{1139C61B-B549-4251-8ED3-27250A1EDEC8}"},
}

// log adds an event at true time t, written as h's clock showed it.
func (h *host) log(ch string, eid uint16, t time.Time, data []evtxw.KV, ud []evtxw.KV) {
	p := providers[ch]
	r := evtxw.Record{
		Provider: p[0], ProviderGUID: p[1], EventID: eid, Level: 4, Time: t.Add(h.clock),
		ProcessID: 1012, ThreadID: 2240, Channel: ch, Computer: h.name + ".corp.example", Data: data,
	}
	if ch == chSecurity {
		r.Level, r.Keywords, r.ProcessID, r.ThreadID = 0, 0x8020000000000000, 712, 820
	}
	if ud != nil {
		r.UserData = &evtxw.UserData{Element: "EventXML", NS: "Event_NS", Fields: ud}
		r.Data = nil
	}
	if ch != chSecurity {
		r.UserSID = "S-1-5-18"
	}
	h.logs[ch] = append(h.logs[ch], r)
}

func kv(pairs ...any) []evtxw.KV {
	var out []evtxw.KV
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, evtxw.KV{Name: pairs[i].(string), Value: pairs[i+1]})
	}
	return out
}

var logonSeq uint64

func nextLogon() evtxw.Hex64 { logonSeq += 0x1b7; return evtxw.Hex64(logonSeq) }

func logon(h *host, t time.Time, logonType uint32, user, workstation, ip string, port int, id evtxw.Hex64) {
	proc, pkg := "User32 ", "Negotiate"
	if logonType == 3 {
		proc, pkg = "NtLmSsp ", "NTLM"
	}
	if logonType == 5 {
		proc, pkg = "Advapi  ", "Negotiate"
	}
	h.log(chSecurity, 4624, t, kv(
		"SubjectUserSid", "S-1-5-18", "SubjectUserName", h.name+"$", "SubjectDomainName", domain, "SubjectLogonId", evtxw.Hex64(0x3e7),
		"TargetUserSid", "S-1-5-21-1004336348-1177238915-682003330-1"+fmt.Sprint(len(user)*37), "TargetUserName", user, "TargetDomainName", domain,
		"TargetLogonId", id, "LogonType", logonType, "LogonProcessName", proc, "AuthenticationPackageName", pkg,
		"WorkstationName", workstation, "LogonGuid", "{00000000-0000-0000-0000-000000000000}", "TransmittedServices", "-",
		"LmPackageName", "-", "KeyLength", uint32(0), "ProcessId", evtxw.Hex64(0x2c8), "ProcessName", `C:\Windows\System32\svchost.exe`,
		"IpAddress", ip, "IpPort", fmt.Sprint(port), "ImpersonationLevel", "%%1833", "ElevatedToken", "%%1842",
	), nil)
}

// rdpIn is what the host connected to records for one Remote Desktop
// session from fromIP (workstation the client's name), user logging on.
func rdpIn(h *host, t, end time.Time, user, workstation, fromIP string, port int, session string) {
	h.log(chCore, 131, t, kv("ConnType", "TCP", "ClientIP", fmt.Sprintf("%s:%d", fromIP, port)), nil)
	logon(h, t.Add(2*time.Second), 3, user, workstation, fromIP, port, nextLogon()) // network level authentication
	h.log(chRCM, 1149, t.Add(3*time.Second), nil, kv("Param1", user, "Param2", domain, "Param3", fromIP))
	id := nextLogon()
	logon(h, t.Add(4*time.Second), 10, user, workstation, fromIP, port, id)
	h.log(chSecurity, 4672, t.Add(4*time.Second), kv("SubjectUserSid", "S-1-5-21-1004336348-1177238915-682003330-1105",
		"SubjectUserName", user, "SubjectDomainName", domain, "SubjectLogonId", id, "PrivilegeList", "SeBackupPrivilege\n\t\t\tSeRestorePrivilege"), nil)
	who := domain + `\` + user
	h.log(chLSM, 21, t.Add(5*time.Second), nil, kv("User", who, "SessionID", session, "Address", fromIP))
	h.log(chLSM, 22, t.Add(6*time.Second), nil, kv("User", who, "SessionID", session, "Address", fromIP))
	h.log(chLSM, 24, end, nil, kv("User", who, "SessionID", session, "Address", fromIP))
	h.log(chSecurity, 4779, end, kv("AccountName", user, "AccountDomain", domain, "LogonID", id, "SessionName", "RDP-Tcp#3",
		"ClientName", workstation, "ClientAddress", fromIP), nil)
	h.log(chLSM, 23, end.Add(20*time.Second), nil, kv("User", who, "SessionID", session))
	h.log(chSecurity, 4634, end.Add(21*time.Second), kv("TargetUserSid", "S-1-5-21-1004336348-1177238915-682003330-1105",
		"TargetUserName", user, "TargetDomainName", domain, "TargetLogonId", id, "LogonType", uint32(10)), nil)
}

// rdpOut is what the client records when user connects to target (as typed:
// a name or an address), whose address is targetIP.
func rdpOut(h *host, t time.Time, localUser, user, target, targetIP string) {
	h.log(chClient, 1024, t.Add(-2*time.Second), kv("Name", "Server Name", "Value", target, "CustomLevel", "Info"), nil)
	h.log(chSecurity, 4648, t.Add(-1*time.Second), kv(
		"SubjectUserSid", "S-1-5-21-1004336348-1177238915-682003330-1104", "SubjectUserName", localUser, "SubjectDomainName", domain,
		"SubjectLogonId", evtxw.Hex64(0x2f1c4), "LogonGuid", "{00000000-0000-0000-0000-000000000000}",
		"TargetUserName", user, "TargetDomainName", domain, "TargetLogonGuid", "{00000000-0000-0000-0000-000000000000}",
		"TargetServerName", target, "TargetInfo", "TERMSRV/"+target, "ProcessId", evtxw.Hex64(0x1a38),
		"ProcessName", `C:\Windows\System32\mstsc.exe`, "IpAddress", "-", "IpPort", "-"), nil)
	if targetIP != "" {
		h.log(chClient, 1102, t.Add(1*time.Second), kv("Name", "Server Address", "Value", targetIP, "CustomLevel", "Info"), nil)
	}
}

// background is ordinary activity, so the RDP events are not alone.
func background(h *host, user string) {
	for i, hhmm := range []string{"07:58:12", "08:30:00", "09:00:00", "09:30:00", "10:00:00", "10:30:00", "11:00:00"} {
		logon(h, at(hhmm), 5, "SYSTEM", "", "-", 0, evtxw.Hex64(0x3e7))
		if user != "" && i == 0 {
			logon(h, at(hhmm).Add(40*time.Second), 2, user, h.name, "127.0.0.1", 0, nextLogon())
		}
	}
}

// Write writes each host's logs into a folder of its own under dir0
// (WS-ALICE, SRV-FILE01, DC01), named as Windows names them, and README.txt.
func Write(dir0 string) error {
	logonSeq = 0x5a3f00 // the same files every time
	alice := &host{name: "WS-ALICE", ip: "10.1.1.20", clock: 3 * time.Minute, logs: map[string][]evtxw.Record{}}
	file := &host{name: "SRV-FILE01", ip: "10.1.1.50", logs: map[string][]evtxw.Record{}}
	dc := &host{name: "DC01", ip: "10.1.1.10", logs: map[string][]evtxw.Record{}}
	background(alice, "alice")
	background(file, "")
	background(dc, "")

	// 08:55 Someone on the internet logs on to the file server as svc_backup
	// after two failures. Only the file server's side exists.
	for i, s := range []string{"08:54:31", "08:54:47"} {
		file.log(chSecurity, 4625, at(s), kv("TargetUserName", "svc_backup", "TargetDomainName", domain, "Status", evtxw.Hex64(0xc000006d),
			"SubStatus", evtxw.Hex64(0xc000006a), "LogonType", uint32(3), "WorkstationName", "DESKTOP-J4H2Q9P",
			"IpAddress", "203.0.113.45", "IpPort", fmt.Sprint(51320+i)), nil)
	}
	rdpIn(file, at("08:55:10"), at("09:31:02"), "svc_backup", "DESKTOP-J4H2Q9P", "203.0.113.45", 51388, "3")

	// 09:14 alice connects from her workstation to the file server, typing
	// its name. Both ends exist; her clock is three minutes fast.
	rdpOut(alice, at("09:14:20"), "alice", "alice", "SRV-FILE01", "10.1.1.50")
	rdpIn(file, at("09:14:20"), at("09:52:40"), "alice", "WS-ALICE", "10.1.1.20", 50642, "4")

	// 09:41 From the file server, svc_backup connects to the domain
	// controller by address.
	rdpOut(file, at("09:41:05"), "svc_backup", "svc_backup", "10.1.1.10", "10.1.1.10")
	rdpIn(dc, at("09:41:05"), at("10:12:30"), "svc_backup", "SRV-FILE01", "10.1.1.50", 49733, "2")

	// 10:05 alice's workstation tries an address that is not in the case.
	rdpOut(alice, at("10:05:44"), "alice", "alice", "10.9.9.9", "")

	// 10:30 The domain controller records a session from alice's address,
	// but her workstation has no record of it (its client log was cleared,
	// or another program was used).
	rdpIn(dc, at("10:30:15"), at("10:44:00"), "alice", "WS-ALICE", "10.1.1.20", 50990, "3")

	names := map[string]string{
		chSecurity: "Security.evtx",
		chClient:   "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
		chRCM:      "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
		chLSM:      "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
		chCore:     "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
	}
	for _, h := range []*host{alice, file, dc} {
		dir := filepath.Join(dir0, h.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for ch, recs := range h.logs {
			sort.SliceStable(recs, func(i, j int) bool { return recs[i].Time.Before(recs[j].Time) })
			f, err := os.Create(filepath.Join(dir, names[ch]))
			if err != nil {
				return err
			}
			if err := evtxw.Write(f, recs); err != nil {
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir0, "README.txt"), []byte(strings.TrimLeft(readme, "\n")), 0o644); err != nil {
		return err
	}
	return nil
}

const readme = `
Made-up Remote Desktop logs from three hosts (scripts/mkrdp). Nothing here
describes a real machine, person or network.

1. Make a new case, and on the Details tab add three hosts:

     Computer name   IP addresses   Other names              Clock difference
     WS-ALICE        10.1.1.20      WS-ALICE.corp.example    3 minutes ahead
     SRV-FILE01      10.1.1.50      SRV-FILE01.corp.example  (leave empty)
     DC01            10.1.1.10      DC01.corp.example        (leave empty)

   Time zone: UTC for all three.

2. Add each folder's logs, choosing its host in the add dialog.

3. Open the Connections tab. It should show, on 20 November 2026 (UTC):

   08:55  203.0.113.45 -> SRV-FILE01   svc_backup   seen on the target only
                                        (an address outside the case)
   09:14  WS-ALICE -> SRV-FILE01        alice        both ends: strong
   09:41  SRV-FILE01 -> DC01            svc_backup   both ends: strong
   10:05  WS-ALICE -> 10.9.9.9          alice        seen on the source only
   10:30  WS-ALICE -> DC01              alice        seen on the target only

   Without WS-ALICE's clock difference stated, the 09:14 connection is
   three minutes apart and pairs only as "possible"; with it, the times
   agree to within seconds.
`
