// Package lateraldemo writes a made-up set of Windows event logs (and one
// user's NTUSER.DAT and jump list) from three
// hosts that connect to each other by Remote Desktop, file shares,
// PsExec, PowerShell remoting, a remote scheduled task, WMI and DCOM: for trying
// the Connections view (scripts/mklateral) and for the tests. No real machine, person or network is described: the domain is
// corp.example, and the addresses are private or documentation ranges.
//
// The story, in true time (UTC) on 20 November 2026:
//
//	08:55  203.0.113.45 -> SRV-FILE01  RDP     svc_backup  (the target's side only)
//	09:14  WS-ALICE -> SRV-FILE01      RDP     alice       (both ends)
//	09:22  WS-ALICE -> SRV-FILE01      share   alice       (both ends: net use, 5140)
//	09:41  SRV-FILE01 -> DC01          RDP     svc_backup  (both ends)
//	09:48  SRV-FILE01 -> DC01          PsExec  svc_backup  (both ends)
//	10:05  WS-ALICE -> 10.9.9.9        RDP     alice       (the source's side only)
//	10:20  WS-ALICE -> DC01            service alice       (the target's side only)
//	10:30  WS-ALICE -> DC01            RDP     alice       (the target's side only)
//	10:50  WS-ALICE -> SRV-FILE01      WinRM   alice       (both ends: Invoke-Command)
//	11:05  a service installed on SRV-FILE01 with nothing from the network near it
//	11:20  SRV-FILE01 -> DC01          task    svc_backup  (both ends: schtasks /s)
//	11:35  WS-ALICE -> DC01            WMI     alice       (both ends: wmic /node:)
//	11:50  WS-ALICE -> SRV-FILE01      share   alice       (both ends: Excel's jump list, 5140)
//	12:05  WS-ALICE -> SRV-FILE01      DCOM    alice       (both ends: MMC20.Application)
//	08:10  a task alice makes on her own workstation, taken as local
//
// alice's NTUSER.DAT names SRV-FILE01, DC01 and 10.9.9.9 as Remote Desktop
// servers (supporting those connections), JUMP-OLD (a computer outside the
// case, named nowhere else: a connection with no time), \\SRV-FILE01\Finance
// and \\DC01\C$ (the second supports nothing, so it stands alone).
//
// WS-ALICE's SYSTEM hive records a USB stick, a Kingston DataTraveler,
// first plugged in at 08:40 and last connected from 11:52 to 11:58.
//
// WS-ALICE's clock is three minutes fast.
package lateraldemo

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/artw"
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
	chSystem   = "System"
	chWinRM    = "Microsoft-Windows-WinRM/Operational"
)

var providers = map[string][2]string{
	chSecurity: {"Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}"},
	chClient:   {"Microsoft-Windows-TerminalServices-ClientActiveXCore", "{28AA95BB-D444-4719-A36F-40462168127E}"},
	chRCM:      {"Microsoft-Windows-TerminalServices-RemoteConnectionManager", "{C76BAA63-AE81-421C-B425-340B4B24157F}"},
	chLSM:      {"Microsoft-Windows-TerminalServices-LocalSessionManager", "{5D896912-022D-40AA-A3A8-4FA5515C76D7}"},
	chCore:     {"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", "{1139C61B-B549-4251-8ED3-27250A1EDEC8}"},
	chSystem:   {"Service Control Manager", "{555908d1-a6d7-4695-8e1e-26931d2012f4}"},
	chWinRM:    {"Microsoft-Windows-WinRM", "{A7975C8F-AC13-49F1-87DA-5A984A4AB417}"},
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

const userSID = "S-1-5-21-1004336348-1177238915-682003330-1104"

// process is a program started on h by user, with its command line
// (Security 4688, with command-line auditing on).
func process(h *host, t time.Time, user, image, cmd string) {
	processAs(h, t, user, image, cmd, `C:\Windows\System32\cmd.exe`, "-")
}

// processAs is a program started on h with the parent given, and the account
// it runs as when that is not its creator (4688 names both from Windows 10).
func processAs(h *host, t time.Time, user, image, cmd, parent, runAs string) {
	td := "-"
	if runAs != "-" {
		td = domain
	}
	h.log(chSecurity, 4688, t, kv(
		"SubjectUserSid", userSID, "SubjectUserName", user, "SubjectDomainName", domain, "SubjectLogonId", evtxw.Hex64(0x2f1c4),
		"NewProcessId", evtxw.Hex64(0x1f30), "NewProcessName", image, "TokenElevationType", "%%1936", "ProcessId", evtxw.Hex64(0x1a10),
		"CommandLine", cmd, "TargetUserSid", "S-1-0-0", "TargetUserName", runAs, "TargetDomainName", td, "TargetLogonId", evtxw.Hex64(0),
		"ParentProcessName", parent, "MandatoryLabel", "S-1-16-12288"), nil)
}

// task is h recording a scheduled task created by user (Security 4698).
func task(h *host, t time.Time, user, name, command string) {
	xml := `<?xml version="1.0" encoding="UTF-16"?>` + "\r\n" + `<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions Context="Author"><Exec><Command>` +
		command + `</Command></Exec></Actions></Task>`
	h.log(chSecurity, 4698, t, kv("SubjectUserSid", userSID, "SubjectUserName", user, "SubjectDomainName", domain, "SubjectLogonId", evtxw.Hex64(0x7d3e2),
		"TaskName", name, "TaskContent", xml), nil)
}

// share is h recording user at fromIP connecting to a share (5140), or,
// with rel, checking an object on it (5145) with the access mask given.
func share(h *host, t time.Time, user, fromIP string, port int, name, local, rel string, mask uint32) {
	data := kv("SubjectUserSid", userSID, "SubjectUserName", user, "SubjectDomainName", domain, "SubjectLogonId", evtxw.Hex64(0x6c2a1),
		"ObjectType", "File", "IpAddress", fromIP, "IpPort", fmt.Sprint(port), "ShareName", `\\*\`+name, "ShareLocalPath", local)
	if rel == "" {
		h.log(chSecurity, 5140, t, append(data, kv("AccessMask", uint32(1), "AccessList", "%%4416")...), nil)
		return
	}
	h.log(chSecurity, 5145, t, append(data, kv("RelativeTargetName", rel, "AccessMask", mask, "AccessList", "%%4416", "AccessReason", "-")...), nil)
}

// service is h installing a service (System 7045).
func service(h *host, t time.Time, name, image string) {
	h.log(chSystem, 7045, t, kv("ServiceName", name, "ImagePath", image, "ServiceType", "user mode service",
		"StartType", "demand start", "AccountName", "LocalSystem"), nil)
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

	// 09:22 alice maps the file server's Finance share and opens a file.
	process(alice, at("09:22:30"), "alice", `C:\Windows\System32\net.exe`, `net  use F: \\SRV-FILE01\Finance /persistent:no`)
	logon(file, at("09:22:31"), 3, "alice", "WS-ALICE", "10.1.1.20", 50710, nextLogon())
	share(file, at("09:22:31"), "alice", "10.1.1.20", 50710, "Finance", `\??\D:\Shares\Finance`, "", 0)
	share(file, at("09:23:02"), "alice", "10.1.1.20", 50710, "Finance", `\??\D:\Shares\Finance`, `Q4\budget.xlsx`, 0x120089)

	// 09:48 svc_backup runs PsExec on the file server against the domain
	// controller: it copies its service to ADMIN$, installs and starts it,
	// and talks to it over named pipes.
	process(file, at("09:48:10"), "svc_backup", `C:\Tools\PsExec64.exe`, `PsExec64.exe \\DC01 -accepteula -s cmd.exe`)
	logon(dc, at("09:48:11"), 3, "svc_backup", "SRV-FILE01", "10.1.1.50", 49801, nextLogon())
	share(dc, at("09:48:11"), "svc_backup", "10.1.1.50", 49801, "ADMIN$", `\??\C:\Windows`, "", 0)
	share(dc, at("09:48:11"), "svc_backup", "10.1.1.50", 49801, "ADMIN$", `\??\C:\Windows`, "PSEXESVC.exe", 0x120196)
	share(dc, at("09:48:12"), "svc_backup", "10.1.1.50", 49801, "IPC$", "", "svcctl", 0x12019f)
	service(dc, at("09:48:12"), "PSEXESVC", `%SystemRoot%\PSEXESVC.exe`)
	share(dc, at("09:48:13"), "svc_backup", "10.1.1.50", 49801, "IPC$", "", "PSEXESVC-SRV-FILE01-4312-stdin", 0x12019f)
	share(dc, at("09:48:13"), "svc_backup", "10.1.1.50", 49801, "IPC$", "", "PSEXESVC-SRV-FILE01-4312-stdout", 0x12019f)
	share(dc, at("09:48:13"), "svc_backup", "10.1.1.50", 49801, "IPC$", "", "srvsvc", 0x12019f) // ordinary: not read

	// 10:20 From alice's address, a program is copied to the domain
	// controller's ADMIN$ and installed as a service. Her workstation has no
	// record of it (no command was logged there).
	logon(dc, at("10:20:00"), 3, "alice", "WS-ALICE", "10.1.1.20", 50912, nextLogon())
	share(dc, at("10:20:01"), "alice", "10.1.1.20", 50912, "ADMIN$", `\??\C:\Windows`, "updsvc.exe", 0x120196)
	share(dc, at("10:20:02"), "alice", "10.1.1.20", 50912, "IPC$", "", "svcctl", 0x12019f)
	service(dc, at("10:20:03"), "UpdSvc", `%SystemRoot%\updsvc.exe`)

	// 11:05 An agent installed on the file server from its own console:
	// nothing from the network near it, so no connection.
	service(file, at("11:05:00"), "BackupAgent", `"C:\Program Files\BackupAgent\agent.exe"`)

	// 10:50 alice runs a command on the file server over PowerShell
	// remoting (WinRM). The client logs the session it creates; the server
	// logs the shell and the remoting host starting as her.
	process(alice, at("10:50:05"), "alice", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`powershell.exe -NoProfile -Command "Invoke-Command -ComputerName SRV-FILE01 -ScriptBlock { Get-ChildItem D:\Shares }"`)
	alice.log(chWinRM, 6, at("10:50:06"), kv("connection", "SRV-FILE01/wsman?PSVersion=5.1.19041.4648"), nil)
	logon(file, at("10:50:06"), 3, "alice", "WS-ALICE", "10.1.1.20", 51022, nextLogon())
	file.log(chWinRM, 91, at("10:50:07"), kv("resourceUri", "http://schemas.microsoft.com/powershell/Microsoft.PowerShell", "shellId", "{6A8F1C3B-2E4D-4F70-9B1A-5C3D2E1F0A9B}"), nil)
	processAs(file, at("10:50:07"), "SRV-FILE01$", `C:\Windows\System32\wsmprovhost.exe`, `C:\Windows\system32\wsmprovhost.exe -Embedding`,
		`C:\Windows\System32\svchost.exe`, "alice")

	// 11:20 svc_backup, on the file server, makes a task on the domain
	// controller with schtasks /s.
	process(file, at("11:20:30"), "svc_backup", `C:\Windows\System32\schtasks.exe`,
		`schtasks.exe /create /s DC01 /tn Cleanup /tr C:\Windows\Temp\cleanup.bat /sc once /st 23:00 /ru SYSTEM`)
	logon(dc, at("11:20:31"), 3, "svc_backup", "SRV-FILE01", "10.1.1.50", 49910, nextLogon())
	share(dc, at("11:20:31"), "svc_backup", "10.1.1.50", 49910, "IPC$", "", "atsvc", 0x12019f)
	task(dc, at("11:20:32"), "svc_backup", `\Cleanup`, `C:\Windows\Temp\cleanup.bat`)

	// 11:35 alice starts a program on the domain controller through WMI.
	process(alice, at("11:35:40"), "alice", `C:\Windows\System32\wbem\WMIC.exe`,
		`wmic /node:DC01 process call create "cmd.exe /c whoami > C:\Windows\Temp\w.txt"`)
	logon(dc, at("11:35:41"), 3, "alice", "WS-ALICE", "10.1.1.20", 51130, nextLogon())
	processAs(dc, at("11:35:42"), "DC01$", `C:\Windows\System32\cmd.exe`, `cmd.exe /c whoami > C:\Windows\Temp\w.txt`,
		`C:\Windows\System32\wbem\WmiPrvSE.exe`, "alice")

	// 08:10 A task alice makes on her own workstation: no network logon by
	// her near it, so it is taken as local and named in the notes.
	task(alice, at("08:10:00"), "alice", `\Backup reminder`, `C:\Users\alice\remind.cmd`)

	// 11:50 alice opens a spreadsheet on the file server's share in Excel:
	// her jump list has it, the file server its share access.
	logon(file, at("11:50:18"), 3, "alice", "WS-ALICE", "10.1.1.20", 51188, nextLogon())
	share(file, at("11:50:18"), "alice", "10.1.1.20", 51188, "Finance", `\??\D:\Shares\Finance`, "", 0)
	share(file, at("11:50:19"), "alice", "10.1.1.20", 51188, "Finance", `\??\D:\Shares\Finance`, `Q3 results.xlsx`, 0x120089)

	// 12:05 alice makes MMC20.Application on the file server over DCOM and
	// runs a command through it: PowerShell on her side; a network logon,
	// mmc.exe started by the DCOM launcher as her, and its child there.
	process(alice, at("12:05:10"), "alice", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`powershell -c "$m=[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','SRV-FILE01')); $m.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c hostname','7')"`)
	logon(file, at("12:05:11"), 3, "alice", "WS-ALICE", "10.1.1.20", 51240, nextLogon())
	processAs(file, at("12:05:12"), "SRV-FILE01$", `C:\Windows\System32\mmc.exe`, `C:\Windows\system32\mmc.exe -Embedding`, `C:\Windows\System32\svchost.exe`, "alice")
	processAs(file, at("12:05:13"), "SRV-FILE01$", `C:\Windows\System32\cmd.exe`, `"C:\Windows\System32\cmd.exe" /c hostname`, `C:\Windows\System32\mmc.exe`, "alice")

	// Ordinary network logons with nothing else: not connections.
	logon(dc, at("08:40:00"), 3, "alice", "WS-ALICE", "10.1.1.20", 50001, nextLogon())
	logon(dc, at("08:40:00"), 3, "SRV-FILE01$", "SRV-FILE01", "10.1.1.50", 50002, nextLogon())

	names := map[string]string{
		chSecurity: "Security.evtx",
		chClient:   "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
		chRCM:      "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
		chLSM:      "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
		chCore:     "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
		chSystem:   "System.evtx",
		chWinRM:    "Microsoft-Windows-WinRM%4Operational.evtx",
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
	if err := userFiles(alice, filepath.Join(dir0, alice.name)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir0, "README.txt"), []byte(strings.TrimLeft(readme, "\n")), 0o644); err != nil {
		return err
	}
	return nil
}

// userFiles writes alice's own records of where she connected: her
// NTUSER.DAT (the Remote Desktop server lists and MountPoints2, whose times
// are only the keys' last writes) and Excel's jump list. Times are as her
// clock had them.
func userFiles(h *host, dir string) error {
	local := func(t time.Time) time.Time { return t.Add(h.clock) }
	start := local(day.Add(-30 * 24 * time.Hour))
	root := &artw.Key{Name: "ROOT", Written: start}
	root.Path(`Environment`, start).Values = []artw.Value{artw.SZ("TEMP", `%USERPROFILE%\AppData\Local\Temp`)}
	root.Path(`Control Panel\Desktop`, start)
	tsc := `Software\Microsoft\Terminal Server Client`
	for _, s := range []struct {
		name string
		at   time.Time
	}{
		{"SRV-FILE01", local(at("09:14:25"))},
		{"10.9.9.9", local(at("10:05:50"))},
		{"DC01", local(at("10:30:20"))},
		// A server named nowhere else: an undated connection to a
		// computer outside the case.
		{"JUMP-OLD", local(day.Add(-18*24*time.Hour + 14*time.Hour))},
	} {
		root.Path(tsc+`\Servers\`+s.name, s.at).Values = []artw.Value{artw.SZ("UsernameHint", domain+`\alice`)}
	}
	root.Path(tsc+`\Default`, local(at("10:30:20"))).Values = []artw.Value{
		artw.SZ("MRU0", "DC01"), artw.SZ("MRU1", "10.9.9.9"), artw.SZ("MRU2", "SRV-FILE01"), artw.SZ("MRU3", "JUMP-OLD")}
	mp := `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\`
	root.Path(mp+`##SRV-FILE01#Finance`, local(at("09:22:31"))).Values = []artw.Value{artw.DWORD("BaseClass", 0)}
	root.Path(mp+`##DC01#C$`, local(at("10:20:01"))).Values = []artw.Value{artw.DWORD("BaseClass", 0)}
	hive, err := artw.Hive(root, `\??\C:\Users\alice\ntuser.dat`, local(at("12:00:00")))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "NTUSER.DAT"), hive, 0o644); err != nil {
		return err
	}
	if err := systemHive(h, dir); err != nil {
		return err
	}
	jl := artw.JumpList([]artw.JumpEntry{
		{Path: `C:\Users\alice\Documents\expenses.xlsx`, LastUsed: local(at("08:31:12")), Count: 4, Machine: "WS-ALICE"},
		{Path: `\\SRV-FILE01\Finance\Q3 results.xlsx`, LastUsed: local(at("11:50:20")), Count: 1, Machine: "SRV-FILE01"},
	})
	return os.WriteFile(filepath.Join(dir, "6e855c85de07bc6a.automaticDestinations-ms"), jl, 0o644)
}

// systemHive writes WS-ALICE's SYSTEM hive: its name, and a USB stick
// (Enum\USBSTOR) with the times Windows keeps for it. Its times are as
// its clock had them.
func systemHive(h *host, dir string) error {
	local := func(t time.Time) time.Time { return t.Add(h.clock) }
	start := local(day.Add(-30 * 24 * time.Hour))
	root := &artw.Key{Name: "ROOT", Written: start}
	root.Path(`Select`, start).Values = []artw.Value{artw.DWORD("Current", 1)}
	root.Path(`ControlSet001\Control\ComputerName\ComputerName`, start).Values = []artw.Value{artw.SZ("ComputerName", h.name)}
	stick := `ControlSet001\Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\60A44C3FAE22EEA0797900F7&0`
	root.Path(stick, local(at("11:52:04"))).Values = []artw.Value{artw.SZ("FriendlyName", "Kingston DataTraveler 3.0 USB Device")}
	for _, p := range []struct{ id, at string }{{"0064", "08:40:11"}, {"0065", "08:40:11"}, {"0066", "11:52:04"}, {"0067", "11:58:30"}} {
		t := local(at(p.at))
		ft := make([]byte, 8)
		binary.LittleEndian.PutUint64(ft, uint64(t.UnixNano()/100+116444736000000000))
		root.Path(stick+`\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\`+p.id, t).Values = []artw.Value{{Name: "", Type: 0x10, Data: ft}}
	}
	hive, err := artw.Hive(root, `\REGISTRY\MACHINE\SYSTEM`, local(at("12:00:00")))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "SYSTEM"), hive, 0o644)
}

const readme = `
Made-up event logs from three hosts that connect to each other by Remote
Desktop, file shares, PsExec, PowerShell remoting, a scheduled task, WMI, DCOM,
with one user's NTUSER.DAT and Excel jump list
(scripts/mklateral). Nothing here
describes a real machine, person or network.

1. Make a new case, and on the Details tab add three hosts:

     Computer name   IP addresses   Other names              Clock difference
     WS-ALICE        10.1.1.20      WS-ALICE.corp.example    3 minutes ahead
     SRV-FILE01      10.1.1.50      SRV-FILE01.corp.example  (leave empty)
     DC01            10.1.1.10      DC01.corp.example        (leave empty)

   Time zone: UTC for all three.

2. Add each folder's files, choosing its host in the add dialog. WS-ALICE's
   folder also holds alice's NTUSER.DAT and Excel's jump list, and the
   computer's SYSTEM hive (a USB stick).

3. Open the Connections tab. It should show, on 20 November 2026 (UTC):

   no time WS-ALICE -> JUMP-OLD       Remote Desktop  alice       source only
          (only alice's registry names it; its key was written on 2 November)
   08:55  203.0.113.45 -> SRV-FILE01  Remote Desktop  svc_backup  target only
                                      (an address outside the case)
   09:14  WS-ALICE -> SRV-FILE01      Remote Desktop  alice       both ends: strong
   09:22  WS-ALICE -> SRV-FILE01      File share      alice       both ends: strong
   09:41  SRV-FILE01 -> DC01          Remote Desktop  svc_backup  both ends: strong
   09:48  SRV-FILE01 -> DC01          PsExec          svc_backup  both ends: strong
   10:05  WS-ALICE -> 10.9.9.9        Remote Desktop  alice       source only
   10:20  WS-ALICE -> DC01            Remote service  alice       target only
   no time WS-ALICE -> DC01           File share      alice       source only
          (\\DC01\C$ in alice's MountPoints2, its key written at 10:20)
   10:30  WS-ALICE -> DC01            Remote Desktop  alice       target only
   10:50  WS-ALICE -> SRV-FILE01      WinRM           alice       both ends: strong
   11:20  SRV-FILE01 -> DC01          Scheduled task  svc_backup  both ends: strong
   11:35  WS-ALICE -> DC01            WMI             alice       both ends: strong
   11:50  WS-ALICE -> SRV-FILE01      File share      alice       both ends: strong
          (Excel's jump list on one end, the share's access on the other)
   12:05  WS-ALICE -> SRV-FILE01      DCOM            alice       both ends: strong
          (MMC20.Application made from PowerShell; mmc.exe and cmd.exe)

   alice's registry also names SRV-FILE01, 10.9.9.9 and DC01 as Remote
   Desktop servers, and \\SRV-FILE01\Finance as a share: those are added to
   the reasons of the connections above, not shown again.

   Without WS-ALICE's clock difference stated, its connections are three
   minutes apart and pair only as "possible"; with it, the times agree to
   within seconds. A service installed on SRV-FILE01 at 11:05 with nothing
   from the network near it is named in the notes, not shown as a
   connection, and so is a task alice made on her own workstation at 08:10.
   The Connections tab's "Started remotely" filter shows PsExec, the
   service, PowerShell remoting, the task, WMI and DCOM together.
`
