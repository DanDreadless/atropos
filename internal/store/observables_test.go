package store

import (
	"fmt"
	"reflect"
	"testing"
)

// Each Remote Desktop record gives the computer at the other end, the
// account, and which way the connection went; console sessions, other
// logon types and other credentials give nothing.
func TestObserveRemoteDesktop(t *testing.T) {
	sec := func(eid, data string) string {
		return `{"channel":"Security","event_id":"` + eid + `","event":{"EventData":{` + data + `}}}`
	}
	ud := func(ch, eid, data string) string {
		return `{"channel":"` + ch + `","event_id":"` + eid + `","event":{"UserData":{"EventXML":{` + data + `}}}}`
	}
	cases := []struct {
		name, fields, act string
		items             []Observable
	}{
		{"4624 type 10", sec("4624", `"LogonType":10,"IpAddress":"::ffff:10.1.1.20","WorkstationName":"ws-alice","TargetUserName":"alice","TargetDomainName":"CORP"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"host", "WS-ALICE", "source"}, {"account", `CORP\alice`, "target"}}},
		{"4624 type 12 as text", sec("4624", `"LogonType":"12","IpAddress":"-","WorkstationName":"-","TargetUserName":"bob"`), "rdp-in",
			[]Observable{{"account", "bob", "target"}}},
		{"4624 type 3", sec("4624", `"LogonType":3,"IpAddress":"10.1.1.20"`), "", nil},
		{"4778", sec("4778", `"ClientAddress":"10.1.1.20","ClientName":"WS-ALICE","AccountName":"alice","AccountDomain":"CORP"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"host", "WS-ALICE", "source"}, {"account", `CORP\alice`, "target"}}},
		{"4648 to TERMSRV", sec("4648", `"TargetServerName":"srv-file01.corp.example","TargetInfo":"TERMSRV/srv-file01.corp.example","TargetUserName":"alice","TargetDomainName":"CORP","SubjectUserName":"alice","SubjectDomainName":"CORP"`), "rdp-out",
			[]Observable{{"host", "SRV-FILE01.CORP.EXAMPLE", "target"}, {"account", `CORP\alice`, "target"}, {"account", `CORP\alice`, "subject"}}},
		{"4648 to localhost", sec("4648", `"TargetServerName":"localhost","TargetInfo":"TERMSRV/10.1.1.50","TargetUserName":"alice"`), "rdp-out",
			[]Observable{{"ip", "10.1.1.50", "target"}, {"account", "alice", "target"}}},
		{"4648 to a share", sec("4648", `"TargetServerName":"srv","TargetInfo":"cifs/srv","TargetUserName":"bob"`), "smb-out",
			[]Observable{{"host", "SRV", "target"}, {"account", "bob", "target"}}},
		{"4648 for WMI", sec("4648", `"TargetServerName":"WIN-77LTAPHIQ1R.example.corp","TargetInfo":"RPCSS/WIN-77LTAPHIQ1R.example.corp","ProcessName":"C:\\Windows\\System32\\svchost.exe","TargetUserName":"administrator","SubjectUserName":"user01"`), "exec-out",
			[]Observable{{"host", "WIN-77LTAPHIQ1R.EXAMPLE.CORP", "target"}, {"account", "administrator", "target"}, {"account", "user01", "subject"}}},
		{"4648 for WinRM", sec("4648", `"TargetServerName":"dc01","TargetInfo":"HTTP/dc01","ProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","TargetUserName":"bob"`), "exec-out",
			[]Observable{{"host", "DC01", "target"}, {"account", "bob", "target"}}},
		{"4648 to a web server", sec("4648", `"TargetServerName":"intranet","TargetInfo":"HTTP/intranet","ProcessName":"C:\\Program Files\\Browser\\browser.exe","TargetUserName":"bob"`), "", nil},
		{"4648 host/", sec("4648", `"TargetServerName":"srv","TargetInfo":"host/srv"`), "", nil},
		{"4698 by a person", sec("4698", `"TaskName":"\\LMST","SubjectUserName":"a-jbrown","SubjectDomainName":"3B","TaskContent":"<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c tasklist</Arguments></Exec></Actions></Task>"`), "exec-in",
			[]Observable{{"task", `\LMST`, "object"}, {"program", "cmd.exe", "object"}, {"account", `3B\a-jbrown`, "target"}, {"via", "task", "object"}}},
		{"4702 by a person", sec("4702", `"TaskName":"\\LMST","SubjectUserName":"a-jbrown","TaskContentNew":"<Task><Command>C:\\x.exe</Command></Task>"`), "exec-in",
			[]Observable{{"task", `\LMST`, "object"}, {"program", `C:\x.exe`, "object"}, {"account", "a-jbrown", "target"}, {"via", "task", "object"}}},
		{"4698 by the computer", sec("4698", `"TaskName":"\\Microsoft\\Windows\\X","SubjectUserName":"WS-ALICE$"`), "", nil},
		{"4698 by SYSTEM", sec("4698", `"TaskName":"\\Updater","SubjectUserName":"SYSTEM","SubjectDomainName":"NT AUTHORITY"`), "", nil},
		{"WinRM 6", `{"channel":"` + chWinRM + `","event_id":"6","event":{"EventData":{"connection":"dc01.corp.example/wsman?PSVersion=5.1.17763.1"}}}`, "exec-out",
			[]Observable{{"host", "DC01.CORP.EXAMPLE", "target"}}},
		{"WinRM 6 URL", `{"channel":"` + chWinRM + `","event_id":"6","event":{"EventData":{"connection":"http://10.1.1.10:5985/wsman"}}}`, "exec-out",
			[]Observable{{"ip", "10.1.1.10", "target"}}},
		{"WinRM 6 localhost", `{"channel":"` + chWinRM + `","event_id":"6","event":{"EventData":{"connection":"localhost/wsman?PSVersion=5.1"}}}`, "", nil},
		{"WinRM 91 unreadable", `{"channel":"` + chWinRM + `","event_id":"91","event":{"ProcessingErrorData":{"DataItemName":"shellId"}}}`, "exec-in",
			[]Observable{{"via", "winrm", "object"}}},
		{"Sysmon 1 under winrshost", `{"channel":"` + chSysmon + `","event_id":"1","event":{"EventData":{"Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Windows\\System32\\winrshost.exe","CommandLine":"cmd.exe /C ipconfig","User":"insecurebank\\Administrator"}}}`, "exec-in",
			[]Observable{{"via", "winrm", "object"}, {"account", `insecurebank\Administrator`, "target"}, {"program", `C:\Windows\System32\cmd.exe`, "object"}}},
		{"Sysmon 1 wsmprovhost", `{"channel":"` + chSysmon + `","event_id":"1","event":{"EventData":{"Image":"C:\\Windows\\System32\\wsmprovhost.exe","ParentImage":"C:\\Windows\\System32\\svchost.exe","User":"CORP\\bob"}}}`, "exec-in",
			[]Observable{{"via", "winrm", "object"}, {"account", `CORP\bob`, "target"}, {"program", `C:\Windows\System32\wsmprovhost.exe`, "object"}}},
		{"4688 under WmiPrvSE", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\cmd.exe","ParentProcessName":"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe","SubjectUserName":"DC01$","TargetUserName":"alice","TargetDomainName":"CORP"`), "exec-in",
			[]Observable{{"via", "wmi", "object"}, {"account", `CORP\alice`, "target"}, {"program", `C:\Windows\System32\cmd.exe`, "object"}}},
		{"4688 under WmiPrvSE as the computer", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\cmd.exe","ParentProcessName":"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe","SubjectUserName":"DC01$"`), "", nil},
		{"Sysmon 1 under WmiPrvSE as SYSTEM", `{"channel":"` + chSysmon + `","event_id":"1","event":{"EventData":{"Image":"C:\\x.exe","ParentImage":"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe","User":"NT AUTHORITY\\SYSTEM"}}}`, "", nil},
		{"4688 wmic /node", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\wbem\\WMIC.exe","CommandLine":"wmic /node:\"10.0.2.20\" /user:administrator process call create calc.exe","SubjectUserName":"user01"`), "exec-out",
			[]Observable{{"ip", "10.0.2.20", "target"}, {"account", "administrator", "target"}, {"account", "user01", "subject"}, {"program", `C:\Windows\System32\wbem\WMIC.exe`, "object"}}},
		{"4688 wmic local", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\wbem\\WMIC.exe","CommandLine":"wmic /node:localhost os get caption","SubjectUserName":"user01"`), "", nil},
		{"4688 winrs", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\winrs.exe","CommandLine":"winrs -r:http://srv-file01:5985 ipconfig","SubjectUserName":"alice"`), "exec-out",
			[]Observable{{"host", "SRV-FILE01", "target"}, {"account", "alice", "subject"}, {"program", `C:\Windows\System32\winrs.exe`, "object"}}},
		{"4688 schtasks /s", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\schtasks.exe","CommandLine":"schtasks /create /s DC01 /tn Upd /tr C:\\x.exe /sc once /st 00:00","SubjectUserName":"alice"`), "exec-out",
			[]Observable{{"host", "DC01", "target"}, {"account", "alice", "subject"}, {"program", `C:\Windows\System32\schtasks.exe`, "object"}}},
		{"4688 Invoke-Command", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -c \"Invoke-Command -ComputerName srv-file01 -ScriptBlock { hostname }\"","SubjectUserName":"alice"`), "exec-out",
			[]Observable{{"host", "SRV-FILE01", "target"}, {"account", "alice", "subject"}, {"program", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "object"}}},
		{"4688 Enter-PSSession", sec("4688", `"NewProcessName":"C:\\pwsh.exe","CommandLine":"pwsh -NoExit -c Enter-PSSession dc01","SubjectUserName":"alice"`), "exec-out",
			[]Observable{{"host", "DC01", "target"}, {"account", "alice", "subject"}, {"program", `C:\pwsh.exe`, "object"}}},
		{"4688 PowerShell to a variable", sec("4688", `"NewProcessName":"C:\\pwsh.exe","CommandLine":"pwsh -c Invoke-Command -ComputerName $h {1}","SubjectUserName":"alice"`), "", nil},
		{"4688 Get-Service -ComputerName", sec("4688", `"NewProcessName":"C:\\pwsh.exe","CommandLine":"pwsh -c Get-Service -ComputerName dc01","SubjectUserName":"alice"`), "", nil},
		{"4624 type 3", sec("4624", `"LogonType":3,"IpAddress":"10.1.1.20","WorkstationName":"WS-ALICE","TargetUserName":"alice","TargetDomainName":"CORP"`), "logon-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"host", "WS-ALICE", "source"}, {"account", `CORP\alice`, "target"}}},
		{"4624 type 3 computer account", sec("4624", `"LogonType":3,"IpAddress":"10.1.1.20","TargetUserName":"WS-ALICE$"`), "", nil},
		{"4624 type 3 anonymous", sec("4624", `"LogonType":3,"IpAddress":"10.1.1.20","TargetUserName":"ANONYMOUS LOGON"`), "", nil},
		{"4624 type 3 from itself", sec("4624", `"LogonType":3,"IpAddress":"::1","TargetUserName":"alice"`), "", nil},
		{"5140 a share", sec("5140", `"IpAddress":"10.1.1.20","ShareName":"\\\\*\\Finance","SubjectUserName":"alice","SubjectDomainName":"CORP"`), "smb-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"account", `CORP\alice`, "target"}, {"share", "Finance", "object"}}},
		{"5140 SYSVOL", sec("5140", `"IpAddress":"10.1.1.20","ShareName":"\\\\*\\SYSVOL","SubjectUserName":"alice"`), "", nil},
		{"5140 IPC$", sec("5140", `"IpAddress":"10.1.1.20","ShareName":"\\\\*\\IPC$","SubjectUserName":"alice"`), "", nil},
		{"5145 IPC$ srvsvc", sec("5145", `"IpAddress":"10.1.1.20","ShareName":"\\\\*\\IPC$","RelativeTargetName":"srvsvc","SubjectUserName":"alice"`), "", nil},
		{"5145 svcctl", sec("5145", `"IpAddress":"10.0.2.17","ShareName":"\\\\*\\IPC$","RelativeTargetName":"svcctl","SubjectUserName":"Administrator","SubjectDomainName":"EXAMPLE"`), "exec-in",
			[]Observable{{"ip", "10.0.2.17", "source"}, {"account", `EXAMPLE\Administrator`, "target"}, {"share", "IPC$", "object"}}},
		{"5145 PsExec pipe", sec("5145", `"IpAddress":"10.0.2.16","ShareName":"\\\\*\\IPC$","RelativeTargetName":"blabla-NLLT108334-37048-stdin","SubjectUserName":"IEUser"`), "exec-in",
			[]Observable{{"ip", "10.0.2.16", "source"}, {"account", "IEUser", "target"}, {"share", "IPC$", "object"}}},
		{"5145 program written to ADMIN$", sec("5145", `"IpAddress":"10.0.2.16","ShareName":"\\\\*\\ADMIN$","RelativeTargetName":"System32\\RemComSvc.exe","AccessMask":1180054,"SubjectUserName":"IEUser"`), "exec-in",
			[]Observable{{"program", `System32\RemComSvc.exe`, "object"}, {"ip", "10.0.2.16", "source"}, {"account", "IEUser", "target"}, {"share", "ADMIN$", "object"}}},
		{"5145 program written to C$", sec("5145", `"IpAddress":"10.0.2.15","ShareName":"\\\\*\\C$","RelativeTargetName":"malwr.exe","AccessMask":"0x120196","SubjectUserName":"Administrator"`), "smb-in",
			[]Observable{{"program", "malwr.exe", "object"}, {"ip", "10.0.2.15", "source"}, {"account", "Administrator", "target"}, {"share", "C$", "object"}}},
		{"5145 program read on ADMIN$", sec("5145", `"IpAddress":"10.0.2.16","ShareName":"\\\\*\\ADMIN$","RelativeTargetName":"x.exe","AccessMask":"0x80","SubjectUserName":"IEUser"`), "smb-in",
			[]Observable{{"ip", "10.0.2.16", "source"}, {"account", "IEUser", "target"}, {"share", "ADMIN$", "object"}}},
		{"5145 by a computer account", sec("5145", `"IpAddress":"10.1.1.20","ShareName":"\\\\*\\C$","RelativeTargetName":"x","SubjectUserName":"WS-ALICE$"`), "", nil},
		{"7045", `{"channel":"System","event_id":"7045","event":{"EventData":{"ServiceName":"PSEXESVC","ImagePath":"%SystemRoot%\\PSEXESVC.exe"}}}`, "exec-in",
			[]Observable{{"program", `%SystemRoot%\PSEXESVC.exe`, "object"}, {"service", "PSEXESVC", "object"}, {"via", "service", "object"}}},
		{"4688 PsExec", sec("4688", `"NewProcessName":"C:\\Tools\\PsExec64.exe","CommandLine":"PsExec64.exe \\\\dc01 -u CORP\\svc_backup -s cmd.exe","SubjectUserName":"svc_backup","SubjectDomainName":"CORP"`), "exec-out",
			[]Observable{{"host", "DC01", "target"}, {"account", `CORP\svc_backup`, "target"}, {"account", `CORP\svc_backup`, "subject"}, {"program", `C:\Tools\PsExec64.exe`, "object"}}},
		{"4688 net use", sec("4688", `"NewProcessName":"C:\\Windows\\System32\\net.exe","CommandLine":"net  use \\\\Target\\C$ P@ss /u:DOMAIN\\Administrator","SubjectUserName":"alice"`), "smb-out",
			[]Observable{{"host", "TARGET", "target"}, {"account", `DOMAIN\Administrator`, "target"}, {"account", "alice", "subject"}, {"program", `C:\Windows\System32\net.exe`, "object"}}},
		{"Sysmon 1 to the host itself", `{"channel":"` + chSysmon + `","event_id":"1","event":{"EventData":{"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1556 2>&1","User":"X\\y"}}}`, "", nil},
		{"4688 a device path", sec("4688", `"NewProcessName":"C:\\x.exe","CommandLine":"x.exe \\\\?\\C:\\a \\\\.\\pipe\\b"`), "", nil},
		{"Sysmon 1 PsExec service", `{"channel":"` + chSysmon + `","event_id":"1","event":{"EventData":{"Image":"C:\\Windows\\PSEXESVC.exe","CommandLine":"C:\\WINDOWS\\PSEXESVC.exe"}}}`, "exec-in",
			[]Observable{{"via", "service", "object"}, {"program", `C:\Windows\PSEXESVC.exe`, "object"}}},
		{"1149", ud(chRCM, "1149", `"Param1":"alice","Param2":"CORP","Param3":"10.1.1.20"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"account", `CORP\alice`, "target"}}},
		{"21 remote", ud(chLSM, "21", `"User":"CORP\\alice","SessionID":"2","Address":"10.1.1.20"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"account", `CORP\alice`, "target"}}},
		{"21 at the console", ud(chLSM, "21", `"User":"CORP\\alice","Address":"LOCAL"`), "", nil},
		{"131 IPv4", `{"channel":"` + chCoreTS + `","event_id":"131","event":{"EventData":{"ClientIP":"10.1.1.20:50642"}}}`, "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}}},
		{"131 IPv6", `{"channel":"` + chCoreTS + `","event_id":"131","event":{"EventData":{"ClientIP":"[fe80::1]:50642"}}}`, "rdp-in",
			[]Observable{{"ip", "fe80::1", "source"}}},
		{"1024 by name", `{"channel":"` + chRDPCli + `","event_id":"1024","event":{"EventData":{"Value":"srv-file01"}}}`, "rdp-out",
			[]Observable{{"host", "SRV-FILE01", "target"}}},
		{"1102 by address", `{"channel":"` + chRDPCli + `","event_id":"1102","event":{"EventData":{"Value":"10.1.1.50"}}}`, "rdp-out",
			[]Observable{{"ip", "10.1.1.50", "target"}}},
		{"not JSON", `{`, "", nil},
	}
	for _, c := range cases {
		var oe ObservedEvent
		ok := observeEvent(&oe, c.fields)
		if ok != (c.act != "") || oe.Act != c.act && ok || !reflect.DeepEqual(oe.Items, c.items) && ok {
			t.Errorf("%s: %v %q %+v, want %q %+v", c.name, ok, oe.Act, oe.Items, c.act, c.items)
		}
	}
}

// DCOM and Sysmon's network connections. Which end of a Sysmon connection
// is this computer differs between Sysmon versions; both are read.
func TestObserveDCOMAndNetwork(t *testing.T) {
	sm := func(eid, data string) string {
		return `{"channel":"` + chSysmon + `","event_id":"` + eid + `","event":{"EventData":{` + data + `}}}`
	}
	conn := func(sIP, sHost string, sPort int, dIP, dHost string, dPort int, init bool, image, user string) string {
		return sm("3", fmt.Sprintf(`"SourceIp":%q,"SourceHostname":%q,"SourcePort":%d,"DestinationIp":%q,"DestinationHostname":%q,"DestinationPort":%d,"Initiated":%v,"Image":%q,"User":%q`,
			sIP, sHost, sPort, dIP, dHost, dPort, init, image, user))
	}
	cases := []struct {
		name, host, fields, act string
		items                   []Observable
	}{
		{"old Sysmon: into mmc.exe, this computer as source", "IEWIN7", conn("10.0.2.18", "IEWIN7", 49163, "10.0.2.19", "", 33474, false, `C:\Windows\System32\mmc.exe`, `IEWIN7\IEUser`), "exec-in",
			[]Observable{{"ip", "10.0.2.19", "source"}, {"via", "dcom", "object"}, {"program", `C:\Windows\System32\mmc.exe`, "object"}, {"account", `IEWIN7\IEUser`, "target"}}},
		{"new Sysmon: into explorer.exe, other computer as source", "SRV.corp.example", conn("10.0.0.7", "ws7.corp.example", 50123, "10.0.0.5", "srv.corp.example", 49702, false, `C:\Windows\explorer.exe`, `CORP\bob`), "exec-in",
			[]Observable{{"ip", "10.0.0.7", "source"}, {"host", "WS7.CORP.EXAMPLE", "source"}, {"via", "dcom", "object"}, {"program", `C:\Windows\explorer.exe`, "object"}, {"account", `CORP\bob`, "target"}}},
		{"inbound, no names: the server's port says which end", "SRV", conn("10.0.0.7", "", 50123, "10.0.0.5", "", 3389, false, `C:\Windows\System32\svchost.exe`, `NT AUTHORITY\NETWORK SERVICE`), "rdp-in",
			[]Observable{{"ip", "10.0.0.7", "source"}}},
		{"inbound to 445: only supports", "SRV", conn("10.0.2.18", "SRV", 445, "10.0.2.19", "", 45622, false, "System", `NT AUTHORITY\SYSTEM`), "net-in",
			[]Observable{{"ip", "10.0.2.19", "source"}}},
		{"inbound to WinRM", "SRV", conn("10.0.0.7", "", 50200, "10.0.0.5", "SRV", 5985, false, "System", `NT AUTHORITY\SYSTEM`), "exec-in",
			[]Observable{{"ip", "10.0.0.7", "source"}, {"via", "winrm", "object"}}},
		{"outbound Remote Desktop", "WS7", conn("10.0.0.7", "WS7", 50300, "10.0.0.5", "srv", 3389, true, `C:\Windows\System32\mstsc.exe`, `CORP\bob`), "rdp-out",
			[]Observable{{"ip", "10.0.0.5", "target"}, {"host", "SRV", "target"}, {"account", `CORP\bob`, "subject"}}},
		{"outbound to 135", "WS7", conn("10.0.0.7", "WS7", 50301, "10.0.0.5", "", 135, true, `C:\Windows\System32\svchost.exe`, `NT AUTHORITY\NETWORK SERVICE`), "net-out",
			[]Observable{{"ip", "10.0.0.5", "target"}}},
		{"outbound to a web server", "WS7", conn("10.0.0.7", "WS7", 50302, "93.184.216.34", "", 443, true, `C:\b.exe`, `CORP\bob`), "", nil},
		{"loopback", "IEWIN7", conn("127.0.0.1", "IEWIN7", 49164, "127.0.0.1", "IEWIN7", 445, true, "System", `NT AUTHORITY\SYSTEM`), "", nil},
		{"mmc started as a DCOM object", "IEWIN7", sm("1", `"Image":"C:\\Windows\\System32\\mmc.exe","CommandLine":"C:\\Windows\\system32\\mmc.exe -Embedding","ParentImage":"C:\\Windows\\System32\\svchost.exe","ParentCommandLine":"svchost.exe -k DcomLaunch","User":"IEWIN7\\IEUser"`), "exec-in",
			[]Observable{{"via", "dcom", "object"}, {"account", `IEWIN7\IEUser`, "target"}, {"program", `C:\Windows\System32\mmc.exe`, "object"}}},
		{"mmc opened by a person", "IEWIN7", sm("1", `"Image":"C:\\Windows\\System32\\mmc.exe","CommandLine":"\"C:\\Windows\\system32\\mmc.exe\" compmgmt.msc","ParentImage":"C:\\Windows\\explorer.exe","User":"IEWIN7\\IEUser"`), "", nil},
		{"Excel automation as SYSTEM", "SRV", sm("1", `"Image":"C:\\Office\\EXCEL.EXE","CommandLine":"EXCEL.EXE /automation -Embedding","ParentImage":"C:\\Windows\\System32\\svchost.exe","User":"NT AUTHORITY\\SYSTEM"`), "", nil},
		{"child of a DCOM object (Sysmon)", "IEWIN7", sm("1", `"Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Windows\\System32\\mmc.exe","ParentCommandLine":"C:\\Windows\\system32\\mmc.exe -Embedding","User":"IEWIN7\\IEUser"`), "exec-in",
			[]Observable{{"via", "dcom", "object"}, {"account", `IEWIN7\IEUser`, "target"}, {"program", `C:\Windows\System32\cmd.exe`, "object"}}},
		{"child of Excel opened by a person", "IEWIN7", sm("1", `"Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Office\\EXCEL.EXE","ParentCommandLine":"\"C:\\Office\\EXCEL.EXE\" C:\\a.xlsx","User":"IEWIN7\\IEUser"`), "", nil},
		{"child of mmc (4688, no parent command line)", "DC01", `{"channel":"Security","event_id":"4688","event":{"EventData":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","ParentProcessName":"C:\\Windows\\System32\\mmc.exe","TargetUserName":"alice","TargetDomainName":"CORP"}}}`, "exec-in",
			[]Observable{{"via", "dcom", "object"}, {"account", `CORP\alice`, "target"}, {"program", `C:\Windows\System32\cmd.exe`, "object"}}},
		{"10016 remote", "MSEDGEWIN10", `{"channel":"System","event_id":"10016","event":{"EventData":{"param2":"Remote","param3":"Launch","param4":"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}","param6":"MSEDGEWIN10","param7":"IEUser","param9":"10.0.2.17"}}}`, "exec-in",
			[]Observable{{"ip", "10.0.2.17", "source"}, {"account", `MSEDGEWIN10\IEUser`, "target"}, {"class", "MMC20.Application", "object"}, {"via", "dcom-refused", "object"}}},
		{"10016 local", "MSEDGEWIN10", `{"channel":"System","event_id":"10016","event":{"EventData":{"param2":"Local","param3":"Launch","param4":"Windows.SecurityCenter.WscBrokerManager","param6":"NT AUTHORITY","param7":"SYSTEM","param9":"LocalHost (Using LRPC)"}}}`, "", nil},
		{"PowerShell DCOM", "WS7", `{"channel":"Security","event_id":"4688","event":{"EventData":{"NewProcessName":"C:\\pwsh.exe","CommandLine":"pwsh -c $o=[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','srv-file01'))","SubjectUserName":"bob"}}}`, "exec-out",
			[]Observable{{"host", "SRV-FILE01", "target"}, {"account", "bob", "subject"}, {"program", `C:\pwsh.exe`, "object"}}},
	}
	for _, c := range cases {
		oe := ObservedEvent{Host: c.host}
		ok := observeEvent(&oe, c.fields)
		if ok != (c.act != "") || oe.Act != c.act && ok || !reflect.DeepEqual(oe.Items, c.items) && ok {
			t.Errorf("%s: %v %q %+v, want %q %+v", c.name, ok, oe.Act, oe.Items, c.act, c.items)
		}
	}
}

// A host's stated clock difference is read whichever way it is written,
// and refused when which way it was out cannot be told.
func TestParseClockOffset(t *testing.T) {
	for in, want := range map[string]int64{
		"3 minutes ahead": 180, "90 seconds behind": -90, "1 min 30 s slow": -90, "+3m": 180, "-1m30s": -90,
		"-00:01:30": -90, "1h2m fast": 3720, "0": 0, "none": 0, "Correct": 0, "2 minutes and 5 seconds fast": 125, "+00:00:07": 7,
	} {
		got, ok := ParseClockOffset(in)
		if !ok || int64(got.Seconds()) != want {
			t.Errorf("%q: %v %v, want %ds", in, got, ok, want)
		}
	}
	for _, bad := range []string{"3 minutes", "180", "about right", "3 minutes ahead and behind", "+3m behind", "fast"} {
		if got, ok := ParseClockOffset(bad); ok {
			t.Errorf("%q accepted as %v", bad, got)
		}
	}
}

// The registry's lists name computers connected to without timing the
// connection; a jump list entry on a share is a file opened there.
func TestObserveArtefacts(t *testing.T) {
	cases := []struct {
		name, typ, path, fields, act string
		items                        []Observable
	}{
		{"server list", "rdp-client-server-key-last-write", "SRV-FILE01", `{"values":{"UsernameHint":{"type":"REG_SZ","data":"CORP\\alice"}}}`, "rdp-named",
			[]Observable{{"host", "SRV-FILE01", "target"}, {"account", `CORP\alice`, "target"}}},
		{"server list with a port", "rdp-client-server-key-last-write", "10.0.0.9:3390", `{}`, "rdp-named",
			[]Observable{{"ip", "10.0.0.9", "target"}}},
		{"server list loopback", "rdp-client-server-key-last-write", "127.0.0.2", `{}`, "", nil},
		{"recent list", "rdp-client-recent-key-last-write", `\Software\Microsoft\Terminal Server Client\Default`,
			`{"values":{"MRU0":{"data":"dc01.corp.example"},"MRU1":{"data":"[fe80::1]:3389"},"MRU2":{"data":"localhost"}}}`, "rdp-named",
			[]Observable{{"host", "DC01.CORP.EXAMPLE", "target"}, {"ip", "fe80::1", "target"}, {"via", "recent-list", "object"}}},
		{"recent list empty", "rdp-client-recent-key-last-write", `\x`, `{"values":{}}`, "", nil},
		{"MountPoints2 share", "network-share-key-last-write", `\\SRV-FILE01\Finance`, `{}`, "smb-named",
			[]Observable{{"host", "SRV-FILE01", "target"}, {"share", `\\SRV-FILE01\Finance`, "object"}}},
		{"MountPoints2 by address", "network-share-key-last-write", `\\10.0.0.9\c$`, `{}`, "smb-named",
			[]Observable{{"ip", "10.0.0.9", "target"}, {"share", `\\10.0.0.9\c$`, "object"}}},
		{"MountPoints2 WebDAV", "network-share-key-last-write", `\\live.sysinternals.com@SSL\DavWWWRoot`, `{}`, "smb-named",
			[]Observable{{"host", "LIVE.SYSINTERNALS.COM", "target"}, {"share", `\\live.sysinternals.com@SSL\DavWWWRoot`, "object"}}},
		{"MountPoints2 no share", "network-share-key-last-write", `\\SRV-FILE01`, `{}`, "", nil},
		{"jump list on a share", "jumplist-entry-last-used", `\\SRV-FILE01\Finance\Q3.xlsx`, `{"application":"Microsoft Office Excel 2010 x64"}`, "smb-out",
			[]Observable{{"host", "SRV-FILE01", "target"}, {"share", `\\SRV-FILE01\Finance`, "object"}, {"file", `\\SRV-FILE01\Finance\Q3.xlsx`, "object"}}},
		{"jump list local", "jumplist-entry-last-used", `C:\Users\alice\notes.txt`, `{}`, "", nil},
		{"jump list device path", "jumplist-entry-last-used", `\\?\Volume{1}\x`, `{}`, "", nil},
		{"jump list loopback", "jumplist-entry-last-used", `\\127.0.0.1\c$\x`, `{}`, "", nil},
	}
	for _, c := range cases {
		var oe ObservedEvent
		ok := observeArtefact(&oe, c.typ, c.path, c.fields)
		if ok != (c.act != "") || oe.Act != c.act {
			t.Errorf("%s: ok %v act %q, want %q", c.name, ok, oe.Act, c.act)
			continue
		}
		if ok && !reflect.DeepEqual(oe.Items, c.items) {
			t.Errorf("%s: items %v, want %v", c.name, oe.Items, c.items)
		}
	}
}
