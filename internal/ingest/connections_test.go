package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/evtxw/lateraldemo"
	"github.com/DanDreadless/atropos/internal/store"
)

// The made-up logs of three hosts, each added under its host, give the
// connections of the story: Remote Desktop, a file share, PsExec,
// PowerShell remoting, a remote task and WMI, both ends paired where both
// exist (after correcting WS-ALICE's clock), one end otherwise, addresses
// outside the case as nodes of their own. Without the clock difference
// stated the pairs are only possible; with a host's evidence excluded, its
// ends go. Network logons alone, and a service installed or a task made with
// nothing from the network near it, are not connections.
func TestLateralMovementConnections(t *testing.T) {
	dir := t.TempDir()
	if err := lateraldemo.Write(dir); err != nil {
		t.Fatal(err)
	}
	c := newCase(t)
	byHost := map[string][]*store.Evidence{}
	for _, h := range lateraldemo.Hosts {
		hst, err := c.s.AddHost(h.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.s.SetDetails(h.Name, map[string]string{"ip_addresses": h.IP, "other_names": h.OtherName, "time_zone": "UTC"}); err != nil {
			t.Fatal(err)
		}
		batch, _ := c.s.NextBatch()
		if err := c.s.AssignBatch(batch, &hst.ID, ""); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob(filepath.Join(dir, h.Name, "*.evtx"))
		for _, f := range files {
			e, err := c.in.IntakePath(batch, f)
			if err != nil {
				t.Fatal(err)
			}
			byHost[h.Name] = append(byHost[h.Name], e)
		}
		c.in.Process(byHost[h.Name])
	}
	type want struct{ start, kind, from, to, seen, conf, account string }
	check := func(label string, wants []want) *analysis.ConnectionsReport {
		t.Helper()
		rep, err := analysis.Connections(c.s)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Ready {
			t.Errorf("%s: not every run was read", label)
		}
		if len(rep.Connections) != len(wants) {
			for _, cn := range rep.Connections {
				t.Logf("%s %s %s -> %s %s %s %v", time.Unix(0, cn.Start).UTC().Format("15:04:05"), cn.Kind, cn.From, cn.To, cn.SeenOn, cn.Confidence, cn.Reasons)
			}
			t.Fatalf("%s: %d connections, want %d", label, len(rep.Connections), len(wants))
		}
		for i, w := range wants {
			cn := rep.Connections[i]
			got := want{time.Unix(0, cn.Start).UTC().Format("15:04:05"), cn.Kind, cn.From, cn.To, cn.SeenOn, cn.Confidence, cn.Account}
			if got != w {
				t.Errorf("%s: connection %d is %+v\nwant %+v\nreasons %v", label, i, got, w, cn.Reasons)
			}
		}
		return rep
	}

	// WS-ALICE's clock difference not yet stated: its ends are three minutes
	// out, so its pairs are only possible.
	rep := check("clock not stated", []want{
		{"08:55:10", "rdp", "ip:203.0.113.45", "host:SRV-FILE01", "target", "one-end", `CORP\svc_backup`},
		{"09:17:18", "rdp", "host:WS-ALICE", "host:SRV-FILE01", "both", "possible", `CORP\alice`},
		{"09:25:30", "smb", "host:WS-ALICE", "host:SRV-FILE01", "both", "possible", `CORP\alice`},
		{"09:41:03", "rdp", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"09:48:10", "exec", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"10:08:42", "rdp", "host:WS-ALICE", "ip:10.9.9.9", "source", "one-end", `CORP\alice`},
		{"10:20:00", "exec", "host:WS-ALICE", "host:DC01", "target", "one-end", `CORP\alice`},
		{"10:30:15", "rdp", "host:WS-ALICE", "host:DC01", "target", "one-end", `CORP\alice`},
		{"10:53:05", "exec", "host:WS-ALICE", "host:SRV-FILE01", "both", "possible", `CORP\alice`},
		{"11:20:30", "exec", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"11:38:40", "exec", "host:WS-ALICE", "host:DC01", "both", "possible", `CORP\alice`},
	})
	if a := rep.Connections[1].Apart; a == nil || *a != int64(-178*time.Second) {
		t.Errorf("apart %v, want -2m58s", a)
	}
	notes := strings.Join(rep.Notes, " | ")
	if !strings.Contains(notes, "1 remote-execution record had no network logon or share access within 2 minutes") || !strings.Contains(notes, "Service installed: BackupAgent (System 7045) on SRV-FILE01") {
		t.Errorf("notes lack the service with no source: %s", notes)
	}

	if _, err := c.s.SetDetails("WS-ALICE", map[string]string{"clock_offset": "3 minutes ahead"}); err != nil {
		t.Fatal(err)
	}
	rep = check("clock stated", []want{
		{"08:55:10", "rdp", "ip:203.0.113.45", "host:SRV-FILE01", "target", "one-end", `CORP\svc_backup`},
		{"09:14:18", "rdp", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"09:22:30", "smb", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"09:41:03", "rdp", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"09:48:10", "exec", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"10:05:42", "rdp", "host:WS-ALICE", "ip:10.9.9.9", "source", "one-end", `CORP\alice`},
		{"10:20:00", "exec", "host:WS-ALICE", "host:DC01", "target", "one-end", `CORP\alice`},
		{"10:30:15", "rdp", "host:WS-ALICE", "host:DC01", "target", "one-end", `CORP\alice`},
		{"10:50:05", "exec", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"11:20:30", "exec", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"11:35:40", "exec", "host:WS-ALICE", "host:DC01", "both", "strong", `CORP\alice`},
	})
	cn := rep.Connections[1]
	if *cn.Apart != int64(2*time.Second) || len(cn.Source.Events) != 3 || len(cn.Target.Events) != 5 {
		t.Errorf("09:14: apart %v, %d source events, %d target events", *cn.Apart, len(cn.Source.Events), len(cn.Target.Events))
	}
	reasons := strings.Join(cn.Reasons, " | ")
	for _, w := range []string{"connected to SRV-FILE01", "from 10.1.1.20, an address stated for WS-ALICE", "after correcting WS-ALICE's clock (stated as 3 minutes ahead)", "the same account at both ends"} {
		if !strings.Contains(reasons, w) {
			t.Errorf("09:14 reasons lack %q: %s", w, reasons)
		}
	}
	if len(cn.EventIDs) != 8 {
		t.Errorf("09:14 has %d event ids, want 8", len(cn.EventIDs))
	}
	// PsExec: the command on one, and on the other the network logon, the
	// program written to ADMIN$, the service manager's and PsExec's pipes,
	// and the service installed, tied by time; the ordinary srvsvc pipe and
	// IPC$ itself are not read.
	cn = rep.Connections[4]
	reasons = strings.Join(cn.Reasons, " | ")
	for _, w := range []string{"SRV-FILE01 ran a program against DC01", "DC01 recorded a service or task started remotely from 10.1.1.50",
		"shares on DC01: ADMIN$, IPC$", "services installed on DC01: PSEXESVC", "PSEXESVC (System 7045) (event", "by time alone"} {
		if !strings.Contains(reasons, w) {
			t.Errorf("09:48 reasons lack %q: %s", w, reasons)
		}
	}
	if len(cn.Source.Events) != 1 || len(cn.Target.Events) != 7 {
		t.Errorf("09:48: %d source events, %d target events, want 1 and 7: %+v", len(cn.Source.Events), len(cn.Target.Events), cn.Target.Events)
	}
	if !strings.Contains(strings.Join(rep.Connections[2].Reasons, " | "), "shares on SRV-FILE01: Finance") {
		t.Errorf("09:22 reasons %v", rep.Connections[2].Reasons)
	}
	// PowerShell remoting, a remote task and WMI: each target record with no
	// source is tied by time, and by account where it names one.
	for i, ws := range map[int][]string{
		8: {"SRV-FILE01 recorded a remote management (WinRM) session from 10.1.1.20", "Remote management shell created (WinRM 91)", "by time alone",
			"PowerShell remoting session started (wsmprovhost.exe)", `by time and by its account, CORP\alice`},
		9:  {"DC01 recorded a scheduled task made remotely from 10.1.1.50", `scheduled tasks on DC01: \Cleanup`, `C:\Windows\Temp\cleanup.bat`},
		10: {"DC01 recorded a program started remotely by WMI from 10.1.1.20", "Program started by WMI: cmd.exe (by WmiPrvSE.exe)"},
	} {
		reasons := strings.Join(rep.Connections[i].Reasons, " | ")
		for _, w := range ws {
			if !strings.Contains(reasons, w) {
				t.Errorf("connection %d reasons lack %q: %s", i, w, reasons)
			}
		}
	}
	if notes := strings.Join(rep.Notes, " | "); !strings.Contains(notes, `1 scheduled task or program started by WMI under a person's account had no network logon by that account within 2 minutes, so it is taken as made on the host itself: Scheduled task created: \Backup reminder (Security 4698) on WS-ALICE`) {
		t.Errorf("notes lack the local task: %s", notes)
	}
	var edges []string
	for _, e := range rep.Edges {
		edges = append(edges, e.Kind+":"+e.From+">"+e.To)
	}
	if got := strings.Join(edges, " "); got != "rdp:ip:203.0.113.45>host:SRV-FILE01 rdp:host:WS-ALICE>host:SRV-FILE01 smb:host:WS-ALICE>host:SRV-FILE01 rdp:host:SRV-FILE01>host:DC01 exec:host:SRV-FILE01>host:DC01 rdp:host:WS-ALICE>ip:10.9.9.9 exec:host:WS-ALICE>host:DC01 rdp:host:WS-ALICE>host:DC01 exec:host:WS-ALICE>host:SRV-FILE01" {
		t.Errorf("edges %s", got)
	}
	if len(rep.Nodes) != 5 || !rep.Nodes[0].InCase || rep.Nodes[3].Kind != "address" {
		t.Errorf("nodes %+v", rep.Nodes)
	}
	var text strings.Builder
	if err := analysis.WriteConnectionsText(&text, rep); err != nil || !strings.Contains(text.String(), `SRV-FILE01 -> DC01  Program started remotely  CORP\svc_backup`) {
		t.Errorf("text output: %v\n%s", err, text.String())
	}

	// Without DC01's evidence, SRV-FILE01's connections to it are seen at one end.
	for _, e := range byHost["DC01"] {
		if err := c.s.SetExcluded(e.ID, true, "test"); err != nil {
			t.Fatal(err)
		}
	}
	rep = check("DC01 excluded", []want{
		{"08:55:10", "rdp", "ip:203.0.113.45", "host:SRV-FILE01", "target", "one-end", `CORP\svc_backup`},
		{"09:14:18", "rdp", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"09:22:30", "smb", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"09:41:03", "rdp", "host:SRV-FILE01", "host:DC01", "source", "one-end", `CORP\svc_backup`},
		{"09:48:10", "exec", "host:SRV-FILE01", "host:DC01", "source", "one-end", `CORP\svc_backup`},
		{"10:05:42", "rdp", "host:WS-ALICE", "ip:10.9.9.9", "source", "one-end", `CORP\alice`},
		{"10:50:05", "exec", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"11:20:30", "exec", "host:SRV-FILE01", "host:DC01", "source", "one-end", `CORP\svc_backup`},
		{"11:35:40", "exec", "host:WS-ALICE", "host:DC01", "source", "one-end", `CORP\alice`},
	})
	if !strings.Contains(strings.Join(rep.Connections[3].Reasons, " "), "DC01 has no matching logon") ||
		!strings.Contains(strings.Join(rep.Connections[4].Reasons, " "), "DC01 has no matching record") {
		t.Errorf("reasons %v %v", rep.Connections[3].Reasons, rep.Connections[4].Reasons)
	}
	os.RemoveAll(dir)
}

// The public samples of Remote Desktop tunnelled through the target itself
// (4624 type 10 from 127.0.0.1, 1149 and RdpCoreTS 131 from the client's
// address): read, with no host described, as connections seen at the
// target's end only.
func TestRemoteDesktopPublicSamples(t *testing.T) {
	var paths []string
	for _, f := range []string{
		"Command_and_Control__DE_RDP_Tunneling_4624.evtx",
		"Command_and_Control__DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx",
		"Lateral_Movement__dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx",
	} {
		p := filepath.Join("..", "..", "testdata", "evtx-attack", f)
		if _, err := os.Stat(p); err != nil {
			t.Skip("public samples not present; run scripts/fetch-testdata.sh")
		}
		paths = append(paths, p)
	}
	c := newCase(t)
	batch, _ := c.s.NextBatch()
	var list []*store.Evidence
	for _, p := range paths {
		e, err := c.in.IntakePath(batch, p)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, e)
	}
	c.in.Process(list)
	rep, err := analysis.Connections(c.s)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, cn := range rep.Connections {
		if cn.SeenOn != "target" || cn.Confidence != "one-end" {
			t.Errorf("%+v", cn)
		}
		kinds[cn.From[:strings.IndexByte(cn.From, ':')]]++
	}
	if kinds["loopback"] == 0 || kinds["ip"] == 0 {
		t.Errorf("connections by kind of source: %v (want some from the host itself and some from addresses)", kinds)
	}
	for _, cn := range rep.Connections {
		t.Logf("%s %s -> %s %s %d events", time.Unix(0, cn.Start).UTC().Format(time.RFC3339), cn.From, cn.To, cn.Account, len(cn.EventIDs))
	}
}

// The public samples of share access, PsExec renamed, RemCom, a remote
// service and a remote task, as Windows wrote them: read as connections
// seen at the target's end only (no host is described), of the kind each
// sample shows; and the share mapped with net use, at the source's.
func TestLateralMovementPublicSamples(t *testing.T) {
	want := map[string]string{
		"Lateral_Movement__LM_5145_Remote_FileCopy.evtx":                              "smb target",
		"Lateral_Movement__LM_renamed_psexecsvc_5145.evtx":                            "exec target",
		"Lateral_Movement__LM_REMCOM_5145_TargetHost.evtx":                            "exec target",
		"Lateral_Movement__LM_Remote_Service01_5145_svcctl.evtx":                      "exec target",
		"Lateral_Movement__LM_ScheduledTask_ATSVC_target_host.evtx":                   "exec target",
		"AutomatedTestingTools__PanacheSysmon_vs_AtomicRedTeam01.evtx":                "smb source",
		"Lateral_Movement__LM_WMIC_4648_rpcss.evtx":                                   "exec source",
		"Lateral_Movement__remote_task_update_4624_4702_same_logonid.evtx":            "exec target",
		"Lateral_Movement__LM_winrm_exec_sysmon_1_winrshost.evtx":                     "note:Remote shell host started (winrshost.exe)",
		"Lateral_Movement__LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx":           "note:hostname.exe (by wsmprovhost.exe)",
		"Lateral_Movement__LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx": "note:Remote management shell created (WinRM 91)",
		"Lateral_Movement__LM_wmiexec_impacket_sysmon_whoami.evtx":                    "note:taken as made on the host itself: Program started by WMI: cmd.exe",
	}
	for f, w := range want {
		p := filepath.Join("..", "..", "testdata", "evtx-attack", f)
		if _, err := os.Stat(p); err != nil {
			t.Skip("public samples not present; run scripts/fetch-testdata.sh")
		}
		c := newCase(t)
		batch, _ := c.s.NextBatch()
		e, err := c.in.IntakePath(batch, p)
		if err != nil {
			t.Fatal(err)
		}
		c.in.Process([]*store.Evidence{e})
		rep, err := analysis.Connections(c.s)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, cn := range rep.Connections {
			got[cn.Kind+" "+cn.SeenOn]++
			t.Logf("%s: %s %s %s -> %s %s %d events %q", f, time.Unix(0, cn.Start).UTC().Format(time.RFC3339), cn.Kind, cn.From, cn.To, cn.Account, len(cn.EventIDs), cn.Reasons)
		}
		if note, ok := strings.CutPrefix(w, "note:"); ok {
			if len(rep.Connections) > 0 || !strings.Contains(strings.Join(rep.Notes, " | "), note) {
				t.Errorf("%s: connections %v, notes %q, want none and a note naming %q", f, got, rep.Notes, note)
			}
		} else if got[w] == 0 {
			t.Errorf("%s: connections %v, want some %q", f, got, w)
		}
	}
}
