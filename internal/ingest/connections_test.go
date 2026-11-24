package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/evtxw/rdpdemo"
	"github.com/DanDreadless/atropos/internal/store"
)

// The made-up Remote Desktop logs of three hosts, each added under its host,
// give the five connections of the story: both ends paired where both exist
// (after correcting WS-ALICE's clock), one end otherwise, addresses outside
// the case as nodes of their own. Without the clock difference stated the
// pair is only possible; with a host's evidence excluded, its end goes.
func TestRemoteDesktopConnections(t *testing.T) {
	dir := t.TempDir()
	if err := rdpdemo.Write(dir); err != nil {
		t.Fatal(err)
	}
	c := newCase(t)
	byHost := map[string][]*store.Evidence{}
	for _, h := range rdpdemo.Hosts {
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
	type want struct{ start, from, to, seen, conf, account string }
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
				t.Logf("%s %s -> %s %s %s %v", time.Unix(0, cn.Start).UTC().Format("15:04:05"), cn.From, cn.To, cn.SeenOn, cn.Confidence, cn.Reasons)
			}
			t.Fatalf("%s: %d connections, want %d", label, len(rep.Connections), len(wants))
		}
		for i, w := range wants {
			cn := rep.Connections[i]
			got := want{time.Unix(0, cn.Start).UTC().Format("15:04:05"), cn.From, cn.To, cn.SeenOn, cn.Confidence, cn.Account}
			if got != w {
				t.Errorf("%s: connection %d is %+v\nwant %+v\nreasons %v", label, i, got, w, cn.Reasons)
			}
		}
		return rep
	}

	// WS-ALICE's clock difference not yet stated: its end is three minutes
	// out, so the pair is only possible.
	rep := check("clock not stated", []want{
		{"08:55:10", "ip:203.0.113.45", "host:SRV-FILE01", "target", "one-end", `CORP\svc_backup`},
		{"09:17:18", "host:WS-ALICE", "host:SRV-FILE01", "both", "possible", `CORP\alice`},
		{"09:41:03", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"10:08:42", "host:WS-ALICE", "ip:10.9.9.9", "source", "one-end", `CORP\alice`},
		{"10:30:15", "host:WS-ALICE", "host:DC01", "target", "one-end", `CORP\alice`},
	})
	if a := rep.Connections[1].Apart; a == nil || *a != int64(-178*time.Second) {
		t.Errorf("apart %v, want -2m58s", a)
	}

	if _, err := c.s.SetDetails("WS-ALICE", map[string]string{"clock_offset": "3 minutes ahead"}); err != nil {
		t.Fatal(err)
	}
	rep = check("clock stated", []want{
		{"08:55:10", "ip:203.0.113.45", "host:SRV-FILE01", "target", "one-end", `CORP\svc_backup`},
		{"09:14:18", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"09:41:03", "host:SRV-FILE01", "host:DC01", "both", "strong", `CORP\svc_backup`},
		{"10:05:42", "host:WS-ALICE", "ip:10.9.9.9", "source", "one-end", `CORP\alice`},
		{"10:30:15", "host:WS-ALICE", "host:DC01", "target", "one-end", `CORP\alice`},
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
	var edges []string
	for _, e := range rep.Edges {
		edges = append(edges, e.From+">"+e.To)
	}
	if got := strings.Join(edges, " "); got != "ip:203.0.113.45>host:SRV-FILE01 host:WS-ALICE>host:SRV-FILE01 host:SRV-FILE01>host:DC01 host:WS-ALICE>ip:10.9.9.9 host:WS-ALICE>host:DC01" {
		t.Errorf("edges %s", got)
	}
	if len(rep.Nodes) != 5 || !rep.Nodes[0].InCase || rep.Nodes[3].Kind != "address" {
		t.Errorf("nodes %+v", rep.Nodes)
	}

	// Without DC01's evidence, SRV-FILE01's connection to it is seen at one end.
	for _, e := range byHost["DC01"] {
		if err := c.s.SetExcluded(e.ID, true, "test"); err != nil {
			t.Fatal(err)
		}
	}
	rep = check("DC01 excluded", []want{
		{"08:55:10", "ip:203.0.113.45", "host:SRV-FILE01", "target", "one-end", `CORP\svc_backup`},
		{"09:14:18", "host:WS-ALICE", "host:SRV-FILE01", "both", "strong", `CORP\alice`},
		{"09:41:03", "host:SRV-FILE01", "host:DC01", "source", "one-end", `CORP\svc_backup`},
		{"10:05:42", "host:WS-ALICE", "ip:10.9.9.9", "source", "one-end", `CORP\alice`},
	})
	if !strings.Contains(strings.Join(rep.Connections[2].Reasons, " "), "DC01 has no matching logon") {
		t.Errorf("reasons %v", rep.Connections[2].Reasons)
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
