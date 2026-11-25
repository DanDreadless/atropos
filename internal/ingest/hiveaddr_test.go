package ingest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/artw"
	"github.com/DanDreadless/atropos/internal/evtxw"
	"github.com/DanDreadless/atropos/internal/store"
)

// systemHive is a SYSTEM hive naming the computer, with one address leased
// by DHCP and the domain.
func systemHive(t *testing.T, name, ip string) []byte {
	t.Helper()
	t0 := time.Date(2026, 11, 2, 7, 0, 0, 0, time.UTC)
	root := &artw.Key{Name: "ROOT", Written: t0}
	root.Path(`Select`, t0).Values = []artw.Value{artw.DWORD("Current", 1)}
	root.Path(`ControlSet001\Control\ComputerName\ComputerName`, t0).Values = []artw.Value{artw.SZ("ComputerName", name)}
	tcp := `ControlSet001\Services\Tcpip\Parameters`
	root.Path(tcp, t0).Values = []artw.Value{artw.SZ("Hostname", name), artw.SZ("Domain", "corp.example")}
	root.Path(tcp+`\Interfaces\{0D1C2B3A-0000-4000-8000-000000000001}`, t0).Values = []artw.Value{
		artw.DWORD("EnableDHCP", 1), artw.SZ("DhcpIPAddress", ip), artw.DWORD("LeaseObtainedTime", uint32(t0.Unix())),
	}
	b, err := artw.Hive(root, `\REGISTRY\MACHINE\SYSTEM`, t0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A Remote Desktop logon that names only an address is matched to the host
// whose own SYSTEM hive records that address, when no address is stated;
// a hive naming another computer than its submission's host is not used.
func TestConnectionFromHiveAddress(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	var logs bytes.Buffer
	if err := evtxw.Write(&logs, []evtxw.Record{{
		Provider: "Microsoft-Windows-TerminalServices-RemoteConnectionManager", ProviderGUID: "{C76BAA63-AE81-421C-B425-340B4B24157F}",
		EventID: 1149, Level: 4, Time: at, ProcessID: 1012, ThreadID: 2240, UserSID: "S-1-5-20",
		Channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", Computer: "SRV-B.corp.example",
		UserData: &evtxw.UserData{Element: "EventXML", NS: "Event_NS", Fields: []evtxw.KV{{Name: "Param1", Value: "alice"}, {Name: "Param2", Value: "CORP"}, {Name: "Param3", Value: "10.1.2.30"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"WS-A/SYSTEM": systemHive(t, "WS-A", "10.1.2.30"),
		"SRV-B/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx": logs.Bytes(),
	}
	for p, b := range files {
		p = filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := newCase(t)
	add := func(host, folder string) {
		t.Helper()
		hst, err := c.s.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
		batch, _ := c.s.NextBatch()
		if err := c.s.AssignBatch(batch, &hst.ID, ""); err != nil {
			t.Fatal(err)
		}
		paths, _ := filepath.Glob(filepath.Join(dir, folder, "*"))
		var evs []*store.Evidence
		for _, f := range paths {
			e, err := c.in.IntakePath(batch, f)
			if err != nil {
				t.Fatal(err)
			}
			evs = append(evs, e)
		}
		c.in.Process(evs)
	}
	add("WS-A", "WS-A")
	add("SRV-B", "SRV-B")
	rep, err := analysis.Connections(c.s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Connections) != 1 {
		t.Fatalf("%d connections: %+v", len(rep.Connections), rep.Connections)
	}
	cn := rep.Connections[0]
	reasons := strings.Join(cn.Reasons, " | ")
	if cn.From != "host:WS-A" || cn.To != "host:SRV-B" || !strings.Contains(reasons, "10.1.2.30, the address WS-A's SYSTEM hive records") {
		t.Errorf("connection %s -> %s, reasons %s", cn.From, cn.To, reasons)
	}
	notes := strings.Join(rep.Notes, " | ")
	if !strings.Contains(notes, "10.1.2.30 is taken to be WS-A's address: its SYSTEM hive (item ") ||
		!strings.Contains(notes, "records it as leased by DHCP (obtained 2026-11-02 07:00:00 UTC). That is the address the computer last had") {
		t.Errorf("notes: %s", notes)
	}
	var ws *store.HostIdentity
	for i := range rep.Hosts {
		if rep.Hosts[i].Name == "WS-A" {
			ws = &rep.Hosts[i]
		}
	}
	if ws == nil || len(ws.HiveIPs) != 1 || len(ws.HiveNames) != 1 || ws.HiveNames[0].Value != "WS-A.CORP.EXAMPLE" {
		t.Errorf("WS-A's identity: %+v", ws)
	}

	// A stated address of another host wins, and says so.
	if _, err := c.s.SetDetails("SRV-B", map[string]string{"ip_addresses": "10.1.2.30"}); err != nil {
		t.Fatal(err)
	}
	rep, _ = analysis.Connections(c.s)
	if notes := strings.Join(rep.Notes, " | "); !strings.Contains(notes, "WS-A's SYSTEM hive (item ") || !strings.Contains(notes, "records 10.1.2.30 as its address, but that is stated as an address of SRV-B; the stated address is used") {
		t.Errorf("stated conflict notes: %s", notes)
	}
	if _, err := c.s.SetDetails("SRV-B", map[string]string{"ip_addresses": ""}); err != nil {
		t.Fatal(err)
	}

	// The same hive added under another host names WS-A, not that host: its
	// addresses are not that host's.
	other := filepath.Join(dir, "other")
	os.MkdirAll(other, 0o750)
	os.WriteFile(filepath.Join(other, "SYSTEM"), systemHive(t, "WS-A", "10.7.7.7"), 0o600)
	add("SRV-C", "other")
	rep, _ = analysis.Connections(c.s)
	for _, h := range rep.Hosts {
		if h.Name == "SRV-C" && (len(h.HiveIPs) != 0 || !strings.Contains(strings.Join(h.Unread, " "), "names the computer WS-A, so the addresses it records are not used")) {
			t.Errorf("SRV-C: %+v", h)
		}
	}
	if notes := strings.Join(rep.Notes, " | "); !strings.Contains(notes, "SRV-C: a SYSTEM hive in its evidence") {
		t.Errorf("mismatch notes: %s", notes)
	}
}
