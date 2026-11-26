package parsers

import (
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/artw"
)

// A standalone computer's SECURITY hive has no Cache key (only domain
// logons make one): Policy, Recovery and RXACT, as on the owner's Windows
// 11. It is still known as SECURITY, and its audit policy is read.
func TestSecurityHiveWithoutCache(t *testing.T) {
	t0 := time.Date(2025, 3, 4, 9, 0, 0, 0, time.UTC)
	root := &artw.Key{Name: "ROOT", Written: t0}
	pol := make([]byte, 12+2*59+2)
	pol[8] = byte(len(pol))
	pol[12+2*33] = 1 // Process Creation: success
	for _, n := range []byte{5, 11, 14, 3, 6, 6, 6, 4, 4} {
		pol = append(pol, n, 0)
	}
	root.Path(`Policy\PolAdtEv`, t0).Values = []artw.Value{{Name: "", Type: 0, Data: pol}}
	root.Path(`Recovery`, t0)
	root.Path(`RXACT`, t0)
	hive, err := artw.Hive(root, `\REGISTRY\MACHINE\SECURITY`, t0)
	if err != nil {
		t.Fatal(err)
	}
	r := run(t, write(t, "SECURITY", hive), nil)
	if r.err != nil || r.facts["hive.kind"] != "SECURITY" || r.facts["security.audit_policy"] != "Process Creation (success); everything else not audited" {
		t.Fatalf("err %v kind %q policy %q", r.err, r.facts["hive.kind"], r.facts["security.audit_policy"])
	}
}

// A SYSTEM hive gives the computer's addresses and its name in the domain,
// which connections from other hosts are matched on.
func TestSystemHiveAddresses(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	root := &artw.Key{Name: "ROOT", Written: t0}
	root.Path(`Select`, t0).Values = []artw.Value{artw.DWORD("Current", 1)}
	cs := `ControlSet001`
	root.Path(cs+`\Control\ComputerName\ComputerName`, t0).Values = []artw.Value{artw.SZ("ComputerName", "WS-ALICE")}
	tcp := cs + `\Services\Tcpip\Parameters`
	root.Path(tcp, t0).Values = []artw.Value{artw.SZ("Hostname", "WS-ALICE"), artw.SZ("Domain", ""), artw.SZ("NV Domain", "corp.example.")}
	ifs := tcp + `\Interfaces`
	root.Path(ifs+`\{11111111-2222-3333-4444-555555555555}`, t0).Values = []artw.Value{
		artw.DWORD("EnableDHCP", 1), artw.SZ("DhcpIPAddress", "10.1.2.30"), artw.SZ("DhcpServer", "10.1.2.1"),
		artw.DWORD("LeaseObtainedTime", uint32(t0.Unix())), artw.DWORD("LeaseTerminatesTime", uint32(t0.Add(8*24*time.Hour).Unix())),
		// The static list is ignored while DHCP is on.
		artw.MultiSZ("IPAddress", "10.9.9.99"),
	}
	root.Path(ifs+`\{22222222-2222-3333-4444-555555555555}`, t0).Values = []artw.Value{
		artw.DWORD("EnableDHCP", 0), artw.MultiSZ("IPAddress", "192.168.50.7", "0.0.0.0", "10.1.2.30"),
	}
	// Nothing usable: an unplugged adapter, link-local and loopback.
	root.Path(ifs+`\{33333333-2222-3333-4444-555555555555}`, t0).Values = []artw.Value{
		artw.DWORD("EnableDHCP", 1), artw.SZ("DhcpIPAddress", "0.0.0.0"),
	}
	root.Path(ifs+`\{44444444-2222-3333-4444-555555555555}`, t0).Values = []artw.Value{
		artw.DWORD("EnableDHCP", 0), artw.MultiSZ("IPAddress", "169.254.10.10", "127.0.0.1", "not an address"),
	}
	hive, err := artw.Hive(root, `\REGISTRY\MACHINE\SYSTEM`, t0)
	if err != nil {
		t.Fatal(err)
	}
	type fact struct{ k, v, d string }
	var facts []fact
	r := run(t, write(t, "SYSTEM", hive), func(c *Context) {
		c.Fact = func(k, v, d string) { facts = append(facts, fact{k, v, d}) }
	})
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err %v warns %v", r.err, r.warns)
	}
	var got []string
	for _, f := range facts {
		switch f.k {
		case "host.name", "host.dns_name", "host.ip_address":
			got = append(got, f.k+"="+f.v)
		}
		if f.k == "host.ip_address" && f.v == "10.1.2.30" &&
			!strings.Contains(f.d, "leased by DHCP (obtained 2026-11-02 08:00:00 UTC, ending 2026-11-10 08:00:00 UTC, from the DHCP server 10.1.2.1)") {
			t.Errorf("DHCP detail %q", f.d)
		}
		if f.k == "host.ip_address" && f.v == "192.168.50.7" && !strings.Contains(f.d, `set on the interface, from ControlSet001\Services\Tcpip\Parameters\Interfaces\{22222222`) {
			t.Errorf("static detail %q", f.d)
		}
	}
	want := "host.name=WS-ALICE host.dns_name=WS-ALICE.CORP.EXAMPLE host.ip_address=10.1.2.30 host.ip_address=192.168.50.7"
	if strings.Join(got, " ") != want {
		t.Errorf("facts\n got %s\nwant %s", strings.Join(got, " "), want)
	}
}
