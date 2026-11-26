package ingest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/artw"
	"github.com/DanDreadless/atropos/internal/store"
)

// phoneHive is a SYSTEM hive with a phone connected as a composite USB
// device (its MTP interface, MI_00, of the portable devices class) at the
// given time, and a mouse with a serial, connected at the same time.
func phoneHive(t *testing.T, name string, at time.Time) []byte {
	t.Helper()
	t0 := time.Date(2026, 11, 2, 7, 0, 0, 0, time.UTC)
	root := &artw.Key{Name: "ROOT", Written: t0}
	root.Path(`Select`, t0).Values = []artw.Value{artw.DWORD("Current", 1)}
	root.Path(`ControlSet001\Control\ComputerName\ComputerName`, t0).Values = []artw.Value{artw.SZ("ComputerName", name)}
	ft := make([]byte, 8)
	binary.LittleEndian.PutUint64(ft, uint64(at.UnixNano()/100+116444736000000000))
	connected := func(key string) {
		root.Path(key+`\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066`, t0).Values = []artw.Value{{Name: "", Type: 0x10, Data: ft}}
	}
	phone := `ControlSet001\Enum\USB\VID_04E8&PID_6860\R58M1234ABC`
	root.Path(phone, t0).Values = []artw.Value{artw.SZ("DeviceDesc", "@usb.inf,%usb\\composite.devicedesc%;USB Composite Device"),
		artw.SZ("Service", "usbccgp"), artw.SZ("ParentIdPrefix", "7&2bd6ef1&0")}
	connected(phone)
	root.Path(`ControlSet001\Enum\USB\VID_04E8&PID_6860&MI_00\7&2bd6ef1&0&0000`, t0).Values = []artw.Value{
		artw.SZ("Class", "WPD"), artw.SZ("Service", "WUDFWpdMtp"), artw.SZ("FriendlyName", "Galaxy S21")}
	mouse := `ControlSet001\Enum\USB\VID_046D&PID_C52B\ABCDEF123456`
	root.Path(mouse, t0).Values = []artw.Value{artw.SZ("Class", "HIDClass"), artw.SZ("Service", "HidUsb")}
	connected(mouse)
	b, err := artw.Hive(root, `\REGISTRY\MACHINE\SYSTEM`, t0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The same phone in two hosts' SYSTEM hives links them, named by its MTP
// interface; a mouse with the same serial on both does not.
func TestPhoneLinksHosts(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"WS-A/SYSTEM":  phoneHive(t, "WS-A", time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)),
		"SRV-B/SYSTEM": phoneHive(t, "SRV-B", time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)),
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
	for _, host := range []string{"WS-A", "SRV-B"} {
		hst, err := c.s.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
		batch, _ := c.s.NextBatch()
		if err := c.s.AssignBatch(batch, &hst.ID, ""); err != nil {
			t.Fatal(err)
		}
		e, err := c.in.IntakePath(batch, filepath.Join(dir, host, "SYSTEM"))
		if err != nil {
			t.Fatal(err)
		}
		c.in.Process([]*store.Evidence{e})
	}
	rep, err := analysis.Connections(c.s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Connections) != 1 {
		t.Fatalf("%d connections: %+v", len(rep.Connections), rep.Connections)
	}
	cn := rep.Connections[0]
	r := strings.Join(cn.Reasons, " | ")
	if cn.Kind != "usb" || cn.From != "host:WS-A" || cn.To != "host:SRV-B" || time.Unix(0, cn.Start).UTC().Format("15:04") != "11:30" ||
		!strings.Contains(r, "the same phone or camera, Galaxy S21 (serial R58M1234ABC), is recorded on both computers (read from the SYSTEM hive)") ||
		cn.Target == nil || len(cn.Target.Events) != 1 || cn.Target.Events[0].What != `Phone or camera (MTP or PTP) last connected: Galaxy S21 (registry, Enum\USB)` {
		t.Errorf("%s -> %s at %s: %s; target %+v", cn.From, cn.To, time.Unix(0, cn.Start).UTC(), r, cn.Target)
	}
	var leaves []string
	for _, l := range rep.Leaves {
		leaves = append(leaves, l.Node+" "+l.Label)
	}
	if strings.Join(leaves, ", ") != "host:SRV-B Galaxy S21, host:WS-A Galaxy S21" {
		t.Errorf("leaves: %v", leaves)
	}
}
