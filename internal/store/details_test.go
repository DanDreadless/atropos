package store

import (
	"strings"
	"testing"
)

func TestDetails(t *testing.T) {
	s := open(t)
	seed(t, s) // states a case reference

	n, err := s.SetDetails("WS-042", map[string]string{"serial_number": " PF3ABCDE ", "make": "Lenovo", "clock_offset": "4 minutes fast"})
	if err != nil || n != 3 {
		t.Fatalf("stating host details: %d %v", n, err)
	}
	// Saying the same again writes nothing; the host is the same host in any case.
	if n, err := s.SetDetails("ws-042", map[string]string{"make": "Lenovo", "model": "T14"}); err != nil || n != 1 {
		t.Errorf("restating: %d %v", n, err)
	}
	// A correction is appended, and a blank withdraws.
	if n, err := s.SetDetails("WS-042", map[string]string{"serial_number": "PF3ABCDF", "make": ""}); err != nil || n != 2 {
		t.Errorf("correcting: %d %v", n, err)
	}
	d, err := s.Details()
	if err != nil {
		t.Fatal(err)
	}
	ws := hostNamed(d, "WS-042")
	if ws == nil {
		t.Fatalf("hosts: %+v", d.Hosts)
	}
	v := ws.Values
	if v["serial_number"].Value != "PF3ABCDF" || v["model"].Value != "T14" || v["clock_offset"].Value != "4 minutes fast" || v["serial_number"].Actor != "tester" {
		t.Errorf("values: %+v", v)
	}
	if _, ok := v["make"]; ok {
		t.Error("a withdrawn detail is still shown")
	}
	if d.Case["case_reference"].Value == "" {
		t.Errorf("case details: %+v", d.Case)
	}
	// Nothing is lost: the first serial number and the withdrawn make are in the history.
	hist, err := s.DetailHistory()
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, c := range hist {
		seen = append(seen, c.Host+"/"+c.Field+"="+c.Value)
	}
	all := strings.Join(seen, " ")
	for _, want := range []string{"WS-042/serial_number=PF3ABCDE", "WS-042/serial_number=PF3ABCDF", "WS-042/make=Lenovo", "WS-042/make="} {
		if !strings.Contains(all+" ", want+" ") {
			t.Errorf("history lacks %q: %v", want, seen)
		}
	}
	// Each statement is in the audit log with what was stated.
	rows, _ := s.ListAudit(3)
	if len(rows) == 0 || rows[0].Action != "details.set" || rows[0].Target != "host:WS-042" || !strings.Contains(string(rows[0].Details), "PF3ABCDF") {
		t.Errorf("audit: %+v", rows)
	}

	// Refusals.
	if _, err := s.SetDetails("WS-042", map[string]string{"favourite_colour": "blue"}); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := s.SetDetails("", map[string]string{"serial_number": "x"}); err == nil {
		t.Error("a host field was accepted for the case")
	}
	if _, err := s.SetDetails("WS-042", map[string]string{"notes": strings.Repeat("x", maxDetailValue+1)}); err == nil {
		t.Error("an oversized value was accepted")
	}
	if _, err := s.SetDetails("a\nb", map[string]string{"make": "x"}); err == nil {
		t.Error("a host name with a line break was accepted")
	}

	// A host with everything withdrawn is still one of the case's hosts,
	// with nothing stated: hosts are records, never removed.
	s.SetDetails("WS-042", map[string]string{"serial_number": "", "model": "", "clock_offset": ""})
	if d, _ := s.Details(); hostNamed(d, "WS-042") == nil || len(hostNamed(d, "WS-042").Values) != 0 {
		t.Errorf("host after withdrawing every detail: %+v", d.Hosts)
	}
}

func TestDetailsShowWhatTheEvidenceSays(t *testing.T) {
	s := open(t)
	e := &Evidence{SHA256: strings.Repeat("1", 64), Name: "SYSTEM", Origin: "/x/SYSTEM", BatchID: 7, Kind: "windows-registry-hive", DetectReason: "test"}
	if err := s.AddEvidence(e); err != nil {
		t.Fatal(err)
	}
	s.AddFact(e.ID, "host.name", "DESKTOP-1", "")
	s.AddFact(e.ID, "host.timezone", "Europe/London", "")
	d, _ := s.Details()
	if len(d.KnownHosts) != 1 || d.KnownHosts[0] != "DESKTOP-1" {
		t.Fatalf("hosts the evidence names: %v", d.KnownHosts)
	}
	s.SetDetails("desktop-1", map[string]string{"exhibit_reference": "DP/1"})
	d, _ = s.Details()
	if len(d.Hosts) != 1 || d.Hosts[0].Found["time_zone"] != "Europe/London" || len(d.KnownHosts) != 0 {
		t.Errorf("found values: %+v known %v", d.Hosts, d.KnownHosts)
	}
	// What was read is offered, never written as if the examiner had stated it.
	if _, ok := d.Hosts[0].Values["time_zone"]; ok {
		t.Error("a value read from evidence was stored as a stated detail")
	}
}

func hostNamed(d *AllDetails, name string) *HostDetails {
	for i := range d.Hosts {
		if d.Hosts[i].Name == name {
			return &d.Hosts[i]
		}
	}
	return nil
}
