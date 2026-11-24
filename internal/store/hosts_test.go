package store

import (
	"strings"
	"testing"
)

// A host is added once whatever its capitalisation; a submission is assigned
// to a host or to no host with a stated source; the latest assignment is in
// force, every one is kept and audited, and the evidence list shows it.
func TestHostsAndAssignments(t *testing.T) {
	s := open(t)
	a, err := s.AddHost("  WS-042 ")
	if err != nil || a.Name != "WS-042" {
		t.Fatalf("add: %+v %v", a, err)
	}
	if b, _ := s.AddHost("ws-042"); b.ID != a.ID {
		t.Errorf("the same host added twice: %d and %d", a.ID, b.ID)
	}
	for _, bad := range []string{"", "   ", "a\nb", strings.Repeat("x", 256)} {
		if _, err := s.AddHost(bad); err == nil {
			t.Errorf("host name %q accepted", bad)
		}
	}
	dc, _ := s.AddHost("DC-01")
	if hs, _ := s.Hosts(); len(hs) != 2 || hs[0].Name != "WS-042" || hs[1].Name != "DC-01" {
		t.Errorf("hosts: %+v", hs)
	}

	e := &Evidence{SHA256: strings.Repeat("a", 64), Name: "Security.evtx", Origin: "x", BatchID: 3, Kind: "windows-event-log", DetectReason: "t"}
	if err := s.AddEvidence(e); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.BatchAssignment(3); got != nil {
		t.Errorf("an unassigned submission has an assignment: %+v", got)
	}
	if err := s.AssignBatch(3, nil, "  "); err == nil {
		t.Error("not from a host, with no source, was accepted")
	}
	missing := int64(99)
	if err := s.AssignBatch(3, &missing, ""); err == nil {
		t.Error("an assignment to a host that does not exist was accepted")
	}
	if err := s.AssignBatch(3, &a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignBatch(3, &dc.ID, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := s.BatchAssignment(3)
	if got == nil || got.HostName != "DC-01" || *got.HostID != dc.ID {
		t.Errorf("latest assignment: %+v", got)
	}
	if err := s.AssignBatch(3, nil, "firewall logs exported by IT"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.BatchAssignment(3)
	if got == nil || got.HostID != nil || got.Source != "firewall logs exported by IT" {
		t.Errorf("not from a host: %+v", got)
	}
	list, _ := s.ListEvidence()
	if len(list) != 1 || list[0].Assigned == nil || list[0].Assigned.Source != "firewall logs exported by IT" {
		t.Errorf("evidence list: %+v", list[0].Assigned)
	}
	var kept, audited int
	s.r.QueryRow(`SELECT count(*) FROM batch_hosts WHERE batch_id = 3`).Scan(&kept)
	s.r.QueryRow(`SELECT count(*) FROM audit WHERE action = 'submission.assigned'`).Scan(&audited)
	if kept != 3 || audited != 3 {
		t.Errorf("%d assignments kept and %d audited, want 3 and 3", kept, audited)
	}
}

// The zone stated for a host is used only when it is a zone name.
func TestHostTimeZone(t *testing.T) {
	s := open(t)
	if _, err := s.SetDetails("WS-042", map[string]string{"time_zone": "Europe/London"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDetails("DC-01", map[string]string{"time_zone": "GMT Standard Time, I think"}); err != nil {
		t.Fatal(err)
	}
	if z := s.HostTimeZone("ws-042"); z != "Europe/London" {
		t.Errorf("WS-042: %q", z)
	}
	if z := s.HostTimeZone("DC-01"); z != "" {
		t.Errorf("a zone that is not a zone name was used: %q", z)
	}
	if hs, _ := s.Hosts(); len(hs) != 2 {
		t.Errorf("describing a host did not add it: %+v", hs)
	}
}
