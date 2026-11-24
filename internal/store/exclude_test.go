package store

import (
	"fmt"
	"strings"
	"testing"
)

// Excluding an item takes it, and everything that came out of it, out of the
// timeline, its counts and the text searches, without removing anything:
// every run still verifies, and including it again brings it all back.
func TestExcludeAndIncludeEvidence(t *testing.T) {
	s := open(t)
	n := 0
	add := func(name string, parent *int64, events int, text string) int64 {
		n++
		e := &Evidence{SHA256: fmt.Sprintf("%064x", n), SHA1: "s", MD5: "m", Size: 1, Name: name, Origin: name,
			ParentID: parent, BatchID: 1, Kind: "text", DetectReason: "test"}
		if err := s.AddEvidence(e); err != nil {
			t.Fatal(err)
		}
		run, err := s.BeginRun(e.ID, "text-log", "1", "assumed: UTC")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < events; i++ {
			if err := run.Add(Event{TSUTC: int64(1700000000+i) * 1e9, TSType: "logged", TZSource: "native-utc", TZName: "UTC", MACB: "....",
				Category: "log", Source: "log", Message: "line from " + name, RecordRef: "line"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := run.Finish("parsed", ""); err != nil {
			t.Fatal(err)
		}
		if text != "" {
			if err := s.AddText(e.ID, "full text", false, text); err != nil {
				t.Fatal(err)
			}
		}
		return e.ID
	}
	image := add("disk.E01", nil, 1, "")
	hive := add("NTUSER.DAT", &image, 3, "zebracorn inside the image")
	add("other.log", nil, 4, "zebracorn elsewhere")

	count := func(q string) int64 {
		t.Helper()
		sum, err := s.Summarise(Query{Text: q}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return sum.Count
	}
	hits := func() int {
		h, err := s.SearchText("zebracorn", 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(h)
	}
	if count("") != 8 || hits() != 2 {
		t.Fatalf("before: %d events, %d text hits", count(""), hits())
	}

	if err := s.SetExcluded(image, true, "  "); err == nil {
		t.Error("an exclusion without a reason was accepted")
	}
	if err := s.SetExcluded(image, true, "wrong machine's image"); err != nil {
		t.Fatal(err)
	}
	if got := count(""); got != 4 {
		t.Errorf("after excluding the image: %d events, want 4 (the image's and the hive's are out)", got)
	}
	if got := count("line from NTUSER.DAT"); got != 0 {
		t.Errorf("a search still finds %d events of the excluded hive", got)
	}
	if hits() != 1 {
		t.Errorf("text search still finds the excluded hive's text: %d hits", hits())
	}
	f, err := s.FacetsFor(Query{Text: "source:log"})
	if err != nil || f["source"]["log"] != 4 {
		t.Errorf("chip counts after excluding: %v %v", f, err)
	}
	list, err := s.ListEvidence()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		switch e.ID {
		case image:
			if !e.Excluded || e.ExcludedBy != image || e.ExcludeReason != "wrong machine's image" {
				t.Errorf("image: %+v", e)
			}
		case hive:
			if !e.Excluded || e.ExcludedBy != image {
				t.Errorf("the hive taken out of the image is not excluded with it: %+v", e)
			}
		default:
			if e.Excluded {
				t.Errorf("%s excluded", e.Name)
			}
		}
	}
	if err := s.SetExcluded(hive, false, ""); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("#%d", image)) {
		t.Errorf("including an item excluded with its image: %v", err)
	}
	if _, bad, err := s.VerifyRuns(); err != nil || len(bad) != 0 {
		t.Errorf("runs no longer verify after an exclusion: %v %v", bad, err)
	}

	if err := s.SetExcluded(image, false, "it was the right machine"); err != nil {
		t.Fatal(err)
	}
	if count("") != 8 || hits() != 2 {
		t.Errorf("after including again: %d events, %d text hits", count(""), hits())
	}
	var audited int
	s.r.QueryRow(`SELECT count(*) FROM audit WHERE action IN ('evidence.exclude','evidence.include')`).Scan(&audited)
	if audited != 2 {
		t.Errorf("%d exclusion audit entries, want 2", audited)
	}
}
