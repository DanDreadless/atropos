package store

import (
	"fmt"
	"testing"
)

// domain: finds a site's browser events, its subdomains included and other
// sites not; visit: finds one visit by the browser's own number.
func TestDomainAndVisitFilters(t *testing.T) {
	s := open(t)
	e := &Evidence{SHA256: fmt.Sprintf("%064x", 1), SHA1: "s", MD5: "m", Size: 1, Name: "History", Origin: "History", BatchID: 1, Kind: "sqlite-database", DetectReason: "t"}
	if err := s.AddEvidence(e); err != nil {
		t.Fatal(err)
	}
	run, _ := s.BeginRun(e.ID, "sqlite", "9", "")
	for i, x := range []struct{ src, domain string }{
		{"browser", "example.com"}, {"browser", "www.example.com"}, {"browser-synced", "mail.example.com"},
		{"browser", "notexample.com"}, {"browser", "example.com.evil.test"}, {"registry", "example.com"},
	} {
		if err := run.Add(Event{TSUTC: int64(1700000000+i) * 1e9, TSType: "url-visited (link)", TZSource: "native-utc", TZName: "UTC", MACB: "....",
			Category: "browser", Source: x.src, Message: "m", RecordRef: "r",
			Fields: fmt.Sprintf(`{"domain":%q,"visit_id":%d}`, x.domain, 100+i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := run.Finish("parsed", ""); err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int64{
		"domain:example.com": 3, "domain:www.example.com": 3, "domain:EXAMPLE.COM": 3, "domain:mail.example.com": 1,
		"-domain:example.com source:browser": 2, "domain:evil.test": 1,
		fmt.Sprintf("evidence:%d visit:102", e.ID): 1, "visit:105": 0, "visit:999": 0,
	} {
		sum, err := s.Summarise(Query{Text: q}, 0)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if sum.Count != want {
			t.Errorf("%s: %d events, want %d", q, sum.Count, want)
		}
	}
}
