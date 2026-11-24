package store

import "testing"

// Chip counts follow a filter.
func TestFacetsFor(t *testing.T) {
	s := open(t)
	seed(t, s)
	all, err := s.FacetsFor(Query{})
	if err != nil || all["category"]["execution"] != 1 || all["source"]["log"] != 3 {
		t.Fatalf("all: %v %v", all, err)
	}
	some, err := s.FacetsFor(Query{Text: "powershell"})
	if err != nil || some["source"]["log"] != 1 || some["category"]["account"] != 0 || len(some["category"]) != 1 {
		t.Fatalf("filtered: %v %v", some, err)
	}
	// A category chosen: the categories are counted without it, so the other
	// two stay to choose from, while sources follow the choice.
	cat, err := s.FacetsFor(Query{Text: "category:execution"})
	if err != nil || cat["category"]["account"] != 1 || cat["category"]["execution"] != 1 || cat["source"]["log"] != 1 {
		t.Fatalf("category chosen: %v %v", cat, err)
	}
	// Words and chips together: every group follows the words.
	both, err := s.FacetsFor(Query{Text: `"logon by" category:execution`})
	if err != nil || both["category"]["account"] != 1 || len(both["category"]) != 1 || len(both["source"]) != 0 {
		t.Fatalf("words and a chip: %v %v", both, err)
	}
	// An excluded source is left out of everything but the source counts.
	neg, err := s.FacetsFor(Query{Text: "-source:log"})
	if err != nil || neg["source"]["log"] != 3 || len(neg["category"]) != 0 {
		t.Fatalf("excluded source: %v %v", neg, err)
	}
	none, err := s.FacetsFor(Query{Text: "evidence:999"})
	if err != nil || len(none["source"]) != 0 {
		t.Fatalf("no events: %v %v", none, err)
	}
}
