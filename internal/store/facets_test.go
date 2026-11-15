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
	none, err := s.FacetsFor(Query{Text: "evidence:999"})
	if err != nil || len(none["source"]) != 0 {
		t.Fatalf("no events: %v %v", none, err)
	}
}
