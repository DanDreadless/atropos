package store

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

// Counting from run summaries must give exactly what reading the events
// gives: totals, first and last times, chip counts, and every bar of the
// chart, for each kind of filter the summaries answer, with an item
// excluded, and for times before 1970.
func TestStatsAgreeWithEvents(t *testing.T) {
	s := open(t)
	n := 0
	add := func(name string, parent *int64, kind string) int64 {
		n++
		e := &Evidence{SHA256: fmt.Sprintf("%064x", n), SHA1: "s", MD5: "m", Size: 1, Name: name, Origin: name,
			ParentID: parent, BatchID: int64(1 + n%2), Kind: kind, DetectReason: "test"}
		if err := s.AddEvidence(e); err != nil {
			t.Fatal(err)
		}
		run, err := s.BeginRun(e.ID, "p", "1", "")
		if err != nil {
			t.Fatal(err)
		}
		sources := []string{"mft", "evtx", "registry"}
		cats := []string{"file-system", "execution", "log"}
		tzs := []string{"native-utc", "assumed", "explicit-offset"}
		for i := 0; i < 400; i++ {
			// Spread over years, minutes and before 1970, with repeats in one hour.
			ts := int64(-2e17) + int64(i*i*n)*int64(7.3e12) + int64(i%5)*60e9
			if err := run.Add(Event{TSUTC: ts, TSType: "t", TZSource: tzs[(i+n)%3], TZName: "UTC", MACB: "....", Host: []string{"PC-1", "pc-2", ""}[(i+n)%3],
				Category: cats[(i/3)%3], Source: sources[(i+n)%3], Message: fmt.Sprintf("event %d of %s", i, name), RecordRef: "r"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := run.Finish("parsed", ""); err != nil {
			t.Fatal(err)
		}
		return e.ID
	}
	image := add("disk.E01", nil, "ewf-image")
	hive := add("NTUSER.DAT", &image, "windows-registry-hive")
	add("Security.evtx", nil, "windows-event-log")
	other := add("NTUSER.DAT", nil, "windows-registry-hive")
	if err := s.SetExcluded(other, true, "test"); err != nil {
		t.Fatal(err)
	}
	if !s.statsReady() {
		t.Fatal("runs sealed by Finish have no summaries")
	}

	queries := []string{"", "source:mft", "-source:mft", "category:execution", "tz:assumed source:evtx",
		fmt.Sprintf("from:%d", image), fmt.Sprintf("evidence:%d", hive), "submission:1", "item:ntuser.dat", "kind:windows-event-log",
		"-kind:windows-event-log category:log", "source:mft source:evtx", "category:execution category:log -source:mft", "tz:assumed tz:native-utc source:registry", "host:pc-1", "host:PC-2 source:mft", "-host:pc-1"}
	for _, q := range queries {
		if !s.byStats(Query{Text: q}) {
			t.Errorf("%q is not counted from summaries", q)
		}
		for _, buckets := range []int{3, 120, 240} {
			s.noStats = true
			want, err := s.Summarise(Query{Text: q}, buckets)
			if err != nil {
				t.Fatal(err)
			}
			wantF, _ := s.FacetsFor(Query{Text: q})
			s.noStats = false
			got, err := s.Summarise(Query{Text: q}, buckets)
			if err != nil {
				t.Fatal(err)
			}
			gotF, _ := s.FacetsFor(Query{Text: q})
			if got.Count != want.Count || got.MinTS != want.MinTS || got.MaxTS != want.MaxTS {
				t.Errorf("%q: summaries give %d %d..%d, events %d %d..%d", q, got.Count, got.MinTS, got.MaxTS, want.Count, want.MinTS, want.MaxTS)
			}
			if !reflect.DeepEqual(gotF, wantF) {
				t.Errorf("%q: chip counts differ:\n summaries %v\n events    %v", q, gotF, wantF)
			}
			if got.Buckets > int64(buckets) {
				t.Errorf("%q: %d bars for %d asked", q, got.Buckets, buckets)
			}
			// Every bar holds exactly the events in its span.
			s.noStats = true
			var total int64
			for _, b := range got.Bars {
				from := got.Start + b.Index*got.Bucket
				x, _ := s.Summarise(Query{Text: q, From: from, To: from + got.Bucket - 1}, 1)
				if x.Count != b.Count {
					t.Errorf("%q bar %d: %d events, %d in its span", q, b.Index, b.Count, x.Count)
				}
				total += b.Count
			}
			s.noStats = false
			if total != want.Count {
				t.Errorf("%q: bars hold %d of %d events", q, total, want.Count)
			}
		}
	}
	// Words, a time range or a group read the events.
	for _, q := range []Query{{Text: "event"}, {Text: "source:mft event"}, {From: 1}, {Group: "g"}, {Text: "from:abc"}, {Text: "user:x"}} {
		if s.byStats(q) {
			t.Errorf("%+v would be counted from summaries", q)
		}
	}
}

// A case made before summaries existed gains them, and the indexes, in the
// background; until then it is counted from the events.
func TestBuildDerivedForAnOlderCase(t *testing.T) {
	s := open(t)
	e := &Evidence{SHA256: fmt.Sprintf("%064x", 1), SHA1: "s", MD5: "m", Size: 1, Name: "a.log", Origin: "a.log", BatchID: 1, Kind: "text", DetectReason: "t"}
	if err := s.AddEvidence(e); err != nil {
		t.Fatal(err)
	}
	run, _ := s.BeginRun(e.ID, "p", "1", "")
	run.Add(Event{TSUTC: 1e18, TSType: "t", TZSource: "native-utc", TZName: "UTC", MACB: "....", Category: "log", Source: "log", Message: "m", RecordRef: "r"})
	// Seal the run as an earlier version did: no summary.
	run.flush()
	if _, err := s.w.Exec(`INSERT INTO run_results(run_id,status,event_count,event_digest,notes,finished_utc) VALUES (?,?,?,?,?,?)`,
		run.ID, "parsed", 1, "d", "", 1); err != nil {
		t.Fatal(err)
	}
	if s.byStats(Query{}) {
		t.Fatal("counted from summaries that do not exist")
	}
	if err := s.BuildDerived(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.byStats(Query{}) {
		t.Fatal("still not counted from summaries after BuildDerived")
	}
	sum, _ := s.Summarise(Query{}, 10)
	if sum.Count != 1 {
		t.Errorf("count %d", sum.Count)
	}
	var ix int
	s.r.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('events_source_nc','events_category_nc','events_tz_nc','events_run_ts','events_ts_run')`).Scan(&ix)
	if ix != 5 {
		t.Errorf("%d of 5 indexes built", ix)
	}
	if err := s.BuildDerived(context.Background()); err != nil {
		t.Errorf("a second build: %v", err)
	}
}

// Two values of one field are alternatives, as two chips picked in one row
// are: source:a source:b counts the events of either, not of both at once.
func TestSameFieldFiltersAreAlternatives(t *testing.T) {
	s := open(t)
	e := &Evidence{SHA256: fmt.Sprintf("%064x", 9), SHA1: "s", MD5: "m", Size: 1, Name: "x", Origin: "x", BatchID: 1, Kind: "text", DetectReason: "t"}
	if err := s.AddEvidence(e); err != nil {
		t.Fatal(err)
	}
	run, _ := s.BeginRun(e.ID, "p", "1", "")
	for i, x := range []struct{ src, cat string }{{"a", "browser"}, {"a", "browser-automatic"}, {"b", "browser"}, {"c", "log"}} {
		run.Add(Event{TSUTC: int64(1700000000+i) * 1e9, TSType: "t", TZSource: "native-utc", TZName: "UTC", MACB: "....", Category: x.cat, Source: x.src, Message: "m", RecordRef: "r"})
	}
	run.Finish("parsed", "")
	for _, stats := range []bool{false, true} {
		s.noStats = !stats
		for q, want := range map[string]int64{
			"category:browser category:browser-automatic": 3, "source:a source:b": 3, "source:a source:b category:browser": 2,
			"SOURCE:A source:c": 3, "source:a -category:browser-automatic": 1, "source:a source:b -source:b": 2, "category:browser category:none": 2,
		} {
			sum, err := s.Summarise(Query{Text: q}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if sum.Count != want {
				t.Errorf("%q (summaries %v): %d events, want %d", q, stats, sum.Count, want)
			}
		}
	}
}
