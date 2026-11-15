package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// Groups are timelines the examiner builds from the main one. They live in
// the notes layer: nothing about an event changes when it is picked.
func TestGroups(t *testing.T) {
	s := open(t)
	seed(t, s)
	var ids []int64
	rows, _ := s.Search(Query{})
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	var before string
	s.w.QueryRow(`SELECT group_concat(message || macb || fields, '|') FROM events`).Scan(&before)

	g, err := s.CreateGroup("  Malware   delivery ", "how it got in")
	if err != nil || g.Name != "Malware delivery" {
		t.Fatalf("create: %+v %v", g, err)
	}
	for name, why := range map[string]string{"malware DELIVERY": "duplicate ignoring case", "": "empty", "   ": "blank",
		strings.Repeat("x", 61): "too long", `say "hi"`: "quote", "a\x00b": "control character"} {
		if _, err := s.CreateGroup(name, ""); err == nil {
			t.Errorf("group name accepted (%s): %q", why, name)
		}
	}

	audited := func() int64 { n, _, _, _ := s.VerifyAudit(); return n }
	a0 := audited()
	n, err := s.AddToGroup(g.Name, append(ids[:2:2], 999999), "selected events")
	if err != nil || n != 2 {
		t.Fatalf("add: %d %v (an id that is not an event must be skipped, not fail)", n, err)
	}
	if audited() != a0+1 {
		t.Errorf("a bulk add wrote %d audit entries, want one", audited()-a0)
	}
	if n, _ := s.AddToGroup(g.Name, ids, "again"); n != 1 {
		t.Errorf("adding all three when two are members added %d, want 1", n)
	}
	for q, want := range map[Query]int{
		{Group: "Malware delivery"}: 3, {Group: "malware delivery"}: 3, {Group: "Other"}: 0,
		{Text: `group:"Malware delivery"`}: 3, {Text: `-group:"Malware delivery"`}: 0,
		{Group: "Malware delivery", Text: "powersh"}: 1,
	} {
		got, err := s.Search(q)
		if err != nil || len(got) != want {
			t.Errorf("%+v: %d events (%v), want %d", q, len(got), err, want)
		}
	}
	got, _ := s.Search(Query{Group: g.Name})
	if len(got[0].Groups) != 1 || got[0].Groups[0] != "Malware delivery" || len(got[0].Tags) != 1 {
		t.Errorf("row shows groups %v and tags %v", got[0].Groups, got[0].Tags)
	}
	if sum, _ := s.Summarise(Query{Group: g.Name}, 5); sum.Count != 3 {
		t.Errorf("summary of the group counts %d", sum.Count)
	}

	if n, _ := s.RemoveFromGroup(g.Name, ids[:1]); n != 1 {
		t.Errorf("remove: %d", n)
	}
	if n, _ := s.RemoveFromGroup(g.Name, ids[:1]); n != 0 {
		t.Errorf("removing a non-member removed %d", n)
	}
	list, _ := s.Groups()
	var mine *Group
	for i := range list {
		if list[i].ID == g.ID {
			mine = &list[i]
		}
	}
	if mine == nil || mine.Count != 2 || mine.Note != "how it got in" {
		t.Fatalf("listing: %+v", list)
	}
	// Removed membership is retracted, not deleted, and can be added again.
	var kept int
	s.w.QueryRow(`SELECT count(*) FROM annotations WHERE kind='group'`).Scan(&kept)
	if kept != 3 {
		t.Errorf("%d membership rows remain, want all 3 kept", kept)
	}
	if n, _ := s.AddToGroup(g.Name, ids[:1], "back"); n != 1 {
		t.Errorf("re-adding a removed event added %d", n)
	}

	// MatchingIDs is how "everything this search shows" becomes a list.
	if m, err := s.MatchingIDs(Query{Text: "logon"}, 10); err != nil || len(m) != 1 {
		t.Errorf("matching ids: %v %v", m, err)
	}
	if _, err := s.MatchingIDs(Query{}, 2); err == nil {
		t.Error("a search larger than the limit was not refused")
	}

	if err := s.ArchiveGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveGroup(g.ID); err == nil {
		t.Error("archived a group twice")
	}
	list, _ = s.Groups()
	for _, x := range list {
		if x.ID == g.ID {
			t.Error("archived group still listed")
		}
	}
	// The name is free again, and the events picked before come back with it.
	g2, err := s.CreateGroup("Malware delivery", "")
	if err != nil {
		t.Fatal(err)
	}
	list, _ = s.Groups()
	if last := list[len(list)-1]; last.ID != g2.ID || last.Count != 3 {
		t.Errorf("recreated group: %+v", last)
	}

	var after string
	s.w.QueryRow(`SELECT group_concat(message || macb || fields, '|') FROM events`).Scan(&after)
	if before != after {
		t.Error("grouping changed event rows")
	}
	if checked, bad, _ := s.VerifyRuns(); checked != 1 || len(bad) != 0 {
		t.Errorf("run digests after grouping: %v", bad)
	}
	if _, _, broken, _ := s.VerifyAudit(); broken != 0 {
		t.Errorf("audit chain broken at %d", broken)
	}
}

// A case made by a build with a different storage format is refused with an
// explanation, not opened and silently misread.
func TestOtherStorageFormatIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := Open(path, "tester")
	if err != nil {
		t.Fatal(err)
	}
	dropTriggers(t, s)
	s.w.Exec(`UPDATE case_meta SET value = '1' WHERE key = 'schema_version'`)
	s.Close()
	if _, err := Open(path, "tester"); err == nil || !strings.Contains(err.Error(), "storage format 1") {
		t.Errorf("opening a format-1 case: %v", err)
	}
}
