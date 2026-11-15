package web

import (
	"fmt"
	"testing"

	"github.com/DanDreadless/atropos/internal/store"
)

// A change-journal record's folder is looked up in the file table of the
// same submission when the event is opened, and stored nowhere.
func TestJournalFolderFromTheFileTable(t *testing.T) {
	h := start(t)
	s := h.s
	add := func(n int, batch int64, events ...store.Event) {
		e := &store.Evidence{SHA256: fmt.Sprintf("%064d", n), Name: "x", Origin: "/x", BatchID: batch, Kind: "x", DetectReason: "test"}
		if err := s.AddEvidence(e); err != nil {
			t.Fatal(err)
		}
		run, _ := s.BeginRun(e.ID, "p", "1", "")
		for _, ev := range events {
			ev.TZSource, ev.TZName, ev.MACB, ev.TSUTC = "native-utc", "UTC", "....", 1700000000e9
			if err := run.Add(ev); err != nil {
				t.Fatal(err)
			}
		}
		run.Finish("parsed", "")
	}
	add(1, 1, store.Event{TSType: "$SI MACB", Source: "mft", Path: "/Users/a/Temp", RecordRef: "MFT entry 77-3", Fields: `{"entry":77,"sequence":3,"is_dir":true}`},
		store.Event{TSType: "$SI MACB", Source: "mft", Path: "/Users/a/Old", RecordRef: "MFT entry 78-4", Fields: `{"entry":78,"sequence":4,"is_dir":true}`})
	add(2, 1, store.Event{TSType: "usn-change", Source: "usn", Path: "evil.exe", RecordRef: "USN 1", Fields: `{"name":"evil.exe","parent_entry":77,"parent_sequence":3}`},
		store.Event{TSType: "usn-change", Source: "usn", Path: "gone.exe", RecordRef: "USN 2", Fields: `{"name":"gone.exe","parent_entry":78,"parent_sequence":5}`})
	// The same folder numbers in another submission are another volume's.
	add(3, 2, store.Event{TSType: "usn-change", Source: "usn", Path: "other.exe", RecordRef: "USN 3", Fields: `{"name":"other.exe","parent_entry":77,"parent_sequence":3}`})

	rows, _ := s.Search(store.Query{Text: "source:usn", Limit: 10})
	want := map[string]string{"evil.exe": "/Users/a/Temp", "gone.exe": "", "other.exe": ""}
	for _, r := range rows {
		var d struct {
			Folder *store.JournalFolder `json:"journal_folder"`
		}
		h.get(fmt.Sprintf("/api/event/%d", r.ID), &d)
		got := ""
		if d.Folder != nil {
			got = d.Folder.Path
		}
		if got != want[r.Path] {
			t.Errorf("%s: folder %q, want %q (a reused entry with another sequence number is not the same folder)", r.Path, got, want[r.Path])
		}
	}
}
