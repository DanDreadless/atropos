package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/evtxw"
)

func recoverLog(t *testing.T) []byte {
	t.Helper()
	base := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	var recs []evtxw.Record
	for i, user := range []string{"alice", "bob", "carol", "mallory", "trent"} {
		recs = append(recs, evtxw.Record{
			Provider: "Microsoft-Windows-Security-Auditing", EventID: 4624, Time: base.Add(time.Duration(i) * time.Minute),
			Channel: "Security", Computer: "WS-1", Data: []evtxw.KV{{Name: "TargetUserName", Value: user}, {Name: "LogonType", Value: uint32(10)}},
		})
	}
	var buf bytes.Buffer
	if err := evtxw.Write(&buf, recs); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Older records in a chunk's unused space: the log has been told it holds
// three records, so the last two lie past its free-space offset, as records
// do that a log no longer lists. They come back as recovered events, marked,
// and the live records are unchanged. Found missing comparing with Plaso
// (27 November 2026); checked on 7,240 records of the public logs.
func TestEvtxRecoversOldRecords(t *testing.T) {
	data := recoverLog(t)
	le := binary.LittleEndian
	ch := data[4096 : 4096+0x10000]
	off := 0x200
	var starts []int
	for i := 0; i < 5; i++ {
		starts = append(starts, off)
		off += int(le.Uint32(ch[off+4:]))
	}
	le.PutUint64(ch[16:], 3)
	le.PutUint64(ch[32:], 3)
	le.PutUint32(ch[44:], uint32(starts[2]))
	le.PutUint32(ch[48:], uint32(starts[3]))
	r := run(t, write(t, "Security.evtx", data), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err %v warns %v", r.err, r.warns)
	}
	var live, rec []string
	for _, e := range r.events {
		user := fmt.Sprint(e.Fields["event"].(map[string]any)["EventData"].(map[string]any)["TargetUserName"])
		switch e.Type {
		case "event-logged":
			live = append(live, user)
		case "event-logged (recovered)":
			rec = append(rec, user)
			if e.Fields["recovered"] == nil || !strings.HasPrefix(e.Message, "Recovered record: ") || e.Stamp.UTC.Minute() != 3 && e.Stamp.UTC.Minute() != 4 {
				t.Errorf("recovered event %s %+v", e.Message, e.Fields)
			}
			if want := fmt.Sprintf("at offset %d of the chunk at offset 4096", starts[3+len(rec)-1]); !strings.Contains(e.Ref, want) {
				t.Errorf("ref %q, want %q", e.Ref, want)
			}
		}
	}
	if strings.Join(live, " ") != "alice bob carol" || strings.Join(rec, " ") != "mallory trent" {
		t.Errorf("live %v, recovered %v", live, rec)
	}
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "2 older records were recovered") {
		t.Errorf("notes %q", r.notes)
	}

	// Unchanged, nothing is recovered: the same records are live.
	r = run(t, write(t, "Security.evtx", recoverLog(t)), nil)
	for _, e := range r.events {
		if e.Type != "event-logged" {
			t.Errorf("%s in an untouched log", e.Type)
		}
	}
	if len(r.events) != 5 || len(r.notes) != 0 {
		t.Errorf("%d events, notes %q", len(r.events), r.notes)
	}
}

// A record claiming four thousand million template arguments: the unpatched
// library appended a descriptor for each and ran out of memory, which Go
// cannot recover from (a recovered record did exactly this on a public log).
// The patched copy in third_party/evtx refuses the count; the log is read.
func TestEvtxArgumentCountBounded(t *testing.T) {
	data := recoverLog(t)
	le := binary.LittleEndian
	ch := data[4096 : 4096+0x10000]
	at := 0x200 + 28 // the first record's template instance
	if ch[at] != 0x0C || int(le.Uint32(ch[at+6:])) != at+10 {
		t.Fatalf("the first record's template is not inline (%#x)", ch[at])
	}
	body := int(le.Uint32(ch[at+30:]))
	le.PutUint32(ch[at+34+body:], 0xFFFFFFFF)
	done := make(chan result, 1)
	go func() { done <- run(t, write(t, "Security.evtx", data), nil) }()
	select {
	case r := <-done:
		if r.err != nil || len(r.events) < 4 {
			t.Errorf("err %v, %d events", r.err, len(r.events))
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the log did not finish in a minute")
	}
}
