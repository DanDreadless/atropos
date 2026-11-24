package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/evtxw"
)

// Logs made by evtxw (for tests and demonstrations) read back exactly: the
// time to the 100 nanoseconds, typed EventData, UserData, record numbers,
// and records across several chunks, with valid checksums.
func TestEvtxWriterRoundTrip(t *testing.T) {
	base := time.Date(2026, 11, 20, 9, 14, 3, 123456700, time.UTC)
	var recs []evtxw.Record
	for i := 0; i < 400; i++ {
		recs = append(recs, evtxw.Record{
			Provider: "Microsoft-Windows-Security-Auditing", ProviderGUID: "{54849625-5478-4994-A5BA-3E3B0328C30D}",
			EventID: 4624, Version: 2, Task: 12544, Keywords: 0x8020000000000000, Time: base.Add(time.Duration(i) * time.Second),
			ProcessID: 712, ThreadID: 800, Channel: "Security", Computer: "SRV-FILE01.corp.example",
			Data: []evtxw.KV{
				{Name: "TargetUserName", Value: "svc_backup"}, {Name: "TargetDomainName", Value: "CORP"},
				{Name: "TargetLogonId", Value: evtxw.Hex64(0x3e7a1)}, {Name: "LogonType", Value: uint32(10)},
				{Name: "WorkstationName", Value: "WS-ALICE"}, {Name: "IpAddress", Value: "10.1.1.20"}, {Name: "IpPort", Value: "0"},
				{Name: "TransmittedServices", Value: nil},
			},
		})
	}
	recs = append(recs, evtxw.Record{
		Provider: "Microsoft-Windows-TerminalServices-LocalSessionManager", EventID: 21, Time: base.Add(time.Hour),
		Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", Computer: "SRV-FILE01", UserSID: "S-1-5-18",
		UserData: &evtxw.UserData{Element: "EventXML", NS: "Event_NS", Fields: []evtxw.KV{
			{Name: "User", Value: `CORP\svc_backup`}, {Name: "SessionID", Value: "2"}, {Name: "Address", Value: "10.1.1.20"}}},
	})
	var buf bytes.Buffer
	if err := evtxw.Write(&buf, recs); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if crc32.ChecksumIEEE(data[:120]) != binary.LittleEndian.Uint32(data[124:]) {
		t.Error("file header checksum")
	}
	chunks := (len(data) - 4096) / 0x10000
	if chunks < 2 {
		t.Fatalf("%d chunks; the test needs records across chunks", chunks)
	}
	for c := 0; c < chunks; c++ {
		ch := data[4096+c*0x10000:][:0x10000]
		free := binary.LittleEndian.Uint32(ch[48:])
		if crc32.ChecksumIEEE(ch[512:free]) != binary.LittleEndian.Uint32(ch[52:]) {
			t.Errorf("chunk %d records checksum", c)
		}
		h := crc32.NewIEEE()
		h.Write(ch[:120])
		h.Write(ch[128:512])
		if h.Sum32() != binary.LittleEndian.Uint32(ch[124:]) {
			t.Errorf("chunk %d header checksum", c)
		}
	}

	r := run(t, write(t, "Security.evtx", data), nil)
	if r.err != nil || len(r.warns) > 0 {
		t.Fatalf("err %v, warnings %v", r.err, r.warns)
	}
	if len(r.events) != len(recs) {
		t.Fatalf("%d events, want %d", len(r.events), len(recs))
	}
	for i, e := range r.events[:400] {
		if want := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano); utc(e) != want {
			t.Fatalf("record %d time %s, want %s", i+1, utc(e), want)
		}
		if e.Fields["record_id"] != uint64(i+1) {
			t.Fatalf("record %d numbered %v", i+1, e.Fields["record_id"])
		}
	}
	e := r.events[0]
	ed := e.Fields["event"].(map[string]any)["EventData"].(map[string]any)
	if e.Fields["event_id"] != "4624" || e.Host != "SRV-FILE01.corp.example" || e.User != "svc_backup" ||
		str(ed["LogonType"]) != "10" || ed["IpAddress"] != "10.1.1.20" || str(ed["TargetLogonId"]) != fmt.Sprint(0x3e7a1) {
		t.Errorf("4624 read as %+v %v", e, ed)
	}
	if v, present := ed["TransmittedServices"]; !present || v != "" {
		t.Errorf("an empty Data value read as %v (present %v), want an empty string", v, present)
	}
	last := r.events[len(r.events)-1]
	ud := last.Fields["event"].(map[string]any)["UserData"].(map[string]any)["EventXML"].(map[string]any)
	if last.Fields["event_id"] != "21" || ud["Address"] != "10.1.1.20" || ud["User"] != `CORP\svc_backup` {
		t.Errorf("session logon read as %v", ud)
	}
}
