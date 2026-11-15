package parsers

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/detect"
)

// dhVal builds one value of a Defender detection record.
func dhVal(typ uint32, data []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(data)))
	b = binary.LittleEndian.AppendUint32(b, typ)
	b = append(b, data...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

func dhNum(n uint32) []byte { return dhVal(dhNumber6, binary.LittleEndian.AppendUint32(nil, n)) }
func dhStr(s string) []byte { return dhVal(dhString, append(wide(s), 0, 0)) }
func dhTime(s string) []byte {
	return dhVal(dhFiletime, binary.LittleEndian.AppendUint64(nil, filetime(s)))
}

func TestDefenderDetectionRecord(t *testing.T) {
	le := binary.LittleEndian
	// The named values of the resource: a string, a time and a number.
	var kv []byte
	add := func(key string, typ uint32, val []byte) {
		k := append(wide(key), 0, 0)
		kv = le.AppendUint32(kv, uint32(len(k)))
		kv = append(kv, k...)
		kv = le.AppendUint32(kv, typ)
		kv = append(kv, val...)
	}
	sha := append(wide(strings.Repeat("ab", 32)), 0, 0)
	add("ThreatTrackingSha256", 6, append(le.AppendUint32(nil, uint32(len(sha))), sha...))
	add("ThreatTrackingStartTime", 4, le.AppendUint64(nil, filetime("2024-03-01T10:00:00Z")))
	add("ThreatTrackingSize", 4, le.AppendUint64(nil, 91648))
	blob := le.AppendUint32(nil, 1)
	blob = le.AppendUint32(blob, 20)
	blob = le.AppendUint32(blob, uint32(len(kv)))
	blob = le.AppendUint32(blob, uint32(24+len(kv)))
	blob = le.AppendUint32(blob, 0)
	blob = le.AppendUint32(blob, uint32(len(kv)))
	blob = append(blob, kv...)

	var b []byte
	put := func(v ...[]byte) {
		for _, x := range v {
			b = append(b, x...)
		}
	}
	put(dhVal(dhNumber8, le.AppendUint64(nil, 242420)), dhVal(dhGUID, []byte{0x3D, 0xBE, 0xC4, 0x8C, 0x3F, 0x8D, 0x52, 0x49, 0x99, 0x53, 0xF2, 0x4E, 0xB6, 0x63, 0x8A, 0x37}))
	// Severity 5, category 8, status 3, one resource.
	put(dhStr("Magic.Version:1.2"), dhStr("Trojan:Win32/Test.A"), dhNum(0), dhNum(5), dhNum(8), dhNum(112), dhNum(4), dhNum(3), dhNum(2), dhNum(1))
	put(dhStr("Magic.Version:1.2"), dhStr("file"), dhStr(`C:\Users\a\Downloads\tool.exe`), dhNum(0x10000001), dhNum(uint32(len(blob))), dhVal(dhBinary, blob))
	put(dhTime("2024-03-01T10:00:30Z"), dhNum(0), dhNum(8), dhVal(dhGUID, make([]byte, 16)), dhNum(1), dhNum(2), dhStr(`WS1\alice`), dhNum(3), dhStr(`C:\Windows\explorer.exe`),
		dhNum(3), dhNum(0), dhNum(0), dhTime("2024-03-01T10:00:01Z"), dhNum(0), dhTime("2024-03-01T10:00:30Z"), dhNum(0), dhNum(0), dhNum(0), dhStr(`NT AUTHORITY\SYSTEM`), dhNum(0))

	if k := kindOf(b); k != detect.DefenderDH {
		t.Fatalf("identified as %s", k)
	}
	// The name says nothing: detection is by content.
	r := run(t, write(t, "anything.bin", b), nil)
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 2 {
		t.Fatalf("err %v, warnings %v, %d events", r.err, r.warns, len(r.events))
	}
	e := r.events[0]
	f := e.Fields
	if e.Type != "defender-detection" || utc(e) != "2024-03-01T10:00:01Z" || e.Category != CatSecurity || e.User != `WS1\alice` ||
		e.Path != `C:\Users\a\Downloads\tool.exe` || e.MACB != "" || e.Ref != "detection 8CC4BE3D-8D3F-4952-9953-F24EB6638A37" {
		t.Errorf("detection event: %+v", e)
	}
	if f["threat_name"] != "Trojan:Win32/Test.A" || f["severity"] != "severe" || f["category"] != "trojan" || f["threat_status"] != "quarantined" ||
		f["detection_source"] != "real-time" || f["execution_status"] != "blocked" || f["process"] != `C:\Windows\explorer.exe` ||
		f["remediation_account"] != `NT AUTHORITY\SYSTEM` || f["sha256"] != strings.Repeat("ab", 32) || f["size"] != uint64(91648) {
		t.Errorf("fields: %v", f)
	}
	res := f["resources"].([]map[string]any)
	if len(res) != 1 || res[0]["type"] != "file" || res[0]["ThreatTrackingStartTime"] != "2024-03-01T10:00:00Z" {
		t.Errorf("resources: %v", res)
	}
	// The status changed at the moment of remediation: one event, not two.
	if e := r.events[1]; e.Type != "defender-remediation" || utc(e) != "2024-03-01T10:00:30Z" {
		t.Errorf("second event: %s %s", e.Type, utc(e))
	}

	// A record cut short inside a value is read as far as it goes, and says so.
	r = run(t, write(t, "cut", b[:len(b)-100]), nil)
	if len(r.warns) == 0 {
		t.Errorf("a truncated record gave no warning")
	}
	// Sizes that point past the end must not crash it.
	bad := append([]byte{}, b...)
	le.PutUint32(bad[0x240:], 0xFFFFFFF0)
	run(t, write(t, "bad", bad), nil)
}

func TestDefenderMPLog(t *testing.T) {
	log := "\r\n" + strings.Join([]string{
		`2024-07-01T09:00:00.100 [RTP] Setting something`,
		`2024-07-01T09:00:01.000 Engine:Setting original file name "a.dll" for "c:\x\a.dll", hr=0x0`,
		`2024-07-01T09:00:02.000 DETECTIONEVENT MPSOURCE_REALTIME Trojan:Win32/Test.A file:C:\Users\a\Downloads\tool.exe;`,
		`2024-07-01T09:00:03.000 DETECTION_CLEANEVENT MPSOURCE_REALTIME MP_THREAT_ACTION_QUARANTINE 0x00000000 Trojan:Win32/Test.A file:C:\Users\a\Downloads\tool.exe;`,
		`2024-07-01T09:00:04.000 Engine:command line reported as lowfi: C:\Windows\System32\cmd.exe(cmd.exe /c whoami)`,
		`2024-07-01T09:00:05.000 [RTP] [Exclusion] F:\ is discarded due to error 0x80070003`,
		`2024-07-01T09:00:06.000 ProcessImageName: tool.exe, Pid: 4321, TotalTime: 250, Count: 12, MaxTime: 90, MaxTimeFile: \Device\HarddiskVolume3\x\y.dll, EstimatedImpact: 7%`,
		`BEGIN BM telemetry`,
		`GUID:{11111111-2222-3333-4444-555555555555}`,
		`ProcessID:4321`,
		`ProcessCreationTime:133642980000000000`,
		`ImagePath:C:\Users\a\Downloads\tool.exe`,
		`END BM telemetry`,
		`2024-07-01T09:00:07.000 [Cloud] End of cloud report`,
		`a continuation line`,
	}, "\r\n") + "\r\n"
	r := run(t, write(t, "defender.txt", append([]byte{0xFF, 0xFE}, wide(log)...)), nil)
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 9 {
		t.Fatalf("err %v, warnings %v, %d events, notes %v", r.err, r.warns, len(r.events), r.notes)
	}
	by := map[string]Event{}
	for _, e := range r.events {
		if e.Source != "defender" || e.Stamp.ZoneFrom != "native-utc" {
			t.Errorf("%s: source %s, zone %s", e.Type, e.Source, e.Stamp.ZoneFrom)
		}
		by[e.Type] = e
	}
	if e := by["defender-detection (mplog)"]; utc(e) != "2024-07-01T09:00:02Z" || e.Category != CatSecurity || e.Path != `C:\Users\a\Downloads\tool.exe` ||
		e.Fields["threat_name"] != "Trojan:Win32/Test.A" || e.Fields["detection_source"] != "realtime" {
		t.Errorf("detection: %+v", e)
	}
	if e := by["defender-action (mplog)"]; e.Fields["action"] != "quarantine" {
		t.Errorf("action: %+v", e)
	}
	if e := by["defender-command-line-reported"]; e.Fields["reported_as"] != "lowfi" || !strings.Contains(e.Fields["command_line"].(string), "whoami") {
		t.Errorf("command line: %+v", e)
	}
	if e := by["process-scan-impact (defender)"]; e.Category != CatExecution || e.Fields["pid"] != int64(4321) || e.Fields["estimated_impact_percent"] != int64(7) {
		t.Errorf("impact: %+v", e)
	}
	// The telemetry block is placed at the process's creation time, a FILETIME.
	if e := by["process-created (defender telemetry)"]; utc(e) != "2024-07-01T09:00:00Z" || e.Path != `C:\Users\a\Downloads\tool.exe` || e.Fields["pid"] != int64(4321) {
		t.Errorf("telemetry: %s %+v", utc(e), e)
	}
	if e := r.events[len(r.events)-1]; !strings.Contains(e.Message, "a continuation line") {
		t.Errorf("continuation line lost: %q", e.Message)
	}
	// An ordinary log timed the same way is not taken for Defender's.
	plain := "2024-07-01T09:00:00.100 service started\n2024-07-01T09:00:01.100 service ready\n"
	if r := run(t, write(t, "app.log", []byte(plain)), nil); len(r.events) != 2 || r.events[0].Source != "log" {
		t.Errorf("plain log: %d events, source %s", len(r.events), r.events[0].Source)
	}
}
