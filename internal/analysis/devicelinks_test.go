package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

// A USB stick on three hosts links each to the next in time; times that
// overlap say it went back and forth; a serial Windows made up, and a host
// outside the case, are never matched; a key's last write does not date
// the device.
func TestDeviceLinks(t *testing.T) {
	c := &connCtx{hosts: map[string]*store.HostIdentity{}, byName: map[string]string{}}
	for _, n := range []string{"A", "B", "C"} {
		c.hosts[n] = &store.HostIdentity{Name: n}
		c.byName[n] = n
	}
	c.hosts["B"].Clock = 2 * time.Minute // B's clock is two minutes fast
	at := func(hm string) int64 {
		tm, _ := time.Parse("15:04", hm)
		return time.Date(2026, 11, 20, tm.Hour(), tm.Minute(), 0, 0, time.UTC).UnixNano()
	}
	n := int64(0)
	dev := func(host, hm, serial, what string) store.ObservedEvent {
		n++
		return store.ObservedEvent{EventID: n, TSUTC: at(hm), Host: host, Act: "device", What: what,
			Items: []store.Observable{{Kind: "device", Value: "Stick", Role: "object"}, {Kind: "serial", Value: serial, Role: "object"}}}
	}
	got := c.deviceLinks([]store.ObservedEvent{
		dev("A", "08:00", "AA1234567890", "USB storage device first connected"),
		dev("A", "09:00", "AA1234567890", "USB storage device last removed"),
		dev("A", "23:00", "AA1234567890", "USB storage device's key last written"), // not a time of the device
		dev("B", "08:32", "aa1234567890", "USB storage device first connected"),    // 08:30 by true time: overlaps A
		dev("C", "10:00", "AA1234567890", "USB storage device first connected"),
		dev("A", "08:00", "7&abc&0", "USB storage device first connected"), // made up by Windows
		dev("B", "09:00", "7&abc&0", "USB storage device first connected"),
		dev("OTHER", "07:00", "AA1234567890", "USB storage device first connected"), // not a host of the case
	})
	if len(got) != 2 {
		t.Fatalf("%d links: %+v", len(got), got)
	}
	ab, bc := got[0], got[1]
	if ab.From != "host:A" || ab.To != "host:B" || time.Unix(0, ab.Start).UTC().Format("15:04") != "08:30" || ab.Kind != "usb" || ab.Confidence != "strong" ||
		len(ab.Source.Events) != 3 || ab.Target.Start != at("08:32") {
		t.Errorf("A to B: %+v", ab)
	}
	r := strings.Join(ab.Reasons, " | ")
	if !strings.Contains(r, "on A from 2026-11-20 08:00:00 to 2026-11-20 09:00:00; on B at 2026-11-20 08:30:00") || !strings.Contains(r, "went between them more than once") {
		t.Errorf("A to B reasons: %s", r)
	}
	if bc.From != "host:B" || bc.To != "host:C" || !strings.Contains(strings.Join(bc.Reasons, " | "), "first connected to C after it was last connected to B") {
		t.Errorf("B to C: %+v", bc)
	}
}

// The same file on three hosts, seen by Sysmon (SHA-1 and SHA-256), by
// Amcache (SHA-1 alone) and by a browser download (SHA-256 alone): one file,
// linked A to B to C, renamed on B. A Windows file on two hosts, and a file
// on one, are not links.
func TestFileLinks(t *testing.T) {
	c := &connCtx{hosts: map[string]*store.HostIdentity{}, byName: map[string]string{}}
	for _, n := range []string{"A", "B", "C"} {
		c.hosts[n] = &store.HostIdentity{Name: n}
		c.byName[n] = n
	}
	at := func(hm string) int64 {
		tm, _ := time.Parse("15:04", hm)
		return time.Date(2026, 11, 20, tm.Hour(), tm.Minute(), 0, 0, time.UTC).UnixNano()
	}
	sha1, sha256 := "sha1:"+strings.Repeat("1a", 20), "sha256:"+strings.Repeat("2b", 32)
	n := int64(0)
	file := func(host, hm, what, path string, hashes ...string) store.ObservedEvent {
		n++
		e := store.ObservedEvent{EventID: n, TSUTC: at(hm), Host: host, Act: "file", What: what}
		for _, h := range hashes {
			e.Items = append(e.Items, store.Observable{Kind: "hash", Value: h, Role: "object"})
		}
		e.Items = append(e.Items, store.Observable{Kind: "file", Value: path, Role: "object"})
		return e
	}
	notepad := "sha1:" + strings.Repeat("3c", 20)
	got := c.fileLinks([]store.ObservedEvent{
		file("A", "08:00", "Program started (Sysmon 1): x", `C:\Users\a\Downloads\pd.exe`, sha1, sha256),
		file("B", "09:00", "File recorded in Amcache with its SHA-1 (of the first 31.4 MB): x", `c:\windows\temp\svcupd.exe`, sha1),
		file("C", "10:00", "File downloaded by the browser, with its SHA-256: x", `C:\Users\c\Downloads\pd.exe`, sha256),
		file("A", "07:00", "File recorded in Amcache with its SHA-1 (of the first 31.4 MB): x", `c:\windows\system32\notepad.exe`, notepad),
		file("B", "07:00", "File recorded in Amcache with its SHA-1 (of the first 31.4 MB): x", `c:\windows\system32\notepad.exe`, notepad),
		file("C", "07:00", "Program started (Sysmon 1): x", `C:\Tools\only-here.exe`, "sha1:"+strings.Repeat("4d", 20)),
	}, nil)
	// A file Defender detected in System32 on two hosts is shown.
	det := "sha256:" + strings.Repeat("5e", 32)
	if d := c.fileLinks([]store.ObservedEvent{
		file("A", "11:00", "File detected by Defender, with its hashes: x", `C:\Windows\System32\evil.dll`, det),
		file("B", "11:30", "File detected by Defender, with its hashes: x", `C:\Windows\System32\evil.dll`, det),
	}, nil); len(d) != 1 || d[0].From != "host:A" || d[0].To != "host:B" {
		t.Errorf("Defender detections in System32: %+v", d)
	}
	if len(got) != 2 {
		t.Fatalf("%d links: %+v", len(got), got)
	}
	ab, bc := got[0], got[1]
	r := strings.Join(ab.Reasons, " | ")
	if ab.Kind != "file" || ab.From != "host:A" || ab.To != "host:B" || time.Unix(0, ab.Start).UTC().Format("15:04") != "09:00" ||
		!strings.Contains(r, "the same file, by its SHA-1 "+strings.Repeat("1a", 20)+" and SHA-256 "+strings.Repeat("2b", 32)+", is on both computers") ||
		!strings.Contains(r, `on A as C:\Users\a\Downloads\pd.exe, first recorded 2026-11-20 08:00:00; on B as c:\windows\temp\svcupd.exe, first recorded 2026-11-20 09:00:00`) ||
		!strings.Contains(r, "it was renamed") || !strings.Contains(r, "Amcache's SHA-1 covers only") {
		t.Errorf("A to B: %s -> %s: %s", ab.From, ab.To, r)
	}
	if r := strings.Join(bc.Reasons, " | "); bc.From != "host:B" || bc.To != "host:C" || !strings.Contains(r, "renamed") {
		t.Errorf("B to C: %s -> %s: %s", bc.From, bc.To, r)
	}
	// The case's own evidence items: one collected from B with a record of
	// it on A, and one collected from both B and C with none.
	tool := strings.Repeat("6f", 32)
	coll := c.fileLinks([]store.ObservedEvent{
		file("A", "12:00", "Program started (Sysmon 1): x", `C:\Users\a\Downloads\tool.exe`, "sha256:"+tool),
	}, []collectedFile{
		{ID: 7, Host: "B", Origin: `triage.zip/Users/b/AppData/Local/Temp/t.exe`, SHA256: tool},
		{ID: 8, Host: "B", Origin: `notes.docx`, SHA1: strings.Repeat("7a", 20)},
		{ID: 9, Host: "C", Origin: `C/Users/c/Desktop/notes.docx`, SHA1: strings.Repeat("7a", 20)},
		{ID: 10, Host: "C", Origin: `image.E01/Windows/System32/kernel32.dll`, SHA1: strings.Repeat("8b", 20)},
		{ID: 11, Host: "B", Origin: `image.E01/Windows/System32/kernel32.dll`, SHA1: strings.Repeat("8b", 20)},
	})
	if len(coll) != 2 {
		t.Fatalf("collected: %d links: %+v", len(coll), coll)
	}
	ab, bc = coll[0], coll[1]
	r = strings.Join(ab.Reasons, " | ")
	if ab.From != "host:A" || ab.To != "host:B" || !ab.Undated || ab.NoTime != "the file was collected from B, and that gives no time" ||
		time.Unix(0, ab.Start).UTC().Format("15:04") != "12:00" || !strings.Contains(r, "on B collected as item 7 (triage.zip/Users/b/AppData/Local/Temp/t.exe)") ||
		!strings.Contains(r, "renamed") || !strings.Contains(r, "which way it went is not known") {
		t.Errorf("A to B, collected: %+v %s", ab, r)
	}
	if bc.From != "host:B" || bc.To != "host:C" || bc.Start != 0 || bc.NoTime != "the file was collected from both, and that gives no time" ||
		strings.Contains(strings.Join(bc.Reasons, " | "), "renamed") {
		t.Errorf("B to C, collected: %+v", bc)
	}
	if !collectedCommon(`image.E01/Windows/System32/x.dll`) || collectedCommon(`image.E01/Windows/Temp/x.dll`) || collectedCommon(`x.exe`) {
		t.Error("collectedCommon")
	}
	assigned := func(h string) *store.Assignment { return &store.Assignment{HostName: h} }
	got2 := collectedFiles([]store.Evidence{
		{ID: 1, Kind: "pe-executable", Size: 10, Name: "a.exe", SHA256: strings.ToUpper(tool), Assigned: assigned("A")},
		{ID: 2, Kind: "windows-registry-hive", Size: 10, Name: "SYSTEM", SHA256: tool, Assigned: assigned("A")},
		{ID: 3, Kind: "pe-executable", Size: 10, Name: "b.exe", SHA256: tool},
		{ID: 4, Kind: "pe-executable", Size: 10, Name: "c.exe", SHA256: tool, Assigned: assigned("A"), Excluded: true},
		{ID: 5, Kind: "text", Size: 10, Name: `x\Desktop.ini`, SHA256: tool, Assigned: assigned("A")},
	})
	if len(got2) != 1 || got2[0].ID != 1 || got2[0].SHA256 != tool || got2[0].Origin != "a.exe" {
		t.Errorf("collectedFiles: %+v", got2)
	}
	for p, want := range map[string]bool{`C:\Windows\System32\x.exe`: true, `c:\windows\temp\x.exe`: false, `\SystemRoot\System32\drivers\x.sys`: true,
		`C:\Program Files (x86)\App\a.exe`: true, `C:\ProgramData\Microsoft\Windows Defender\x.exe`: true, `C:\ProgramData\x.exe`: false, `C:\Users\a\x.exe`: false} {
		if commonPlace(p) != want {
			t.Errorf("commonPlace(%s) = %v", p, !want)
		}
	}
}
