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
