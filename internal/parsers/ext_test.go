package parsers

import (
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

func TestExtVolumeTimeline(t *testing.T) {
	p := write(t, "linux.img", imagetest.Ext4())
	res := run(t, p, func(c *Context) {
		if c.Kind != detect.ExtVolume {
			t.Fatalf("kind %s", c.Kind)
		}
	})
	if res.err != nil || len(res.warns) > 0 {
		t.Fatalf("%v %v", res.err, res.warns)
	}
	if res.facts["ext.volume_uuid"] != "deadbeef-0102-0304-0506-0708090a0b0c" || res.facts["ext.volume_label"] != "builder" {
		t.Errorf("facts: %v", res.facts)
	}
	got := map[string]string{}
	for _, e := range eventsAt(res, "/docs/report.txt") {
		got[e.MACB] = utc(e)
		if e.Stamp.ZoneFrom != timeutil.ZoneNative || e.Source != "ext" || e.Category != CatFileSystem || e.Fields["inode"] != uint32(13) || e.Fields["mode"] != "100640" {
			t.Errorf("event: %+v", e)
		}
	}
	want := map[string]string{"M.C.": "2024-04-03T11:11:11.000000001Z", ".A..": "2024-04-04T11:11:11Z", "...B": "2024-04-02T10:00:00.5Z"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q (%v)", k, got[k], v, got)
		}
	}
	if tr := eventsAt(res, "/tree.dat"); len(tr) != 2 || utc(tr[1]) != "2040-01-01T00:00:00.25Z" {
		t.Errorf("a time past 2038: %+v", tr)
	}
	old := eventsAt(res, "/docs/old.txt")
	var freed, times int
	for _, e := range old {
		if e.Fields["deleted"] != true {
			t.Errorf("deleted name: %+v", e)
		}
		if e.Category == CatDeletion {
			freed++
			if utc(e) != "2024-05-01T12:00:00Z" || e.MACB != "" || !strings.Contains(e.Message, "Deleted:") {
				t.Errorf("deletion event: %+v", e)
			}
		} else {
			times++
		}
	}
	if freed != 1 || times != 3 {
		t.Errorf("old.txt: %d deletion events, %d time events: %+v", freed, times, old)
	}
	if r := eventsAt(res, "/docs/reused.txt"); len(r) != 0 {
		t.Errorf("a name whose inode belongs to another file has no times of its own: %+v", r)
	}
	if !strings.Contains(strings.Join(res.notes, "\n"), "7 names, 2 of them deleted names recovered from directory slack (1 with a deletion time); 1 deleted names whose inode now belongs to another file") {
		t.Errorf("notes: %v", res.notes)
	}
}

// dfVFS's ext4 image, in a partition: names and times on the timeline.
func TestExtInADisk(t *testing.T) {
	p := write(t, "disk.dd", imagetest.MBR(imagetest.Ext4(), 0x83))
	res := run(t, p, nil)
	if res.err != nil || len(res.warns) > 0 || len(eventsAt(res, "/p1/docs/report.txt")) != 3 || res.facts["ext.p1.volume_uuid"] == "" {
		t.Errorf("%v %v %d events %v", res.err, res.warns, len(res.events), res.facts)
	}
}
