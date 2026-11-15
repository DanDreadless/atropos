package parsers

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

func eventsAt(res result, path string) []Event {
	var out []Event
	for _, e := range res.events {
		if e.Path == path {
			out = append(out, e)
		}
	}
	return out
}

// A disk image holding a FAT16 partition: every entry, deleted ones too, is
// put on the timeline at the host's local zone.
func TestFATPartitionTimeline(t *testing.T) {
	p := write(t, "stick.dd", imagetest.MBR(imagetest.FAT16(), 0x0E))
	london, _ := time.LoadLocation("Europe/London")
	res := run(t, p, func(c *Context) {
		if c.Kind != detect.MBRDisk {
			t.Fatalf("kind %s", c.Kind)
		}
		c.Local = timeutil.LocalContext{Loc: london, ZoneFrom: timeutil.ZoneHost, ZoneName: "Europe/London"}
	})
	if res.err != nil || len(res.warns) > 0 {
		t.Fatalf("%v %v", res.err, res.warns)
	}
	if res.facts["fat.p1.volume_serial"] != "1234ABCD" || res.facts["fat.p1.volume_label"] != "TESTSTICK" {
		t.Errorf("facts: %v", res.facts)
	}
	got := map[string]string{}
	for _, e := range eventsAt(res, "/p1/Report final.docx") {
		got[e.MACB] = utc(e) + " " + e.Stamp.ZoneFrom
		if e.Category != CatFileSystem || e.Source != "fat" || !strings.HasPrefix(e.Ref, "partition p1, directory entry at byte ") {
			t.Errorf("event: %+v", e)
		}
	}
	// British Summer Time had not begun on 1-5 March 2023, so local is UTC.
	want := map[string]string{
		"...B": "2023-03-01T10:20:30.5Z host-registry",
		"M...": "2023-03-02T11:22:44Z host-registry",
		".A..": "2023-03-05T00:00:00Z host-registry",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all %v)", k, got[k], v, got)
		}
	}
	del := eventsAt(res, "/p1/secret plan.txt")
	if len(del) != 3 {
		t.Fatalf("deleted entry: %+v", del)
	}
	for _, e := range del {
		if !strings.HasPrefix(e.Type, "deleted FAT ") || e.Fields["deleted"] != true || e.Fields["short_name_first_character_from_checksum"] != true ||
			!strings.Contains(e.Message, "not when it was deleted") {
			t.Errorf("deleted event: %+v", e)
		}
	}
	for _, e := range res.events {
		if e.MACB == ".A.." && (e.Fields["time_precision"] != "day" || !strings.HasSuffix(e.Type, "(day only)")) {
			t.Errorf("a FAT access date must say it is a day: %+v", e)
		}
	}
	if len(res.events) != 3+2+2+3 { // report 3, DCIM (B=M) 2, img (B=M) 2, deleted 3
		t.Errorf("%d events", len(res.events))
	}
}

// An exFAT volume on its own: a time with its UTC offset is a true time; a
// time without one is local.
func TestExFATVolumeTimeline(t *testing.T) {
	p := write(t, "card.raw", imagetest.ExFAT())
	res := run(t, p, func(c *Context) {
		if c.Kind != detect.FATVolume {
			t.Fatalf("kind %s", c.Kind)
		}
	})
	if res.err != nil || len(res.warns) > 0 {
		t.Fatalf("%v %v", res.err, res.warns)
	}
	for _, e := range eventsAt(res, "/Holiday photo.jpg") {
		// Written at 14:30:21.5 on a clock at UTC+01:00.
		if e.MACB == "...B" && (utc(e) != "2024-07-15T13:30:21.5Z" || e.Stamp.ZoneFrom != timeutil.ZoneExplicit || e.Stamp.ZoneName != "+01:00") {
			t.Errorf("created: %s %+v", utc(e), e.Stamp)
		}
	}
	for _, e := range eventsAt(res, "/Docs/notes.txt") {
		if e.Stamp.ZoneFrom != timeutil.ZoneAssumed {
			t.Errorf("no offset recorded, no host zone: must be assumed: %+v", e.Stamp)
		}
	}
	if d := eventsAt(res, "/gone.txt"); len(d) != 1 || d[0].MACB != "MA.B" || d[0].Fields["deleted"] != true {
		t.Errorf("deleted exFAT entry: %+v", d)
	}
	if res.facts["fat.volume_serial"] != "C0FFEE11" {
		t.Errorf("facts: %v", res.facts)
	}
}

func TestDiskImageWithoutFAT(t *testing.T) {
	p := write(t, "blank.dd", imagetest.MBR(make([]byte, 1<<20), 0x83))
	res := run(t, p, nil)
	if res.err != nil || len(res.events) != 0 || len(res.warns) != 0 {
		t.Fatalf("%v %v %d", res.err, res.warns, len(res.events))
	}
	if !strings.Contains(strings.Join(res.notes, "\n"), "no FAT, exFAT or ext volume") {
		t.Errorf("notes: %v", res.notes)
	}
}

// dfVFS's FAT test images: a FAT12 volume on its own, and a differencing
// VHD and VHDX whose parents hold a FAT partition.
func TestFATSamples(t *testing.T) {
	dir := "../../testdata/fat/"
	if _, err := os.Stat(dir + "fat12.raw"); err != nil {
		t.Skip("testdata/fat not fetched")
	}
	res := run(t, dir+"fat12.raw", nil)
	if res.err != nil || len(res.warns) > 0 || len(eventsAt(res, "/a_directory/another_file")) == 0 {
		t.Errorf("fat12: %v %v %d events", res.err, res.warns, len(res.events))
	}
	for _, c := range [][2]string{{"fat-differential.vhd", "fat-parent.vhd"}, {"fat-differential.vhdx", "fat-parent.vhdx"}} {
		alone := run(t, dir+c[0], nil)
		if len(alone.warns) == 0 || !strings.Contains(alone.warns[0], "parent") {
			t.Errorf("%s without its parent: %v", c[0], alone.warns)
		}
		res := run(t, dir+c[0], func(ctx *Context) { ctx.Segments = []string{dir + "fat12.raw", dir + c[1]} })
		if res.err != nil || len(res.warns) > 0 {
			t.Errorf("%s: %v %v", c[0], res.err, res.warns)
		}
		paths := map[string]bool{}
		for _, e := range res.events {
			paths[e.Path] = true
		}
		t.Logf("%s: %d events, paths %v", c[0], len(res.events), paths)
		if len(paths) == 0 {
			t.Errorf("%s: nothing on the timeline", c[0])
		}
	}
}
