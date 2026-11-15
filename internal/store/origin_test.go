package store

import (
	"fmt"
	"strings"
	"testing"
)

// Events can be found by where their evidence came from: an item and all
// that was copied out of it, a submission, or part of a name or path.
func TestSearchByOrigin(t *testing.T) {
	s := open(t)
	add := func(name, origin string, parent *int64, batch int64, depth int, events int) int64 {
		e := &Evidence{SHA256: fmt.Sprintf("%064d", len(name)*1000+int(batch)*10+depth) + "", SHA1: "s", MD5: "m", Size: 1, Name: name, Origin: origin,
			ParentID: parent, BatchID: batch, Depth: depth, Kind: "text", DetectReason: "test"}
		e.SHA256 = strings.Repeat("0", 64-len(name)) + strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'f' || r >= '0' && r <= '9' {
				return r
			}
			return 'a'
		}, strings.ToLower(name))
		if err := s.AddEvidence(e); err != nil {
			t.Fatal(err)
		}
		if events > 0 {
			run, err := s.BeginRun(e.ID, "text-log", "1", "assumed: UTC")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < events; i++ {
				if err := run.Add(Event{TSUTC: int64(1700000000+i) * 1e9, TSType: "logged", TZSource: "native-utc", TZName: "UTC", MACB: "....",
					Category: "log", Source: "log", Message: "from " + name, RecordRef: "line"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := run.Finish("parsed", ""); err != nil {
				t.Fatal(err)
			}
		}
		return e.ID
	}
	image := add("disk.E01", `C:\in\disk.E01`, nil, 1, 0, 1)
	hive := add("NTUSER.DAT", `C:\in\disk.E01!/Users/dan/NTUSER.DAT`, &image, 1, 1, 3)
	zip := add("logs.zip", `C:\in\disk.E01!/Users/dan/logs.zip`, &image, 1, 1, 0)
	add("app_100%.log", `C:\in\disk.E01!/Users/dan/logs.zip!app_100%.log`, &zip, 1, 2, 2)
	add("other.log", `C:\elsewhere\other.log`, nil, 2, 0, 4)

	for _, c := range []struct {
		q    string
		want int
	}{
		{"", 10},
		{fmt.Sprintf("from:%d", image), 6},      // the image, the hive, and the log inside the archive inside it
		{fmt.Sprintf("from:%d", zip), 2},        // the archive's members only
		{fmt.Sprintf("from:%d", hive), 3},       // an item with nothing inside it is just itself
		{fmt.Sprintf("-from:%d", image), 4},     // everything else
		{fmt.Sprintf("evidence:%d", image), 1},  // the item alone
		{fmt.Sprintf("-evidence:%d", image), 9}, //
		{"from:999", 0},                         //
		{"submission:1", 6},                     //
		{"submission:2", 4},                     //
		{"-submission:2", 6},                    //
		{"file:ntuser", 3},                      // part of a name, any case
		{"file:disk.E01", 6},                    // a path inside the image names the image
		{"file:logs.zip", 2},                    //
		{`file:"users/dan"`, 5},                 // part of a path inside an image
		{"file:100%", 2},                        // a percent sign is a character, not a wildcard
		{"file:app_1", 2},                       // and so is an underscore
		{"file:appx1", 0},                       //
		{"-file:elsewhere", 6},                  //
		{"file:other from other", 4},            // combined with words
	} {
		rows, err := s.Search(Query{Text: c.q, Limit: 100})
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		if len(rows) != c.want {
			t.Errorf("%q: %d events, want %d", c.q, len(rows), c.want)
		}
	}
}
