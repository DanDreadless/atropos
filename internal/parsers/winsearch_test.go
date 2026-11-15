package parsers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// sidrReport reads one of SIDR's JSON reports: one object per line.
func sidrReport(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(line))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, m)
	}
	return out
}

// SIDR's reports on the public Windows.db are the answer: every property
// each report gives, for every item, must be what Atropos reads.
func TestWindowsSearchAgainstSIDR(t *testing.T) {
	compareSIDR(t, "Windows.db", "DESKTOP-O47KVAD", 800, 20000)
}

// The ESE form, Windows.edb, against SIDR's reports on it.
func TestWindowsSearchESEAgainstSIDR(t *testing.T) {
	compareSIDR(t, "Windows.edb", "DESKTOP-80RDGLC", 1000, 5000)
}

func compareSIDR(t *testing.T, db, host string, minItems, minValues int) {
	dir := "../../testdata/winsearch/"
	if _, err := os.Stat(dir + db); err != nil {
		t.Skip("testdata/winsearch not fetched")
	}
	r := run(t, dir+db, nil)
	if r.err != nil || len(r.warns) > 0 {
		t.Fatalf("%v %v", r.err, r.warns)
	}
	props := map[string]map[string]any{}
	kinds := map[string]string{}
	for _, e := range r.events {
		w := fmt.Sprint(e.Fields["work_id"])
		p := map[string]any{}
		for k, v := range e.Fields["properties"].(map[string]any) {
			p[strings.ReplaceAll(k, ".", "_")] = v
		}
		// SIDR takes these two from the activity's address; so does Atropos.
		if v, ok := e.Fields["volume_id"]; ok {
			p["VolumeId"] = v
		}
		if v, ok := e.Fields["object_id"]; ok {
			p["ObjectId"] = v
		}
		props[w], kinds[w] = p, e.Fields["index_kind"].(string)
	}
	if r.facts["windows_search.computer_name"] != host {
		t.Errorf("facts %v", r.facts)
	}
	compared, items, timeless, kindDiff, summaryGap := 0, 0, 0, 0, 0
	bad := map[string]int{}
	for report, kind := range map[string]string{"File": "file", "Activity_History": "activity", "Internet_History": "internet"} {
		for _, row := range sidrReport(t, dir+host+"_"+report+"_Report.json") {
			w := fmt.Sprint(row["WorkId"])
			p, seen := props[w]
			if !seen {
				timeless++ // an item with no time of its own gives no event
				continue
			}
			items++
			// SIDR's two readers sort web addresses differently (by link
			// target in one, by history address in the other); Atropos uses
			// both. Only the values must agree.
			if kinds[w] != kind {
				if kind == "activity" || kinds[w] == "activity" {
					t.Errorf("WorkId %s: %s here, in SIDR's %s report", w, kinds[w], report)
				}
				kindDiff++
			}
			for k, want := range row {
				if k == "WorkId" || fmt.Sprint(want) == "" {
					continue // SIDR writes an empty value where there is none
				}
				// SIDR writes the local-clock times as if UTC; Atropos says they are local.
				if k == "System_ActivityHistory_LocalStartTime" || k == "System_ActivityHistory_LocalEndTime" {
					if got, _ := p[k].(string); got != strings.TrimSuffix(fmt.Sprint(want), "Z")+" (the device's local clock)" {
						bad[k]++
					}
					compared++
					continue
				}
				// The library does not return every long text value: the
				// indexed summary is compared where it has one.
				if k == "System_Search_AutoSummary" {
					if _, ok := p[k]; !ok {
						summaryGap++
						continue
					}
					want = trunc(clean(fmt.Sprint(want)), 2000)
				}
				compared++
				if got := fmt.Sprint(p[k]); got != fmt.Sprint(want) {
					if bad[k] == 0 {
						t.Logf("first difference in %s (WorkId %s): %q here, %q in SIDR", k, w, got, fmt.Sprint(want))
					}
					bad[k]++
				}
			}
		}
	}
	if len(bad) > 0 {
		var ks []string
		for k, n := range bad {
			ks = append(ks, fmt.Sprintf("%s:%d", k, n))
		}
		sort.Strings(ks)
		t.Errorf("differences: %v", ks)
	}
	if items < minItems || compared < minValues {
		t.Errorf("only %d items and %d values compared", items, compared)
	}
	t.Logf("%d items (%d with no time), %d values compared with SIDR; %d events; %d web items sorted differently; %d summaries the library did not return", items, timeless, compared, len(r.events), kindDiff, summaryGap)
}
