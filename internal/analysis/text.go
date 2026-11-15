package analysis

import (
	"fmt"
	"io"
	"sort"
)

// KindTitles gives each kind of finding a plain heading.
var KindTitles = map[string]string{
	KindModifiedBeforeShimCache:  "Modified earlier than ShimCache recorded",
	KindLinkedAfterFileTimes:     "Built after its own creation and modification times",
	KindCreatedBeforeOlderRecord: "Created earlier than an older copy of its own times",
	KindCreatedBeforeJournal:     "Created earlier than the change journal recorded",
}

// WriteText prints a report for the terminal.
func WriteText(w io.Writer, r *Report) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("Timestamp consistency: %d finding(s) listed\n\nCompared:\n", len(r.Findings))
	keys := make([]string, 0, len(r.Compared))
	for k := range r.Compared {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p("  %-45s %d\n", k, r.Compared[k])
	}
	if len(keys) == 0 {
		p("  nothing\n")
	}
	last := ""
	for _, f := range r.Findings {
		if f.Kind != last {
			last = f.Kind
			p("\n%s (%d)\n", KindTitles[f.Kind], r.Counts[f.Kind])
			p("  Caution: %s\n", f.Caveat)
		}
		flag := ""
		if f.AlsoFlagged {
			flag = "  [also flagged within the file table]"
		}
		p("\n  %s%s\n    file table: %s   other: %s   gap: %s\n    events: %v\n", f.Path, flag, f.FileTime, f.OtherTime, gap(f.GapSeconds), f.EventIDs)
	}
	p("\nNotes:\n")
	for _, n := range r.Notes {
		p("  - %s\n", n)
	}
	return nil
}

func gap(s int64) string {
	switch {
	case s >= 2*86400:
		return fmt.Sprintf("%d days", s/86400)
	case s >= 2*3600:
		return fmt.Sprintf("%d hours", s/3600)
	case s >= 120:
		return fmt.Sprintf("%d minutes", s/60)
	}
	return fmt.Sprintf("%d seconds", s)
}
