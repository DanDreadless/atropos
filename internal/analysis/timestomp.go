// Package analysis compares artefacts with each other. Parsers each read one
// file; the checks here ask whether what several files say about the same
// thing can all be true.
//
// Nothing here writes events. A finding points at the events it compared, so
// the examiner can open them, check them and put them in a group.
package analysis

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

// Kinds of finding, strongest first.
const (
	// The file table says the file was last modified earlier than the
	// modification time Windows itself recorded for it in ShimCache. A file's
	// modification time does not move backwards on its own.
	KindModifiedBeforeShimCache = "modified-earlier-than-shimcache"
	// The program was built after the file table says it was created and
	// last modified. A file cannot hold code that did not exist yet.
	KindLinkedAfterFileTimes = "built-after-file-times"
	// The change journal recorded the file being created later than the
	// creation time the file table now shows for it.
	KindCreatedBeforeJournal = "created-earlier-than-journal"
	// A copy of the file's times kept elsewhere on the volume (unused space
	// in a directory index, or the transaction log) shows a later creation
	// time than the file table shows now.
	KindCreatedBeforeOlderRecord = "created-earlier-than-older-record"
)

// Finding is one disagreement between artefacts about a file's times.
type Finding struct {
	Kind        string         `json:"kind"`
	Path        string         `json:"path"`
	Host        string         `json:"host,omitempty"`
	Summary     string         `json:"summary"`
	Caveat      string         `json:"caveat"`
	FileTime    string         `json:"file_time"`  // what the file table says, UTC
	OtherTime   string         `json:"other_time"` // what the other artefact says, UTC
	GapSeconds  int64          `json:"gap_seconds"`
	AlsoFlagged bool           `json:"also_flagged_in_file_table"` // $SI earlier than $FN, or zeroed sub-seconds
	EventIDs    []int64        `json:"event_ids"`                  // the events compared, file table first
	EvidenceIDs []int64        `json:"evidence_ids"`
	Details     map[string]any `json:"details,omitempty"`
}

// Report is the result of the timestamp checks.
type Report struct {
	Findings []Finding `json:"findings"`
	// What was available to compare. A check with nothing to compare finds
	// nothing, which is not the same as finding nothing wrong.
	Compared  map[string]int64 `json:"compared"`
	Counts    map[string]int   `json:"counts"`
	Truncated map[string]bool  `json:"truncated,omitempty"`
	Notes     []string         `json:"notes"`
}

// MaxPerKind bounds the findings of one kind. A volume full of installed
// software can have tens of thousands of files whose creation time predates
// their arrival, and a list that long helps nobody.
const MaxPerKind = 2000

// Tolerances. ShimCache holds the exact modification time, so one second is
// generous. Link times are compared with an hour's grace. The journal and
// the file table are written by the same operation, two seconds apart at most.
const (
	shimTolerance    = int64(time.Second)
	linkTolerance    = int64(time.Hour)
	journalTolerance = 2 * int64(time.Second)
)

// normPath reduces the ways artefacts write a path to one form: lower case,
// forward slashes, no drive letter or volume prefix, no leading slash.
func normPath(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	p = strings.TrimPrefix(p, "//?/")
	p = strings.TrimPrefix(p, "/??/")
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	} else if strings.HasPrefix(p, "sysvol/") {
		p = p[len("sysvol"):]
	}
	return strings.TrimLeft(p, "/")
}

type mftFile struct {
	path               string
	host               string
	evidence           int64
	siM, siB           int64 // 0 if not seen
	siMEvent, siBEvent int64
	fnBLater           bool // a $FN creation time later than $SI's was emitted
	flagged            bool
}

type other struct {
	ts       int64
	event    int64
	evidence int64
	host     string
	path     string
	recorded int64 // when the artefact itself was written, where that is known
}

func utc(ns int64) string { return time.Unix(0, ns).UTC().Format("2006-01-02 15:04:05.000000") }

func hostsDiffer(a, b string) bool { return a != "" && b != "" && !strings.EqualFold(a, b) }

// mftRef reads "MFT entry 123-4".
func mftRef(ref string) (string, bool) {
	const p = "MFT entry "
	if !strings.HasPrefix(ref, p) {
		return "", false
	}
	return ref[len(p):], true
}

// Timestomp runs the checks over the events currently on the timeline.
func Timestomp(s *store.Store) (*Report, error) {
	rep := &Report{Compared: map[string]int64{}, Counts: map[string]int{}, Truncated: map[string]bool{}}

	// What other artefacts say, keyed the way the file table can be matched.
	shim := map[string][]other{}    // by path
	link := map[string][]other{}    // by path
	journal := map[string][]other{} // by "entry-sequence"
	older := map[string][]other{}   // by "entry-sequence": the latest creation time an older record gives

	err := s.Stream(store.Query{Text: "source:registry"}, func(e store.EventRow) error {
		switch e.TSType {
		case "file-modified (shimcache)":
			rep.Compared["shimcache entries"]++
			if k := normPath(e.Path); k != "" {
				shim[k] = append(shim[k], other{ts: e.TSUTC, event: e.ID, evidence: e.EvidenceID, host: e.Host, path: e.Path})
			}
		case "amcache-file-recorded":
			var f struct {
				LinkDate string `json:"link_date"`
			}
			if json.Unmarshal(e.Fields, &f) != nil || f.LinkDate == "" {
				return nil
			}
			t, err := time.Parse("01/02/2006 15:04:05", strings.TrimSpace(f.LinkDate))
			if err != nil || t.Year() < 1995 {
				return nil
			}
			// A link time later than the moment Amcache recorded the file
			// is not a real build time (reproducible builds put a hash in
			// that field), so it proves nothing.
			if t.UnixNano() > e.TSUTC {
				rep.Compared["amcache link dates ignored as implausible"]++
				return nil
			}
			rep.Compared["amcache link dates"]++
			if k := normPath(e.Path); k != "" {
				link[k] = append(link[k], other{ts: t.UnixNano(), event: e.ID, evidence: e.EvidenceID, host: e.Host, path: e.Path, recorded: e.TSUTC})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = s.Stream(store.Query{Text: "source:usn"}, func(e store.EventRow) error {
		var f struct {
			Reasons  []string `json:"reasons"`
			Entry    uint64   `json:"entry"`
			Sequence uint64   `json:"sequence"`
		}
		if json.Unmarshal(e.Fields, &f) != nil {
			return nil
		}
		for _, r := range f.Reasons {
			if r == "FILE_CREATE" {
				rep.Compared["change journal creations"]++
				k := strconv.FormatUint(f.Entry, 10) + "-" + strconv.FormatUint(f.Sequence, 10)
				// The first creation record for this file is the one that counts.
				if len(journal[k]) == 0 {
					journal[k] = []other{{ts: e.TSUTC, event: e.ID, evidence: e.EvidenceID, host: e.Host, path: e.Path}}
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Copies of a file's times in index slack and the transaction log.
	for _, src := range []string{"i30", "logfile"} {
		err = s.Stream(store.Query{Text: "source:" + src}, func(e store.EventRow) error {
			if !strings.Contains(e.MACB, "B") || !strings.HasPrefix(e.TSType, "$I30-slack ") && !strings.HasPrefix(e.TSType, "$LogFile-") {
				return nil
			}
			var f struct {
				Entry    *uint64 `json:"entry"`
				Sequence uint64  `json:"sequence"`
			}
			if json.Unmarshal(e.Fields, &f) != nil || f.Entry == nil || f.Sequence == 0 {
				return nil // a carved entry that lost its header does not say which file it was
			}
			rep.Compared["older copies of creation times"]++
			k := strconv.FormatUint(*f.Entry, 10) + "-" + strconv.FormatUint(f.Sequence, 10)
			if len(older[k]) == 0 || e.TSUTC > older[k][0].ts {
				older[k] = []other{{ts: e.TSUTC, event: e.ID, evidence: e.EvidenceID, host: e.Host, path: e.Path}}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// The file table, once through. Only files something else speaks about
	// are kept, so a volume of a million files does not sit in memory.
	files := map[string]*mftFile{} // by entry-sequence
	err = s.Stream(store.Query{Text: "source:mft"}, func(e store.EventRow) error {
		ref, ok := mftRef(e.RecordRef)
		if !ok {
			return nil
		}
		rep.Compared["file table times"]++
		f := files[ref]
		if f == nil {
			k := normPath(e.Path)
			if len(shim[k]) == 0 && len(link[k]) == 0 && len(journal[ref]) == 0 && len(older[ref]) == 0 {
				return nil
			}
			f = &mftFile{path: e.Path, host: e.Host, evidence: e.EvidenceID}
			files[ref] = f
		}
		switch {
		case strings.HasPrefix(e.TSType, "$SI "):
			if strings.Contains(e.MACB, "M") {
				f.siM, f.siMEvent = e.TSUTC, e.ID
			}
			if strings.Contains(e.MACB, "B") {
				f.siB, f.siBEvent = e.TSUTC, e.ID
			}
			if strings.Contains(e.Message, "SI<FN") || strings.Contains(e.Message, "zero-subseconds") {
				f.flagged = true
			}
		case strings.HasPrefix(e.TSType, "$FN ") && strings.Contains(e.MACB, "B"):
			f.fnBLater = true // refined below, once $SI's creation time is known
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	add := func(f Finding) {
		if rep.Counts[f.Kind] >= MaxPerKind {
			rep.Truncated[f.Kind] = true
			rep.Counts[f.Kind]++
			return
		}
		rep.Counts[f.Kind]++
		rep.Findings = append(rep.Findings, f)
	}
	refs := make([]string, 0, len(files))
	for r := range files {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		f := files[ref]
		k := normPath(f.path)

		// 1. Modified earlier than ShimCache recorded.
		if f.siM != 0 {
			var worst *other
			for i := range shim[k] {
				o := &shim[k][i]
				if hostsDiffer(o.host, f.host) || o.ts-f.siM <= shimTolerance {
					continue
				}
				if worst == nil || o.ts > worst.ts {
					worst = o
				}
			}
			if worst != nil {
				add(Finding{
					Kind: KindModifiedBeforeShimCache, Path: f.path, Host: f.host,
					Summary: fmt.Sprintf("The file table says %s was last modified %s. ShimCache recorded its modification time as %s, which is later. A modification time does not go backwards unless it is set.",
						f.path, utc(f.siM), utc(worst.ts)),
					Caveat:   "ShimCache matches by path only: a different file that once stood at this path, since replaced by an older one (restoring a backup, reinstalling an older version), gives the same result. The drive letter is not compared.",
					FileTime: utc(f.siM), OtherTime: utc(worst.ts), GapSeconds: (worst.ts - f.siM) / int64(time.Second),
					AlsoFlagged: f.flagged, EventIDs: []int64{f.siMEvent, worst.event}, EvidenceIDs: []int64{f.evidence, worst.evidence},
					Details: map[string]any{"mft_entry": ref, "shimcache_path": worst.path},
				})
			}
		}

		// 2. Built after the file's creation and modification times.
		if f.siM != 0 && f.siB != 0 {
			for _, o := range link[k] {
				if hostsDiffer(o.host, f.host) || o.ts-f.siM <= linkTolerance || o.ts-f.siB <= linkTolerance {
					continue
				}
				later := f.siM
				if f.siB > later {
					later = f.siB
				}
				add(Finding{
					Kind: KindLinkedAfterFileTimes, Path: f.path, Host: f.host,
					Summary: fmt.Sprintf("Amcache records that %s was built on %s. The file table says it was created %s and last modified %s, both before it was built.",
						f.path, utc(o.ts), utc(f.siB), utc(f.siM)),
					Caveat:   "The build time comes from the program's own header and can be false: some build systems write a fixed or meaningless value there. Amcache matches by path only, and the drive letter is not compared.",
					FileTime: utc(later), OtherTime: utc(o.ts), GapSeconds: (o.ts - later) / int64(time.Second),
					AlsoFlagged: f.flagged, EventIDs: []int64{f.siBEvent, f.siMEvent, o.event}, EvidenceIDs: []int64{f.evidence, o.evidence},
					Details: map[string]any{"mft_entry": ref, "amcache_recorded": utc(o.recorded)},
				})
				break
			}
		}

		// 3. Created earlier than an older copy of its own times says.
		if f.siB != 0 {
			for _, o := range older[ref] {
				if hostsDiffer(o.host, f.host) || o.ts-f.siB <= journalTolerance {
					continue
				}
				add(Finding{
					Kind: KindCreatedBeforeOlderRecord, Path: f.path, Host: f.host,
					Summary: fmt.Sprintf("An older copy of this file's times, kept in a directory index or the transaction log, gives its creation time as %s. The file table now says %s was created %s, which is earlier. A creation time changes only when something sets it.",
						utc(o.ts), f.path, utc(f.siB)),
					Caveat:   "Something set the creation time after the file arrived. Installers, archive extractors and copy tools do that as a matter of course, to give a file its original date, and so does anyone hiding a file's age. This check cannot tell them apart; where and what the file is can.",
					FileTime: utc(f.siB), OtherTime: utc(o.ts), GapSeconds: (o.ts - f.siB) / int64(time.Second),
					AlsoFlagged: f.flagged, EventIDs: []int64{f.siBEvent, o.event}, EvidenceIDs: []int64{f.evidence, o.evidence},
					Details: map[string]any{"mft_entry": ref},
				})
			}
		}

		// 4. Created earlier than the journal saw it created.
		if f.siB != 0 {
			for _, o := range journal[ref] {
				if hostsDiffer(o.host, f.host) || o.ts-f.siB <= journalTolerance {
					continue
				}
				add(Finding{
					Kind: KindCreatedBeforeJournal, Path: f.path, Host: f.host,
					Summary: fmt.Sprintf("The change journal recorded %s being created %s. The file table gives its creation time as %s, which is earlier.",
						f.path, utc(o.ts), utc(f.siB)),
					Caveat:   "This is the weakest of the checks. Installers, archive extractors and copy tools routinely give a new file its original creation time, so most of these are innocent. It matters for a file already of interest, and where the file table shows no other sign.",
					FileTime: utc(f.siB), OtherTime: utc(o.ts), GapSeconds: (o.ts - f.siB) / int64(time.Second),
					AlsoFlagged: f.flagged, EventIDs: []int64{f.siBEvent, o.event}, EvidenceIDs: []int64{f.evidence, o.evidence},
					Details: map[string]any{"mft_entry": ref, "fn_creation_time_differs": f.fnBLater},
				})
			}
		}
	}

	order := map[string]int{KindModifiedBeforeShimCache: 0, KindLinkedAfterFileTimes: 1, KindCreatedBeforeOlderRecord: 2, KindCreatedBeforeJournal: 3}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		if a.AlsoFlagged != b.AlsoFlagged {
			return a.AlsoFlagged
		}
		if a.GapSeconds != b.GapSeconds {
			return a.GapSeconds > b.GapSeconds
		}
		return a.Path < b.Path
	})

	if rep.Compared["file table times"] == 0 {
		rep.Notes = append(rep.Notes, "No file table ($MFT) is in the case, so nothing could be compared. Add the $MFT of the same machine.")
	} else {
		if rep.Compared["shimcache entries"] == 0 {
			rep.Notes = append(rep.Notes, "No ShimCache entries are in the case (they come from the SYSTEM hive), so file modification times could not be checked against it.")
		}
		if rep.Compared["amcache link dates"] == 0 {
			rep.Notes = append(rep.Notes, "No Amcache build times are in the case (they come from Amcache.hve), so build times could not be checked.")
		}
		if rep.Compared["change journal creations"] == 0 {
			rep.Notes = append(rep.Notes, "No change journal creations are in the case (they come from $UsnJrnl:$J), so creation times could not be checked against it.")
		}
	}
	rep.Notes = append(rep.Notes,
		"Artefacts are compared across the whole case. Where both name a host and the hosts differ they are not compared; where one does not name a host, make sure they came from the same machine.",
		"A finding is a contradiction between records, not proof of tampering. Each one lists the events compared so they can be checked.")
	for k, v := range rep.Truncated {
		if v {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d found, the first %d listed.", k, rep.Counts[k], MaxPerKind))
		}
	}
	sort.Strings(rep.Notes[len(rep.Notes)-len(rep.Truncated):])
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	return rep, nil
}
