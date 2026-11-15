// Package ingest is the evidence pipeline: intake into the vault, hashing,
// identification, container unpacking, parsing and the audit trail around it.
package ingest

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/hivelog"
	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/parsers"
	"github.com/DanDreadless/atropos/internal/store"
	"github.com/DanDreadless/atropos/internal/timeutil"
	"github.com/DanDreadless/atropos/internal/vault"
)

const (
	maxDepth   = 8
	maxMembers = 500000
	maxNotes   = 25

	// DefaultMaxUnpack bounds what one submission's archives may expand to.
	DefaultMaxUnpack = 64 << 30
)

type Ingester struct {
	S *store.Store
	V *vault.Vault

	// ExaminerZone, when set, is the zone the examiner has stated applies to
	// zoneless local timestamps where the evidence itself does not say.
	ExaminerZone     *time.Location
	ExaminerZoneName string

	// WorkerExe, when set, is the program run to parse each file in its own
	// process (see worker.go); WorkerArgs are its arguments. Empty means
	// parse in this process, which is simpler but lets a parser that hangs
	// or crashes on hostile input take everything else with it.
	WorkerExe  string
	WorkerArgs []string
	// ParseTimeout stops a worker that runs longer than this. Zero is no limit.
	ParseTimeout time.Duration
	// MaxUnpack is the most bytes one submission's archives may expand to.
	// Zero means DefaultMaxUnpack.
	MaxUnpack int64

	mu     sync.Mutex // one batch is processed at a time
	stMu   sync.Mutex
	status Status
	active int // batches submitted and not yet finished; guarded by stMu

	lastMu sync.Mutex
	last   string // outcome of the most recent extraction from an image
}

type Status struct {
	Busy    bool   `json:"busy"`
	Current string `json:"current"`
	Queued  int    `json:"queued"`
	Done    int    `json:"done"`
	Last    string `json:"last,omitempty"`
}

func (in *Ingester) Status() Status {
	in.stMu.Lock()
	defer in.stMu.Unlock()
	return in.status
}

func (in *Ingester) setStatus(f func(*Status)) {
	in.stMu.Lock()
	f(&in.status)
	in.stMu.Unlock()
}

// Intake copies one submitted file into the vault, hashes and identifies it,
// and registers it as evidence. It does not parse.
func (in *Ingester) Intake(batch int64, name, origin string, r io.Reader, parent *int64, depth int) (*store.Evidence, error) {
	hs, existed, err := in.V.Put(r)
	if err != nil {
		return nil, fmt.Errorf("storing %s: %w", name, err)
	}
	f, err := in.V.Open(hs.SHA256)
	if err != nil {
		return nil, err
	}
	det := detect.Identify(f, hs.Size)
	f.Close()
	e := &store.Evidence{
		SHA256: hs.SHA256, SHA1: hs.SHA1, MD5: hs.MD5, Size: hs.Size,
		Name: parsers.Clean(name), Origin: parsers.Clean(origin), ParentID: parent, BatchID: batch, Depth: depth,
		Kind: det.Kind, DetectReason: det.Reason,
	}
	if first, ok := in.S.FirstBySHA(hs.SHA256); ok {
		e.DuplicateOf = &first
	}
	if err := in.S.AddEvidence(e); err != nil {
		return nil, err
	}
	if err := in.S.Audit("evidence.intake", fmt.Sprintf("evidence:%d", e.ID), map[string]any{
		"name": e.Name, "origin": e.Origin, "sha256": e.SHA256, "sha1": e.SHA1, "md5": e.MD5, "size": e.Size,
		"kind": e.Kind, "detect_reason": e.DetectReason, "batch": batch, "parent": parent,
		"duplicate_of": e.DuplicateOf, "content_already_in_vault": existed,
	}); err != nil {
		return nil, err
	}
	return e, nil
}

// IntakePath ingests a file from disk, opening it read-only.
func (in *Ingester) IntakePath(batch int64, p string) (*store.Evidence, error) {
	f, err := os.OpenFile(p, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	abs, _ := filepath.Abs(p)
	return in.Intake(batch, filepath.Base(p), abs, f, nil, 0)
}

const maxStreamsPerFile = 32

// IntakeStreams preserves the alternate data streams of a file just taken in
// from disk, each as an item of its own under that file: Windows keeps the
// "mark of the web" (Zone.Identifier: where a download came from) in one, and
// copying only a file's content would leave it behind. It can only see
// streams where the source is an NTFS volume read through Windows. A stream
// that cannot be read is returned as an error; the rest are still taken.
func (in *Ingester) IntakeStreams(batch int64, p string, parent *store.Evidence) (out []*store.Evidence, errs []error) {
	names, err := namedStreams(p)
	if err != nil {
		errs = append(errs, fmt.Errorf("listing the streams of %s: %w", p, err))
	}
	abs, _ := filepath.Abs(p)
	for _, name := range names {
		f, err := os.OpenFile(p+":"+name, os.O_RDONLY, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s:%s: %w", p, name, err))
			continue
		}
		e, err := in.Intake(batch, filepath.Base(p)+":"+name, abs+":"+name, f, &parent.ID, parent.Depth+1)
		f.Close()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, e)
	}
	return out, errs
}

// Process expands any containers among the given evidence and parses
// everything, context-establishing artefacts first.
func (in *Ingester) Process(top []*store.Evidence) {
	in.begin()
	defer in.end()
	in.process(top)
}

// ProcessAsync is Process in the background. The ingester reports busy from
// the moment this returns, so a caller polling Status cannot see a gap
// between submitting work and that work starting.
func (in *Ingester) ProcessAsync(top []*store.Evidence) {
	in.begin()
	go func() {
		defer in.end()
		in.process(top)
	}()
}

func (in *Ingester) begin() {
	in.setStatus(func(s *Status) { in.active++; s.Busy = true })
}

func (in *Ingester) end() {
	in.setStatus(func(s *Status) {
		in.active--
		if in.active == 0 {
			*s = Status{}
		}
	})
}

func (in *Ingester) process(top []*store.Evidence) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.setStatus(func(s *Status) { s.Queued += len(top) })

	var leaves []*store.Evidence
	members := 0
	room := in.MaxUnpack
	if room <= 0 {
		room = DefaultMaxUnpack
	}
	var expand func(e *store.Evidence)
	expand = func(e *store.Evidence) {
		if e.DuplicateOf != nil {
			return
		}
		if !isContainer(e.Kind) {
			leaves = append(leaves, e)
			return
		}
		in.setStatus(func(s *Status) { s.Current = "unpacking " + e.Name })
		children, notes, err := in.unpack(e, &members, &room)
		status := "unpacked"
		if err != nil {
			status = "partial"
			notes = append(notes, err.Error())
		}
		in.sealContainer(e, status, len(children), notes)
		for _, c := range children {
			expand(c)
		}
	}
	for _, e := range top {
		expand(e)
	}
	sort.SliceStable(leaves, func(i, j int) bool {
		return in.priority(leaves[i]) < in.priority(leaves[j])
	})
	in.setStatus(func(s *Status) { s.Queued = len(leaves); s.Done = 0 })
	for _, e := range leaves {
		in.setStatus(func(s *Status) { s.Current = e.Name })
		if err := in.Parse(e); err != nil {
			in.S.Audit("parse.error", fmt.Sprintf("evidence:%d", e.ID), map[string]any{"error": err.Error()})
		}
		in.setStatus(func(s *Status) { s.Done++ })
	}
	in.completeImages(leaves)
	in.completeHives(leaves)
}

// completeHives parses a hive again when this submission brought one of
// its transaction logs and the hive itself came earlier. Logs are matched
// to hives by the copy of the hive's base block they begin with.
func (in *Ingester) completeHives(leaves []*store.Evidence) {
	arrived := map[int64]bool{}
	var logs []hivelog.Base
	for _, e := range leaves {
		arrived[e.ID] = true
		if e.Kind == detect.RegistryLog && e.DuplicateOf == nil {
			if b, ok := in.baseBlock(e); ok {
				logs = append(logs, b)
			}
		}
	}
	if len(logs) == 0 {
		return
	}
	all, err := in.S.ListEvidence()
	if err != nil {
		return
	}
	for i := range all {
		e := &all[i]
		if e.Kind != detect.Registry || arrived[e.ID] || e.DuplicateOf != nil {
			continue
		}
		hb, ok := in.baseBlock(e)
		if !ok || !hb.Dirty() {
			continue
		}
		for _, l := range logs {
			if hb.SameHive(l) {
				in.setStatus(func(s *Status) { s.Current = e.Name })
				if err := in.Parse(e); err != nil {
					in.S.Audit("parse.error", fmt.Sprintf("evidence:%d", e.ID), map[string]any{"error": err.Error()})
				}
				break
			}
		}
	}
}

// baseBlock reads the registry base block at the start of a stored file.
func (in *Ingester) baseBlock(e *store.Evidence) (hivelog.Base, bool) {
	f, err := in.V.Open(e.SHA256)
	if err != nil {
		return hivelog.Base{}, false
	}
	defer f.Close()
	b := make([]byte, 4096)
	n, _ := f.ReadAt(b, 0)
	base, err := hivelog.ParseBase(b[:n])
	return base, err == nil
}

// completeImages parses again the split images that were waiting for a
// segment, when this submission brought more segment files. An E01 image
// added one file at a time is checked as soon as its last file arrives.
func (in *Ingester) completeImages(leaves []*store.Evidence) {
	arrived := map[int64]bool{}
	for _, e := range leaves {
		if e.Kind == detect.EWF {
			arrived[e.ID] = true
		}
	}
	if len(arrived) == 0 {
		return
	}
	all, err := in.S.ListEvidence()
	if err != nil {
		return
	}
	for i := range all {
		e := &all[i]
		if e.Kind != detect.EWF || e.Status != "partial" || arrived[e.ID] || e.DuplicateOf != nil {
			continue
		}
		in.setStatus(func(s *Status) { s.Current = e.Name })
		if err := in.Parse(e); err != nil {
			in.S.Audit("parse.error", fmt.Sprintf("evidence:%d", e.ID), map[string]any{"error": err.Error()})
		}
	}
}

// priority orders a submission. Registry hives go first, and among them the
// SYSTEM hive, because it names the host and its time zone and the other
// hives hold local times that need that zone (the networks a machine joined,
// in SOFTWARE). A hive records the end of its own path in its header; that
// is used here only to choose an order, never to decide what a file is.
func (in *Ingester) priority(e *store.Evidence) int {
	p := parsers.Priority(e.Kind)
	if e.Kind != detect.Registry {
		return p + 1
	}
	f, err := in.V.Open(e.SHA256)
	if err != nil {
		return p + 1
	}
	defer f.Close()
	b := make([]byte, 64)
	if _, err := f.ReadAt(b, 0x30); err != nil {
		return p + 1
	}
	u := make([]uint16, 0, 32)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	if strings.HasSuffix(strings.ToLower(string(utf16.Decode(u))), `\system`) {
		return p
	}
	return p + 1
}

func isContainer(kind string) bool {
	return kind == detect.Zip || kind == detect.Tar || kind == detect.Gzip
}

func (in *Ingester) sealContainer(e *store.Evidence, status string, n int, notes []string) {
	run, err := in.S.BeginRun(e.ID, "container", "1", "")
	if err != nil {
		return
	}
	note := fmt.Sprintf("%d members extracted and registered as evidence", n)
	if len(notes) > 0 {
		note += "; " + strings.Join(capNotes(notes), "; ")
	}
	digest, _ := run.Finish(status, note)
	in.S.Audit("container.unpack", fmt.Sprintf("evidence:%d", e.ID), map[string]any{"run": run.ID, "status": status, "members": n, "notes": note, "event_digest": digest})
}

func capNotes(n []string) []string {
	if len(n) <= maxNotes {
		return n
	}
	return append(n[:maxNotes:maxNotes], fmt.Sprintf("… and %d more", len(n)-maxNotes))
}

// unpack registers each member of a container as child evidence. members and
// room are the submission's remaining allowances: an archive that expands
// without end stops at the limit, and says so, rather than filling the disk.
func (in *Ingester) unpack(e *store.Evidence, members *int, room *int64) (children []*store.Evidence, notes []string, err error) {
	if e.Depth >= maxDepth {
		return nil, nil, fmt.Errorf("nesting limit of %d reached; contents not unpacked", maxDepth)
	}
	f, err := in.V.Open(e.SHA256)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	limited, skipped := false, false
	defer func() {
		if limited && err == nil {
			err = errors.New("a limit was reached; not everything in this container was unpacked")
		}
	}()
	add := func(name string, r io.Reader) {
		if *members >= maxMembers {
			if !skipped {
				notes = append(notes, fmt.Sprintf("limit of %d members per submission reached; remaining members not unpacked", maxMembers))
			}
			limited, skipped = true, true
			return
		}
		if *room <= 0 {
			if !skipped {
				notes = append(notes, "unpack size limit for this submission reached; remaining members not unpacked")
			}
			limited, skipped = true, true
			return
		}
		*members++
		// One byte more than the allowance is requested, so a member that
		// exactly fits can be told from one that was cut short.
		lr := &io.LimitedReader{R: r, N: *room + 1}
		c, ierr := in.Intake(e.BatchID, path.Base(name), e.Origin+"!/"+name, lr, &e.ID, e.Depth+1)
		if ierr != nil {
			notes = append(notes, fmt.Sprintf("member %q could not be read: %v", name, ierr))
			return
		}
		*room -= c.Size
		if lr.N == 0 {
			limited = true
			notes = append(notes, fmt.Sprintf("member %q is larger than the remaining unpack allowance; evidence #%d holds only its first %d bytes", name, c.ID, c.Size))
		}
		children = append(children, c)
	}
	switch e.Kind {
	case detect.Zip:
		zr, zerr := zip.NewReader(f, e.Size)
		if zerr != nil {
			return nil, nil, fmt.Errorf("zip: %w", zerr)
		}
		for _, m := range zr.File {
			if m.FileInfo().IsDir() {
				continue
			}
			rc, oerr := m.Open()
			if oerr != nil {
				notes = append(notes, fmt.Sprintf("member %q could not be opened: %v", m.Name, oerr))
				continue
			}
			add(m.Name, rc)
			rc.Close()
		}
	case detect.Gzip:
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return nil, nil, fmt.Errorf("gzip: %w", gerr)
		}
		name := gz.Name
		if name == "" {
			name = strings.TrimSuffix(e.Name, ".gz")
			if name == e.Name {
				name += ".decompressed"
			}
		}
		add(name, gz)
	case detect.Tar:
		tr := tar.NewReader(f)
		for {
			h, terr := tr.Next()
			if terr == io.EOF {
				break
			}
			if terr != nil {
				return children, notes, fmt.Errorf("tar: %w", terr)
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			add(h.Name, tr)
		}
	}
	return children, notes, nil
}

// localContext decides how zoneless local timestamps in this evidence are
// converted, in order of evidential strength: the host's own registry within
// the same batch, then a zone stated by the examiner, then an assumption that
// is flagged on every affected event.
func (in *Ingester) localContext(e *store.Evidence) (timeutil.LocalContext, string) {
	zones, _ := in.S.BatchFacts(e.BatchID, "host.timezone")
	if len(zones) == 1 {
		if loc, err := time.LoadLocation(zones[0]); err == nil {
			return timeutil.LocalContext{Loc: loc, ZoneFrom: timeutil.ZoneHost, ZoneName: zones[0]},
				"host-registry: " + zones[0]
		}
	}
	if in.ExaminerZone != nil {
		note := "examiner-set: " + in.ExaminerZoneName
		if len(zones) > 1 {
			note += " (batch contains several host zones: " + strings.Join(zones, ", ") + ")"
		}
		return timeutil.LocalContext{Loc: in.ExaminerZone, ZoneFrom: timeutil.ZoneExaminer, ZoneName: in.ExaminerZoneName}, note
	}
	note := "assumed: UTC"
	if len(zones) > 1 {
		note += " (batch contains several host zones: " + strings.Join(zones, ", ") + ")"
	}
	return timeutil.AssumedUTC(), note
}

// Parse runs the appropriate parser over one evidence item as a new run.
// Earlier runs are kept; the newest becomes the one shown on the timeline.
func (in *Ingester) Parse(e *store.Evidence) error {
	p := parsers.For(e.Kind)
	var carried []string
	if p != nil {
		status, count, notes, err := in.runParser(e, p)
		if err != nil {
			return err
		}
		// An image is not text: when it cannot be opened, the reason given
		// is the result, and strings from its compressed chunks are not.
		if count > 0 || status == "parsed" || e.Kind == detect.EWF {
			return nil
		}
		carried = append([]string{fmt.Sprintf("dedicated parser %q (version %s) produced no events", p.Name(), p.Version())}, notes...)
	} else if Browsable(e.Kind) {
		carried = []string{"this is an image: open it under Files to browse its contents and choose what goes on the timeline"}
	} else if e.Kind != detect.Unknown && e.Kind != detect.Empty && e.Kind != detect.PE {
		carried = []string{fmt.Sprintf("recognised as %s; this version has no dedicated parser for it", e.Kind)}
	}
	_, _, _, err := in.runParserWith(e, parsers.Generic(), "generic", carried)
	return err
}

func (in *Ingester) runParser(e *store.Evidence, p parsers.Parser) (string, int64, []string, error) {
	return in.runParserWith(e, p, "parsed", nil)
}

func (in *Ingester) runParserWith(e *store.Evidence, p parsers.Parser, okStatus string, carried []string) (status string, count int64, notes []string, err error) {
	lc, zoneNote := in.localContext(e)
	host := ""
	if hosts, _ := in.S.BatchFacts(e.BatchID, "host.name"); len(hosts) == 1 {
		host = hosts[0]
	}
	run, err := in.S.BeginRun(e.ID, p.Name(), p.Version(), zoneNote)
	if err != nil {
		return "", 0, nil, err
	}
	var warns, infos []string
	received := time.Unix(0, e.ReceivedUTC).UTC()
	j := job{
		Path: in.V.Path(e.SHA256), Size: e.Size, Name: e.Name, Kind: e.Kind, Host: host,
		ZoneFrom: lc.ZoneFrom, ZoneName: lc.ZoneName,
		ReceivedYear: received.Year(), ReceivedMonth: int(received.Month()),
		Generic: okStatus == "generic", Segments: in.segments(e),
	}
	out := sink{
		event: run.Add,
		fact:  func(key, value, detail string) { in.S.AddFact(e.ID, key, parsers.Clean(value), detail) },
		warn:  func(s string) { warns = append(warns, s) },
		note:  func(s string) { infos = append(infos, s) },
		text: func(method string, truncated bool, body string) {
			if terr := in.S.AddText(e.ID, method, truncated, body); terr != nil {
				// Text for this evidence was already indexed by an earlier run.
				infos = append(infos, "extracted text already indexed by an earlier run")
			}
		},
	}
	out.listing, out.file = func(string, []imagefs.Entry) {}, func(string, string) error { return nil }
	perr := in.run(j, out)
	count = run.Count()
	status = okStatus
	switch {
	case errors.Is(perr, parsers.ErrNothingExtracted):
		status = "no-content"
		warns = append(warns, perr.Error())
	case perr != nil && count == 0:
		status = "failed"
		warns = append(warns, perr.Error())
	case perr != nil:
		status = "partial"
		warns = append(warns, "stopped early: "+perr.Error())
	case len(warns) > 0:
		status = "partial"
	}
	notes = append(append(append([]string{}, carried...), capNotes(warns)...), capNotes(infos)...)
	digest, ferr := run.Finish(status, strings.Join(notes, "; "))
	if ferr != nil {
		return status, count, notes, ferr
	}
	err = in.S.Audit("parse.complete", fmt.Sprintf("evidence:%d", e.ID), map[string]any{
		"run": run.ID, "parser": p.Name(), "parser_version": p.Version(), "tool_version": store.ToolVersion,
		"status": status, "events": count, "event_digest": digest, "zone_context": zoneNote,
		"sha256": e.SHA256, "warnings": len(warns),
	})
	return status, count, append(capNotes(warns), capNotes(infos)...), err
}

// Report is the result of a full integrity check.
type Report struct {
	OK              bool     `json:"ok"`
	EvidenceChecked int      `json:"evidence_checked"`
	EvidenceBad     []string `json:"evidence_bad"`
	RunsChecked     int      `json:"runs_checked"`
	RunsBad         []int64  `json:"runs_bad"`
	// RunsUnaudited are sealed runs the audit log does not vouch for;
	// RunsMissing are runs the audit log sealed that are gone.
	RunsUnaudited []int64 `json:"runs_unaudited"`
	RunsMissing   []int64 `json:"runs_missing"`
	AuditEntries  int64   `json:"audit_entries"`
	AuditHead     string  `json:"audit_head"`
	AuditBrokenAt int64   `json:"audit_broken_at"`
	CheckedUTC    string  `json:"checked_utc"`
}

// Verify re-hashes every stored evidence file, recomputes every run's event
// digest and walks the audit chain.
func (in *Ingester) Verify() (Report, error) {
	rep := Report{EvidenceBad: []string{}, RunsBad: []int64{}, RunsUnaudited: []int64{}, RunsMissing: []int64{}, CheckedUTC: time.Now().UTC().Format(time.RFC3339)}
	list, err := in.S.ListEvidence()
	if err != nil {
		return rep, err
	}
	seen := map[string]bool{}
	for _, e := range list {
		if seen[e.SHA256] {
			continue
		}
		seen[e.SHA256] = true
		rep.EvidenceChecked++
		if err := in.V.Verify(e.SHA256); err != nil {
			rep.EvidenceBad = append(rep.EvidenceBad, fmt.Sprintf("%s (%s): %v", e.Name, e.SHA256, err))
		}
	}
	var bad []int64
	rep.RunsChecked, bad, err = in.S.VerifyRuns()
	if err != nil {
		return rep, err
	}
	if bad != nil {
		rep.RunsBad = bad
	}
	unaudited, missing, err := in.S.VerifyRunsAudited()
	if err != nil {
		return rep, err
	}
	if unaudited != nil {
		rep.RunsUnaudited = unaudited
	}
	if missing != nil {
		rep.RunsMissing = missing
	}
	rep.AuditEntries, rep.AuditHead, rep.AuditBrokenAt, err = in.S.VerifyAudit()
	if err != nil {
		return rep, err
	}
	rep.OK = len(rep.EvidenceBad) == 0 && len(rep.RunsBad) == 0 && rep.AuditBrokenAt == 0 &&
		len(rep.RunsUnaudited) == 0 && len(rep.RunsMissing) == 0
	// The check itself is recorded. The head reported above is the chain as
	// verified, before this entry is appended.
	in.S.Audit("case.verify", "case", map[string]any{"ok": rep.OK, "evidence_checked": rep.EvidenceChecked,
		"evidence_bad": len(rep.EvidenceBad), "runs_checked": rep.RunsChecked, "runs_bad": len(rep.RunsBad),
		"runs_unaudited": len(rep.RunsUnaudited), "runs_missing": len(rep.RunsMissing),
		"audit_entries": rep.AuditEntries, "audit_head": rep.AuditHead, "audit_broken_at": rep.AuditBrokenAt})
	return rep, nil
}

// Stale says why this build of Atropos would read an item differently from
// the run now shown, or "" when it would not. A parser's version changes
// whenever its output does, so a run made by another version is worth
// making again; so is one that ended in a crash, and one where the parser
// for the item's kind found nothing and a different version is now present.
func Stale(e *store.Evidence) string {
	if e.DuplicateOf != nil || e.Parser == "" || isContainer(e.Kind) {
		return ""
	}
	p := parsers.For(e.Kind)
	switch {
	case strings.Contains(e.Notes, "parser panic"):
		return "the parser stopped on an error last time"
	case e.Parser == "generic" && p != nil:
		if !strings.Contains(e.Notes, "(version "+p.Version()+")") {
			return fmt.Sprintf("the %s parser found nothing in it before, and has changed since", p.Name())
		}
	case e.Parser == "generic":
		if e.ParserVersion != parsers.Generic().Version() {
			return "the general-purpose reader has changed since this was read"
		}
	case p != nil && p.Name() == e.Parser && p.Version() != e.ParserVersion:
		return fmt.Sprintf("read by %s version %q; this build has %q", e.Parser, firstWord(e.ParserVersion), firstWord(p.Version()))
	}
	return ""
}

// firstWord is the number at the front of a parser's version text.
func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}
