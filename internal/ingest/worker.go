package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/parsers"
	"github.com/DanDreadless/atropos/internal/store"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Evidence is hostile input, and the parsers for it include third-party
// libraries that trust what they read. A crafted file can make one loop for
// ever, exhaust memory or crash. So that none of that can take the case or
// the server with it, each parse can be run in a separate worker process:
// the worker opens one file read-only, parses it and streams what it finds
// back as JSON lines. The parent owns the database, enforces a time limit
// and records an abnormal end as a visible failure of that one file.
//
// The worker and the in-process path share runJob, and events are converted
// to their stored form before they leave it, so the two produce identical
// events and identical run digests.

// job is everything a parser needs, in a form that crosses a process boundary.
type job struct {
	Path          string // vault copy of the evidence
	Size          int64
	Name          string
	Kind          string
	Host          string
	ZoneFrom      string // timeutil.Zone* constant for zoneless local times
	ZoneName      string // IANA name to load, or "UTC"
	ReceivedYear  int
	ReceivedMonth int
	Generic       bool // run the generic parser instead of the dedicated one
	// Segments are the vault copies of other files that may be segments of
	// the same split image (E01). The reader keeps only those that are.
	Segments []string

	// Op is empty for a parse. "browse" lists the directory Inner of an
	// image; "extract" copies Items (and, with Triage, the standard Windows
	// artefacts) out of an image into temporary files in OutDir.
	Op       string
	Inner    string
	Items    []string
	Triage   bool
	OutDir   string
	MaxFiles int
	MaxBytes int64
}

// sink receives what a parser produces.
type sink struct {
	event func(store.Event) error
	fact  func(key, value, detail string)
	warn  func(string)
	note  func(string)
	text  func(method string, truncated bool, body string)
	// For image jobs: a directory listing, and a file copied out to tmp.
	listing func(describe string, entries []imagefs.Entry)
	file    func(tmp, inner string) error
}

// storeEvent converts a parser's event to its stored, canonical form.
func storeEvent(ev parsers.Event) store.Event {
	if ev.Stamp.Caveat != "" {
		// Parsers may share one fields map between events; copy before adding.
		withCaveat := make(map[string]any, len(ev.Fields)+1)
		maps.Copy(withCaveat, ev.Fields)
		withCaveat["_time_caveat"] = ev.Stamp.Caveat
		ev.Fields = withCaveat
	}
	return store.Event{
		TSUTC: ev.Stamp.UTC.UnixNano(), TSType: ev.Type, TSRaw: parsers.Clean(ev.Stamp.Raw),
		TZSource: ev.Stamp.ZoneFrom, TZName: ev.Stamp.ZoneName,
		MACB: ev.MACB, Category: ev.Category,
		Source: ev.Source, Host: parsers.Clean(ev.Host), User: parsers.Clean(ev.User),
		Path: parsers.Clean(ev.Path), Message: parsers.Clean(ev.Message),
		Fields: parsers.FieldsJSON(ev.Fields), RecordRef: ev.Ref,
	}
}

// runJob opens the evidence read-only and runs the parser over it.
func runJob(j job, s sink) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	p := parsers.Generic()
	if !j.Generic {
		if p = parsers.For(j.Kind); p == nil {
			return fmt.Errorf("no parser for %s", j.Kind)
		}
	}
	lc := timeutil.LocalContext{Loc: time.UTC, ZoneFrom: j.ZoneFrom, ZoneName: j.ZoneName}
	if j.ZoneFrom != timeutil.ZoneAssumed {
		loc, lerr := time.LoadLocation(j.ZoneName)
		if lerr != nil {
			return fmt.Errorf("time zone %q: %w", j.ZoneName, lerr)
		}
		lc.Loc = loc
	}
	f, err := os.OpenFile(j.Path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return p.Parse(&parsers.Context{
		File: f, Size: j.Size, Name: j.Name, Kind: j.Kind, Host: j.Host, Local: lc,
		ReceivedYear: j.ReceivedYear, ReceivedMonth: j.ReceivedMonth, Segments: j.Segments, WorkDir: j.OutDir,
		Emit: func(ev parsers.Event) error { return s.event(storeEvent(ev)) },
		Fact: s.fact,
		Warn: func(format string, args ...any) { s.warn(fmt.Sprintf(format, args...)) },
		Note: func(format string, args ...any) { s.note(fmt.Sprintf(format, args...)) },
		Text: s.text,
	})
}

// message is one line of the worker's output.
type message struct {
	T string          `json:"t"` // event | fact | warn | note | text | done
	E *store.Event    `json:"e,omitempty"`
	K string          `json:"k,omitempty"`
	V string          `json:"v,omitempty"`
	D string          `json:"d,omitempty"`
	S string          `json:"s,omitempty"` // warn, note or text body; done: error text
	B bool            `json:"b,omitempty"` // text: truncated; done: nothing to extract
	L []imagefs.Entry `json:"l,omitempty"` // listing
}

// RunWorker is the worker process: one job in on r, messages out on w. It
// returns the process exit code. It never touches a case database.
func RunWorker(r io.Reader, w io.Writer) int {
	var j job
	if err := json.NewDecoder(r).Decode(&j); err != nil {
		fmt.Fprintln(os.Stderr, "worker: reading job:", err)
		return 2
	}
	out := bufio.NewWriterSize(w, 1<<20)
	enc := json.NewEncoder(out)
	var werr error
	send := func(m message) {
		if werr == nil {
			werr = enc.Encode(m)
		}
	}
	s := sink{
		event: func(e store.Event) error { send(message{T: "event", E: &e}); return werr },
		fact:  func(k, v, d string) { send(message{T: "fact", K: k, V: v, D: d}) },
		warn:  func(s string) { send(message{T: "warn", S: s}) },
		note:  func(s string) { send(message{T: "note", S: s}) },
		text: func(method string, truncated bool, body string) {
			send(message{T: "text", K: method, B: truncated, S: body})
		},
		listing: func(d string, l []imagefs.Entry) { send(message{T: "listing", S: d, L: l}) },
		// The parent must take each file before the next is written, so the
		// line goes out at once rather than waiting in the buffer.
		file: func(tmp, inner string) error {
			send(message{T: "file", K: tmp, V: inner})
			if werr == nil {
				werr = out.Flush()
			}
			return werr
		},
	}
	var perr error
	if j.Op != "" {
		perr = runImage(j, s)
	} else {
		perr = runJob(j, s)
	}
	done := message{T: "done"}
	switch {
	case errors.Is(perr, parsers.ErrNothingExtracted):
		done.B = true
	case perr != nil:
		done.S = perr.Error()
	}
	send(done)
	if werr == nil {
		werr = out.Flush()
	}
	if werr != nil {
		fmt.Fprintln(os.Stderr, "worker: writing results:", werr)
		return 3
	}
	return 0
}

// tail keeps the last few kilobytes written to it.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

// runIsolated runs the job in a worker process and feeds its output to s.
// An error here is the parser's outcome (and becomes the run's status), in
// the same way as an error returned by a parser run in-process.
func (in *Ingester) runIsolated(j job, s sink) error {
	ctx := context.Background()
	if in.ParseTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, in.ParseTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, in.WorkerExe, in.WorkerArgs...)
	spec, err := json.Marshal(j)
	if err != nil {
		return err
	}
	cmd.Stdin = bytes.NewReader(spec)
	var stderr tail
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the parser process: %w", err)
	}
	var done *message
	var sinkErr error
	dec := json.NewDecoder(bufio.NewReaderSize(stdout, 1<<20))
	for done == nil {
		var m message
		if err := dec.Decode(&m); err != nil {
			break // end of output, or the worker died mid-line
		}
		switch m.T {
		case "event":
			if m.E != nil {
				if sinkErr = s.event(*m.E); sinkErr != nil {
					cmd.Process.Kill()
				}
			}
		case "fact":
			s.fact(m.K, m.V, m.D)
		case "warn":
			s.warn(m.S)
		case "note":
			s.note(m.S)
		case "text":
			s.text(m.K, m.B, m.S)
		case "listing":
			s.listing(m.S, m.L)
		case "file":
			// Only a path inside this case's work directory is accepted: the
			// worker is not trusted to name any file it likes.
			if j.OutDir == "" || filepath.Dir(m.K) != filepath.Clean(j.OutDir) {
				s.warn("the worker reported a file outside the work directory; ignored")
			} else if err := s.file(m.K, m.V); err != nil {
				s.warn(fmt.Sprintf("%s: %v", m.V, err))
			}
		case "done":
			done = &m
		}
		if sinkErr != nil {
			break
		}
	}
	io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	switch {
	case sinkErr != nil:
		return sinkErr
	case ctx.Err() == context.DeadlineExceeded:
		return fmt.Errorf("the parser was stopped after exceeding the time limit of %s", in.ParseTimeout)
	case done == nil:
		detail := strings.TrimSpace(string(stderr.b))
		if i := strings.IndexByte(detail, '\n'); i > 0 {
			detail = detail[:i] // the first line names the fault; the rest is a stack trace
		}
		if len(detail) > 300 {
			detail = detail[:300] + "…"
		}
		return fmt.Errorf("the parser process ended unexpectedly (%v): %s", waitErr, parsers.Clean(detail))
	case done.B:
		return parsers.ErrNothingExtracted
	case done.S != "":
		return errors.New(done.S)
	}
	return nil
}
