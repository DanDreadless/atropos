// Atropos: drop in forensic artefacts, get one searchable UTC timeline.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/caselock"
	"github.com/DanDreadless/atropos/internal/ingest"
	"github.com/DanDreadless/atropos/internal/report"
	"github.com/DanDreadless/atropos/internal/store"
	"github.com/DanDreadless/atropos/internal/vault"
	"github.com/DanDreadless/atropos/internal/web"
)

const usage = `atropos %s

  atropos serve   --case DIR [--listen 127.0.0.1:8484]
  atropos ingest  --case DIR [--host NAME | --not-from-host TEXT] PATH...
  atropos verify  --case DIR
  atropos export  --case DIR [--format csv|jsonl|timesketch|bodyfile] [--query TEXT] [--group NAME] [-o FILE]
  atropos report  --case DIR [--format html|json] [-o FILE]
  atropos analyse --case DIR [--check all|anomalies|timestamps] [--tag] [--format text|json] [-o FILE]
  atropos version

A case is a directory holding the write-once evidence vault and the case
database. One Atropos process works on a case at a time.

On Windows, ingest also takes in the alternate data streams of each file on
an NTFS volume (Zone.Identifier, which says where a download came from,
among them). Files dropped on the web page arrive without their streams.

Options for any command that takes --case:
  --examiner NAME      recorded in the audit log (default: your login name)
  --local-zone ZONE    IANA zone (e.g. Europe/London) you state for local
                       timestamps whose zone the evidence does not establish

Options for ingest:
  --host NAME          the computer the files come from; added to the case's
                       hosts if new. Its events carry the name, and a time zone
                       stated for it on the Details tab reads local times
  --not-from-host TEXT the files come from no single computer (a packet
                       capture, firewall or cloud logs); say where from

Options for serve and ingest:
  --parse-timeout D    stop a parser that runs longer than this (default 30m; 0 for no limit)
  --max-unpack-gb N    most that one submission's archives may expand to (default 64)
  --in-process         parse inside this process instead of an isolated worker.
                       Slightly faster, but a file that makes a parser hang or
                       crash then takes the whole run with it

serve prints an address ending in ?token=... Open that exact address: the
token signs your browser in and changes every time the server starts. The
interface only listens on loopback addresses.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, store.ToolVersion)
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "worker":
		// The isolated parser process (see internal/ingest/worker.go). It is
		// started by Atropos itself and never opens a case.
		os.Exit(ingest.RunWorker(os.Stdin, os.Stdout))
	case "version", "--version", "-v":
		fmt.Printf("atropos %s (storage format %s)\n", store.ToolVersion, store.SchemaVersion)
		return
	case "help", "--help", "-h":
		fmt.Printf(usage, store.ToolVersion)
		return
	case "serve", "ingest", "verify", "export", "report", "analyse", "analyze":
	default:
		fmt.Fprintf(os.Stderr, "atropos: unknown command %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, store.ToolVersion)
		os.Exit(2)
	}

	fl := flag.NewFlagSet(cmd, flag.ExitOnError)
	caseDir := fl.String("case", "", "case directory")
	listen := fl.String("listen", "127.0.0.1:8484", "address to serve on (loopback only)")
	examiner := fl.String("examiner", defaultExaminer(), "examiner name recorded in the audit log")
	zone := fl.String("local-zone", "", "IANA zone for local timestamps the evidence does not place")
	check := fl.String("check", "all", "analyse: all, anomalies or timestamps")
	tag := fl.Bool("tag", false, "analyse: tag every event the anomaly checks list, so tag:anomaly finds them")
	format := fl.String("format", "", "export: csv, jsonl, timesketch or bodyfile; report: html or json; analyse: text or json")
	query := fl.String("query", "", "export only events matching this search")
	group := fl.String("group", "", "export only events in this group")
	out := fl.String("o", "", "output file (default stdout)")
	hostName := fl.String("host", "", "ingest: the computer the files come from")
	notFromHost := fl.String("not-from-host", "", "ingest: the files come from no single computer; where from")
	parseTimeout := fl.Duration("parse-timeout", 30*time.Minute, "stop a parser that runs longer than this (0 for no limit)")
	maxUnpack := fl.Int64("max-unpack-gb", ingest.DefaultMaxUnpack>>30, "most that one submission's archives may expand to, in GiB")
	inProcess := fl.Bool("in-process", false, "parse in this process instead of an isolated worker")
	fl.Parse(os.Args[2:])
	if *caseDir == "" {
		fatal("--case is required")
	}
	if cmd == "serve" {
		if err := web.CheckListen(*listen); err != nil {
			fatal(err)
		}
	}
	if err := os.MkdirAll(*caseDir, 0o750); err != nil {
		fatal(err)
	}
	release, err := caselock.Acquire(*caseDir)
	if err != nil {
		fatal(err)
	}
	// fatal exits without running defers, so everything that must be undone
	// is undone through this instead.
	var s *store.Store
	cleanup = func() {
		if s != nil {
			s.Close()
		}
		release()
	}
	defer cleanup()

	if s, err = store.Open(filepath.Join(*caseDir, "case.db"), *examiner); err != nil {
		fatal(err)
	}
	v, err := vault.Open(*caseDir)
	if err != nil {
		fatal(err)
	}
	in := &ingest.Ingester{S: s, V: v, ParseTimeout: *parseTimeout, MaxUnpack: *maxUnpack << 30}
	if !*inProcess {
		exe, err := os.Executable()
		if err != nil {
			fatal(fmt.Errorf("cannot find this program to start parser workers (%w); use --in-process", err))
		}
		in.WorkerExe, in.WorkerArgs = exe, []string{"worker"}
	}
	// This process holds the case lock, so any run still open was left by a
	// process that stopped part-way. Seal those before doing anything else.
	if sealed, err := s.SealInterrupted(); err != nil {
		fatal(err)
	} else if len(sealed) > 0 {
		fmt.Fprintf(os.Stderr, "atropos: %d parse run(s) were cut short when Atropos last stopped. They are marked \"interrupted\"; parse those items again.\n", len(sealed))
	}
	if *zone != "" {
		loc, err := time.LoadLocation(*zone)
		if err != nil {
			fatal(fmt.Errorf("--local-zone: %w", err))
		}
		in.ExaminerZone, in.ExaminerZoneName = loc, *zone
		s.Audit("case.local_zone", "case", map[string]any{"zone": *zone, "stated_by": *examiner})
	}

	switch cmd {
	case "serve":
		token, err := web.NewToken()
		if err != nil {
			fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		s.Audit("session.start", "case", map[string]any{"listen": *listen, "tool_version": store.ToolVersion, "isolated_parsers": !*inProcess})
		// A case made by an earlier version lacks the indexes and run
		// summaries that keep searches fast on millions of events. They are
		// built while the page is in use; until then searches work as before.
		go func() {
			if err := s.BuildDerived(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "atropos: preparing faster searches for this case:", err)
			}
		}()
		err = web.Serve(ctx, *listen, token, s, in, func() {
			fmt.Printf("Atropos %s — case %s\n\nOpen this address (it signs your browser in; keep it private):\n\n  http://%s/?token=%s\n\nPress Ctrl+C to stop.\n", store.ToolVersion, *caseDir, *listen, token)
		})
		if err != nil {
			fatal(err)
		}
		if in.Status().Busy {
			fmt.Fprintln(os.Stderr, "atropos: stopping while evidence was still being parsed. That item will be marked \"interrupted\" next time; parse it again then.")
		}
		s.Audit("session.end", "case", map[string]any{"parsing_in_progress": in.Status().Busy})
	case "ingest":
		if fl.NArg() == 0 {
			fatal("nothing to ingest")
		}
		batch, err := s.NextBatch()
		if err != nil {
			fatal(err)
		}
		switch {
		case *hostName != "" && *notFromHost != "":
			fatal("give --host or --not-from-host, not both")
		case *hostName != "":
			h, err := s.AddHost(*hostName)
			if err != nil {
				fatal(err)
			}
			if err := s.AssignBatch(batch, &h.ID, ""); err != nil {
				fatal(err)
			}
		case *notFromHost != "":
			if err := s.AssignBatch(batch, nil, *notFromHost); err != nil {
				fatal(err)
			}
		default:
			fmt.Fprintln(os.Stderr, "atropos: no --host given: these files are assigned to no host (assign the submission on the Evidence tab later)")
		}
		var top []*store.Evidence
		failed := 0
		for _, root := range fl.Args() {
			err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					// A folder that cannot be read (no permission, say) is
					// reported and recorded; it does not stop the rest.
					failed++
					fmt.Fprintf(os.Stderr, "could not read: %s: %v\n", p, err)
					s.Audit("evidence.intake_failed", "case", map[string]any{"path": p, "error": err.Error(), "batch": batch})
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if !d.Type().IsRegular() {
					return nil
				}
				e, err := in.IntakePath(batch, p)
				if err != nil {
					failed++
					fmt.Fprintf(os.Stderr, "intake failed: %s: %v\n", p, err)
					s.Audit("evidence.intake_failed", "case", map[string]any{"path": p, "error": err.Error(), "batch": batch})
					return nil
				}
				top = append(top, e)
				// A file's alternate data streams (where a download came
				// from, among them) are evidence too, and are not part of
				// its content.
				streams, errs := in.IntakeStreams(batch, p, e)
				top = append(top, streams...)
				for _, err := range errs {
					failed++
					fmt.Fprintf(os.Stderr, "stream not read: %v\n", err)
					s.Audit("evidence.intake_failed", "case", map[string]any{"path": p, "error": err.Error(), "batch": batch})
				}
				return nil
			})
			if err != nil {
				fatal(err)
			}
		}
		in.Process(top)
		list, _ := s.ListEvidence()
		var total int64
		for _, e := range list {
			if e.BatchID != batch {
				continue
			}
			total += e.EventCount
			fmt.Printf("%-11s %-24s %8d events  %s\n", e.Status, e.Kind, e.EventCount, e.Origin)
			if e.Notes != "" {
				fmt.Printf("            note: %s\n", e.Notes)
			}
		}
		fmt.Printf("submission %d: %d events on the timeline\n", batch, total)
		if failed > 0 {
			fmt.Fprintf(os.Stderr, "atropos: %d file(s) could not be read and are NOT in the case. Each is recorded in the audit log.\n", failed)
			cleanup()
			os.Exit(1)
		}
	case "verify":
		rep, err := in.Verify()
		if err != nil {
			fatal(err)
		}
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		if !rep.OK {
			cleanup()
			os.Exit(1)
		}
	case "export":
		if *format == "" {
			*format = "csv"
		}
		w, done := output(*out)
		res, err := web.ExportWith(s, store.Query{Text: *query, Group: *group}, *format, w)
		done()
		if err != nil {
			fatal(err)
		}
		details := map[string]any{"format": *format, "query": *query, "group": *group, "events": res.Events, "output": *out}
		if *format == "bodyfile" {
			details["lines"], details["left_out_no_file_time"] = res.Lines, res.LeftOut
			fmt.Fprintf(os.Stderr, "bodyfile: %d line(s) from %d file-time event(s); %d event(s) that are not file times were left out\n", res.Lines, res.Events, res.LeftOut)
		}
		s.Audit("export", "case", details)
	case "analyse", "analyze":
		if *format == "" {
			*format = "text"
		}
		if *format != "text" && *format != "json" {
			fatal("analyse --format must be text or json")
		}
		if *check != "all" && *check != "anomalies" && *check != "timestamps" {
			fatal("analyse --check must be all, anomalies or timestamps")
		}
		if *tag && *check == "timestamps" {
			fatal("analyse --tag tags what the anomaly checks find; use --check all or anomalies")
		}
		var anom *analysis.AnomalyReport
		var times *analysis.Report
		var err error
		if *check != "timestamps" {
			if anom, err = analysis.Anomalies(s); err != nil {
				fatal(err)
			}
		}
		if *check != "anomalies" {
			if times, err = analysis.Timestomp(s); err != nil {
				fatal(err)
			}
		}
		w, done := output(*out)
		if *format == "json" {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			switch *check {
			case "anomalies":
				err = enc.Encode(anom)
			case "timestamps":
				err = enc.Encode(times)
			default:
				err = enc.Encode(map[string]any{"anomalies": anom, "timestamps": times})
			}
		} else {
			if anom != nil {
				err = analysis.WriteAnomaliesText(w, anom)
			}
			if anom != nil && times != nil {
				fmt.Fprintln(w)
			}
			if times != nil && err == nil {
				err = analysis.WriteText(w, times)
			}
		}
		done()
		if err != nil {
			fatal(err)
		}
		if anom != nil {
			s.Audit("analysis.anomalies", "case", map[string]any{"findings": anom.Counts, "scanned": anom.Scanned, "output": *out})
			if *tag {
				n, err := analysis.TagAnomalies(s, anom)
				if err != nil {
					fatal(err)
				}
				s.Audit("analysis.anomalies.tag", "case", map[string]any{"findings": anom.Counts, "tags_added": n})
				fmt.Fprintf(os.Stderr, "tagged: %d tag(s) added; search the timeline for tag:anomaly\n", n)
			}
		}
		if times != nil {
			s.Audit("analysis.timestamps", "case", map[string]any{"findings": times.Counts, "compared": times.Compared, "output": *out})
		}
	case "report":
		if *format == "" {
			*format = "html"
		}
		if *format != "html" && *format != "json" {
			fatal("report --format must be html or json")
		}
		rep, err := report.Build(s, in)
		if err != nil {
			fatal(err)
		}
		w, done := output(*out)
		err = report.Write(s, rep, *format, w)
		done()
		if err != nil {
			fatal(err)
		}
		if !rep.Integrity.OK {
			fmt.Fprintln(os.Stderr, "atropos: the report was written, but the case did NOT verify. See its Integrity section.")
			cleanup()
			os.Exit(1)
		}
	}
}

// output opens the -o file, or standard output when there is none.
func output(path string) (io.Writer, func()) {
	if path == "" {
		return os.Stdout, func() {}
	}
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	return f, func() {
		if err := f.Close(); err != nil {
			fatal(err)
		}
	}
}

func defaultExaminer() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

var cleanup = func() {}

func fatal(v any) {
	fmt.Fprintln(os.Stderr, "atropos:", v)
	cleanup()
	os.Exit(1)
}
