// Package report produces the case report: one document stating what was
// examined, how, with what, and whether it still verifies. It is meant to be
// attached to a statement or handed to another examiner, so it is complete
// in itself (the HTML form has no external resources) and it says plainly
// which timestamps rest on an assumption.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/ingest"
	"github.com/DanDreadless/atropos/internal/store"
)

// htmlAuditLimit keeps the HTML report openable for a very large case. The
// JSON report always carries the whole audit trail.
const htmlAuditLimit = 5000

// groupEventLimit bounds how many events of one group are written out.
const groupEventLimit = 5000

type GroupTimeline struct {
	store.Group
	Events    []store.EventRow `json:"events"`
	Truncated bool             `json:"truncated"`
}

type Report struct {
	GeneratedUTC string                      `json:"generated_utc"`
	GeneratedBy  string                      `json:"generated_by"`
	ToolVersion  string                      `json:"tool_version"`
	Case         map[string]string           `json:"case"`
	LocalZone    string                      `json:"examiner_local_zone"`
	Integrity    ingest.Report               `json:"integrity"`
	EventCount   int64                       `json:"event_count"`
	FirstUTC     string                      `json:"first_event_utc"`
	LastUTC      string                      `json:"last_event_utc"`
	Facets       map[string]map[string]int64 `json:"facets"`
	Details      *store.AllDetails           `json:"details"`
	DetailLog    []store.DetailChange        `json:"detail_history"`
	Facts        []store.Fact                `json:"facts"`
	Evidence     []store.Evidence            `json:"evidence"`
	Runs         []store.RunRow              `json:"runs"`
	Groups       []GroupTimeline             `json:"groups"`
	Notes        []store.NoteRow             `json:"notes"`
	Audit        []store.AuditRow            `json:"audit"`
	AuditTotal   int64                       `json:"audit_total"`
}

type statedDetail struct {
	Label, Value, Actor string
	MadeUTC             int64
}

func utc(ns int64) string {
	if ns == 0 {
		return ""
	}
	return time.Unix(0, ns).UTC().Format("2006-01-02 15:04:05.000000")
}

// Build verifies the case and gathers everything the report states. The
// verification is the one recorded in the audit log by this call.
func Build(s *store.Store, in *ingest.Ingester) (*Report, error) {
	integrity, err := in.Verify()
	if err != nil {
		return nil, err
	}
	r := &Report{
		GeneratedUTC: time.Now().UTC().Format("2006-01-02 15:04:05"), GeneratedBy: s.Actor,
		ToolVersion: store.ToolVersion, LocalZone: in.ExaminerZoneName, Integrity: integrity,
	}
	if r.Case, err = s.Meta(); err != nil {
		return nil, err
	}
	sum, err := s.Summarise(store.Query{}, 1)
	if err != nil {
		return nil, err
	}
	r.EventCount, r.FirstUTC, r.LastUTC = sum.Count, utc(sum.MinTS), utc(sum.MaxTS)
	if r.Facets, err = s.Facets(); err != nil {
		return nil, err
	}
	if r.Details, err = s.Details(); err != nil {
		return nil, err
	}
	if r.DetailLog, err = s.DetailHistory(); err != nil {
		return nil, err
	}
	all, err := s.Facts("")
	if err != nil {
		return nil, err
	}
	for _, f := range all { // per-file measurements would swamp the facts that matter
		if strings.HasPrefix(f.Key, "host.") || f.Key == "hive.kind" {
			r.Facts = append(r.Facts, f)
		}
	}
	if r.Evidence, err = s.ListEvidence(); err != nil {
		return nil, err
	}
	if r.Runs, err = s.ListRuns(); err != nil {
		return nil, err
	}
	groups, err := s.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		gt := GroupTimeline{Group: g}
		rows, err := s.Search(store.Query{Group: g.Name, Limit: groupEventLimit})
		if err != nil {
			return nil, err
		}
		gt.Events, gt.Truncated = rows, g.Count > int64(len(rows))
		r.Groups = append(r.Groups, gt)
	}
	if r.Notes, err = s.AllAnnotations(); err != nil {
		return nil, err
	}
	if r.Audit, r.AuditTotal, err = s.AuditAscending(0); err != nil {
		return nil, err
	}
	return r, nil
}

// Write renders the report as "json" or "html" and records that it was made.
func Write(s *store.Store, r *Report, format string, w io.Writer) error {
	var err error
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		err = enc.Encode(r)
	case "html":
		err = page.Execute(w, r)
	default:
		return fmt.Errorf("report format must be html or json")
	}
	details := map[string]any{"format": format, "integrity_ok": r.Integrity.OK, "audit_head": r.Integrity.AuditHead}
	if err != nil {
		details["error"] = err.Error()
	}
	s.Audit("report.generate", "case", details)
	return err
}

type kv struct {
	K string
	V int64
}

func sorted(m map[string]int64) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
	return out
}

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"utc":    utc,
	"sorted": sorted,
	"short":  func(s string) string { return s },
	"deref": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
	"details": func(d json.RawMessage) string { return string(d) },
	"auditShown": func(a []store.AuditRow) []store.AuditRow {
		if len(a) > htmlAuditLimit {
			return a[len(a)-htmlAuditLimit:]
		}
		return a
	},
	// stated lists the fields that have a value, in the order they are defined.
	"stated": func(fields []store.DetailField, values map[string]store.Detail) []statedDetail {
		var out []statedDetail
		for _, f := range fields {
			if d, ok := values[f.Key]; ok {
				out = append(out, statedDetail{f.Label, d.Value, d.Actor, d.MadeUTC})
			}
		}
		return out
	},
	"auditCut": func(a []store.AuditRow) bool { return len(a) > htmlAuditLimit },
	"limit":    func() int { return htmlAuditLimit },
	"groupCap": func() int { return groupEventLimit },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Atropos case report</title>
<style>
body{font:13px/1.45 system-ui,"Segoe UI",sans-serif;color:#1b1d20;margin:28px auto;max-width:1180px;padding:0 20px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:30px 0 8px;border-bottom:2px solid #1b1d20;padding-bottom:3px}
h3{font-size:13.5px;margin:18px 0 6px}
table{border-collapse:collapse;width:100%;margin:6px 0 12px} th,td{border:1px solid #cfcfc9;padding:3px 7px;text-align:left;vertical-align:top}
th{background:#eeeeea;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em}
.mono,td.h{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;overflow-wrap:anywhere}
.ok{background:#e1f3e5;color:#1c6b34;padding:8px 12px;font-weight:700;border-radius:4px}
.bad{background:#fbe4e2;color:#b3261e;padding:8px 12px;font-weight:700;border-radius:4px}
.warn{background:#fdf0d9;color:#8a4700;padding:6px 10px;border-radius:4px;margin:6px 0}
.dim{color:#62666d} .num{text-align:right} dl{display:grid;grid-template-columns:230px 1fr;gap:3px 12px;margin:6px 0} dt{color:#62666d} dd{margin:0}
s{color:#8b9098} .pre{white-space:pre-wrap}
@media print{body{margin:0;max-width:none;font-size:10.5px} h2{break-after:avoid} tr{break-inside:avoid}}
</style></head><body>
<h1>Case report</h1>
<div class="dim">Generated {{.GeneratedUTC}} UTC by {{.GeneratedBy}} with Atropos {{.ToolVersion}}. All times in this report are UTC.</div>

<h2>Case</h2>
<dl>
<dt>Case created</dt><dd>{{index .Case "created_utc"}} by {{index .Case "created_by"}}</dd>
<dt>Created with</dt><dd>Atropos {{index .Case "tool_version"}}, storage format {{index .Case "schema_version"}}</dd>
<dt>Evidence items</dt><dd>{{len .Evidence}}</dd>
<dt>Events on the timeline</dt><dd>{{.EventCount}}{{if .EventCount}}, from {{.FirstUTC}} to {{.LastUTC}}{{end}}</dd>
<dt>Local zone stated by examiner</dt><dd>{{if .LocalZone}}{{.LocalZone}}{{else}}none stated for this session{{end}}</dd>
</dl>

{{with .Details}}{{$case := stated .CaseFields .Case}}
{{if $case}}<h2>Case details stated by the examiner</h2>
<dl>{{range $case}}<dt>{{.Label}}</dt><dd class="pre">{{.Value}}</dd>{{end}}</dl>{{end}}
{{if .Hosts}}<h2>Hosts examined</h2>
<p class="dim">Stated by the examiner. Where the evidence itself gives a value, it is shown beside the stated one.</p>
{{$fields := .HostFields}}{{range .Hosts}}<h3>{{.Name}}</h3>
<dl>{{range stated $fields .Values}}<dt>{{.Label}}</dt><dd class="pre">{{.Value}}</dd>{{end}}
{{range $k, $v := .Found}}<dt>Read from the evidence: {{$k}}</dt><dd>{{$v}}</dd>{{end}}</dl>
{{end}}{{end}}{{end}}

<h2>Integrity</h2>
{{with .Integrity}}
<div class="{{if .OK}}ok{{else}}bad{{end}}">{{if .OK}}Everything verified{{else}}VERIFICATION FAILED{{end}} at {{.CheckedUTC}}</div>
<dl>
<dt>Stored evidence files re-hashed</dt><dd>{{.EvidenceChecked}} checked, {{len .EvidenceBad}} failed</dd>
<dt>Parse runs: digests recomputed</dt><dd>{{.RunsChecked}} checked, {{len .RunsBad}} failed</dd>
<dt>Parse runs against the audit log</dt><dd>{{len .RunsUnaudited}} not vouched for, {{len .RunsMissing}} missing</dd>
<dt>Audit chain</dt><dd>{{.AuditEntries}} entries{{if .AuditBrokenAt}}, BROKEN at entry {{.AuditBrokenAt}}{{else}}, intact{{end}}</dd>
<dt>Audit chain head at verification</dt><dd class="mono">{{.AuditHead}}</dd>
</dl>
{{range .EvidenceBad}}<div class="bad">{{.}}</div>{{end}}
{{if .RunsBad}}<div class="bad">Runs whose events no longer match their digest: {{.RunsBad}}</div>{{end}}
{{if .RunsUnaudited}}<div class="bad">Runs not vouched for by the audit log: {{.RunsUnaudited}}</div>{{end}}
{{if .RunsMissing}}<div class="bad">Runs sealed in the audit log and now missing: {{.RunsMissing}}</div>{{end}}
{{end}}
<p class="dim">The head hash covers every audit entry before it. Compared with a copy recorded elsewhere, it shows whether entries were later removed from the end of the log.</p>

<h2>How time zones were established</h2>
{{$assumed := index (index .Facets "tz_source") "assumed"}}
{{if $assumed}}<div class="warn">{{$assumed}} events have a time zone that was <b>assumed</b>: their source recorded local time without a zone and none could be established, so UTC was applied. Their true time may differ by the host's UTC offset.</div>{{end}}
<table><tr><th>Zone established by</th><th class="num">Events</th></tr>
{{range sorted (index .Facets "tz_source")}}<tr><td>{{.K}}</td><td class="num">{{.V}}</td></tr>{{end}}</table>
{{if .Facts}}<h3>Host facts read from the evidence</h3>
<table><tr><th>Evidence</th><th>Fact</th><th>Value</th><th>Read from</th></tr>
{{range .Facts}}<tr><td>#{{.EvidenceID}}</td><td>{{.Key}}</td><td>{{.Value}}</td><td>{{.Detail}}</td></tr>{{end}}</table>{{end}}

<h2>What the events are</h2>
<table><tr><th>Evidence of</th><th class="num">Events</th></tr>
{{range sorted (index .Facets "category")}}<tr><td>{{.K}}</td><td class="num">{{.V}}</td></tr>{{end}}</table>
<table><tr><th>Artefact source</th><th class="num">Events</th></tr>
{{range sorted (index .Facets "source")}}<tr><td>{{.K}}</td><td class="num">{{.V}}</td></tr>{{end}}</table>

{{if .Groups}}<h2>Timelines built by the examiner</h2>
{{range .Groups}}<h3>{{.Name}} ({{.Count}} events)</h3>
{{if .Note}}<p>{{.Note}}</p>{{end}}
<p class="dim">Created {{utc .MadeUTC}} by {{.Actor}}.{{if .Truncated}} Only the first {{groupCap}} events are listed here.{{end}}</p>
{{if .Events}}<table><tr><th>Time (UTC)</th><th>MACB</th><th>Zone</th><th>Meaning</th><th>Source</th><th>Host</th><th>User</th><th>Message</th><th>Evidence</th><th>Event</th></tr>
{{range .Events}}<tr><td class="mono">{{utc .TSUTC}}</td><td class="mono">{{.MACB}}</td><td>{{.TZSource}}</td><td>{{.TSType}}</td><td>{{.Source}}</td><td>{{.Host}}</td><td>{{.User}}</td><td class="mono">{{.Message}}</td><td>#{{.EvidenceID}}</td><td>{{.ID}}</td></tr>{{end}}</table>{{end}}
{{end}}{{end}}

<h2>Evidence</h2>
<table><tr><th>#</th><th>Name and origin</th><th>Hashes</th><th class="num">Bytes</th><th>Identified as</th><th>Received</th><th>Result</th></tr>
{{range .Evidence}}<tr><td>{{.ID}}</td>
<td>{{.Name}}<div class="dim mono">{{.Origin}}</div><div class="dim">submission {{.BatchID}}{{if .ParentID}}, unpacked from #{{deref .ParentID}}{{end}}{{if .DuplicateOf}}, duplicate of #{{deref .DuplicateOf}}{{end}}</div></td>
<td class="h">SHA-256 {{.SHA256}}<br>SHA-1 {{.SHA1}}<br>MD5 {{.MD5}}</td>
<td class="num">{{.Size}}</td>
<td>{{.Kind}}<div class="dim">{{.DetectReason}}</div></td>
<td>{{utc .ReceivedUTC}}<div class="dim">{{.ReceivedBy}}</div></td>
<td>{{.Status}}{{if .Parser}} ({{.Parser}}){{end}}, {{.EventCount}} events{{if .ZoneCtx}}<div class="dim">zone: {{.ZoneCtx}}</div>{{end}}{{if .Notes}}<div class="dim">{{.Notes}}</div>{{end}}</td></tr>{{end}}</table>

<h2>Parse runs</h2>
<p class="dim">Every run is listed, including runs a later run superseded. The digest is SHA-256 over the run's events in order.</p>
<table><tr><th>Run</th><th>Evidence</th><th>Parser and version</th><th>Tool</th><th>Started</th><th>Status</th><th class="num">Events</th><th>Event digest</th></tr>
{{range .Runs}}<tr><td>{{.ID}}{{if not .Current}} <span class="dim">(superseded)</span>{{end}}</td><td>#{{.EvidenceID}}</td><td>{{.Parser}}<div class="dim">{{.ParserVersion}}</div></td><td>{{.ToolVersion}}</td><td>{{utc .StartedUTC}}</td><td>{{.Status}}</td><td class="num">{{.EventCount}}</td><td class="h">{{.EventDigest}}</td></tr>{{end}}</table>

{{if .Notes}}<h2>Examiner notes</h2>
<p class="dim">Tags, comments and group memberships. Withdrawn notes are kept and shown struck through.</p>
<table><tr><th>Event</th><th>Event time</th><th>Event</th><th>Kind</th><th>Note</th><th>By</th><th>Made</th></tr>
{{range .Notes}}<tr><td>{{.EventID}}</td><td class="mono">{{utc .EventTS}}</td><td class="mono">{{.EventMessage}}</td><td>{{.Kind}}</td><td>{{if .Retracted}}<s>{{.Body}}</s> (withdrawn){{else}}{{.Body}}{{end}}</td><td>{{.Actor}}</td><td>{{utc .MadeUTC}}</td></tr>{{end}}</table>{{end}}

<h2>Audit trail</h2>
{{if auditCut .Audit}}<div class="warn">The case has {{.AuditTotal}} audit entries. The most recent {{limit}} are shown here; the JSON form of this report contains all of them.</div>{{end}}
<table><tr><th>#</th><th>Time</th><th>By</th><th>Action</th><th>Target</th><th>Details</th><th>Entry hash</th></tr>
{{range auditShown .Audit}}<tr><td>{{.ID}}</td><td class="mono">{{utc .TS}}</td><td>{{.Actor}}</td><td>{{.Action}}</td><td>{{.Target}}</td><td class="mono">{{details .Details}}</td><td class="h">{{.Hash}}</td></tr>{{end}}</table>
</body></html>
`))
