package parsers

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// MPLog is Microsoft Defender's own running log, in
// ProgramData\Microsoft\Windows Defender\Support\MPLog-<date>-<time>.log. It
// is UTF-16 text and is kept for months, far longer than the event log. Most
// lines open with a time to the millisecond and no zone:
//
//	2026-07-22T18:05:38.936 [RTP] Setting ...
//
// These are UTC. That was checked on a real log from a machine on British
// Summer Time: the blocks of behaviour-monitoring telemetry carry each
// process's creation time as a FILETIME, which is UTC by definition, and
// those fall minutes either side of the line times around them, where a
// local clock would have put them an hour apart.
//
// Lines of a kind an examiner looks for are given a type and a category of
// their own; every other timed line is kept as "logged". Between the timed
// lines are blocks with no time of their own. One of them is read: a
// "BEGIN BM telemetry" block names a program and when its process was
// created.

var (
	reMPLine      = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}) (\S.*)$`)
	reMPDetection = regexp.MustCompile(`^DETECTION(?:EVENT|_(?:ADD|MERGE)#\d+|_CLEANEVENT) (?:MPSOURCE_(\w+) )?(?:(MP_THREAT_ACTION_\w+) (?:0x[0-9a-fA-F]+ )?)?(\S+) (\w+):(.*)$`)
	reMPImpact    = regexp.MustCompile(`^ProcessImageName: (.*?), Pid: (\d+), TotalTime: (\d+), Count: (\d+), MaxTime: (\d+), MaxTimeFile: (.*?),? ?(?:EstimatedImpact: (\d+)%)?\s*$`)
	reMPCmdLine   = regexp.MustCompile(`^Engine:command line reported as (\w+): (.*)$`)
	mpMarkers     = []string{"[RTP]", "Engine:", "[Cloud]", "[WSC]", "[ESU]", "BEGIN BM telemetry", "ProcessImageName:", "DETECTIONEVENT", "Dynamic Signature", "[Mini-filter]", "MpCmdRun", "[NRI]"}
)

const mpTimeLayout = "2006-01-02T15:04:05.000"

// looksLikeMPLog reports whether text opens as an MPLog does: its first line
// with anything on it is timed to the millisecond with no zone, and at least
// two of the things only Defender writes appear near the top.
func looksLikeMPLog(head []byte) bool {
	first := bytes.TrimLeft(bytes.TrimPrefix(head, []byte{0xEF, 0xBB, 0xBF}), "\r\n \t")
	end := bytes.IndexByte(first, '\n')
	if end < 0 {
		end = len(first)
	}
	if !reMPLine.Match(bytes.TrimRight(first[:end], "\r")) {
		return false
	}
	n := 0
	for _, m := range mpMarkers {
		if bytes.Contains(head, []byte(m)) {
			n++
		}
	}
	return n >= 2
}

// mpClassify gives a timed line its type, category, path and fields.
func mpClassify(rest string) (typ, cat, path string, fields map[string]any) {
	switch {
	case strings.HasPrefix(rest, "DETECTION"):
		typ, cat = "defender-detection (mplog)", CatSecurity
		if strings.HasPrefix(rest, "DETECTION_CLEANEVENT") {
			typ = "defender-action (mplog)"
		}
		if g := reMPDetection.FindStringSubmatch(rest); g != nil {
			loc := strings.TrimSuffix(strings.TrimSpace(g[5]), ";")
			// DETECTION_ADD lines end with a property bag.
			if i := strings.Index(loc, " PropBag ["); i >= 0 {
				loc = loc[:i]
			}
			fields = map[string]any{"threat_name": g[3], "resource_type": g[4], "resource": loc}
			if g[1] != "" {
				fields["detection_source"] = strings.ToLower(g[1])
			}
			if g[2] != "" {
				fields["action"] = strings.ToLower(strings.TrimPrefix(g[2], "MP_THREAT_ACTION_"))
			}
			path = loc
		}
	case strings.HasPrefix(rest, "Engine:command line reported as "):
		typ, cat = "defender-command-line-reported", CatSecurity
		if g := reMPCmdLine.FindStringSubmatch(rest); g != nil {
			fields = map[string]any{"reported_as": g[1], "command_line": g[2]}
		}
	case strings.Contains(rest, "Engine VFZ block:"):
		typ, cat = "defender-block (mplog)", CatSecurity
		if i := strings.Index(rest, "Engine VFZ block:"); i >= 0 {
			path = strings.TrimSpace(rest[i+len("Engine VFZ block:"):])
			if j := strings.Index(path, ". status="); j >= 0 {
				path = path[:j]
			}
		}
	case strings.Contains(rest, "[Exclusion]"):
		typ, cat = "defender-exclusion (mplog)", CatSecurity
	case strings.HasPrefix(rest, "ProcessImageName: "):
		// Defender's account of what a running process cost it in scanning:
		// the process was running at about this time.
		typ, cat = "process-scan-impact (defender)", CatExecution
		if g := reMPImpact.FindStringSubmatch(rest); g != nil {
			path = g[1]
			fields = map[string]any{"process_image": g[1], "pid": atoiOr(g[2]), "total_time_ms": atoiOr(g[3]), "files_scanned": atoiOr(g[4]),
				"max_time_ms": atoiOr(g[5]), "max_time_file": g[6]}
			if g[7] != "" {
				fields["estimated_impact_percent"] = atoiOr(g[7])
			}
		}
	default:
		typ, cat = "logged", CatLog
	}
	return
}

func atoiOr(s string) any {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return s
}

func parseMPLog(ctx *Context, r io.Reader) error {
	sc := newScanner(r)
	var pending *Event
	flush := func() error {
		if pending == nil {
			return nil
		}
		e := *pending
		pending = nil
		return ctx.Emit(e)
	}
	// A telemetry block being read: nil outside one.
	var bm map[string]any
	bmLine := 0
	counts := map[string]int{}
	lineNo, orphan, untimed := 0, 0, 0
	seen := false // a timed line has been read
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(clean(sc.Text()), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if g := reMPLine.FindStringSubmatch(line); g != nil {
			t, err := time.Parse(mpTimeLayout, g[1])
			stamp, ok := timeutil.FromTimeNative(t, g[1])
			if err == nil && ok {
				if err := flush(); err != nil {
					return err
				}
				seen = true
				typ, cat, path, fields := mpClassify(g[2])
				counts[typ]++
				pending = &Event{Stamp: stamp, Type: typ, Category: cat, Source: "defender", Host: ctx.Host, Path: path,
					Message: trunc(g[2], maxMessage), Fields: fields, Ref: fmt.Sprintf("line %d", lineNo)}
				continue
			}
		}
		switch {
		case line == "BEGIN BM telemetry":
			bm, bmLine = map[string]any{}, lineNo
			continue
		case line == "END BM telemetry":
			if bm != nil {
				if err := flush(); err != nil {
					return err
				}
				if ok, err := emitBM(ctx, bm, bmLine); err != nil {
					return err
				} else if ok {
					counts["process-created (defender telemetry)"]++
				} else {
					untimed++
				}
			}
			bm = nil
			continue
		case bm != nil:
			if i := strings.Index(line, ":"); i > 0 && len(bm) < 64 {
				bm[line[:i]] = trunc(line[i+1:], maxMessage)
			}
			continue
		}
		// Any other line with no time belongs to the entry above it.
		if pending != nil && len(pending.Message) < maxMessage {
			pending.Message = trunc(pending.Message+"\n"+line, maxMessage)
		} else if !seen {
			orphan++
		}
	}
	if err := sc.Err(); err != nil {
		ctx.Warn("reading stopped at line %d: %v", lineNo, err)
	}
	if err := flush(); err != nil {
		return err
	}
	if orphan > 0 {
		ctx.Note("%d lines before the first timed entry were not placed on the timeline", orphan)
	}
	if untimed > 0 {
		ctx.Note("%d telemetry blocks gave no process creation time and are searchable text only", untimed)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return ErrNothingExtracted
	}
	ctx.Note("Microsoft Defender log (MPLog): times are UTC. %d detection and action lines, %d reported command lines, %d blocks, %d exclusion lines, %d scan-impact lines, %d processes from telemetry blocks, %d other lines",
		counts["defender-detection (mplog)"]+counts["defender-action (mplog)"], counts["defender-command-line-reported"], counts["defender-block (mplog)"],
		counts["defender-exclusion (mplog)"], counts["process-scan-impact (defender)"], counts["process-created (defender telemetry)"], counts["logged"])
	return nil
}

// emitBM places one behaviour-monitoring telemetry block on the timeline at
// the time its process was created. That time is a FILETIME.
func emitBM(ctx *Context, bm map[string]any, lineNo int) (bool, error) {
	raw, _ := bm["ProcessCreationTime"].(string)
	ft, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return false, nil
	}
	stamp, ok := timeutil.FromFiletime(ft)
	if !ok {
		return false, nil
	}
	image, _ := bm["ImagePath"].(string)
	fields := map[string]any{}
	for k, v := range map[string]string{"ImagePath": "image_path", "ProcessID": "pid", "SessionID": "session_id", "GUID": "telemetry_guid",
		"SignatureID": "signature_id", "SigSha": "signature_sha1", "ThreatLevel": "threat_level", "Taint Info": "taint_info",
		"Operations": "operations", "CreationTime": "telemetry_written"} {
		if s, ok := bm[k].(string); ok && s != "" {
			if k == "ProcessID" || k == "SessionID" || k == "ThreatLevel" {
				fields[v] = atoiOr(strings.TrimSpace(s))
			} else {
				fields[v] = s
			}
		}
	}
	return true, ctx.Emit(Event{
		Stamp: stamp, Type: "process-created (defender telemetry)", Category: CatExecution, Source: "defender", Host: ctx.Host, Path: image,
		Message: fmt.Sprintf("Process created: %s (pid %v), recorded by Defender behaviour monitoring", image, fields["pid"]),
		Fields:  fields, Ref: fmt.Sprintf("telemetry block at line %d", lineNo),
	})
}
