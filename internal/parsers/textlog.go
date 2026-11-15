package parsers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

// textParser handles line-oriented logs. It recognises a small set of
// unambiguous formats; anything else is left to generic handling, which still
// indexes the full text. Formats whose day/month order is ambiguous
// (01/02/2024) are deliberately not guessed at.
type textParser struct{}

func (textParser) Name() string { return "text-log" }
func (textParser) Version() string {
	return "8 (native: json, w3c, access-log, iso-8601, syslog, scheduled-task xml, notepad++ xml, zone.identifier, powershell transcript, defender mplog, browser bookmarks, preferences, extensions and session json)"
}

const (
	maxWholeJSON = 256 << 20
	maxUTF16     = 512 << 20
	maxLine      = 8 << 20
	maxMessage   = 4000
)

var (
	reISO    = regexp.MustCompile(`^\s*[\[(]?(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d{1,9}))?\s?(Z|[+-]\d{2}:?\d{2})?`)
	reAccess = regexp.MustCompile(`^(\S+) \S+ (\S+) \[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`)
	reSyslog = regexp.MustCompile(`^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$`)
	months   = map[string]int{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
)

var jsonTimeKeys = []string{"eventtime", "@timestamp", "timestamp", "timecreated", "timegenerated", "time", "ts", "datetime", "date",
	"createddatetime", "creationtime", "utctime", "_time", "published", "activitydatetime", "created_at", "start_time", "eventtimestamp"}
var jsonMsgKeys = []string{"message", "msg", "eventname", "operation", "operationname", "activitydisplayname", "event", "action", "log", "summary"}
var jsonUserKeys = []string{"user", "username", "userid", "userprincipalname", "user_name", "account"}
var jsonHostKeys = []string{"host", "hostname", "computer", "computername", "host_name"}

func (textParser) Parse(ctx *Context) error {
	var r io.Reader = io.NewSectionReader(ctx.File, 0, ctx.Size)
	if ctx.Kind == detect.TextUTF16 {
		if ctx.Size > maxUTF16 {
			return fmt.Errorf("UTF-16 text larger than %d bytes is not decoded", maxUTF16)
		}
		raw, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		r = bytes.NewReader(decodeUTF16(raw))
	}
	br := bufio.NewReaderSize(r, 1<<20)
	// A UTF-8 byte order mark is not content; left in place it hides the
	// first line's format from every check below.
	if bom, _ := br.Peek(3); bytes.Equal(bom, []byte{0xEF, 0xBB, 0xBF}) {
		br.Discard(3)
	}

	// A scheduled task definition is XML, and small.
	if head, _ := br.Peek(2048); looksLikeTask(head) && ctx.Size <= 8<<20 {
		doc, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		return parseTask(ctx, doc)
	}

	// Notepad++ keeps its session and its history as XML.
	if head, _ := br.Peek(2048); looksLikeNotepadPP(head) && ctx.Size <= maxNotepadPP {
		doc, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		return parseNotepadPP(ctx, doc)
	}

	// A PowerShell transcript.
	if head, _ := br.Peek(1024); looksLikeTranscript(head) && ctx.Size <= maxTranscript {
		doc, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		return parseTranscript(ctx, doc)
	}

	// A Zone.Identifier stream, saved as an item of its own.
	if head, _ := br.Peek(64); looksLikeZone(head) && ctx.Size <= 1<<20 {
		doc, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		return parseZoneFile(ctx, doc)
	}

	// Microsoft Defender's own log.
	if head, _ := br.Peek(64 << 10); looksLikeMPLog(head) {
		return parseMPLog(ctx, br)
	}

	// A whole-file JSON document (an array of records, or an object wrapping one).
	if ctx.Size <= maxWholeJSON {
		if first, _ := peekNonSpace(br); first == '[' || first == '{' {
			all, err := io.ReadAll(br)
			if err != nil {
				return err
			}
			if first == '{' {
				if handled, err := browserJSON(ctx, all); handled {
					return err
				}
			}
			if recs, ok := jsonRecords(all); ok {
				return emitJSONRecords(ctx, recs)
			}
			br = bufio.NewReaderSize(bytes.NewReader(all), 1<<20)
		}
	}

	// Line mode. The format is chosen from a sample, then applied throughout.
	var sample []string
	var buffered bytes.Buffer
	sc := newScanner(io.TeeReader(br, &buffered))
	for sc.Scan() && len(sample) < 200 {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			sample = append(sample, sc.Text())
		}
	}
	format := chooseFormat(sample)
	if format == "" {
		return ErrNothingExtracted
	}
	// Re-read from the start: everything consumed so far is in buffered,
	// including whatever the scanner read ahead; the rest is still in br.
	full := io.MultiReader(bytes.NewReader(buffered.Bytes()), br)
	switch format {
	case "syslog":
		return parseSyslog(ctx, full)
	default:
		return parseLines(ctx, full, format)
	}
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256<<10), maxLine)
	return sc
}

func peekNonSpace(br *bufio.Reader) (byte, error) {
	for i := 1; i <= 4096; i++ {
		b, err := br.Peek(i)
		if len(b) < i {
			return 0, err
		}
		c := b[i-1]
		if c == 0xEF || c == 0xBB || c == 0xBF || c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		return c, nil
	}
	return 0, nil
}

func decodeUTF16(raw []byte) []byte {
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		raw = raw[2:]
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return []byte(string(utf16.Decode(u)))
}

func chooseFormat(sample []string) string {
	if len(sample) == 0 {
		return ""
	}
	score := map[string]int{}
	for _, l := range sample {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "#Fields:"):
			score["w3c"] += len(sample) // decisive
		case strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") && json.Valid([]byte(t)):
			score["jsonl"]++
		case reAccess.MatchString(l):
			score["access"]++
		case reISO.MatchString(l):
			score["iso"]++
		case reSyslog.MatchString(l):
			score["syslog"]++
		}
	}
	best, bestN := "", 0
	for _, f := range []string{"w3c", "jsonl", "access", "iso", "syslog"} {
		if score[f] > bestN {
			best, bestN = f, score[f]
		}
	}
	need := len(sample) * 3 / 10
	if need < 2 {
		need = 2
	}
	if len(sample) == 1 {
		need = 1
	}
	if bestN < need {
		return ""
	}
	return best
}

// parseISOTime parses an ISO-8601-style timestamp. hasZone reports whether the
// value carried its own offset.
func parseISOTime(s string) (t time.Time, hasZone, ok bool) {
	s = strings.TrimSpace(s)
	for _, l := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999Z0700", "2006-01-02 15:04:05.999999999 Z0700", "2006-01-02 15:04:05.999999999 Z07:00"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, true, true
		}
	}
	for _, l := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05,999999999", "2006-01-02 15:04:05,999999999"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, false, true
		}
	}
	return time.Time{}, false, false
}

func stampFromISO(ctx *Context, raw string) (timeutil.Stamp, bool) {
	t, zoned, ok := parseISOTime(raw)
	if !ok || !timeutil.Plausible(t) {
		return timeutil.Stamp{}, false
	}
	if zoned {
		return timeutil.FromExplicit(t, raw), true
	}
	return timeutil.FromLocal(t, raw, ctx.Local), true
}

func stampFromEpoch(f float64, raw string) (timeutil.Stamp, bool) {
	var t time.Time
	switch {
	case f <= 0:
		return timeutil.Stamp{}, false
	case f < 1e11:
		sec := int64(f)
		t = time.Unix(sec, int64((f-float64(sec))*1e9))
	case f < 1e14:
		t = time.UnixMilli(int64(f))
	case f < 1e17:
		t = time.UnixMicro(int64(f))
	default:
		t = time.Unix(0, int64(f))
	}
	return timeutil.FromTimeNative(t, "epoch "+raw)
}

// ------------------------------------------------------------------ JSON ----

func jsonRecords(all []byte) ([]map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(all))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	if dec.More() {
		return nil, false // several top-level values: JSON lines, handled line by line
	}
	asObjs := func(v any) []map[string]any {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			return nil
		}
		var out []map[string]any
		for _, x := range arr {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	if recs := asObjs(doc); recs != nil {
		return recs, true
	}
	if m, ok := doc.(map[string]any); ok {
		var best []map[string]any
		for _, v := range m {
			if recs := asObjs(v); len(recs) > len(best) {
				best = recs
			}
		}
		if best != nil {
			return best, true
		}
		return []map[string]any{m}, true
	}
	return nil, false
}

func lookupFold(m map[string]any, keys []string) (string, any) {
	lower := make(map[string]string, len(m))
	for k := range m {
		lower[strings.ToLower(k)] = k
	}
	for _, k := range keys {
		if orig, ok := lower[k]; ok && m[orig] != nil {
			return orig, m[orig]
		}
	}
	return "", nil
}

func jsonStamp(ctx *Context, m map[string]any) (timeutil.Stamp, string, bool) {
	key, v := lookupFold(m, jsonTimeKeys)
	switch x := v.(type) {
	case string:
		if s, ok := stampFromISO(ctx, x); ok {
			return s, key, true
		}
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			s, ok := stampFromEpoch(f, x)
			return s, key, ok
		}
	case json.Number:
		if f, err := x.Float64(); err == nil {
			s, ok := stampFromEpoch(f, x.String())
			return s, key, ok
		}
	case float64:
		s, ok := stampFromEpoch(x, strconv.FormatFloat(x, 'f', -1, 64))
		return s, key, ok
	}
	return timeutil.Stamp{}, key, false
}

func jsonEvent(ctx *Context, m map[string]any, ref string) (Event, bool) {
	stamp, key, ok := jsonStamp(ctx, m)
	if !ok {
		return Event{}, false
	}
	compact, _ := json.Marshal(m)
	_, mv := lookupFold(m, jsonMsgKeys)
	msg := str(mv)
	if src := str(m["eventSource"]); src != "" && msg != "" {
		msg = src + " " + msg
	}
	if msg == "" {
		msg = string(compact)
	}
	_, uv := lookupFold(m, jsonUserKeys)
	user := ""
	if s, ok := uv.(string); ok {
		user = s
	}
	if user == "" {
		if ui, ok := m["userIdentity"].(map[string]any); ok {
			user = firstNonEmpty(ui, "userName", "arn", "principalId")
		}
	}
	_, hv := lookupFold(m, jsonHostKeys)
	host, _ := hv.(string)
	if host == "" {
		host = ctx.Host
	}
	fields := map[string]any{"record": m, "time_field": key}
	if len(compact) > 64<<10 {
		fields = map[string]any{"time_field": key, "record_truncated": true, "record_prefix": trunc(string(compact), 64<<10)}
	}
	return Event{Stamp: stamp, Type: "logged", Category: CatLog, Source: "log", Host: clean(host), User: clean(user),
		Message: trunc(clean(msg), maxMessage), Fields: fields, Ref: ref}, true
}

func emitJSONRecords(ctx *Context, recs []map[string]any) error {
	skipped := 0
	for i, m := range recs {
		ev, ok := jsonEvent(ctx, m, fmt.Sprintf("record %d", i+1))
		if !ok {
			skipped++
			continue
		}
		if err := ctx.Emit(ev); err != nil {
			return err
		}
	}
	if skipped == len(recs) {
		return ErrNothingExtracted
	}
	if skipped > 0 {
		ctx.Warn("%d of %d JSON records had no recognised timestamp field and were not placed on the timeline", skipped, len(recs))
	}
	return nil
}

// ----------------------------------------------------------------- lines ----

func parseLines(ctx *Context, r io.Reader, format string) error {
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
	var w3cFields []string
	w3cLocal := false
	lineNo, orphan := 0, 0
	for sc.Scan() {
		lineNo++
		line := clean(sc.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}
		ref := fmt.Sprintf("line %d", lineNo)
		var ev Event
		ok := false
		switch format {
		case "jsonl":
			var m map[string]any
			dec := json.NewDecoder(strings.NewReader(line))
			dec.UseNumber()
			if dec.Decode(&m) == nil {
				ev, ok = jsonEvent(ctx, m, ref)
			}
		case "access":
			if g := reAccess.FindStringSubmatch(line); g != nil {
				if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", g[3]); err == nil && timeutil.Plausible(t) {
					user := g[2]
					if user == "-" {
						user = ""
					}
					req := strings.Fields(g[4])
					path := ""
					if len(req) >= 2 {
						path = req[1]
					}
					ev = Event{Stamp: timeutil.FromExplicit(t, g[3]), Type: "http-request", Category: CatNetwork, Source: "log", Host: ctx.Host, User: user, Path: path,
						Message: trunc(line, maxMessage),
						Fields:  map[string]any{"client": g[1], "request": g[4], "status": g[5], "bytes": g[6], "referrer": g[7], "user_agent": g[8]}, Ref: ref}
					ok = true
				}
			}
		case "w3c":
			if strings.HasPrefix(line, "#") {
				if strings.HasPrefix(line, "#Fields:") {
					w3cFields = strings.Fields(strings.TrimPrefix(line, "#Fields:"))
				}
				if strings.HasPrefix(strings.ToLower(line), "#time format:") && strings.Contains(strings.ToLower(line), "local") {
					w3cLocal = true
				}
				continue
			}
			ev, ok = w3cEvent(ctx, line, w3cFields, w3cLocal, ref)
		case "iso":
			if g := reISO.FindStringSubmatch(line); g != nil {
				raw := g[1] + "T" + g[2]
				if g[3] != "" {
					raw += "." + g[3]
				}
				raw += g[4]
				if stamp, sok := stampFromISO(ctx, raw); sok {
					stamp.Raw = strings.TrimSpace(g[0])
					ev = Event{Stamp: stamp, Type: "logged", Category: CatLog, Source: "log", Host: ctx.Host, Message: trunc(line, maxMessage), Ref: ref}
					ok = true
				}
			}
		}
		if ok {
			if err := flush(); err != nil {
				return err
			}
			e := ev
			pending = &e
			continue
		}
		// A line with no timestamp belongs to the entry above it.
		if pending != nil && len(pending.Message) < maxMessage {
			pending.Message = trunc(pending.Message+"\n"+line, maxMessage)
		} else if pending == nil {
			orphan++
		}
	}
	if err := sc.Err(); err != nil {
		ctx.Warn("reading stopped at line %d: %v", lineNo, err)
	}
	if orphan > 0 {
		ctx.Note("%d lines before the first timestamped entry were not placed on the timeline", orphan)
	}
	return flush()
}

func w3cEvent(ctx *Context, line string, fieldNames []string, local bool, ref string) (Event, bool) {
	if len(fieldNames) == 0 {
		return Event{}, false
	}
	parts := strings.Fields(line)
	fields := map[string]any{}
	for i, n := range fieldNames {
		if i < len(parts) && parts[i] != "-" {
			fields[n] = parts[i]
		}
	}
	d, _ := fields["date"].(string)
	tm, _ := fields["time"].(string)
	if d == "" || tm == "" {
		return Event{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05", d+" "+tm)
	if err != nil || !timeutil.Plausible(t) {
		return Event{}, false
	}
	var stamp timeutil.Stamp
	if local {
		// The file states "#Time Format: Local" (as Windows Firewall logs do).
		stamp = timeutil.FromLocal(t, d+" "+tm, ctx.Local)
	} else {
		// W3C extended log format defines date and time as UTC.
		stamp, _ = timeutil.FromTimeNative(t, d+" "+tm)
	}
	user, _ := fields["cs-username"].(string)
	path, _ := fields["cs-uri-stem"].(string)
	return Event{Stamp: stamp, Type: "logged", Category: CatLog, Source: "log", Host: ctx.Host, User: user, Path: path,
		Message: trunc(line, maxMessage), Fields: fields, Ref: ref}, true
}

// parseSyslog handles the classic syslog line, which records neither year nor
// zone. The year is inferred by anchoring the last entry at or before the date
// the evidence was received and walking backwards across year boundaries. Every
// event says so in its fields, and the zone follows the case's local context.
func parseSyslog(ctx *Context, r io.Reader) error {
	all, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	type entry struct {
		month        int
		g            []string
		line         string
		lineNo       int
		continuation string
	}
	var entries []entry
	sc := newScanner(bytes.NewReader(all))
	lineNo, orphan := 0, 0
	for sc.Scan() {
		lineNo++
		line := clean(sc.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}
		if g := reSyslog.FindStringSubmatch(line); g != nil && months[g[1]] != 0 {
			entries = append(entries, entry{month: months[g[1]], g: g, line: line, lineNo: lineNo})
		} else if len(entries) > 0 {
			e := &entries[len(entries)-1]
			if len(e.continuation) < maxMessage {
				e.continuation += "\n" + line
			}
		} else {
			orphan++
		}
	}
	if len(entries) == 0 {
		return ErrNothingExtracted
	}
	years := make([]int, len(entries))
	y := ctx.ReceivedYear
	if entries[len(entries)-1].month > ctx.ReceivedMonth {
		y--
	}
	years[len(entries)-1] = y
	for i := len(entries) - 2; i >= 0; i-- {
		if entries[i].month-entries[i+1].month >= 6 { // e.g. Dec immediately before Jan
			y--
		}
		years[i] = y
	}
	ctx.Note("syslog lines carry no year; years were inferred backwards from the date the evidence was received (%d-%02d)", ctx.ReceivedYear, ctx.ReceivedMonth)
	for i, e := range entries {
		g := e.g
		raw := fmt.Sprintf("%s %s %s", g[1], g[2], g[3])
		t, err := time.Parse("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s %s %s", years[i], g[1], g[2], g[3]))
		if err != nil {
			continue
		}
		fields := map[string]any{"program": g[5], "year_inferred": years[i]}
		if g[6] != "" {
			fields["pid"] = g[6]
		}
		if err := ctx.Emit(Event{
			Stamp: timeutil.FromLocal(t, raw, ctx.Local), Type: "logged", Category: CatLog, Source: "log",
			Host: g[4], Message: trunc(e.line+e.continuation, maxMessage), Fields: fields,
			Ref: fmt.Sprintf("line %d", e.lineNo),
		}); err != nil {
			return err
		}
	}
	if orphan > 0 {
		ctx.Note("%d lines before the first timestamped entry were not placed on the timeline", orphan)
	}
	return nil
}
