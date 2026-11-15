package parsers

import (
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// The WMI repository (OBJECTS.DATA) holds, among everything else WMI
// knows, the event subscriptions used for persistence: an event filter (a
// query that says when), an event consumer (what to run) and a binding
// that joins the two.
//
// This is a carve, not a parse of the repository. The page map and the
// index are not read: the file is searched for instance records, which
// begin with the SHA-256 of their class name written as 64 hexadecimal
// characters in UTF-16, followed by two FILETIMEs and the length of the
// record's data. That layout was established on a real Windows 11
// repository, not taken from a description. Because pages no longer in use
// are searched too, a record may be an old version or one since deleted;
// nothing in the record says which.
//
// The first FILETIME differs between the instances of a class and the
// second is the same for all of them, on the repository examined: they are
// read as "this instance written" and "its class defined". That meaning is
// inferred, and every event says so.
type wmiParser struct{}

func (wmiParser) Name() string { return "wmi-repository" }
func (wmiParser) Version() string {
	return "1 (native carve: event filters, consumers, bindings and timers)"
}

const (
	maxWMIRepository = 2 << 30
	maxWMIRecord     = 1 << 20
	wmiWindow        = 8 << 20
	maxWMIValues     = 64
)

// The whole run is taken, because the bytes before a hash can themselves
// look like one more hexadecimal character: the record's header follows the
// end of the run, wherever the run began.
var reWMIHash = regexp.MustCompile(`(?:[0-9A-F]\x00){64,}`)

// reWMIRef is a reference to another instance, as a binding holds it.
var reWMIRef = regexp.MustCompile(`^(?:\\\\[^:]*:|[^:.]*:)?([A-Za-z_][A-Za-z0-9_]*)\.Name="(.*)"$`)

// wmiKind says what an instance of a class is in a subscription, or "".
func wmiKind(class string) string {
	switch {
	case class == "__EventFilter":
		return "filter"
	case class == "__FilterToConsumerBinding":
		return "binding"
	case class == "__IntervalTimerInstruction" || class == "__AbsoluteTimerInstruction":
		return "timer"
	case strings.HasSuffix(class, "EventConsumer") && !strings.HasPrefix(class, "__"):
		return "consumer"
	}
	return ""
}

// wmiStrings returns the strings of an instance's data in stored order. A
// string is a flag byte (0: one byte a character; 1: UTF-16), the text and
// a terminator.
func wmiStrings(data []byte) []string {
	var out []string
	for i := 0; i < len(data)-2 && len(out) < maxWMIValues; i++ {
		switch {
		case data[i] == 0 && data[i+1] >= 0x20 && data[i+1] < 0x7F:
			j := i + 1
			for j < len(data) && (data[j] >= 0x20 && data[j] < 0x7F || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j < len(data) && data[j] == 0 && j-i-1 >= 2 {
				out = append(out, string(data[i+1:j]))
				i = j - 1 // the terminator may be the next string's flag
			}
		// The class name comes first and is always in one-byte characters;
		// before it the record's own header holds bytes that would pass for
		// UTF-16. A UTF-16 string is looked for only after a string's end.
		case data[i] == 1 && i+3 < len(data) && len(out) > 0 && data[i-1] == 0:
			var u []uint16
			j := i + 1
			for ; j+1 < len(data); j += 2 {
				c := binary.LittleEndian.Uint16(data[j:])
				if c == 0 {
					break
				}
				if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
					u = nil
					break
				}
				u = append(u, c)
			}
			if len(u) >= 2 && j+1 < len(data) {
				out = append(out, string(utf16.Decode(u)))
				i = j
			}
		}
	}
	return out
}

type wmiRecord struct {
	class, kind string
	values      []string // the strings after the class name, in stored order
	written     uint64
	classTime   uint64
	offset      int64
	copies      int
}

func (wmiParser) Parse(ctx *Context) error {
	size := ctx.Size
	if size > maxWMIRepository {
		ctx.Warn("the repository is %d bytes; only the first %d were searched", size, int64(maxWMIRepository))
		size = maxWMIRepository
	}
	found := map[string]*wmiRecord{}
	var order []string
	buf := make([]byte, wmiWindow+maxWMIRecord+256)
	instances := 0
	for base := int64(0); base < size; base += wmiWindow {
		n, err := ctx.File.ReadAt(buf, base)
		if n == 0 {
			if err != nil && err != io.EOF {
				return err
			}
			break
		}
		b := buf[:n]
		for _, m := range reWMIHash.FindAllIndex(b, -1) {
			// A record is taken in the window where it starts.
			if m[0] >= wmiWindow || m[1]+20 > len(b) {
				continue
			}
			t1, t2 := binary.LittleEndian.Uint64(b[m[1]:]), binary.LittleEndian.Uint64(b[m[1]+8:])
			length := int(binary.LittleEndian.Uint32(b[m[1]+16:]))
			if length < 8 || length > maxWMIRecord || !plausibleFiletime(t1) || !plausibleFiletime(t2) {
				continue // a class definition, or not a record at all
			}
			end := m[1] + 20 + length
			if end > len(b) {
				end = len(b)
			}
			instances++
			strs := wmiStrings(b[m[1]+20 : end])
			if len(strs) == 0 {
				continue
			}
			kind := wmiKind(strs[0])
			if kind == "" {
				continue
			}
			r := &wmiRecord{class: strs[0], kind: kind, values: strs[1:], written: t1, classTime: t2, offset: base + int64(m[0])}
			key := fmt.Sprintf("%s\x00%d\x00%s", r.class, r.written, strings.Join(r.values, "\x00"))
			if have, ok := found[key]; ok {
				have.copies++
				continue
			}
			r.copies = 1
			found[key] = r
			order = append(order, key)
		}
	}
	ctx.Fact("wmi.instance_records", fmt.Sprint(instances), "instance records found by searching the repository")
	ctx.Note("recognised as a WMI repository by its content: 8 KiB pages holding records that begin with a class-name hash. It was searched for event subscriptions; the rest of the repository is not read")
	if len(order) == 0 {
		ctx.Note("no event filters, consumers or bindings were found")
		return nil
	}

	// Names the bindings refer to, so a consumer or filter can be named.
	bound := map[string]bool{}
	for _, k := range order {
		if r := found[k]; r.kind == "binding" {
			for _, v := range r.values {
				if m := reWMIRef.FindStringSubmatch(v); m != nil {
					bound[m[1]+"\x00"+m[2]] = true
				}
			}
		}
	}
	counts := map[string]int{}
	var text strings.Builder
	for _, k := range order {
		r := found[k]
		counts[r.kind]++
		fields := map[string]any{"class": clean(r.class), "record_kind": r.kind, "copies_found": r.copies,
			"time_meaning": "the record's first timestamp, read as when this instance was written; inferred from how the value varies, not documented"}
		vals := make([]string, 0, len(r.values))
		for _, v := range r.values {
			vals = append(vals, clean(trunc(v, 4000)))
		}
		fields["values"] = vals
		if s, ok := timeutil.FromFiletime(r.classTime); ok {
			fields["class_defined"] = s.UTC.Format("2006-01-02T15:04:05.0000000Z")
		}
		var msg string
		switch r.kind {
		case "filter":
			name, query := "", ""
			for _, v := range vals {
				low := strings.ToLower(strings.TrimSpace(v))
				switch {
				case strings.HasPrefix(low, "select "):
					query = v
				case name == "" && bound["__EventFilter\x00"+v]:
					name = v
				}
			}
			if name != "" {
				fields["name"] = name
			}
			if query != "" {
				fields["query"] = query
			}
			msg = fmt.Sprintf("WMI event filter %q: %s", name, trunc(query, 600))
		case "binding":
			for _, v := range vals {
				if m := reWMIRef.FindStringSubmatch(v); m != nil {
					if m[1] == "__EventFilter" {
						fields["filter"] = m[2]
					} else {
						fields["consumer_class"], fields["consumer"] = m[1], m[2]
					}
				}
			}
			msg = fmt.Sprintf("WMI subscription: filter %q runs %v %q", fields["filter"], fields["consumer_class"], fields["consumer"])
		case "consumer":
			for _, v := range vals {
				if bound[r.class+"\x00"+v] {
					fields["name"] = v
					break
				}
			}
			msg = fmt.Sprintf("WMI %s %q: %s", clean(r.class), fields["name"], trunc(strings.Join(vals, " | "), 800))
		default:
			msg = fmt.Sprintf("WMI %s: %s", clean(r.class), trunc(strings.Join(vals, " | "), 800))
		}
		msg = strings.ReplaceAll(msg, "%!q(<nil>)", `""`)
		msg = strings.ReplaceAll(msg, "%!v(<nil>)", "a consumer")
		fmt.Fprintf(&text, "%s\n", msg)
		stamp, ok := timeutil.FromFiletime(r.written)
		if !ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "wmi-subscription-record-written (inferred)", Category: CatPersistence, Source: "wmi", Host: ctx.Host,
			Message: msg, Fields: fields, Ref: fmt.Sprintf("instance record at offset %d", r.offset),
		}); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(counts))
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	kinds := make([]string, 0, len(names))
	for _, k := range names {
		kinds = append(kinds, fmt.Sprintf("%d %s records", counts[k], k))
	}
	ctx.Fact("wmi.subscription_records", strings.Join(kinds, ", "), "distinct event subscription records found")
	body := text.String()
	ctx.Text("wmi event subscriptions", len(body) > maxText, trunc(body, maxText))
	ctx.Note("%s. Pages no longer in use are searched as well, so a record may be an earlier version or one since deleted; Windows itself ships with one subscription (the \"SCM Event Log\" filter and consumer)", strings.Join(kinds, ", "))
	return nil
}

// plausibleFiletime is a FILETIME between 1990 and 2100.
func plausibleFiletime(ft uint64) bool {
	return ft > 0x01B2000000000000 && ft < 0x0240000000000000
}
