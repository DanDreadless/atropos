package parsers

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Microsoft Defender keeps one file per detection under
// ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<nn>\<GUID>.
// It outlives the event log, and holds what was found, where, who was logged
// on, and what was done about it.
//
// The file is a run of values, each
//
//	uint32 size, uint32 type, size bytes of data, padding to 8 bytes
//
// with types 0x00, 0x05, 0x06 and 0x08 for numbers, 0x0A for a FILETIME,
// 0x15 for a UTF-16 string, 0x1E for a GUID and 0x28 for binary data. The
// order gives the meaning:
//
//	threat id (number), detection id (GUID)
//	"Magic.Version:1.2", threat name, then numbers: [1] severity,
//	    [2] category, [5] threat status, the last one the resource count
//	for each resource: "Magic.Version:1.2", its type ("file", "CmdLine",
//	    "regkey"...), its location, two numbers, and a block of named values
//	    ("ThreatTrackingSha256", "ThreatTrackingStartTime"...)
//	then, counted from the end of the last resource: [0] last status change,
//	    [4] execution status, [6] user, [7] detection source, [8] process,
//	    [12] initial detection, [14] remediation, [18] remediation account
//
// The layout was worked out from the published descriptions (Jordan Klepser's
// DHParser write-up, the plaso parser and its dtfabric definition) and then
// checked field by field against real files and what Get-MpThreatDetection
// and Get-MpThreat report for the same detections. Positions not listed here
// have no confirmed meaning and are kept as numbers.
type defenderParser struct{}

func (defenderParser) Name() string    { return "defender-detection" }
func (defenderParser) Version() string { return "1 (native)" }

const (
	dhNumber0  = 0x00
	dhNumber5  = 0x05
	dhNumber6  = 0x06
	dhNumber8  = 0x08
	dhFiletime = 0x0A
	dhString   = 0x15
	dhGUID     = 0x1E
	dhBinary   = 0x28

	maxDetectionFile = 16 << 20
	dhMagic          = "Magic.Version:"
)

type dhValue struct {
	off  int
	typ  uint32
	data []byte
}

func (v dhValue) isNumber() bool {
	return (v.typ == dhNumber0 || v.typ == dhNumber5 || v.typ == dhNumber6 || v.typ == dhNumber8) && len(v.data) <= 8
}

func (v dhValue) num() uint64 {
	var n uint64
	for i := len(v.data) - 1; i >= 0; i-- {
		if i < 8 {
			n = n<<8 | uint64(v.data[i])
		}
	}
	return n
}

func (v dhValue) str() string { return utf16String(v.data) }

func (v dhValue) isMagic() bool { return v.typ == dhString && strings.HasPrefix(v.str(), dhMagic) }

func utf16String(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return clean(string(utf16.Decode(u)))
}

// dhValues splits the file into its values. complete is false when a value
// runs past the end of the file.
func dhValues(b []byte) (vals []dhValue, complete bool) {
	o := 0
	for o+8 <= len(b) {
		n := int(binary.LittleEndian.Uint32(b[o:]))
		if n < 0 || n > len(b)-o-8 {
			return vals, false
		}
		vals = append(vals, dhValue{o, binary.LittleEndian.Uint32(b[o+4:]), b[o+8 : o+8+n]})
		o = (o + 8 + n + 7) &^ 7
	}
	return vals, true
}

func guidString(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	le := binary.LittleEndian
	return strings.ToUpper(fmt.Sprintf("%08x-%04x-%04x-%x-%x", le.Uint32(b), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8:10], b[10:]))
}

// dhTracking reads the block of named values that follows a resource. With
// version 1 it opens with five numbers (version, header size, size of the
// values, total size, unknown) and the size of the values again; each value
// is then
//
//	uint32 key size, key (UTF-16), uint32 type, value
//
// with type 3 a 32-bit number, 4 a 64-bit number, 5 one byte, 6 a sized
// UTF-16 string and 7 sized bytes. ok is false when it stopped early.
func dhTracking(d []byte) (out map[string]any, ok bool) {
	out = map[string]any{}
	le := binary.LittleEndian
	if len(d) < 8 {
		return out, false
	}
	start, end := 4, int(le.Uint32(d))+4
	if le.Uint32(d) == 1 {
		if len(d) < 24 {
			return out, false
		}
		start, end = int(le.Uint32(d[4:]))+4, int(le.Uint32(d[12:]))
	}
	if end > len(d) {
		end = len(d)
	}
	o := start
	need := func(n int) bool { return n >= 0 && o >= 0 && n <= end-o }
	for o < end {
		if !need(4) {
			return out, false
		}
		kn := int(le.Uint32(d[o:]))
		o += 4
		if !need(kn) || kn > 1024 {
			return out, false
		}
		key := utf16String(d[o : o+kn])
		o += kn
		if !need(4) {
			return out, false
		}
		typ := le.Uint32(d[o:])
		o += 4
		switch typ {
		case 3:
			if !need(4) {
				return out, false
			}
			out[key] = le.Uint32(d[o:])
			o += 4
		case 4:
			if !need(8) {
				return out, false
			}
			v := le.Uint64(d[o:])
			o += 8
			if s, isTime := timeutil.FromFiletime(v); isTime && strings.HasSuffix(key, "Time") {
				out[key] = s.UTC.Format(time.RFC3339Nano)
			} else {
				out[key] = v
			}
		case 5:
			if !need(1) {
				return out, false
			}
			out[key] = d[o]
			o++
		case 6, 7:
			if !need(4) {
				return out, false
			}
			n := int(le.Uint32(d[o:]))
			o += 4
			if !need(n) {
				return out, false
			}
			raw := d[o : o+n]
			o += n
			if typ == 6 {
				out[key] = utf16String(raw)
			} else {
				out[key] = bytesValue(raw)
			}
		default:
			return out, false
		}
	}
	return out, true
}

// bytesValue shows sized bytes as text where they are text (a hash in
// ASCII), and as hex otherwise.
func bytesValue(raw []byte) string {
	for len(raw) > 0 && raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	for _, c := range raw {
		if c < 0x20 || c > 0x7E {
			return hex.EncodeToString(raw)
		}
	}
	return string(raw)
}

// The names Windows gives these numbers (MSFT_MpThreat and
// MSFT_MpThreatDetection). A number not listed is shown as a number.
var (
	defenderSeverity = map[uint64]string{0: "unknown", 1: "low", 2: "moderate", 4: "high", 5: "severe"}
	defenderStatus   = map[uint64]string{0: "unknown", 1: "detected", 2: "cleaned", 3: "quarantined", 4: "removed", 5: "allowed", 6: "blocked",
		102: "clean failed", 103: "quarantine failed", 104: "remove failed", 105: "allow failed", 106: "abandoned", 107: "block failed"}
	defenderSource    = map[uint64]string{0: "unknown", 1: "user", 2: "system", 3: "real-time", 4: "download or attachment scan", 5: "network inspection", 7: "early launch", 8: "local attestation", 9: "remote attestation"}
	defenderExecution = map[uint64]string{0: "unknown", 1: "blocked", 2: "allowed", 3: "executing", 4: "not executing"}
	defenderCategory  = map[uint64]string{1: "adware", 2: "spyware", 3: "password stealer", 4: "trojan downloader", 5: "worm", 6: "backdoor",
		7: "remote access trojan", 8: "trojan", 9: "email flooder", 10: "keylogger", 11: "dialer", 12: "monitoring software", 13: "browser modifier",
		19: "joke program", 21: "software bundler", 23: "settings modifier", 27: "potentially unwanted software", 30: "exploit",
		32: "malware creation tool", 34: "tool", 37: "trojan dropper", 42: "virus", 46: "behaviour", 50: "ransomware"}
)

func named(m map[uint64]string, v uint64) string {
	if s, ok := m[v]; ok {
		return s
	}
	return fmt.Sprintf("%d", v)
}

func (defenderParser) Parse(ctx *Context) error {
	if ctx.Size > maxDetectionFile {
		return errors.New("Defender detection record is implausibly large")
	}
	b, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return err
	}
	vals, complete := dhValues(b)
	var marks []int
	for i, v := range vals {
		if v.isMagic() {
			marks = append(marks, i)
		}
	}
	if len(vals) < 4 || len(marks) == 0 || marks[0] != 2 || !vals[0].isNumber() || vals[1].typ != dhGUID {
		return errors.New("not a Defender detection record")
	}
	if !complete {
		ctx.Warn("the record ends inside a value; what could be read is shown")
	}
	section := func(k int) []dhValue {
		end := len(vals)
		if k+1 < len(marks) {
			end = marks[k+1]
		}
		return vals[marks[k]+1 : end]
	}

	fields := map[string]any{
		"threat_id":    vals[0].num(),
		"detection_id": guidString(vals[1].data),
		"record_name":  ctx.Name,
		"format":       vals[2].str(),
	}

	// The threat.
	threat := section(0)
	name := ""
	if len(threat) > 0 && threat[0].typ == dhString {
		name = threat[0].str()
		threat = threat[1:]
	}
	fields["threat_name"] = name
	var nums []uint64
	for _, v := range threat {
		if v.isNumber() {
			nums = append(nums, v.num())
		}
	}
	fields["threat_values"] = nums
	severity, status := "", ""
	if len(nums) >= 6 {
		severity, status = named(defenderSeverity, nums[1]), named(defenderStatus, nums[5])
		fields["severity_id"], fields["severity"] = nums[1], severity
		fields["category_id"], fields["category"] = nums[2], named(defenderCategory, nums[2])
		fields["threat_status_id"], fields["threat_status"] = nums[5], status
	} else {
		ctx.Warn("the threat's values are not laid out as expected: severity, category and status were not read")
	}

	// The resources, and what follows the last of them.
	var resources []map[string]any
	var tail []dhValue
	var tracked time.Time
	path := ""
	for k := 1; k < len(marks); k++ {
		sec := section(k)
		res := map[string]any{}
		if len(sec) >= 2 && sec[0].typ == dhString && sec[1].typ == dhString {
			res["type"], res["location"] = sec[0].str(), sec[1].str()
		} else {
			ctx.Warn("resource %d is not laid out as expected", k)
		}
		blob := -1
		for i, v := range sec {
			if v.typ == dhBinary {
				blob = i
				break
			}
		}
		if blob >= 0 {
			tr, ok := dhTracking(sec[blob].data)
			if !ok {
				ctx.Warn("the named values of resource %d could not be read in full", k)
			}
			for key, v := range tr {
				res[key] = v
			}
			if s, ok := tr["ThreatTrackingStartTime"].(string); ok && tracked.IsZero() {
				tracked, _ = time.Parse(time.RFC3339Nano, s)
			}
		}
		if k == len(marks)-1 {
			from := blob + 1
			if blob < 0 {
				from = len(sec)
				for i, v := range sec {
					if v.typ == dhFiletime {
						from = i
						break
					}
				}
			}
			tail = sec[from:]
			sec = sec[:from]
		}
		loc, _ := res["location"].(string)
		if typ, _ := res["type"].(string); loc != "" && (path == "" || (typ == "file" && fields["file"] == nil)) {
			path = loc
			if typ == "file" {
				fields["file"] = loc
			}
		}
		for _, h := range []string{"ThreatTrackingSha256", "ThreatTrackingSha1", "ThreatTrackingMD5", "ThreatTrackingSize"} {
			if v, ok := res[h]; ok && fields[strings.ToLower(strings.TrimPrefix(h, "ThreatTracking"))] == nil {
				fields[strings.ToLower(strings.TrimPrefix(h, "ThreatTracking"))] = v
			}
		}
		resources = append(resources, res)
	}
	fields["resources"] = resources
	if n := len(nums); n > 0 && int(nums[n-1]) != len(resources) {
		ctx.Note("the record states %d resources and holds %d", nums[n-1], len(resources))
	}

	// What follows the last resource. Each position is used only if it holds
	// the type of value expected there.
	at := func(i int, typ uint32) (dhValue, bool) {
		if i < len(tail) && (tail[i].typ == typ || (typ == dhNumber6 && tail[i].isNumber())) {
			return tail[i], true
		}
		return dhValue{}, false
	}
	stampAt := func(i int) (timeutil.Stamp, bool) {
		if v, ok := at(i, dhFiletime); ok && len(v.data) == 8 {
			return timeutil.FromFiletime(binary.LittleEndian.Uint64(v.data))
		}
		return timeutil.Stamp{}, false
	}
	changed, hasChanged := stampAt(0)
	detected, hasDetected := stampAt(12)
	remediated, hasRemediated := stampAt(14)
	user := ""
	if v, ok := at(6, dhString); ok {
		user = v.str()
		fields["user"] = user
	}
	if v, ok := at(8, dhString); ok {
		fields["process"] = v.str()
	}
	if v, ok := at(18, dhString); ok {
		fields["remediation_account"] = v.str()
	}
	if v, ok := at(4, dhNumber6); ok {
		fields["execution_status_id"], fields["execution_status"] = v.num(), named(defenderExecution, v.num())
	}
	if v, ok := at(7, dhNumber6); ok {
		fields["detection_source_id"], fields["detection_source"] = v.num(), named(defenderSource, v.num())
	}
	if len(tail) < 19 || !hasDetected {
		ctx.Warn("the values after the last resource are not laid out as expected: some of user, process and times were not read")
	}
	if !hasDetected && !tracked.IsZero() {
		detected, hasDetected = timeutil.FromTimeNative(tracked, "")
		fields["time_from"] = "ThreatTrackingStartTime, because the record's own detection time was not found"
	}
	if hasDetected {
		fields["initial_detection_time"] = detected.UTC.Format(time.RFC3339Nano)
	}
	if hasChanged {
		fields["last_status_change_time"] = changed.UTC.Format(time.RFC3339Nano)
	}
	if hasRemediated {
		fields["remediation_time"] = remediated.UTC.Format(time.RFC3339Nano)
	}
	if !hasDetected && !hasChanged && !hasRemediated {
		ctx.Note("the record holds no time that could be read, so nothing was placed on the timeline")
		return ErrNothingExtracted
	}

	what := name
	if what == "" {
		what = fmt.Sprintf("threat %d", vals[0].num())
	}
	where := ""
	if len(resources) > 0 {
		typ, _ := resources[0]["type"].(string)
		where = fmt.Sprintf(" in %s %s", typ, trunc(path, 300))
		if len(resources) > 1 {
			where += fmt.Sprintf(" and %d more", len(resources)-1)
		}
	}
	emit := func(s timeutil.Stamp, typ, msg string) error {
		return ctx.Emit(Event{
			Stamp: s, Type: typ, Category: CatSecurity, Source: "defender", Host: ctx.Host, User: user, Path: path,
			Message: msg, Fields: fields, Ref: "detection " + fields["detection_id"].(string),
		})
	}
	if hasDetected {
		msg := fmt.Sprintf("Defender detected %s%s", what, where)
		if severity != "" {
			msg += fmt.Sprintf(" (severity %s; status now %s)", severity, status)
		}
		if err := emit(detected, "defender-detection", msg); err != nil {
			return err
		}
	}
	if hasRemediated {
		if err := emit(remediated, "defender-remediation", fmt.Sprintf("Defender acted on %s%s (status now %s)", what, where, status)); err != nil {
			return err
		}
	}
	// A status change at the moment of detection or of remediation is that
	// event, not a third one.
	if hasChanged && !(hasDetected && changed.UTC.Equal(detected.UTC)) && !(hasRemediated && changed.UTC.Equal(remediated.UTC)) {
		return emit(changed, "defender-status-changed", fmt.Sprintf("Defender status of %s%s last changed (now %s)", what, where, status))
	}
	return nil
}
