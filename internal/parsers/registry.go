package parsers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"

	"www.velocidex.com/golang/regparser"
	"www.velocidex.com/golang/regparser/appcompatcache"
)

type registryParser struct{}

func (registryParser) Name() string { return "registry" }
func (registryParser) Version() string {
	return "17 (velocidex/regparser 31e704a; the computer's addresses and domain from Tcpip; recent-file lists, SAM accounts and local groups, networks; key times to 100 ns; known folders named; Amcache name-and-hash entries; ShimCache times to 100 ns; BAM entries for Store apps; ShimCache slack and executed flag; transaction logs applied; deleted keys and values recovered; portable device, web folder and property view shell items)"
}

const (
	regMaxDepth  = 512
	regMaxValues = 64
)

// safeData reads a value's data. The library indexes into the data by the
// value's declared type without checking its length, so a value whose type
// says "64-bit number" and whose data is empty (seen in a real Amcache hive)
// makes it panic. Such a value is treated as having no data.
func safeData(v *regparser.CM_KEY_VALUE) (d *regparser.ValueData) {
	defer func() {
		if recover() != nil {
			d = nil
		}
	}()
	return v.ValueData()
}

func valueString(v *regparser.CM_KEY_VALUE) string {
	d := safeData(v)
	if d == nil {
		return ""
	}
	switch d.Type {
	case regparser.REG_SZ, regparser.REG_EXPAND_SZ:
		return trunc(clean(d.String), 512)
	case regparser.REG_MULTI_SZ:
		return trunc(clean(strings.Join(d.MultiSz, " | ")), 512)
	case regparser.REG_DWORD, regparser.REG_DWORD_BIG_ENDIAN, regparser.REG_QWORD:
		return fmt.Sprintf("%d", d.Uint64)
	default:
		if len(d.Data) > 32 {
			return hex.EncodeToString(d.Data[:32]) + fmt.Sprintf("… (%d bytes)", len(d.Data))
		}
		return hex.EncodeToString(d.Data)
	}
}

func hiveKind(root *regparser.CM_KEY_NODE) string {
	names := map[string]bool{}
	for _, k := range root.Subkeys() {
		names[strings.ToLower(keyName(k))] = true
	}
	switch {
	case names["select"] && (names["controlset001"] || names["mounteddevices"]):
		return "SYSTEM"
	case names["sam"] && len(names) <= 3:
		return "SAM"
	case names["policy"] && names["cache"]:
		return "SECURITY"
	case names["microsoft"] && names["classes"]:
		return "SOFTWARE"
	case names["software"] && (names["environment"] || names["control panel"] || names["volatile environment"]):
		return "NTUSER"
	case names["local settings"] || (len(names) > 0 && names["clsid"]):
		return "USRCLASS"
	case names["root"] && len(names) <= 2:
		return "AMCACHE"
	}
	return "UNKNOWN"
}

func (registryParser) Parse(ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	// A hive copied from a running system often has its newest changes
	// only in its transaction logs; they are applied first when present.
	hive, hiveSize, closers := replayLogs(ctx)
	for _, c := range closers {
		defer c()
	}
	reg, err := regparser.NewRegistry(hive)
	if err != nil {
		return err
	}
	root := reg.OpenKey("")
	if root == nil {
		return fmt.Errorf("hive has no readable root key")
	}
	kind := hiveKind(root)
	ctx.Fact("hive.kind", kind, "identified from the hive's top-level keys")

	host := ctx.Host
	if kind == "SYSTEM" {
		if h := systemFacts(ctx, reg); h != "" {
			host = h
		}
	}

	// Some keys are read together with another key of the same hive.
	look := &regLookup{
		open: func(p string) map[string][]byte {
			if k := reg.OpenKey(p); k != nil {
				return rawValues(k.Values())
			}
			return nil
		},
		subkeys: func(p string) (names []string) {
			if k := reg.OpenKey(p); k != nil {
				for _, sk := range k.Subkeys() {
					names = append(names, keyName(sk))
				}
			}
			return names
		},
	}

	type frame struct {
		key   *regparser.CM_KEY_NODE
		path  string
		depth int
	}
	stack := []frame{{root, "", 0}}
	seen := map[int64]bool{}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[f.key.Offset] {
			ctx.Warn("key cycle at %s; branch skipped", f.path)
			continue
		}
		seen[f.key.Offset] = true

		fields := map[string]any{"hive": kind}
		var summary []string
		values := f.key.Values()
		vals := map[string]any{}
		for i, v := range values {
			if i >= regMaxValues {
				fields["values_omitted"] = len(values) - regMaxValues
				break
			}
			name := clean(valueName(v))
			if name == "" {
				name = "(default)"
			}
			vs := valueString(v)
			vals[name] = map[string]any{"type": v.TypeString(), "data": vs}
			if len(summary) < 4 && vs != "" {
				summary = append(summary, name+"="+trunc(vs, 100))
			}
		}
		if len(vals) > 0 {
			fields["values"] = vals
		}
		path := f.path
		if path == "" {
			path = `\`
		}
		lower := strings.ToLower(f.path)
		if stamp, ok := keyStamp(f.key); ok {
			typ, cat, target := "registry-key-last-write", CatRegistry, path
			msg := "Key written: " + path
			if len(summary) > 0 {
				msg += "  " + strings.Join(summary, "; ")
			}
			// Some keys are evidence of something more specific.
			if t, c, m, tgt, special := classifyKey(kind, lower, path, vals); special {
				typ, cat, msg = t, c, m
				fields["key"] = path
				if tgt != "" {
					target = tgt
				}
				if kind == "AMCACHE" {
					amcacheFields(fields, vals)
				}
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: typ, MACB: "M...", Category: cat, Source: "registry",
				Host: host, Path: target, Message: msg, Fields: fields,
				Ref: fmt.Sprintf("key node at offset 0x%X", f.key.Offset),
			}); err != nil {
				return err
			}
		}

		if err := regExtras(ctx, kind, host, lower, path, values); err != nil {
			return err
		}
		if err := regLists(ctx, look, kind, host, lower, path, keyTime(f.key), values); err != nil {
			return err
		}
		// Explorer's record of folders opened, in the user's own hives.
		if strings.HasSuffix(lower, `\shell\bagmru`) || strings.HasSuffix(lower, `\shellnoroam\bagmru`) {
			if err := shellBags(ctx, host, kind, path, f.key); err != nil {
				return err
			}
		}
		if kind == "NTUSER" && strings.Contains(lower, `\explorer\userassist\`) && strings.HasSuffix(lower, `\count`) {
			if err := userAssist(ctx, host, path, values); err != nil {
				return err
			}
		}
		if kind == "SYSTEM" && strings.HasSuffix(lower, `\control\session manager\appcompatcache`) {
			if err := shimCache(ctx, host, path, values, hiveSize); err != nil {
				return err
			}
		}

		if f.depth >= regMaxDepth {
			ctx.Warn("maximum depth reached at %s; subkeys not walked", path)
			continue
		}
		for _, sk := range f.key.Subkeys() {
			stack = append(stack, frame{sk, f.path + `\` + clean(keyName(sk)), f.depth + 1})
		}
	}
	// What is left of deleted keys and values in the hive's free space.
	return recoverDeleted(ctx, hive, hiveSize, host, kind)
}

// systemFacts reads the computer name and time zone from a SYSTEM hive. These
// become case facts and are what lets zoneless local timestamps elsewhere in
// the same batch be converted to UTC on evidence rather than assumption.
func systemFacts(ctx *Context, reg *regparser.Registry) string {
	cs := "ControlSet001"
	if sel := reg.OpenKey("Select"); sel != nil {
		for _, v := range sel.Values() {
			if strings.EqualFold(valueName(v), "Current") {
				if d := safeData(v); d != nil && d.Uint64 > 0 && d.Uint64 < 1000 {
					cs = fmt.Sprintf("ControlSet%03d", d.Uint64)
				}
			}
		}
	}
	ctx.Fact("host.control_set", cs, `from Select\Current`)
	host := ""
	if k := reg.OpenKey(cs + `\Control\ComputerName\ComputerName`); k != nil {
		for _, v := range k.Values() {
			if strings.EqualFold(valueName(v), "ComputerName") {
				host = valueString(v)
			}
		}
	}
	if host != "" {
		ctx.Fact("host.name", host, cs+`\Control\ComputerName\ComputerName`)
	}
	if k := reg.OpenKey(cs + `\Control\TimeZoneInformation`); k != nil {
		var keyName, std string
		for _, v := range k.Values() {
			switch strings.ToLower(valueName(v)) {
			case "timezonekeyname":
				keyName = valueString(v)
			case "standardname":
				std = valueString(v)
			}
		}
		// TimeZoneKeyName can carry trailing junk after its terminator.
		if i := strings.IndexAny(keyName, "\x00�"); i >= 0 {
			keyName = keyName[:i]
		}
		name := strings.TrimSpace(keyName)
		if name == "" {
			name = strings.TrimSpace(std)
		}
		if name != "" {
			if _, iana, ok := timeutil.WindowsZone(name); ok {
				ctx.Fact("host.timezone", iana, fmt.Sprintf(`Windows zone %q from %s\Control\TimeZoneInformation`, name, cs))
			} else {
				ctx.Fact("host.timezone.unmapped", name, "Windows zone name with no known IANA equivalent")
				ctx.Warn("time zone %q could not be mapped to an IANA zone", name)
			}
		}
	}
	tcpipFacts(ctx, reg, cs, host)
	return host
}

// tcpipFacts reads the computer's domain and its IPv4 addresses from
// Services\Tcpip\Parameters: the full name (host.dns_name) and each address
// an interface was set to or last leased by DHCP (host.ip_address, the detail
// saying which and when). Connections from other hosts that name only an
// address are matched on these.
func tcpipFacts(ctx *Context, reg *regparser.Registry, cs, host string) {
	base := cs + `\Services\Tcpip\Parameters`
	vals := func(k *regparser.CM_KEY_NODE) map[string]*regparser.ValueData {
		m := map[string]*regparser.ValueData{}
		for _, v := range k.Values() {
			if d := safeData(v); d != nil {
				m[strings.ToLower(valueName(v))] = d
			}
		}
		return m
	}
	str := func(d *regparser.ValueData) string {
		if d == nil || (d.Type != regparser.REG_SZ && d.Type != regparser.REG_EXPAND_SZ) {
			return ""
		}
		return strings.TrimSpace(strings.TrimRight(d.String, "\x00"))
	}
	num := func(d *regparser.ValueData) (uint64, bool) {
		if d == nil || (d.Type != regparser.REG_DWORD && d.Type != regparser.REG_QWORD) {
			return 0, false
		}
		return d.Uint64, true
	}
	k := reg.OpenKey(base)
	if k == nil {
		return
	}
	p := vals(k)
	name := str(p["hostname"])
	if name == "" {
		name = host
	}
	for _, dk := range []string{"domain", "nv domain", "dhcpdomain"} {
		if dom := strings.Trim(str(p[dk]), ". "); dom != "" && name != "" && validDNS(name+"."+dom) {
			ctx.Fact("host.dns_name", strings.ToUpper(name+"."+dom), fmt.Sprintf(`the computer's name with its domain, from %s (%s)`, base, valueLabel(dk)))
			break
		}
	}
	ifs := reg.OpenKey(base + `\Interfaces`)
	if ifs == nil {
		return
	}
	seen := map[string]bool{}
	for _, ik := range ifs.Subkeys() {
		path := base + `\Interfaces\` + clean(keyName(ik))
		v := vals(ik)
		dhcp, _ := num(v["enabledhcp"])
		var addrs []string
		how := "set on the interface"
		if dhcp == 1 {
			addrs = []string{str(v["dhcpipaddress"])}
			how = "leased by DHCP"
			var when []string
			if t, ok := num(v["leaseobtainedtime"]); ok && t > 0 {
				when = append(when, "obtained "+time.Unix(int64(t), 0).UTC().Format("2006-01-02 15:04:05")+" UTC")
			}
			if t, ok := num(v["leaseterminatestime"]); ok && t > 0 {
				when = append(when, "ending "+time.Unix(int64(t), 0).UTC().Format("2006-01-02 15:04:05")+" UTC")
			}
			if srv := str(v["dhcpserver"]); srv != "" && srv != "255.255.255.255" {
				when = append(when, "from the DHCP server "+srv)
			}
			if len(when) > 0 {
				how += " (" + strings.Join(when, ", ") + ")"
			}
		} else if d := v["ipaddress"]; d != nil {
			switch d.Type {
			case regparser.REG_MULTI_SZ:
				addrs = d.MultiSz
			case regparser.REG_SZ:
				addrs = []string{d.String}
			}
		}
		for _, a := range addrs {
			ip := net.ParseIP(strings.TrimSpace(strings.TrimRight(a, "\x00")))
			if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
				continue
			}
			s := ip.To4().String()
			if seen[s] {
				continue
			}
			seen[s] = true
			ctx.Fact("host.ip_address", s, fmt.Sprintf("an address of this computer, %s, from %s", how, path))
		}
	}
}

func valueLabel(lower string) string {
	switch lower {
	case "nv domain":
		return "NV Domain"
	case "dhcpdomain":
		return "DhcpDomain, given by DHCP"
	}
	return "Domain"
}

// validDNS says whether s is a plausible DNS name: letters, digits, hyphens
// and dots, each label 1 to 63 characters.
func validDNS(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// userAssist decodes Explorer's record of programs a user launched.
func userAssist(ctx *Context, host, keyPath string, values []*regparser.CM_KEY_VALUE) error {
	for _, v := range values {
		d := safeData(v)
		if d == nil {
			continue
		}
		name := rot13(clean(valueName(v)))
		var ft uint64
		var runs uint32
		fields := map[string]any{"key": keyPath}
		// Explorer stores a known folder as its identifier. The folder is
		// shown, and the name as stored is kept beside it.
		if resolved, ok := knownFolderPath(name); ok {
			fields["program_stored"] = name
			name = resolved
		}
		fields["program"] = name
		switch {
		case len(d.Data) >= 72: // Windows 7 and later
			runs = binary.LittleEndian.Uint32(d.Data[4:8])
			fields["focus_count"] = binary.LittleEndian.Uint32(d.Data[8:12])
			fields["focus_time_ms"] = binary.LittleEndian.Uint32(d.Data[12:16])
			ft = binary.LittleEndian.Uint64(d.Data[60:68])
		case len(d.Data) == 16: // Windows XP to Vista
			runs = binary.LittleEndian.Uint32(d.Data[4:8])
			if runs >= 5 {
				runs -= 5
			}
			ft = binary.LittleEndian.Uint64(d.Data[8:16])
		default:
			continue
		}
		fields["run_count"] = runs
		stamp, ok := timeutil.FromFiletime(ft)
		if !ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "program-last-run (userassist)", Category: CatExecution, Source: "registry",
			Host: host, Path: name,
			Message: fmt.Sprintf("UserAssist: %s last run, run count %d", name, runs),
			Fields:  fields, Ref: "UserAssist value " + clean(valueName(v)),
		}); err != nil {
			return err
		}
	}
	return nil
}

// shimCache decodes the application compatibility cache. Its timestamp is the
// file's last-modified time, not when it ran; the type says so.
func shimCache(ctx *Context, host, keyPath string, values []*regparser.CM_KEY_VALUE, hiveSize int64) error {
	for _, v := range values {
		if !strings.EqualFold(valueName(v), "AppCompatCache") {
			continue
		}
		d := safeData(v)
		if d == nil || len(d.Data) == 0 {
			continue
		}
		entries := func() (out []*appcompatcache.CacheEntry) {
			defer func() {
				if r := recover(); r != nil {
					ctx.Warn("AppCompatCache could not be decoded: %v", r)
				}
			}()
			return appcompatcache.ParseValueData(d.Data)
		}()
		native, slack := shimWin10(d.Data)
		// The cells holding a long value are often longer than the value:
		// the space after its end can hold entries from when the cache was
		// longer (AppCompatCacheParser reads it too). An entry found there
		// that is still in the live list is an old copy and is left out.
		if len(native) > 0 {
			tagged := binary.LittleEndian.Uint32(d.Data) == 0x34
			live := map[string]bool{}
			for _, e := range native {
				live[fmt.Sprintf("%s|%d", strings.ToLower(e.path), e.ft)] = true
			}
			var kept []shimEntry
			for _, e := range append(slack, shimScan(valueSlack(v.Reader, hiveSize, v.Offset), tagged, -1)...) {
				if !live[fmt.Sprintf("%s|%d", strings.ToLower(e.path), e.ft)] {
					kept = append(kept, e)
				}
			}
			slack = kept
		}
		exact := native
		if len(native) != len(entries) {
			exact = nil // the two readings disagree on the entries; keep the library's
		}
		for i, e := range entries {
			stamp, ok := timeutil.FromTimeNative(e.Time, "")
			if !ok {
				continue
			}
			fields := map[string]any{"key": keyPath, "position": i}
			msg := "ShimCache entry: "
			// The library gives the time in whole seconds. Where the value
			// is in the Windows 10 layout and this entry is found at the
			// same place with the same second, the stored FILETIME is used.
			if i < len(exact) {
				if full, fok := timeutil.FromFiletime(exact[i].ft); fok && full.UTC.Unix() == stamp.UTC.Unix() {
					stamp = full
					if exact[i].executed {
						fields["executed_flag"] = true
						msg = "ShimCache entry (flagged executed): "
					}
				}
			}
			name := clean(e.Name)
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: "file-modified (shimcache)", MACB: "M...", Category: CatExecution, Source: "registry",
				Host: host, Path: name,
				Message: msg + name,
				Fields:  fields,
				Ref:     fmt.Sprintf("AppCompatCache entry %d", i),
			}); err != nil {
				return err
			}
		}
		// Older entries left after the last one: each keeps its own time.
		for k, e := range slack {
			stamp, ok := timeutil.FromFiletime(e.ft)
			if !ok {
				continue
			}
			name := clean(e.path)
			fields := map[string]any{"key": keyPath, "position": len(entries) + k, "recovered_from_slack": true,
				"slack_note": "found after the last entry of the value: an entry from when the cache was longer, no longer part of it"}
			if e.executed {
				fields["executed_flag"] = true
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: "file-modified (shimcache, recovered from slack)", MACB: "M...", Category: CatExecution, Source: "registry",
				Host: host, Path: name,
				Message: "ShimCache entry recovered from the value's slack: " + name,
				Fields:  fields,
				Ref:     shimSlackRef(e.at),
			}); err != nil {
				return err
			}
		}
		if len(slack) > 0 {
			ctx.Note("%d older ShimCache entries were recovered from the unused end of the AppCompatCache value in %s", len(slack), keyPath)
		}
	}
	return nil
}

// shimEntry is one entry of a ShimCache value in the Windows 10 and 11
// layout, read as stored.
type shimEntry struct {
	path     string
	ft       uint64
	executed bool // the entry's data carries tag 0x100 (Windows 10 1703 and later)
	at       int  // offset in the value
}

// shimWin10 reads a ShimCache value in the Windows 10 and 11 layout: a
// header whose size is its first number, then entries of "10ts", a number,
// the size of what follows, the path's length, the path, the FILETIME, and
// a data block. After the last entry the value can hold older entries, from
// when the cache was longer; they are found as AppCompatCacheParser finds
// them, by their signature, and kept when they read plausibly. Any other
// layout gives nothing, and the library's reading stands alone.
func shimWin10(d []byte) (entries, slack []shimEntry) {
	if len(d) < 0x34 {
		return nil, nil
	}
	off := int(binary.LittleEndian.Uint32(d))
	if off != 0x30 && off != 0x34 {
		return nil, nil
	}
	tagged := off == 0x34 // the Creators Update header, whose entries carry tagged data
	for off+12 <= len(d) && string(d[off:off+4]) == "10ts" && len(entries) < 1<<16 {
		e, next, ok := shimEntryAt(d, off, tagged)
		if !ok {
			break
		}
		entries = append(entries, e)
		off = next
	}
	return entries, shimScan(d[off:], tagged, off)
}

// shimScan finds entries by their signature in bytes that are not part of
// the live list. base is added to each entry's offset.
func shimScan(d []byte, tagged bool, base int) (out []shimEntry) {
	for i := 0; i+12 <= len(d) && len(out) < 1<<16; {
		if d[i] != '1' || string(d[i:i+4]) != "10ts" {
			i++
			continue
		}
		if e, next, ok := shimEntryAt(d, i, tagged); ok && plausibleShimPath(e.path) {
			e.at += base
			out = append(out, e)
			i = next
			continue
		}
		i++
	}
	return out
}

func shimEntryAt(d []byte, i int, tagged bool) (shimEntry, int, bool) {
	le := binary.LittleEndian
	size := int(le.Uint32(d[i+8:]))
	next := i + 12 + size
	if size < 14 || next > len(d) || next < i {
		return shimEntry{}, 0, false
	}
	p := i + 12
	plen := int(le.Uint16(d[p:]))
	p += 2
	if plen%2 != 0 || p+plen+12 > next {
		return shimEntry{}, 0, false
	}
	u := make([]uint16, 0, plen/2)
	for k := 0; k < plen; k += 2 {
		u = append(u, le.Uint16(d[p+k:]))
	}
	e := shimEntry{path: strings.TrimRight(string(utf16.Decode(u)), "\x00"), at: i}
	p += plen
	e.ft = le.Uint64(d[p:])
	p += 8
	dsize := int(le.Uint32(d[p:]))
	p += 4
	if dsize < 0 || p+dsize > next {
		return shimEntry{}, 0, false
	}
	if tagged {
		data := d[p : p+dsize]
		for t := 0; t+8 <= len(data); {
			tag, n := le.Uint32(data[t:]), int(le.Uint32(data[t+4:]))
			if n < 0 || t+8+n > len(data) {
				break
			}
			if tag == 0x100 {
				e.executed = true
			}
			t += 8 + (n+3)&^3
		}
	}
	return e, next, true
}

func plausibleShimPath(p string) bool {
	if p == "" {
		return false
	}
	for _, r := range p {
		if r < 0x20 && r != '\t' {
			return false
		}
	}
	return true
}

// keyStamp reads a key's last-write time from its node. The library's own
// accessor cuts the time to whole seconds; the node holds a FILETIME, good
// to 100 nanoseconds, and that is what is read here.
func keyStamp(key *regparser.CM_KEY_NODE) (timeutil.Stamp, bool) {
	if key == nil || key.Reader == nil || key.Profile == nil {
		return timeutil.Stamp{}, false
	}
	var b [8]byte
	if n, _ := key.Reader.ReadAt(b[:], key.Offset+key.Profile.Off_CM_KEY_NODE_LastWriteTime); n != 8 {
		return timeutil.Stamp{}, false
	}
	return timeutil.FromFiletime(binary.LittleEndian.Uint64(b[:]))
}

// keyTime is keyStamp as a time, zero when the key has none that can be used.
func keyTime(key *regparser.CM_KEY_NODE) time.Time {
	if s, ok := keyStamp(key); ok {
		return s.UTC
	}
	return time.Time{}
}

// A key's or a value's name is stored in one of two ways, and a flag says
// which: one byte a character (Latin-1) when every character fits, UTF-16
// otherwise. The library returns the bytes as they are, which turns any
// name with a character outside Latin-1 into noise, so names are decoded
// here.
const (
	keyNameCompressed   = 0x0020 // KEY_COMP_NAME
	valueNameCompressed = 0x0001 // VALUE_COMP_NAME
)

func keyName(k *regparser.CM_KEY_NODE) string {
	return storedName(k.Name(), k.Flags()&keyNameCompressed != 0)
}

func valueName(v *regparser.CM_KEY_VALUE) string {
	return storedName(v.ValueName(), v.Flags()&valueNameCompressed != 0)
}

// storedName decodes a name whose bytes are in raw.
func storedName(raw string, compressed bool) string {
	if !compressed {
		u := make([]uint16, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	ascii := true
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return raw
	}
	r := make([]rune, len(raw))
	for i := 0; i < len(raw); i++ {
		r[i] = rune(raw[i])
	}
	return string(r)
}

func shimSlackRef(at int) string {
	if at < 0 {
		return "AppCompatCache value, in the unused end of the registry cells holding it"
	}
	return fmt.Sprintf("AppCompatCache value, after its last entry, at offset %#x", at)
}
