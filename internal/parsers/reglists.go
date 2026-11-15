package parsers

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"

	"www.velocidex.com/golang/regparser"
)

// Lists the registry keeps of what an account opened, searched for and
// connected to, the local accounts in a SAM hive, and the networks a machine
// has joined.
//
// Most of the per-user lists are "most recently used" lists: numbered values
// and an MRUListEx value giving their order, newest first. The registry
// records one time for a key, its last write, so only the newest entry can
// be dated: by the key's time. That entry becomes an event; the rest are
// listed in its fields, in order, and say they have no time of their own.
// TypedURLs and the Office lists are the exceptions: every entry there
// carries its own time.

var (
	reRecentDocs  = regexp.MustCompile(`\\explorer\\recentdocs(?:\\([^\\]+))?$`)
	reOpenSave    = regexp.MustCompile(`\\explorer\\comdlg32\\opensavepidlmru\\([^\\]+)$`)
	reLastVisited = regexp.MustCompile(`\\explorer\\comdlg32\\lastvisitedpidlmru(?:legacy)?$`)
	reWordWheel   = regexp.MustCompile(`\\explorer\\wordwheelquery$`)
	reTypedURLs   = regexp.MustCompile(`\\software\\microsoft\\internet explorer\\typedurls$`)
	reOfficeMRU   = regexp.MustCompile(`\\software\\microsoft\\office\\([^\\]+)\\([^\\]+)\\(?:user mru\\[^\\]+\\)?(file mru|place mru)$`)
	reOfficeItem  = regexp.MustCompile(`^(?:\[[A-Za-z][0-9A-Fa-f]{1,16}\])*?\[T([0-9A-Fa-f]{16})\](?:\[[A-Za-z][0-9A-Fa-f]{1,16}\])*\*(.+)$`)

	reSAMUser    = regexp.MustCompile(`^\\sam\\domains\\account\\users\\([0-9a-f]{8})$`)
	reSAMName    = regexp.MustCompile(`^\\sam\\domains\\account\\users\\names\\[^\\]+$`)
	reNetProfile = regexp.MustCompile(`^\\microsoft\\windows nt\\currentversion\\networklist\\profiles\\(\{[0-9a-f-]+\})$`)
)

const (
	regRawMaxValues = 4096
	regRawMaxBytes  = 1 << 20
	mruMaxListed    = 100
)

// regLookup lets a key's handler read other keys of the same hive.
type regLookup struct {
	open    func(path string) map[string][]byte // a key's values, nil if absent
	subkeys func(path string) []string
	sigs    map[string]netSignature // network signatures by profile, built once
}

// rawValues returns a key's values as bytes, by lower-cased name.
func rawValues(values []*regparser.CM_KEY_VALUE) map[string][]byte {
	out := map[string][]byte{}
	for i, v := range values {
		if i >= regRawMaxValues {
			break
		}
		d := safeData(v)
		if d == nil || len(d.Data) > regRawMaxBytes {
			continue
		}
		out[strings.ToLower(valueName(v))] = d.Data
	}
	return out
}

// mruOrder returns the value names of a list, newest first, as MRUListEx
// gives them. ordered is false when the key has no usable MRUListEx: the
// numbered values are then returned in number order, which says nothing
// about which is newest.
func mruOrder(raw map[string][]byte) (names []string, ordered bool) {
	if b := raw["mrulistex"]; len(b) >= 4 {
		seen := map[uint32]bool{}
		for i := 0; i+4 <= len(b) && len(names) < regRawMaxValues; i += 4 {
			n := binary.LittleEndian.Uint32(b[i:])
			if n == 0xFFFFFFFF {
				break
			}
			name := strconv.FormatUint(uint64(n), 10)
			if _, ok := raw[name]; ok && !seen[n] {
				seen[n] = true
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			return names, true
		}
	}
	for name := range raw {
		if name != "" && strings.Trim(name, "0123456789") == "" {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	return names, false
}

// pidlPath reads a list of shell items (an "item ID list") as a path.
func pidlPath(b []byte) string {
	var parts []string
	for off := 0; off+2 <= len(b) && len(parts) < 64; {
		size := int(binary.LittleEndian.Uint16(b[off:]))
		if size < 4 || off+size > len(b) {
			break
		}
		parts = append(parts, parseShellItem(b[off:off+size]).name)
		off += size
	}
	return strings.Join(parts, `\`)
}

// utf16zLen is the number of bytes a NUL-ended UTF-16 string takes at the
// start of b, terminator included.
func utf16zLen(b []byte) int {
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			return i + 2
		}
	}
	return len(b)
}

// emitMRU emits the one datable event of a most-recently-used list.
func emitMRU(ctx *Context, host, path string, when time.Time, typ, cat, what, group string, entries []string, ordered bool) error {
	if len(entries) == 0 {
		return nil
	}
	stamp, ok := timeutil.FromTimeNative(when, "")
	if !ok {
		return nil
	}
	listed := entries
	if len(listed) > mruMaxListed {
		listed = listed[:mruMaxListed]
	}
	fields := map[string]any{"key": path, "entries": listed, "entry_count": len(entries)}
	if group != "" {
		fields["group"] = group
	}
	target, msg := entries[0], ""
	if ordered && len(entries) == 1 {
		fields["newest"] = entries[0]
		msg = fmt.Sprintf("%s: %s  (the only entry in this list, dated by the key's last write)", what, trunc(entries[0], 400))
	} else if ordered {
		fields["newest"] = entries[0]
		msg = fmt.Sprintf("%s: %s  (the newest of %d in this list, dated by the key's last write; the others are in the fields, newest first, and have no time of their own)", what, trunc(entries[0], 400), len(entries))
	} else {
		fields["order"] = "not recorded"
		target = ""
		msg = fmt.Sprintf("%s: list of %d written; the key does not record which entry is the newest", what, len(entries))
	}
	return ctx.Emit(Event{
		Stamp: stamp, Type: typ, Category: cat, Source: "registry", Host: host, Path: target,
		Message: trunc(msg, maxMessage), Fields: fields, Ref: "most-recently-used list in " + path,
	})
}

// regLists emits the events held in the lists described at the top of this
// file. keyTime is the key's last-write time.
func regLists(ctx *Context, look *regLookup, hive, host, lower, path string, keyTime time.Time, values []*regparser.CM_KEY_VALUE) error {
	return regListsRaw(ctx, look, hive, host, lower, path, keyTime, func() map[string][]byte { return rawValues(values) })
}

// regListsRaw is regLists with the key's values supplied on demand, so that
// they are read only for the few keys that are lists.
func regListsRaw(ctx *Context, look *regLookup, hive, host, lower, path string, keyTime time.Time, values func() map[string][]byte) error {
	switch hive {
	case "NTUSER":
		switch {
		case reRecentDocs.MatchString(lower):
			raw := values()
			names, ordered := mruOrder(raw)
			var entries []string
			for _, n := range names {
				// The document's name, then a shell item naming its shortcut.
				if s := clean(utf16zAt(raw[n])); s != "" {
					entries = append(entries, s)
				}
			}
			group := ""
			if g := reRecentDocs.FindStringSubmatch(lower); g[1] != "" {
				group = path[strings.LastIndexByte(path, '\\')+1:]
			}
			return emitMRU(ctx, host, path, keyTime, "recent-document-latest", CatFileOpening, "Recent documents: opened", group, entries, ordered)
		case reOpenSave.MatchString(lower):
			raw := values()
			names, ordered := mruOrder(raw)
			var entries []string
			for _, n := range names {
				if s := pidlPath(raw[n]); s != "" {
					entries = append(entries, s)
				}
			}
			return emitMRU(ctx, host, path, keyTime, "open-save-dialog-latest", CatFileOpening, "Open or Save dialog: file chosen",
				path[strings.LastIndexByte(path, '\\')+1:], entries, ordered)
		case reLastVisited.MatchString(lower):
			raw := values()
			names, ordered := mruOrder(raw)
			var entries []string
			for _, n := range names {
				b := raw[n]
				program := clean(utf16zAt(b))
				if program == "" {
					continue
				}
				entries = append(entries, program+" in "+pidlPath(b[utf16zLen(b):]))
			}
			return emitMRU(ctx, host, path, keyTime, "dialog-last-folder-latest", CatFileOpening, "Open or Save dialog: program and the folder it last used", "", entries, ordered)
		case reWordWheel.MatchString(lower):
			raw := values()
			names, ordered := mruOrder(raw)
			var entries []string
			for _, n := range names {
				if s := clean(utf16zAt(raw[n])); s != "" {
					entries = append(entries, s)
				}
			}
			return emitMRU(ctx, host, path, keyTime, "explorer-search-latest", CatFileOpening, "Explorer search: searched for", "", entries, ordered)
		case reTypedURLs.MatchString(lower):
			return typedURLs(ctx, look, host, path, values())
		case reOfficeMRU.MatchString(lower):
			return officeMRU(ctx, host, lower, path, values())
		}
	case "SAM":
		if g := reSAMUser.FindStringSubmatch(lower); g != nil {
			return samUser(ctx, host, path, g[1], values())
		}
	case "SOFTWARE":
		if g := reNetProfile.FindStringSubmatch(lower); g != nil {
			return networkProfile(ctx, look, host, path, g[1], values())
		}
	}
	return nil
}

// typedURLs: addresses typed into Internet Explorer (and the old Edge), each
// with its own time in the TypedURLsTime key beside it.
func typedURLs(ctx *Context, look *regLookup, host, path string, raw map[string][]byte) error {
	var times map[string][]byte
	if look != nil && look.open != nil {
		times = look.open(strings.TrimPrefix(path, `\`) + "Time")
	}
	names := make([]string, 0, len(raw))
	for n := range raw {
		if strings.HasPrefix(n, "url") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		u := clean(utf16zAt(raw[n]))
		t := times[n]
		if u == "" || len(t) < 8 {
			continue // no time of its own: the key event already lists it
		}
		stamp, ok := timeutil.FromFiletime(binary.LittleEndian.Uint64(t))
		if !ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "url-typed (internet explorer)", Category: CatBrowser, Source: "registry", Host: host, Path: u,
			Message: "Address typed into Internet Explorer: " + trunc(u, 400),
			Fields:  map[string]any{"key": path, "value": n, "url": u},
			Ref:     "value " + n + " of " + path + "Time",
		}); err != nil {
			return err
		}
	}
	return nil
}

// officeMRU: the recent files and folders of an Office program. Each item
// is text of the form [F00000000][T01DA4F0D12345678][O00000000]*C:\path,
// where T is the time it was last opened, a FILETIME in hexadecimal.
func officeMRU(ctx *Context, host, lower, path string, raw map[string][]byte) error {
	g := reOfficeMRU.FindStringSubmatch(lower)
	parts := strings.Split(path, `\`)
	app := g[2]
	for i, p := range parts {
		if strings.EqualFold(p, "office") && i+2 < len(parts) {
			app = parts[i+2]
		}
	}
	typ, word := "office-document-last-opened", "document"
	if g[3] == "place mru" {
		typ, word = "office-folder-last-used", "folder"
	}
	names := make([]string, 0, len(raw))
	for n := range raw {
		if strings.HasPrefix(n, "item ") {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		m := reOfficeItem.FindStringSubmatch(clean(utf16zAt(raw[n])))
		if m == nil {
			continue
		}
		ft, err := strconv.ParseUint(m[1], 16, 64)
		if err != nil {
			continue
		}
		stamp, ok := timeutil.FromFiletime(ft)
		if !ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: typ, Category: CatFileOpening, Source: "registry", Host: host, Path: m[2],
			Message: fmt.Sprintf("Office %s: %s last opened: %s", app, word, trunc(m[2], 400)),
			Fields:  map[string]any{"key": path, "value": n, "application": app, "office_version": g[1]},
			Ref:     "value " + n + " of " + path,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ---- SAM: local accounts -------------------------------------------------

// Account control flags in the F value.
var samFlags = []struct {
	bit  uint16
	name string
}{
	{0x0001, "disabled"}, {0x0002, "home directory required"}, {0x0004, "password not required"},
	{0x0010, "normal user account"}, {0x0040, "interdomain trust account"}, {0x0080, "workstation trust account"},
	{0x0100, "server trust account"}, {0x0200, "password does not expire"}, {0x0400, "locked out"},
}

type samAccount struct {
	lastLogon, passwordSet, expires, lastFailed uint64
	rid                                         uint32
	flags                                       uint16
	failedCount, logonCount                     uint16
}

// parseSAMF reads the fixed-layout F value of an account.
func parseSAMF(b []byte) (samAccount, bool) {
	if len(b) < 68 {
		return samAccount{}, false
	}
	le := binary.LittleEndian
	return samAccount{
		lastLogon: le.Uint64(b[8:]), passwordSet: le.Uint64(b[24:]), expires: le.Uint64(b[32:]), lastFailed: le.Uint64(b[40:]),
		rid: le.Uint32(b[48:]), flags: le.Uint16(b[56:]), failedCount: le.Uint16(b[64:]), logonCount: le.Uint16(b[66:]),
	}, true
}

// parseSAMV reads the names out of an account's V value: a table of
// (offset, length, unused) entries, with offsets counted from 0xCC. Only the
// user name, full name and comment are read. The password hashes that follow
// them in the same value are deliberately left alone.
func parseSAMV(b []byte) (name, full, comment string) {
	le := binary.LittleEndian
	field := func(entry int) string {
		if len(b) < entry*12+12 {
			return ""
		}
		off, n := int(le.Uint32(b[entry*12:]))+0xCC, int(le.Uint32(b[entry*12+4:]))
		if off < 0xCC || n <= 0 || n > 1024 || off+n > len(b) {
			return ""
		}
		return clean(utf16zAt(append(append([]byte(nil), b[off:off+n]...), 0, 0)))
	}
	return field(1), field(2), field(3)
}

func samUser(ctx *Context, host, path, ridHex string, raw map[string][]byte) error {
	f, ok := parseSAMF(raw["f"])
	if !ok {
		return nil
	}
	name, full, comment := parseSAMV(raw["v"])
	if name == "" {
		name = "RID " + strconv.FormatUint(uint64(f.rid), 10)
	}
	var flags []string
	for _, fl := range samFlags {
		if f.flags&fl.bit != 0 {
			flags = append(flags, fl.name)
		}
	}
	fields := map[string]any{"key": path, "account": name, "rid": f.rid, "flags": flags,
		"logon_count": f.logonCount, "failed_logon_count": f.failedCount}
	if full != "" {
		fields["full_name"] = full
	}
	if comment != "" {
		fields["comment"] = comment
	}
	// A Microsoft account signed in to this local account.
	if b := raw["internetusername"]; len(b) > 0 {
		if s := clean(utf16zAt(b)); s != "" {
			fields["internet_user_name"] = s
		}
	}
	if st, ok := timeutil.FromFiletime(f.expires); ok {
		fields["expires"] = st.UTC.Format(time.RFC3339)
	}
	detail := fmt.Sprintf("RID %d", f.rid)
	if len(flags) > 0 {
		detail += "; " + strings.Join(flags, ", ")
	}
	ctx.Fact("sam.account", name+" ("+detail+")", "a local account in the SAM hive")
	for _, t := range []struct {
		ft        uint64
		typ, word string
	}{
		{f.lastLogon, "account-last-logon (sam)", "last logged on"},
		{f.passwordSet, "account-password-set (sam)", "password last set"},
		{f.lastFailed, "account-last-failed-logon (sam)", "last failed to log on"},
	} {
		stamp, ok := timeutil.FromFiletime(t.ft)
		if !ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: t.typ, Category: CatAccount, Source: "registry", Host: host, User: name, Path: name,
			Message: fmt.Sprintf("Local account %s (%s): %s", name, detail, t.word),
			Fields:  fields, Ref: "value F of " + path,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ---- SOFTWARE: networks joined ------------------------------------------

type netSignature struct {
	gatewayMAC, dnsSuffix, firstNetwork, kind string
}

var netTypes = map[uint32]string{6: "wired", 23: "VPN", 71: "wireless", 243: "mobile broadband"}

// systemTime reads a 16-byte SYSTEMTIME. It is a wall-clock reading with no
// zone: NetworkList writes local time.
func systemTime(b []byte) (time.Time, bool) {
	if len(b) < 16 {
		return time.Time{}, false
	}
	le := binary.LittleEndian
	y, mo, d := int(le.Uint16(b)), int(le.Uint16(b[2:])), int(le.Uint16(b[6:]))
	h, mi, s, ms := int(le.Uint16(b[8:])), int(le.Uint16(b[10:])), int(le.Uint16(b[12:])), int(le.Uint16(b[14:]))
	if y < 1980 || y > 2200 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59 || ms > 999 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, ms*1e6, time.UTC), true
}

func (l *regLookup) signatures() map[string]netSignature {
	if l == nil || l.open == nil || l.subkeys == nil {
		return nil
	}
	if l.sigs != nil {
		return l.sigs
	}
	l.sigs = map[string]netSignature{}
	base := `Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\`
	for _, kind := range []string{"Unmanaged", "Managed"} {
		for i, sub := range l.subkeys(base + kind) {
			if i >= 5000 {
				break
			}
			raw := l.open(base + kind + `\` + sub)
			guid := strings.ToLower(clean(utf16zAt(raw["profileguid"])))
			if guid == "" {
				continue
			}
			sig := netSignature{dnsSuffix: clean(utf16zAt(raw["dnssuffix"])), firstNetwork: clean(utf16zAt(raw["firstnetwork"])), kind: strings.ToLower(kind)}
			if mac := raw["defaultgatewaymac"]; len(mac) == 6 {
				sig.gatewayMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
			}
			if _, dup := l.sigs[guid]; !dup {
				l.sigs[guid] = sig
			}
		}
	}
	return l.sigs
}

func networkProfile(ctx *Context, look *regLookup, host, path, guid string, raw map[string][]byte) error {
	name := clean(utf16zAt(raw["profilename"]))
	if name == "" {
		name = guid
	}
	fields := map[string]any{"key": path, "network": name, "profile_guid": guid}
	if d := clean(utf16zAt(raw["description"])); d != "" && d != name {
		fields["description"] = d
	}
	kind := ""
	if b := raw["nametype"]; len(b) >= 4 {
		n := binary.LittleEndian.Uint32(b)
		fields["name_type"] = n
		if kind = netTypes[n]; kind != "" {
			fields["network_type"] = kind
		}
	}
	if sig, ok := look.signatures()[guid]; ok {
		if sig.gatewayMAC != "" {
			fields["gateway_mac"] = sig.gatewayMAC
		}
		if sig.dnsSuffix != "" && sig.dnsSuffix != "<none>" {
			fields["dns_suffix"] = sig.dnsSuffix
		}
		if sig.firstNetwork != "" {
			fields["first_network"] = sig.firstNetwork
		}
		fields["managed"] = sig.kind == "managed"
	}
	label := name
	if kind != "" {
		label += " (" + kind + ")"
	}
	if mac, _ := fields["gateway_mac"].(string); mac != "" {
		label += ", gateway " + mac
	}
	for _, t := range []struct{ value, typ, word string }{
		{"datecreated", "network-first-connected", "first connected to"},
		{"datelastconnected", "network-last-connected", "last connected to"},
	} {
		when, ok := systemTime(raw[t.value])
		if !ok {
			continue
		}
		stamp := timeutil.FromLocal(when, "SYSTEMTIME (local) "+when.Format("2006-01-02 15:04:05.000"), ctx.Local)
		if !timeutil.Plausible(stamp.UTC) {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: t.typ, Category: CatNetwork, Source: "registry", Host: host, Path: name,
			Message: "Network " + t.word + ": " + label,
			Fields:  fields, Ref: "value " + t.value + " of " + path,
		}); err != nil {
			return err
		}
	}
	return nil
}
