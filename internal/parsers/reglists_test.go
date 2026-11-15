package parsers

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// collect gives a context that gathers what a key handler emits.
func collect(local timeutil.LocalContext) (*Context, *[]Event, map[string][]string) {
	var events []Event
	facts := map[string][]string{}
	return &Context{
		Local: local,
		Emit:  func(e Event) error { events = append(events, e); return nil },
		Fact:  func(k, v, _ string) { facts[k] = append(facts[k], v) },
		Warn:  func(string, ...any) {},
		Note:  func(string, ...any) {},
	}, &events, facts
}

func mruEx(order ...uint32) []byte {
	var b []byte
	for _, n := range order {
		b = binary.LittleEndian.AppendUint32(b, n)
	}
	return binary.LittleEndian.AppendUint32(b, 0xFFFFFFFF)
}

func drive(letter byte) []byte {
	b := make([]byte, 25)
	b[2] = 0x2F
	copy(b[3:], []byte{letter, ':', '\\'})
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	return b
}

func pidl(items ...[]byte) []byte {
	var b []byte
	for _, it := range items {
		b = append(b, it...)
	}
	return append(b, 0, 0)
}

func lists(t *testing.T, hive, path string, raw map[string][]byte, look *regLookup, local timeutil.LocalContext) ([]Event, map[string][]string) {
	t.Helper()
	ctx, events, facts := collect(local)
	when := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)
	if err := regListsRaw(ctx, look, hive, "HOST", strings.ToLower(path), path, when, func() map[string][]byte { return raw }); err != nil {
		t.Fatal(err)
	}
	return *events, facts
}

func TestRegistryRecentLists(t *testing.T) {
	const exp = `\Software\Microsoft\Windows\CurrentVersion\Explorer`
	utc := timeutil.AssumedUTC()

	// RecentDocs: the name, then a shell item. Value 1 is the newest.
	doc := func(name string) []byte {
		return append(wide(name+"\x00"), fileItem(0x32, "X.LNK", name+".lnk", 9, "2024-01-01 00:00:00", "2024-01-01 00:00:00", "2024-01-01 00:00:00")...)
	}
	ev, _ := lists(t, "NTUSER", exp+`\RecentDocs\.pdf`, map[string][]byte{
		"mrulistex": mruEx(1, 0, 7), "0": doc("old.pdf"), "1": doc("payroll 2024.pdf"),
	}, nil, utc)
	if len(ev) != 1 {
		t.Fatalf("recent docs: %d events", len(ev))
	}
	e := ev[0]
	if e.Type != "recent-document-latest" || e.Category != CatFileOpening || e.MACB != "" || e.Path != "payroll 2024.pdf" || e.Fields["group"] != ".pdf" ||
		fmt.Sprint(e.Fields["entries"]) != "[payroll 2024.pdf old.pdf]" || e.Fields["entry_count"] != 2 ||
		e.Stamp.UTC.Format(time.RFC3339) != "2024-05-01T10:00:00Z" || !strings.Contains(e.Message, "the newest of 2") {
		t.Errorf("recent docs: %+v", e)
	}
	// Without an order, nothing is claimed to be the newest.
	ev, _ = lists(t, "NTUSER", exp+`\RecentDocs`, map[string][]byte{"0": doc("a.txt"), "10": doc("c.txt"), "2": doc("b.txt")}, nil, utc)
	if len(ev) != 1 || ev[0].Path != "" || ev[0].Fields["order"] != "not recorded" || fmt.Sprint(ev[0].Fields["entries"]) != "[a.txt b.txt c.txt]" || ev[0].Fields["newest"] != nil {
		t.Errorf("unordered list: %+v", ev)
	}
	// An empty list says nothing.
	if ev, _ = lists(t, "NTUSER", exp+`\RecentDocs`, map[string][]byte{"mrulistex": mruEx()}, nil, utc); len(ev) != 0 {
		t.Errorf("empty list: %+v", ev)
	}

	// The Open and Save dialogs: full paths as shell item lists.
	file := pidl(drive('E'), fileItem(0x31, "SECRET", "Secret plans", 9, "2024-02-01 09:00:00", "2024-02-01 09:00:00", "2024-02-01 09:00:00"),
		fileItem(0x32, "BUDGET~1.XLS", "budget.xlsx", 9, "2024-02-01 09:00:00", "2024-02-01 09:00:00", "2024-02-01 09:00:00"))
	ev, _ = lists(t, "NTUSER", exp+`\ComDlg32\OpenSavePidlMRU\xlsx`, map[string][]byte{"mrulistex": mruEx(0), "0": file}, nil, utc)
	if len(ev) != 1 || ev[0].Type != "open-save-dialog-latest" || ev[0].Path != `E:\Secret plans\budget.xlsx` || ev[0].Fields["group"] != "xlsx" {
		t.Errorf("open/save: %+v", ev)
	}
	folder := pidl(drive('E'), fileItem(0x31, "SECRET", "Secret plans", 9, "2024-02-01 09:00:00", "2024-02-01 09:00:00", "2024-02-01 09:00:00"))
	ev, _ = lists(t, "NTUSER", exp+`\ComDlg32\LastVisitedPidlMRU`, map[string][]byte{"mrulistex": mruEx(0), "0": append(wide("7zFM.exe\x00"), folder...)}, nil, utc)
	if len(ev) != 1 || ev[0].Type != "dialog-last-folder-latest" || ev[0].Path != `7zFM.exe in E:\Secret plans` {
		t.Errorf("last visited: %+v", ev)
	}
	ev, _ = lists(t, "NTUSER", exp+`\WordWheelQuery`, map[string][]byte{"mrulistex": mruEx(1, 0), "0": wide("holiday\x00"), "1": wide("passwords.xlsx\x00")}, nil, utc)
	if len(ev) != 1 || ev[0].Type != "explorer-search-latest" || ev[0].Path != "passwords.xlsx" || fmt.Sprint(ev[0].Fields["entries"]) != "[passwords.xlsx holiday]" {
		t.Errorf("searches: %+v", ev)
	}

	// Typed addresses each have their own time, in the key beside them.
	ft := func(s string) []byte {
		tm, _ := time.Parse(time.RFC3339, s)
		return binary.LittleEndian.AppendUint64(nil, uint64(tm.UnixNano()/100)+116444736000000000)
	}
	look := &regLookup{open: func(p string) map[string][]byte {
		if p != `Software\Microsoft\Internet Explorer\TypedURLsTime` {
			t.Errorf("looked up %q", p)
		}
		return map[string][]byte{"url1": ft("2024-03-03T08:00:00Z"), "url2": make([]byte, 8)}
	}}
	ev, _ = lists(t, "NTUSER", `\Software\Microsoft\Internet Explorer\TypedURLs`, map[string][]byte{
		"url1": wide("http://intranet/payroll\x00"), "url2": wide("http://undated/\x00"),
	}, look, utc)
	if len(ev) != 1 || ev[0].Type != "url-typed (internet explorer)" || ev[0].Category != CatBrowser || ev[0].Path != "http://intranet/payroll" ||
		ev[0].Stamp.UTC.Format(time.RFC3339) != "2024-03-03T08:00:00Z" {
		t.Errorf("typed urls: %+v", ev)
	}

	// Office: every item carries its own time.
	item := func(when, p string) []byte {
		tm, _ := time.Parse(time.RFC3339, when)
		return wide(fmt.Sprintf("[F00000000][T%016X][O00000000]*%s\x00", uint64(tm.UnixNano()/100)+116444736000000000, p))
	}
	ev, _ = lists(t, "NTUSER", `\Software\Microsoft\Office\16.0\Word\User MRU\AD_1234\File MRU`, map[string][]byte{
		"item 1": item("2024-04-02T12:00:00Z", `C:\Users\a\Documents\offer.docx`),
		"item 2": item("2024-04-01T12:00:00Z", `\\fs01\hr\salaries.docx`),
		"item 3": wide("not an item\x00"), "max display": {25, 0, 0, 0},
	}, nil, utc)
	if len(ev) != 2 || ev[0].Type != "office-document-last-opened" || ev[0].Path != `C:\Users\a\Documents\offer.docx` || ev[0].Fields["application"] != "Word" ||
		ev[0].Fields["office_version"] != "16.0" || ev[1].Path != `\\fs01\hr\salaries.docx` || ev[1].Stamp.UTC.Format(time.RFC3339) != "2024-04-01T12:00:00Z" {
		t.Errorf("office: %+v", ev)
	}
	ev, _ = lists(t, "NTUSER", `\Software\Microsoft\Office\16.0\Excel\Place MRU`, map[string][]byte{"item 1": item("2024-04-02T12:00:00Z", `E:\Secret plans\`)}, nil, utc)
	if len(ev) != 1 || ev[0].Type != "office-folder-last-used" || ev[0].Fields["application"] != "Excel" {
		t.Errorf("office places: %+v", ev)
	}

	// The same keys in another hive, and look-alike keys, are left alone.
	for hive, path := range map[string]string{
		"SOFTWARE": exp + `\RecentDocs`, "NTUSER": exp + `\RecentDocsBackup`, "USRCLASS": exp + `\WordWheelQuery`,
	} {
		if ev, _ := lists(t, hive, path, map[string][]byte{"mrulistex": mruEx(0), "0": doc("a.txt")}, nil, utc); len(ev) != 0 {
			t.Errorf("%s %s: %+v", hive, path, ev)
		}
	}
	// Damaged values must not panic.
	for n := 0; n < len(file); n++ {
		lists(t, "NTUSER", exp+`\ComDlg32\OpenSavePidlMRU\xlsx`, map[string][]byte{"mrulistex": mruEx(0)[:n%8], "0": file[:n]}, nil, utc)
		lists(t, "NTUSER", exp+`\ComDlg32\LastVisitedPidlMRU`, map[string][]byte{"mrulistex": mruEx(0), "0": file[n:]}, nil, utc)
		lists(t, "NTUSER", exp+`\RecentDocs`, map[string][]byte{"mrulistex": mruEx(0), "0": file[:n]}, nil, utc)
	}
}

func TestSAMAccounts(t *testing.T) {
	ft := func(s string) uint64 {
		tm, _ := time.Parse(time.RFC3339, s)
		return uint64(tm.UnixNano()/100) + 116444736000000000
	}
	le := binary.LittleEndian
	f := make([]byte, 80)
	le.PutUint64(f[8:], ft("2024-05-01T08:30:00Z"))
	le.PutUint64(f[24:], ft("2023-01-15T12:00:00Z"))
	le.PutUint64(f[32:], 0x7FFFFFFFFFFFFFFF) // never expires
	le.PutUint64(f[40:], ft("2024-04-30T23:59:00Z"))
	le.PutUint32(f[48:], 1001)
	le.PutUint16(f[56:], 0x0210)
	le.PutUint16(f[64:], 3)
	le.PutUint16(f[66:], 57)
	// V: a table of entries, then the data they point into.
	v := make([]byte, 0xCC)
	put := func(entry int, s string) {
		w := wide(s)
		le.PutUint32(v[entry*12:], uint32(len(v)-0xCC))
		le.PutUint32(v[entry*12+4:], uint32(len(w)))
		v = append(v, w...)
		for len(v)%4 != 0 {
			v = append(v, 0)
		}
	}
	put(1, "svc_backup")
	put(2, "Backup Service")
	put(3, "added by IT")

	ev, facts := lists(t, "SAM", `\SAM\Domains\Account\Users\000003E9`, map[string][]byte{"f": f, "v": v}, nil, timeutil.AssumedUTC())
	if len(ev) != 3 {
		t.Fatalf("%d events: %+v", len(ev), ev)
	}
	want := map[string]string{
		"account-last-logon (sam)": "2024-05-01T08:30:00Z", "account-password-set (sam)": "2023-01-15T12:00:00Z", "account-last-failed-logon (sam)": "2024-04-30T23:59:00Z",
	}
	for _, e := range ev {
		if want[e.Type] != e.Stamp.UTC.Format(time.RFC3339) || e.Category != CatAccount || e.User != "svc_backup" || e.Fields["rid"] != uint32(1001) ||
			e.Fields["full_name"] != "Backup Service" || e.Fields["comment"] != "added by IT" || e.Fields["logon_count"] != uint16(57) ||
			e.Fields["failed_logon_count"] != uint16(3) || fmt.Sprint(e.Fields["flags"]) != "[normal user account password does not expire]" || e.Fields["expires"] != nil {
			t.Errorf("%s: %s %+v", e.Type, e.Stamp.UTC.Format(time.RFC3339), e.Fields)
		}
	}
	if len(facts["sam.account"]) != 1 || facts["sam.account"][0] != "svc_backup (RID 1001; normal user account, password does not expire)" {
		t.Errorf("fact: %q", facts["sam.account"])
	}
	// An account that has never logged on still appears, as a fact.
	never := make([]byte, 80)
	le.PutUint32(never[48:], 501)
	le.PutUint16(never[56:], 0x0215)
	ev, facts = lists(t, "SAM", `\SAM\Domains\Account\Users\000001F5`, map[string][]byte{"f": never, "v": v[:0xCC]}, nil, timeutil.AssumedUTC())
	if len(ev) != 0 || len(facts["sam.account"]) != 1 || !strings.HasPrefix(facts["sam.account"][0], "RID 501 (RID 501; disabled") {
		t.Errorf("never-used account: %d events, %q", len(ev), facts["sam.account"])
	}
	// The name key, and every truncation of both values.
	typ, cat, msg, _, ok := classifyKey("SAM", `\sam\domains\account\users\names\svc_backup`, `\SAM\Domains\Account\Users\Names\svc_backup`, nil)
	if !ok || typ != "account-name-key-last-write" || cat != CatAccount || !strings.Contains(msg, "svc_backup") {
		t.Errorf("name key: %q %q %q", typ, cat, msg)
	}
	for n := 0; n < len(v); n += 3 {
		lists(t, "SAM", `\SAM\Domains\Account\Users\000003E9`, map[string][]byte{"f": f[:n%len(f)], "v": v[:n]}, nil, timeutil.AssumedUTC())
		lists(t, "SAM", `\SAM\Domains\Account\Users\000003E9`, map[string][]byte{"f": f, "v": v[:n]}, nil, timeutil.AssumedUTC())
	}
}

func TestNetworkHistory(t *testing.T) {
	st := func(y, mo, d, h, mi, s int) []byte {
		b := make([]byte, 16)
		for i, n := range []int{y, mo, 0, d, h, mi, s, 0} {
			binary.LittleEndian.PutUint16(b[i*2:], uint16(n))
		}
		return b
	}
	const guid = "{11111111-2222-3333-4444-555555555555}"
	const base = `Microsoft\Windows NT\CurrentVersion\NetworkList\`
	look := &regLookup{
		subkeys: func(p string) []string {
			if p == base+`Signatures\Unmanaged` {
				return []string{"010103000F0000F0080000000F0000F0AAAA", "other"}
			}
			return nil
		},
		open: func(p string) map[string][]byte {
			switch p {
			case base + `Signatures\Unmanaged\010103000F0000F0080000000F0000F0AAAA`:
				return map[string][]byte{"profileguid": wide(strings.ToUpper(guid) + "\x00"), "defaultgatewaymac": {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E},
					"dnssuffix": wide("hotel.example\x00"), "firstnetwork": wide("Hotel Guest\x00")}
			case base + `Signatures\Unmanaged\other`:
				return map[string][]byte{"profileguid": wide("{other}\x00")}
			}
			return nil
		},
	}
	raw := map[string][]byte{
		"profilename": wide("Hotel Guest 2\x00"), "description": wide("Hotel Guest\x00"), "nametype": {71, 0, 0, 0},
		"datecreated": st(2024, 7, 14, 21, 5, 9), "datelastconnected": st(2024, 7, 16, 7, 30, 0), "category": {0, 0, 0, 0},
	}
	path := `\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\` + guid

	// With the host's zone known, local time is converted on evidence.
	london, _ := time.LoadLocation("Europe/London")
	ev, _ := lists(t, "SOFTWARE", path, raw, look, timeutil.LocalContext{Loc: london, ZoneFrom: timeutil.ZoneHost, ZoneName: "Europe/London"})
	if len(ev) != 2 {
		t.Fatalf("%d events", len(ev))
	}
	first, last := ev[0], ev[1]
	if first.Type != "network-first-connected" || first.Stamp.UTC.Format(time.RFC3339) != "2024-07-14T20:05:09Z" || first.Stamp.ZoneFrom != timeutil.ZoneHost ||
		last.Type != "network-last-connected" || last.Stamp.UTC.Format(time.RFC3339) != "2024-07-16T06:30:00Z" || first.Category != CatNetwork {
		t.Errorf("times: %s %s %s / %s", first.Type, first.Stamp.UTC, first.Stamp.ZoneFrom, last.Stamp.UTC)
	}
	if first.Path != "Hotel Guest 2" || first.Fields["network_type"] != "wireless" || first.Fields["gateway_mac"] != "00:1a:2b:3c:4d:5e" ||
		first.Fields["dns_suffix"] != "hotel.example" || first.Fields["first_network"] != "Hotel Guest" || first.Fields["managed"] != false ||
		!strings.Contains(first.Message, "Hotel Guest 2 (wireless), gateway 00:1a:2b:3c:4d:5e") || !strings.Contains(first.Stamp.Raw, "2024-07-14 21:05:09") {
		t.Errorf("profile: %q %+v", first.Message, first.Fields)
	}
	// Without it, the events say the zone was assumed.
	ev, _ = lists(t, "SOFTWARE", path, raw, look, timeutil.AssumedUTC())
	if len(ev) != 2 || ev[0].Stamp.ZoneFrom != timeutil.ZoneAssumed || ev[0].Stamp.UTC.Format(time.RFC3339) != "2024-07-14T21:05:09Z" {
		t.Errorf("assumed zone: %+v", ev)
	}
	// No signatures, no lookup, impossible dates.
	bad := map[string][]byte{"profilename": wide("x\x00"), "datecreated": st(2024, 13, 1, 0, 0, 0), "datelastconnected": st(2024, 7, 16, 7, 30, 0)[:9]}
	if ev, _ = lists(t, "SOFTWARE", path, bad, nil, timeutil.AssumedUTC()); len(ev) != 0 {
		t.Errorf("bad dates: %+v", ev)
	}
}
