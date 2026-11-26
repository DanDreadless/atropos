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
	// Without TypedURLsTime (as on the owner's Windows 11): url1 is the newest,
	// dated by the key, and url10 comes after url2.
	ev, _ = lists(t, "NTUSER", `\Software\Microsoft\Internet Explorer\TypedURLs`, map[string][]byte{
		"url10": wide("http://ten/\x00"), "url2": wide("http://two/\x00"), "url1": wide("http://one/\x00"), "urlx": wide("http://no/\x00"),
	}, nil, utc)
	if len(ev) != 1 || ev[0].Type != "url-typed-latest (internet explorer)" || ev[0].Category != CatBrowser || ev[0].Path != "http://one/" ||
		fmt.Sprint(ev[0].Fields["entries"]) != "[http://one/ http://two/ http://ten/]" || ev[0].Stamp.UTC.Format(time.RFC3339) != "2024-05-01T10:00:00Z" {
		t.Errorf("typed urls without times: %+v", ev)
	}
	// Paths typed into Explorer's address bar: the same numbering, no times.
	ev, _ = lists(t, "NTUSER", `\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`, map[string][]byte{
		"url2": wide(`\\fs01\share` + "\x00"), "url1": wide(`C:\Windows\System32\config` + "\x00"),
	}, nil, utc)
	if len(ev) != 1 || ev[0].Type != "path-typed-latest (explorer)" || ev[0].Category != CatFileOpening || ev[0].Path != `C:\Windows\System32\config` ||
		ev[0].Fields["entry_count"] != 2 || !strings.HasPrefix(ev[0].Message, `Typed into Explorer's address bar: C:\Windows\System32\config  (the newest of 2`) {
		t.Errorf("typed paths: %+v", ev)
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

// A local group's C value: its name, comment and members as SIDs. A local
// account is named from the same hive when its SID is the machine's; a
// domain account keeps its SID; a well-known SID is named. Layout checked on
// the owner's SAM against Get-LocalGroupMember.
func TestSAMGroups(t *testing.T) {
	le := binary.LittleEndian
	sid := func(auth byte, subs ...uint32) []byte {
		b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, auth}
		for _, s := range subs {
			b = le.AppendUint32(b, s)
		}
		return b
	}
	group := func(name, comment string, members ...[]byte) []byte {
		data := wide(name)
		nameOff := 0
		commOff := len(data)
		data = append(data, wide(comment)...)
		memOff := len(data)
		for _, m := range members {
			data = append(data, m...)
		}
		h := make([]byte, 0x34)
		le.PutUint32(h[0x10:], uint32(nameOff))
		le.PutUint32(h[0x14:], uint32(len(wide(name))))
		le.PutUint32(h[0x1C:], uint32(commOff))
		le.PutUint32(h[0x20:], uint32(len(wide(comment))))
		le.PutUint32(h[0x28:], uint32(memOff))
		le.PutUint32(h[0x2C:], uint32(len(data)-memOff))
		le.PutUint32(h[0x30:], uint32(len(members)))
		return append(h, data...)
	}
	// The hive's own domain is S-1-5-21-111-222-333; account 1001 is dan.
	acct := make([]byte, 40)
	acct = append(acct, le.AppendUint32(le.AppendUint32(le.AppendUint32(nil, 111), 222), 333)...)
	userV := make([]byte, 0xCC)
	le.PutUint32(userV[12:], 0)
	le.PutUint32(userV[16:], uint32(len(wide("dan"))))
	userV = append(userV, wide("dan")...)
	look := &regLookup{open: func(p string) map[string][]byte {
		switch p {
		case `SAM\Domains\Account`:
			return map[string][]byte{"v": acct}
		case `SAM\Domains\Account\Users\000003E9`:
			return map[string][]byte{"v": userV}
		}
		return nil
	}}
	c := group("Administrators", "Administrators have complete and unrestricted access",
		sid(5, 21, 111, 222, 333, 1001), sid(5, 21, 900, 901, 902, 1001), sid(5, 4), sid(5, 21, 900, 901, 902, 512))
	ev, facts := lists(t, "SAM", `\SAM\Domains\Builtin\Aliases\00000220`, map[string][]byte{"c": c}, look, timeutil.AssumedUTC())
	wantList := "dan, S-1-5-21-900-901-902-1001, INTERACTIVE, S-1-5-21-900-901-902-512"
	if len(facts["sam.group"]) != 1 || facts["sam.group"][0] != "Administrators: "+wantList {
		t.Errorf("fact: %q", facts["sam.group"])
	}
	if len(ev) != 1 {
		t.Fatalf("%d events", len(ev))
	}
	e := ev[0]
	if e.Type != "group-key-last-write (sam)" || e.Category != CatAccount || e.Path != "Administrators" || e.Stamp.UTC.Format(time.RFC3339) != "2024-05-01T10:00:00Z" ||
		e.Message != "Local group Administrators (built-in): 4 members, "+wantList || e.Fields["machine_sid"] != "S-1-5-21-111-222-333" ||
		e.Fields["member_count"] != 4 || e.Fields["comment"] != "Administrators have complete and unrestricted access" {
		t.Errorf("%s %q %+v", e.Type, e.Message, e.Fields)
	}
	if ms := e.Fields["members"].([]map[string]any); ms[0]["name"] != "dan" || ms[0]["sid"] != "S-1-5-21-111-222-333-1001" || ms[1]["name"] != nil {
		t.Errorf("members: %+v", ms)
	}
	// A group made on the computer with no members: a fact, no event.
	ev, facts = lists(t, "SAM", `\SAM\Domains\Account\Aliases\000003F4`, map[string][]byte{"c": group("Backup operators (local)", "")}, look, timeutil.AssumedUTC())
	if len(ev) != 0 || len(facts["sam.group"]) != 1 || facts["sam.group"][0] != "Backup operators (local): no members" {
		t.Errorf("empty group: %d events, %q", len(ev), facts["sam.group"])
	}
	// Without the rest of the hive, a local account is its SID.
	ev, _ = lists(t, "SAM", `\SAM\Domains\Builtin\Aliases\00000220`, map[string][]byte{"c": c}, nil, timeutil.AssumedUTC())
	if len(ev) != 1 || !strings.Contains(ev[0].Message, "4 members, S-1-5-21-111-222-333-1001, ") {
		t.Errorf("no lookup: %+v", ev)
	}
	// Every truncation, and a count larger than the members.
	for n := 0; n < len(c); n++ {
		lists(t, "SAM", `\SAM\Domains\Builtin\Aliases\00000220`, map[string][]byte{"c": c[:n]}, look, timeutil.AssumedUTC())
	}
	big := append([]byte(nil), c...)
	le.PutUint32(big[0x30:], 1000)
	if ev, _ := lists(t, "SAM", `\SAM\Domains\Builtin\Aliases\00000220`, map[string][]byte{"c": big}, look, timeutil.AssumedUTC()); len(ev) != 0 {
		t.Errorf("a count beyond the members gave %d events", len(ev))
	}
}

// The SECURITY hive's audit policy: a header whose word at 8 is the offset
// of the nine counts at the end, one setting per subcategory before them.
// The settings below are Windows 11's defaults, as on the owner's hive.
func TestAuditPolicy(t *testing.T) {
	le := binary.LittleEndian
	policy := func(counts []int, set map[int]uint16) []byte {
		total := 0
		for _, n := range counts {
			total += n
		}
		b := make([]byte, 12+2*total+2) // one spare word before the counts, as Windows writes
		le.PutUint16(b[0:], 0x0100)
		le.PutUint16(b[4:], 9)
		le.PutUint16(b[8:], uint16(len(b)))
		for i, v := range set {
			le.PutUint16(b[12+2*i:], v)
		}
		for _, n := range counts {
			b = le.AppendUint16(b, uint16(n))
		}
		return b
	}
	// Positions in the Windows 10 and 11 layout: System 0-4, Logon/Logoff 5-15,
	// Object Access 16-29, Privilege Use 30-32, Detailed Tracking 33-38,
	// Policy Change 39-44, Account Management 45-50.
	defaults := map[int]uint16{0: 1, 2: 3, 4: 3, 5: 3, 6: 1, 7: 1, 9: 1, 13: 3, 39: 1, 40: 1, 45: 1, 47: 1}
	b := policy([]int{5, 11, 14, 3, 6, 6, 6, 4, 4}, defaults)
	ev, facts := lists(t, "SECURITY", `\Policy\PolAdtEv`, map[string][]byte{"": b}, nil, timeutil.AssumedUTC())
	want := "Security State Change (success), System Integrity (success and failure), Other System Events (success and failure), Logon (success and failure), " +
		"Logoff (success), Account Lockout (success), Special Logon (success), Network Policy Server (success and failure), Audit Policy Change (success), " +
		"Authentication Policy Change (success), User Account Management (success), Security Group Management (success); everything else not audited"
	if len(facts["security.audit_policy"]) != 1 || facts["security.audit_policy"][0] != want {
		t.Errorf("fact: %q", facts["security.audit_policy"])
	}
	if len(ev) != 1 {
		t.Fatalf("%d events", len(ev))
	}
	e := ev[0]
	settings := e.Fields["settings"].(map[string]string)
	if e.Type != "audit-policy-key-last-write (security)" || e.Category != CatSecurity || !strings.HasPrefix(e.Message, "Audit policy (12 of 59 subcategories audited): ") ||
		settings["Detailed Tracking: Process Creation"] != "not audited" || settings["Logon/Logoff: Special Logon"] != "success" ||
		settings["Account Logon: Kerberos Authentication Service"] != "not audited" || len(settings) != 59 || e.Fields["caution"] != nil {
		t.Errorf("%q %+v", e.Message, e.Fields)
	}
	// Process creation audited: the 34th subcategory.
	ev, _ = lists(t, "SECURITY", `\Policy\PolAdtEv`, map[string][]byte{"": policy([]int{5, 11, 14, 3, 6, 6, 6, 4, 4}, map[int]uint16{33: 2})}, nil, timeutil.AssumedUTC())
	if len(ev) != 1 || ev[0].Fields["settings"].(map[string]string)["Detailed Tracking: Process Creation"] != "failure" {
		t.Errorf("process creation: %+v", ev)
	}
	// The owner's Windows 11: one Logon/Logoff subcategory more. Named as
	// far as known, the extra one unnamed, and the category marked.
	ev, _ = lists(t, "SECURITY", `\Policy\PolAdtEv`, map[string][]byte{"": policy([]int{5, 12, 14, 3, 6, 6, 6, 4, 4}, map[int]uint16{16: 1, 34: 3})}, nil, timeutil.AssumedUTC())
	if len(ev) != 1 {
		t.Fatalf("Windows 11: %d events", len(ev))
	}
	settings = ev[0].Fields["settings"].(map[string]string)
	if settings["Logon/Logoff: subcategory 12 (not known to Atropos)"] != "success" || settings["Detailed Tracking: Process Creation"] != "success and failure" ||
		fmt.Sprint(ev[0].Fields["categories_of_unknown_layout"]) != "[Logon/Logoff]" || ev[0].Fields["caution"] == nil {
		t.Errorf("Windows 11: %+v", ev[0].Fields)
	}
	// A layout that does not add up is not read; nor is any truncation.
	bad := append([]byte(nil), b...)
	le.PutUint16(bad[8:], 20)
	ev, facts = lists(t, "SECURITY", `\Policy\PolAdtEv`, map[string][]byte{"": bad}, nil, timeutil.AssumedUTC())
	if len(ev) != 0 || len(facts) != 0 {
		t.Errorf("bad layout: %+v %v", ev, facts)
	}
	for n := 0; n < len(b); n++ {
		lists(t, "SECURITY", `\Policy\PolAdtEv`, map[string][]byte{"": b[:n]}, nil, timeutil.AssumedUTC())
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

// The SECURITY hive's own SID, its name, and the domain or workgroup it is
// in: a domain has its SID in PolPrDmS, a workgroup four empty bytes.
func TestSecurityDomain(t *testing.T) {
	le := binary.LittleEndian
	lsa := func(s string) []byte {
		w := wide(s)
		b := le.AppendUint16(le.AppendUint16(nil, uint16(len(w))), uint16(len(w)+2))
		return append(le.AppendUint32(b, 8), append(w, 0, 0)...)
	}
	sid := []byte{1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}
	for _, n := range []uint32{111, 222, 333} {
		sid = le.AppendUint32(sid, n)
	}
	_, facts := lists(t, "SECURITY", `\Policy\PolAcDmS`, map[string][]byte{"": sid}, nil, timeutil.AssumedUTC())
	if facts["security.machine_sid"][0] != "S-1-5-21-111-222-333" {
		t.Errorf("machine SID %q", facts["security.machine_sid"])
	}
	_, facts = lists(t, "SECURITY", `\Policy\PolAcDmN`, map[string][]byte{"": lsa("WS-ALICE")}, nil, timeutil.AssumedUTC())
	if facts["security.computer_name"][0] != "WS-ALICE" {
		t.Errorf("computer name %q", facts["security.computer_name"])
	}
	prs := map[string][]byte{"": {0, 0, 0, 0}}
	look := &regLookup{open: func(p string) map[string][]byte {
		if p == `Policy\PolPrDmS` {
			return prs
		}
		return nil
	}}
	ev, facts := lists(t, "SECURITY", `\Policy\PolPrDmN`, map[string][]byte{"": lsa("WORKGROUP")}, look, timeutil.AssumedUTC())
	if facts["security.primary_domain"][0] != "WORKGROUP (a workgroup: not joined to a domain)" || len(ev) != 1 ||
		ev[0].Type != "domain-membership-key-last-write (security)" || ev[0].Category != CatAccount ||
		ev[0].Message != "In the workgroup WORKGROUP (not joined to a domain)" || ev[0].Fields["membership"] != "workgroup" {
		t.Errorf("workgroup: %q %+v", facts["security.primary_domain"], ev)
	}
	prs[""] = sid
	ev, facts = lists(t, "SECURITY", `\Policy\PolPrDmN`, map[string][]byte{"": lsa("CORP")}, look, timeutil.AssumedUTC())
	if facts["security.primary_domain"][0] != "CORP (a domain, SID S-1-5-21-111-222-333)" || len(ev) != 1 ||
		ev[0].Message != "Member of the domain CORP" || ev[0].Fields["domain_sid"] != "S-1-5-21-111-222-333" {
		t.Errorf("domain: %q %+v", facts["security.primary_domain"], ev)
	}
	// Without PolPrDmS, which it is is not known, and that is said.
	ev, facts = lists(t, "SECURITY", `\Policy\PolPrDmN`, map[string][]byte{"": lsa("CORP")}, nil, timeutil.AssumedUTC())
	if facts["security.primary_domain"][0] != "CORP (domain or workgroup: not known)" || ev[0].Fields["caution"] == nil {
		t.Errorf("unknown: %q %+v", facts["security.primary_domain"], ev)
	}
	// Lengths and offsets that do not fit give nothing.
	good := lsa("CORP")
	for _, bad := range [][]byte{good[:7], good[:10], append(append([]byte{}, good[:4]...), 0xF0, 0, 0, 0), {3, 0, 4, 0, 8, 0, 0, 0, 'a', 0}} {
		ev, facts = lists(t, "SECURITY", `\Policy\PolPrDmN`, map[string][]byte{"": bad}, look, timeutil.AssumedUTC())
		if len(ev) != 0 || len(facts) != 0 {
			t.Errorf("% x: %+v %v", bad, ev, facts)
		}
	}
}
