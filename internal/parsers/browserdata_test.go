package parsers

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func unixMicro(s string) int64 {
	tm, _ := time.Parse(time.RFC3339Nano, s)
	return tm.UnixMicro()
}

// everything a run produced, as one string, for "this must not appear" checks.
func (r result) all() string {
	return fmt.Sprintf("%+v %v %v %v %s", r.events, r.facts, r.notes, r.warns, r.text)
}

func types(r result) string {
	var t []string
	for _, e := range r.events {
		t = append(t, e.Type)
	}
	return strings.Join(t, ",")
}

// Cookies: the site, the name and the times. The value is never read.
func TestChromiumCookies(t *testing.T) {
	p := makeDB(t, "Cookies",
		`CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER,
			is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, is_persistent INTEGER, last_update_utc INTEGER)`,
		fmt.Sprintf(`INSERT INTO cookies VALUES (%d,'.evil.test','session','SECRETVALUE',X'5345435245544249','/login',%d,1,1,%d,1,%d)`,
			webkit("2024-03-01T10:00:00Z"), webkit("2025-03-01T10:00:00Z"), webkit("2024-03-02T11:00:00.5Z"), webkit("2024-03-01T10:00:00Z")),
		`INSERT INTO cookies VALUES (0,'nowhere.test','undated','x',NULL,'/',0,0,0,0,0,0)`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	// Created and last sent; the update time equals the creation time and adds nothing.
	if types(r) != "cookie-created,cookie-last-accessed" {
		t.Fatalf("types: %s", types(r))
	}
	e := r.events[1]
	if utc(e) != "2024-03-02T11:00:00.5Z" || e.Path != "evil.test/login" || e.Fields["cookie_name"] != "session" ||
		e.Fields["expires"] != "2025-03-01T10:00:00Z" || e.Fields["secure"] != true || e.Category != CatBrowser || e.Ref != "cookies rowid 1" {
		t.Errorf("cookie: %s %+v", utc(e), e)
	}
	if s := r.all(); strings.Contains(s, "SECRET") {
		t.Error("a cookie value reached the output")
	}
}

// Saved logins: who and where and when, and never the password.
func TestChromiumLoginsNeverReadThePassword(t *testing.T) {
	p := makeDB(t, "Login Data",
		`CREATE TABLE logins(origin_url TEXT, action_url TEXT, username_value TEXT, password_value BLOB, signon_realm TEXT, date_created INTEGER,
			blacklisted_by_user INTEGER, times_used INTEGER, date_last_used INTEGER, date_password_modified INTEGER)`,
		fmt.Sprintf(`INSERT INTO logins VALUES ('https://bank.test/login','https://bank.test/do','dana',X'48554e54455232','https://bank.test/',%d,0,7,%d,%d)`,
			webkit("2023-05-01T08:00:00Z"), webkit("2024-02-02T09:30:00Z"), webkit("2023-12-25T12:00:00Z")),
		fmt.Sprintf(`INSERT INTO logins VALUES ('https://never.test/','','','','https://never.test/',%d,1,0,0,0)`, webkit("2023-06-01T08:00:00Z")),
		// An old database: seconds since 1970.
		`INSERT INTO logins VALUES ('https://old.test/','','olduser','pw','https://old.test/',1300000000,0,0,0,0)`,
		// One day after 1601, as a real profile holds in "date_last_used" for a login never used: not a time.
		`INSERT INTO logins VALUES ('https://unused.test/','','u','pw','https://unused.test/',0,0,0,86400000000,0)`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if types(r) != "login-saved,login-last-used,login-password-changed,login-save-declined,login-saved" {
		t.Fatalf("types: %s", types(r))
	}
	e := r.events[0]
	if utc(e) != "2023-05-01T08:00:00Z" || e.User != "dana" || e.Path != "https://bank.test/login" || e.Fields["times_used"] != int64(7) {
		t.Errorf("login: %s %+v", utc(e), e)
	}
	if o := r.events[4]; utc(o) != "2011-03-13T07:06:40Z" || !strings.HasPrefix(o.Stamp.Raw, "unix-s") {
		t.Errorf("old login time: %s raw %q", utc(o), o.Stamp.Raw)
	}
	if s := r.all(); strings.Contains(s, "HUNTER2") || strings.Contains(s, "48554e54") || strings.Contains(s, "pw ") {
		t.Error("a password reached the output")
	}
}

func TestChromiumFormValuesShortcutsAndIcons(t *testing.T) {
	p := makeDB(t, "Web Data",
		`CREATE TABLE autofill(name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER)`,
		`INSERT INTO autofill VALUES ('q','how to wipe a disk','how to wipe a disk',1700000000,1700003600,3),('email','a@b.test','a@b.test',1700000000,1700000000,1)`,
	)
	r := run(t, p, nil)
	if r.err != nil || types(r) != "form-value-first-entered,form-value-last-used,form-value-first-entered" {
		t.Fatalf("err=%v types=%s", r.err, types(r))
	}
	if e := r.events[1]; utc(e) != "2023-11-14T23:13:20Z" || e.Fields["value"] != "how to wipe a disk" || e.Fields["form_field"] != "q" {
		t.Errorf("form value: %s %+v", utc(e), e)
	}

	p = makeDB(t, "Shortcuts",
		`CREATE TABLE omni_box_shortcuts(id TEXT, text TEXT, fill_into_edit TEXT, url TEXT, contents TEXT, last_access_time INTEGER, number_of_hits INTEGER)`,
		fmt.Sprintf(`INSERT INTO omni_box_shortcuts VALUES ('a','meg','mega.test','https://mega.test/','Mega',%d,4)`, webkit("2024-04-04T04:04:04Z")),
	)
	r = run(t, p, nil)
	if r.err != nil || len(r.events) != 1 || r.events[0].Type != "address-bar-suggestion-chosen" || r.events[0].Fields["typed"] != "meg" ||
		r.events[0].Path != "https://mega.test/" || utc(r.events[0]) != "2024-04-04T04:04:04Z" {
		t.Fatalf("shortcut: err=%v %+v", r.err, r.events)
	}

	p = makeDB(t, "Favicons",
		`CREATE TABLE favicons(id INTEGER PRIMARY KEY, url TEXT)`,
		`CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY, icon_id INTEGER, last_updated INTEGER)`,
		`CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY, page_url TEXT, icon_id INTEGER)`,
		`INSERT INTO favicons VALUES (1,'https://cleared.test/favicon.ico')`,
		fmt.Sprintf(`INSERT INTO favicon_bitmaps VALUES (1,1,%d),(2,1,%d)`, webkit("2024-01-01T00:00:00Z"), webkit("2024-01-05T00:00:00Z")),
		`INSERT INTO icon_mapping VALUES (1,'https://cleared.test/page',1)`,
	)
	r = run(t, p, nil)
	if r.err != nil || len(r.events) != 1 || r.events[0].Type != "page-icon-updated" || utc(r.events[0]) != "2024-01-05T00:00:00Z" ||
		r.events[0].Fields["icon_url"] != "https://cleared.test/favicon.ico" {
		t.Fatalf("icon: err=%v %+v", r.err, r.events)
	}

	// A list with no times is text, not events.
	p = makeDB(t, "Top Sites",
		`CREATE TABLE top_sites(url TEXT, url_rank INTEGER, title TEXT)`,
		`INSERT INTO top_sites VALUES ('https://first.test/',0,'First'),('https://second.test/',1,'Second')`,
	)
	r = run(t, p, nil)
	if r.err != nil || len(r.events) != 0 || !strings.Contains(r.text, "rank 1: https://second.test/  Second") || r.facts["browser.most_visited"] != "2" {
		t.Fatalf("top sites: err=%v events=%d text=%q facts=%v", r.err, len(r.events), r.text, r.facts)
	}
}

func TestFirefoxCookiesFormsAndBookmarks(t *testing.T) {
	p := makeDB(t, "cookies.sqlite",
		`CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER)`,
		fmt.Sprintf(`INSERT INTO moz_cookies VALUES (3,'sid','SECRETVALUE','.fx.test','/',1800000000,%d,%d,0,1)`, unixMicro("2024-06-02T00:00:00Z"), unixMicro("2024-06-01T00:00:00Z")),
	)
	r := run(t, p, nil)
	if r.err != nil || types(r) != "cookie-created,cookie-last-accessed" || r.events[0].Fields["browser"] != "firefox" ||
		r.events[0].Fields["expires"] != "2027-01-15T08:00:00Z" || strings.Contains(r.all(), "SECRET") {
		t.Fatalf("firefox cookies: err=%v %+v", r.err, r.events)
	}

	p = makeDB(t, "formhistory.sqlite",
		`CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER)`,
		fmt.Sprintf(`INSERT INTO moz_formhistory VALUES (1,'searchbar-history','tor download',2,%d,%d)`, unixMicro("2024-06-01T00:00:00Z"), unixMicro("2024-06-03T00:00:00Z")),
	)
	r = run(t, p, nil)
	if r.err != nil || types(r) != "form-value-first-entered,form-value-last-used" || r.events[1].Fields["value"] != "tor download" {
		t.Fatalf("firefox forms: err=%v %+v", r.err, r.events)
	}

	p = makeDB(t, "places.sqlite",
		`CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT)`,
		`CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER)`,
		`INSERT INTO moz_places VALUES (1,'https://kept.test/','Kept')`,
		fmt.Sprintf(`INSERT INTO moz_bookmarks VALUES (1,2,NULL,0,'toolbar',1,1),(2,1,1,1,'My mark',%d,%d)`, unixMicro("2024-06-01T00:00:00Z"), unixMicro("2024-06-01T00:00:00Z")),
	)
	r = run(t, p, nil)
	if r.err != nil || types(r) != "bookmark-added" || r.events[0].Fields["folder"] != "toolbar" || r.events[0].Path != "https://kept.test/" {
		t.Fatalf("firefox bookmarks: err=%v %+v", r.err, r.events)
	}
}

func TestChromiumBookmarksAndPreferences(t *testing.T) {
	added, used := webkit("2024-02-01T00:00:00Z"), webkit("2024-02-10T00:00:00Z")
	doc := fmt.Sprintf(`{"checksum":"abc","roots":{"bookmark_bar":{"children":[
		{"date_added":"%d","date_last_used":"%d","id":"5","name":"Drop site","type":"url","url":"https://drop.test/"},
		{"children":[{"date_added":"%d","date_last_used":"0","id":"7","name":"Inner","type":"url","url":"https://inner.test/"}],"date_added":"1","name":"Work","type":"folder"}
		],"name":"Bookmarks bar","type":"folder"},"sync_transaction_version":"1"},"version":1}`, added, used, added)
	r := run(t, write(t, "Bookmarks", []byte(doc)), nil)
	if r.err != nil || len(r.warns) != 0 || types(r) != "bookmark-added,bookmark-last-used,bookmark-added" {
		t.Fatalf("bookmarks: err=%v warns=%v types=%s", r.err, r.warns, types(r))
	}
	if e := r.events[2]; e.Fields["folder"] != "bookmark_bar/Work" || e.Path != "https://inner.test/" || utc(e) != "2024-02-01T00:00:00Z" {
		t.Errorf("nested bookmark: %+v", e)
	}
	if !strings.Contains(r.text, "drop.test") {
		t.Error("the document is not indexed")
	}

	doc = fmt.Sprintf(`{"account_info":[{"email":"someone@example.test"}],"profile":{"name":"Person 1"},"extensions":{"settings":{
		"aaaabbbbccccddddeeeeffffgggghhhh":{"first_install_time":"%d","install_time":"%d","location":4,"path":"C:\\Temp\\ext","from_webstore":false,"state":1,
			"manifest":{"name":"Helper","version":"1.2","permissions":["tabs","<all_urls>",{"x":1}]}},
		"bbbb":{"location":5,"manifest":{"name":"Built in"}}}}}`, added, used)
	r = run(t, write(t, "Secure Preferences", []byte(doc)), nil)
	if r.err != nil || len(r.warns) != 0 || types(r) != "browser-extension-installed,browser-extension-updated" {
		t.Fatalf("preferences: err=%v warns=%v types=%s", r.err, r.warns, types(r))
	}
	e := r.events[0]
	if e.Fields["name"] != "Helper" || e.Fields["location_name"] != chromiumExtLocations[4] || e.Path != `C:\Temp\ext` || e.Fields["from_webstore"] != false ||
		fmt.Sprint(e.Fields["permissions"]) != "[tabs <all_urls>]" || r.facts["browser.signed_in_account"] != "someone@example.test" || r.facts["browser.profile_name"] != "Person 1" {
		t.Errorf("extension: %+v facts %v", e, r.facts)
	}

	doc = `{"schemaVersion":36,"addons":[{"id":"x@y.test","version":"2.0","type":"extension","defaultLocale":{"name":"Fox helper"},
		"installDate":1700000000000,"updateDate":1700003600000,"active":false,"path":"C:\\p\\x.xpi","location":"app-profile"}]}`
	r = run(t, write(t, "extensions.json", []byte(doc)), nil)
	if r.err != nil || types(r) != "browser-extension-installed,browser-extension-updated" || r.events[0].Fields["disabled"] != true ||
		utc(r.events[1]) != "2023-11-14T23:13:20Z" {
		t.Fatalf("firefox extensions: err=%v %+v", r.err, r.events)
	}

	// Any other JSON is still read as a log.
	r = run(t, write(t, "log.json", []byte(`[{"timestamp":"2024-01-01T00:00:00Z","message":"hello","extensions":1}]`)), nil)
	if r.err != nil || len(r.events) != 1 || r.facts["browser.file"] != "" {
		t.Fatalf("plain json: err=%v events=%d facts=%v", r.err, len(r.events), r.facts)
	}
}

// mozLz4 builds a Mozilla LZ4 file. With match set, a repeated run in the
// content is written as a back-reference, so the decoder's copy is exercised.
func mozLz4(content []byte, match bool) []byte {
	out := append([]byte(mozLz4Magic), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[8:], uint32(len(content)))
	lits := func(b []byte, matchLen int) {
		tok := byte(0)
		n := len(b)
		if n >= 15 {
			tok = 0xF0
		} else {
			tok = byte(n) << 4
		}
		if matchLen > 0 {
			tok |= byte(matchLen - 4)
		}
		out = append(out, tok)
		if n >= 15 {
			for n -= 15; n >= 255; n -= 255 {
				out = append(out, 255)
			}
			out = append(out, byte(n))
		}
		out = append(out, b...)
	}
	if !match {
		lits(content, 0)
		return out
	}
	// content must begin with eight bytes repeated at once: "abcdabcd".
	lits(content[:4], 4)
	out = append(out, 4, 0) // copy four bytes from four back
	lits(content[8:], 0)
	return out
}

func TestFirefoxSessionStore(t *testing.T) {
	doc := `{"version":["sessionrestore",1],"windows":[{"tabs":[
		{"entries":[{"url":"https://one.test/","title":"One"},{"url":"https://two.test/","title":"Two"}],"index":2,"lastAccessed":1700000000000},
		{"entries":[],"lastAccessed":1700000000000}],
		"_closedTabs":[{"state":{"entries":[{"url":"https://gone.test/","title":"Gone"}],"lastAccessed":1700000001000},"closedAt":1700000002000}]}],
		"selectedWindow":1,"session":{"startTime":1699990000000,"lastUpdate":1700000003000}}`
	r := run(t, write(t, "sessionstore.jsonlz4", mozLz4([]byte(doc), false)), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if types(r) != "browser-session-started,browser-session-saved,tab-last-active (session),tab-last-active (session),tab-closed (session)" {
		t.Fatalf("types: %s", types(r))
	}
	if e := r.events[2]; e.Path != "https://two.test/" || fmt.Sprint(e.Fields["tab_history"]) != "[https://one.test/ https://two.test/]" || utc(e) != "2023-11-14T22:13:20Z" {
		t.Errorf("open tab: %+v", e)
	}
	if e := r.events[4]; e.Path != "https://gone.test/" || e.Fields["tab_state"] != "closed" || utc(e) != "2023-11-14T22:13:22Z" {
		t.Errorf("closed tab: %+v", e)
	}

	// A back-reference in the compressed data, and content that is not a
	// session: decompressed and indexed.
	r = run(t, write(t, "search.json.mozlz4", mozLz4([]byte("abcdabcd engine list, not a session"), true)), nil)
	if r.err != nil || len(r.warns) != 0 || r.text != "abcdabcd engine list, not a session" {
		t.Fatalf("back-reference: err=%v warns=%v text=%q", r.err, r.warns, r.text)
	}
}

// Hostile input must fail or degrade, never panic, hang or allocate what the header claims.
func TestMozLz4Corrupt(t *testing.T) {
	good := mozLz4([]byte(`abcdabcd{"windows":[{"tabs":[]}],"session":{}} and some padding to give the block a little length`), true)
	for i := 0; i < len(good); i++ {
		for _, v := range []byte{0x00, 0xFF, 0x7F} {
			bad := append([]byte(nil), good...)
			bad[i] = v
			run(t, write(t, "x", bad), nil)
		}
		run(t, write(t, "x", good[:i]), nil)
	}
	huge := append([]byte(mozLz4Magic), 0xFF, 0xFF, 0xFF, 0x7F, 0xF0, 0xFF)
	if r := run(t, write(t, "x", huge), nil); r.err == nil {
		t.Error("an impossible declared size was accepted")
	}
}
