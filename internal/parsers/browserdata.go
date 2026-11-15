package parsers

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// The rest of a browser profile: cookies, what was typed into forms, saved
// logins, address-bar shortcuts, page icons and bookmarks. Each is a SQLite
// database recognised by its tables and columns, never by its name.
//
// Two things are deliberately never read: the value of a cookie and the
// password of a saved login. Neither is selected by any query here, so
// neither can reach an event, the index or an export.

// webkitOrUnix reads the time columns of Login Data, which changed unit over
// the years. A value too small to be microseconds since 1601 is seconds
// since 1970 (old versions); the stamp's raw form says which. A real profile
// also holds 86400000000 in "date_last_used", one day after 1601: a
// placeholder for a login never used here, which fails the plausibility
// check either way and gives no event.
func webkitOrUnix(v int64) (timeutil.Stamp, bool) {
	if v <= 0 {
		return timeutil.Stamp{}, false
	}
	if v < 1e11 {
		return unixSeconds(v)
	}
	return timeutil.FromWebkitMicro(v)
}

func unixSeconds(s int64) (timeutil.Stamp, bool) {
	if s <= 0 || s > 1<<36 {
		return timeutil.Stamp{}, false
	}
	return timeutil.FromTimeNative(time.Unix(s, 0), fmt.Sprintf("unix-s %d", s))
}

func unixMillis(ms int64) (timeutil.Stamp, bool) {
	if ms <= 0 || ms > 1<<46 {
		return timeutil.Stamp{}, false
	}
	return timeutil.FromTimeNative(time.UnixMilli(ms), fmt.Sprintf("unix-ms %d", ms))
}

// browserTables runs every reader whose tables are present and returns how
// many events came out.
func browserTables(ctx *Context, db *sql.DB, tables map[string]bool) int {
	done := 0
	try := func(what string, table string, need []string, fn func(*Context, *sql.DB, map[string]bool) (int, error)) {
		if !tables[table] {
			return
		}
		cols, err := columns(db, table)
		if err != nil {
			ctx.Warn("%s: %v", what, err)
			return
		}
		for _, c := range need {
			if !cols[c] {
				return
			}
		}
		n, err := fn(ctx, db, cols)
		if err != nil {
			ctx.Warn("%s: %v", what, err)
		}
		done += n
	}
	try("chromium cookies", "cookies", []string{"host_key", "name", "creation_utc"}, chromiumCookies)
	try("chromium form values", "autofill", []string{"name", "value", "date_created"}, chromiumAutofill)
	try("chromium saved logins", "logins", []string{"origin_url", "username_value", "date_created"}, chromiumLogins)
	try("chromium address-bar shortcuts", "omni_box_shortcuts", []string{"text", "url", "last_access_time"}, chromiumShortcuts)
	if tables["favicon_bitmaps"] {
		try("chromium page icons", "icon_mapping", []string{"page_url", "icon_id"}, chromiumFavicons)
	}
	try("chromium most-visited list", "top_sites", []string{"url", "url_rank"}, chromiumTopSites)
	try("chromium address-bar predictions", "network_action_predictor", []string{"user_text", "url"}, chromiumPredictor)
	try("firefox cookies", "moz_cookies", []string{"host", "name", "creationtime"}, firefoxCookies)
	try("firefox form values", "moz_formhistory", []string{"fieldname", "value", "firstused"}, firefoxForms)
	if tables["moz_places"] {
		try("firefox bookmarks", "moz_bookmarks", []string{"fk", "dateadded"}, firefoxBookmarks)
	}
	return done
}

// timed is one of the times a record carries.
type timed struct {
	stamp timeutil.Stamp
	ok    bool
	kind  string
	word  string
}

// emitTimes emits one event per distinct time of a record, in the order
// given: a later time equal to an earlier one says nothing new.
func emitTimes(ctx *Context, times []timed, ev Event) (int, error) {
	n := 0
	var seen []time.Time
next:
	for _, t := range times {
		if !t.ok {
			continue
		}
		for _, s := range seen {
			if s.Equal(t.stamp.UTC) {
				continue next
			}
		}
		seen = append(seen, t.stamp.UTC)
		e := ev
		e.Stamp, e.Type, e.Message = t.stamp, t.kind, t.word+ev.Message
		if err := ctx.Emit(e); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func chromiumCookies(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT rowid, COALESCE(host_key,''), COALESCE(name,''), %s, COALESCE(creation_utc,0), %s, %s, %s, %s, %s, %s FROM cookies ORDER BY rowid`,
		sel(c, "path", "COALESCE(path,'')", "''"),
		sel(c, "last_access_utc", "COALESCE(last_access_utc,0)", "0"),
		sel(c, "last_update_utc", "COALESCE(last_update_utc,0)", "0"),
		sel(c, "expires_utc", "COALESCE(expires_utc,0)", "0"),
		sel(c, "is_secure", "COALESCE(is_secure,0)", "0"),
		sel(c, "is_httponly", "COALESCE(is_httponly,0)", "0"),
		sel(c, "is_persistent", "COALESCE(is_persistent,0)", "1")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, created, accessed, updated, expires, secure, httpOnly, persistent int64
		var host, name, path string
		if err := rows.Scan(&id, &host, &name, &path, &created, &accessed, &updated, &expires, &secure, &httpOnly, &persistent); err != nil {
			return n, err
		}
		m, err := emitCookie(ctx, "chromium", fmt.Sprintf("cookies rowid %d", id), host, name, path,
			webkitStamp(created), webkitStamp(accessed), webkitStamp(updated), webkitStamp(expires), secure != 0, httpOnly != 0, persistent == 0)
		n += m
		if err != nil {
			return n, err
		}
	}
	if n > 0 {
		ctx.Note("cookie values are not read: they are encrypted with a key held by the user's Windows account, and only the site, the cookie's name and its times are evidence here")
	}
	return n, rows.Err()
}

type optStamp struct {
	s  timeutil.Stamp
	ok bool
}

func webkitStamp(v int64) optStamp {
	s, ok := timeutil.FromWebkitMicro(v)
	return optStamp{s, ok}
}

func emitCookie(ctx *Context, browser, ref, host, name, path string, created, accessed, updated, expires optStamp, secure, httpOnly, session bool) (int, error) {
	host, name, path = clean(host), clean(name), clean(path)
	fields := map[string]any{"browser": browser, "host": host, "cookie_name": name, "cookie_path": path}
	if expires.ok {
		fields["expires"] = expires.s.UTC.Format(time.RFC3339)
	}
	if secure {
		fields["secure"] = true
	}
	if httpOnly {
		fields["http_only"] = true
	}
	if session {
		fields["session_cookie"] = true
	}
	return emitTimes(ctx, []timed{
		{created.s, created.ok, "cookie-created", "Cookie set: "},
		{accessed.s, accessed.ok, "cookie-last-accessed", "Cookie last sent: "},
		{updated.s, updated.ok, "cookie-last-updated", "Cookie last changed: "},
	}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: strings.TrimPrefix(host, ".") + path,
		Message: trunc(name, 200) + " for " + trunc(host, 300), Fields: fields, Ref: ref})
}

func chromiumAutofill(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT rowid, COALESCE(name,''), COALESCE(CAST(value AS TEXT),''), COALESCE(date_created,0), %s, %s FROM autofill ORDER BY rowid`,
		sel(c, "date_last_used", "COALESCE(date_last_used,0)", "0"), sel(c, "count", "COALESCE(count,0)", "0")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, created, used, count int64
		var name, value string
		if err := rows.Scan(&id, &name, &value, &created, &used, &count); err != nil {
			return n, err
		}
		cs, cok := unixSeconds(created)
		us, uok := unixSeconds(used)
		m, err := emitForm(ctx, "chromium", fmt.Sprintf("autofill rowid %d", id), name, value, count, cs, cok, us, uok)
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

func emitForm(ctx *Context, browser, ref, name, value string, count int64, first timeutil.Stamp, fok bool, last timeutil.Stamp, lok bool) (int, error) {
	name, value = clean(name), clean(value)
	fields := map[string]any{"browser": browser, "form_field": name, "value": trunc(value, 4000)}
	if count > 0 {
		fields["times_used"] = count
	}
	return emitTimes(ctx, []timed{
		{first, fok, "form-value-first-entered", "First typed into a form field: "},
		{last, lok, "form-value-last-used", "Last used in a form field: "},
	}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host,
		Message: trunc(name, 200) + " = " + trunc(value, 400), Fields: fields, Ref: ref})
}

// chromiumLogins reads who saved a login for which site and when. The
// password column is never selected.
func chromiumLogins(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT rowid, COALESCE(origin_url,''), COALESCE(CAST(username_value AS TEXT),''), COALESCE(date_created,0), %s, %s, %s, %s, %s, %s FROM logins ORDER BY rowid`,
		sel(c, "action_url", "COALESCE(action_url,'')", "''"),
		sel(c, "signon_realm", "COALESCE(signon_realm,'')", "''"),
		sel(c, "date_last_used", "COALESCE(date_last_used,0)", "0"),
		sel(c, "date_password_modified", "COALESCE(date_password_modified,0)", "0"),
		sel(c, "times_used", "COALESCE(times_used,0)", "0"),
		sel(c, "blacklisted_by_user", "COALESCE(blacklisted_by_user,0)", "0")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, created, used, modified, times, never int64
		var origin, user, action, realm string
		if err := rows.Scan(&id, &origin, &user, &created, &action, &realm, &used, &modified, &times, &never); err != nil {
			return n, err
		}
		origin, user = clean(origin), clean(user)
		fields := map[string]any{"browser": "chromium", "origin_url": origin, "username": user}
		if action != "" {
			fields["action_url"] = clean(action)
		}
		if realm != "" {
			fields["signon_realm"] = clean(realm)
		}
		if times > 0 {
			fields["times_used"] = times
		}
		what := "login for " + trunc(origin, 300)
		if user != "" {
			what += " as " + trunc(user, 200)
		}
		first := timed{kind: "login-saved", word: "Saved "}
		if never != 0 {
			// The user answered "never" when offered: no credentials are kept.
			fields["never_save"] = true
			first = timed{kind: "login-save-declined", word: "Chose never to save a "}
		}
		first.stamp, first.ok = webkitOrUnix(created)
		us, uok := webkitOrUnix(used)
		ms, mok := webkitOrUnix(modified)
		m, err := emitTimes(ctx, []timed{first,
			{us, uok, "login-last-used", "Last filled in the saved "},
			{ms, mok, "login-password-changed", "Password last changed for the saved "},
		}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, User: user, Path: origin,
			Message: what, Fields: fields, Ref: fmt.Sprintf("logins rowid %d", id)})
		n += m
		if err != nil {
			return n, err
		}
	}
	if n > 0 {
		ctx.Note("saved passwords are not read: only the site, the account name and the times of each saved login")
	}
	return n, rows.Err()
}

func chromiumShortcuts(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT rowid, COALESCE(text,''), COALESCE(url,''), COALESCE(last_access_time,0), %s, %s FROM omni_box_shortcuts ORDER BY rowid`,
		sel(c, "contents", "COALESCE(contents,'')", "''"), sel(c, "number_of_hits", "COALESCE(number_of_hits,0)", "0")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, ts, hits int64
		var text, u, contents string
		if err := rows.Scan(&id, &text, &u, &ts, &contents, &hits); err != nil {
			return n, err
		}
		stamp, ok := timeutil.FromWebkitMicro(ts)
		if !ok {
			continue
		}
		text, u = clean(text), clean(u)
		fields := map[string]any{"browser": "chromium", "typed": text, "url": u}
		if contents != "" {
			fields["suggestion"] = clean(trunc(contents, 1000))
		}
		if hits > 0 {
			fields["times_chosen"] = hits
		}
		if err := ctx.Emit(Event{Stamp: stamp, Type: "address-bar-suggestion-chosen", Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: u,
			Message: fmt.Sprintf("Typed %q in the address bar and chose %s", trunc(text, 200), trunc(u, 400)),
			Fields:  fields, Ref: fmt.Sprintf("omni_box_shortcuts rowid %d", id)}); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// chromiumFavicons dates a page by when its icon was last fetched. The icon
// database is not cleared with the history, so a page can appear here and
// nowhere else.
func chromiumFavicons(ctx *Context, db *sql.DB, _ map[string]bool) (int, error) {
	icon := "''"
	join := ""
	if fc, err := columns(db, "favicons"); err == nil && fc["url"] {
		icon, join = "COALESCE(f.url,'')", "LEFT JOIN favicons f ON f.id = m.icon_id"
	}
	rows, err := db.Query(fmt.Sprintf(`SELECT m.rowid, COALESCE(m.page_url,''), %s, COALESCE(MAX(b.last_updated),0)
		FROM icon_mapping m JOIN favicon_bitmaps b ON b.icon_id = m.icon_id %s GROUP BY m.rowid ORDER BY m.rowid`, icon, join))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, ts int64
		var page, iconURL string
		if err := rows.Scan(&id, &page, &iconURL, &ts); err != nil {
			return n, err
		}
		stamp, ok := timeutil.FromWebkitMicro(ts)
		if !ok {
			continue
		}
		page = clean(page)
		fields := map[string]any{"browser": "chromium", "url": page}
		if iconURL != "" {
			fields["icon_url"] = clean(iconURL)
		}
		if err := ctx.Emit(Event{Stamp: stamp, Type: "page-icon-updated", Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: page,
			Message: "Icon fetched for page " + trunc(page, 400), Fields: fields, Ref: fmt.Sprintf("icon_mapping rowid %d", id)}); err != nil {
			return n, err
		}
		n++
	}
	if n > 0 {
		ctx.Note("a page icon's time is when the icon was last fetched, which is at or after a visit to the page, not necessarily the visit itself")
	}
	return n, rows.Err()
}

// The two below record no time at all, so they are indexed text and facts
// rather than events.

func chromiumTopSites(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	return untimedList(ctx, db, fmt.Sprintf(`SELECT url_rank, COALESCE(url,''), %s FROM top_sites ORDER BY url_rank LIMIT ?`, sel(c, "title", "COALESCE(title,'')", "''")),
		"browser.most_visited", "most-visited pages, as the browser ranks them", "most-visited list", "rank %d: %s  %s")
}

func chromiumPredictor(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	return untimedList(ctx, db, fmt.Sprintf(`SELECT %s, COALESCE(url,''), COALESCE(user_text,'') FROM network_action_predictor ORDER BY rowid LIMIT ?`,
		sel(c, "number_of_hits", "COALESCE(number_of_hits,0)", "0")),
		"browser.address_bar_predictions", "pairs of typed text and the address it led to", "address-bar predictions", "chosen %d times: %s  typed: %s")
}

func untimedList(ctx *Context, db *sql.DB, query, fact, factDetail, method, format string) (int, error) {
	rows, err := db.Query(query, maxSideRows)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var b strings.Builder
	n := 0
	for rows.Next() {
		var num int64
		var u, other string
		if err := rows.Scan(&num, &u, &other); err != nil {
			return 0, err
		}
		n++
		if b.Len() < maxText {
			fmt.Fprintf(&b, format+"\n", num, clean(u), clean(other))
		}
	}
	if err := rows.Err(); err != nil || n == 0 {
		return 0, err
	}
	ctx.Fact(fact, fmt.Sprint(n), factDetail)
	ctx.Text(method, b.Len() > maxText, trunc(b.String(), maxText))
	ctx.Note("%d entries of the browser's %s were indexed as text. They carry no time, so they are not on the timeline", n, method)
	// Counted as extracted content, though not as events.
	return 1, nil
}

func firefoxCookies(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT id, COALESCE(host,''), COALESCE(name,''), %s, COALESCE(creationTime,0), %s, %s, %s, %s FROM moz_cookies ORDER BY id`,
		sel(c, "path", "COALESCE(path,'')", "''"),
		sel(c, "lastaccessed", "COALESCE(lastAccessed,0)", "0"),
		sel(c, "expiry", "COALESCE(expiry,0)", "0"),
		sel(c, "issecure", "COALESCE(isSecure,0)", "0"),
		sel(c, "ishttponly", "COALESCE(isHttpOnly,0)", "0")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, created, accessed, expiry, secure, httpOnly int64
		var host, name, path string
		if err := rows.Scan(&id, &host, &name, &path, &created, &accessed, &expiry, &secure, &httpOnly); err != nil {
			return n, err
		}
		cs, cok := timeutil.FromUnixMicro(created, "unix-us")
		as, aok := timeutil.FromUnixMicro(accessed, "unix-us")
		// Expiry is in seconds; newer versions write milliseconds.
		var exp optStamp
		if expiry > 1<<36 {
			exp.s, exp.ok = unixMillis(expiry)
		} else {
			exp.s, exp.ok = unixSeconds(expiry)
		}
		m, err := emitCookie(ctx, "firefox", fmt.Sprintf("moz_cookies.id %d", id), host, name, path,
			optStamp{cs, cok}, optStamp{as, aok}, optStamp{}, exp, secure != 0, httpOnly != 0, false)
		n += m
		if err != nil {
			return n, err
		}
	}
	if n > 0 {
		ctx.Note("cookie values are not read: only the site, the cookie's name and its times")
	}
	return n, rows.Err()
}

func firefoxForms(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT id, COALESCE(fieldname,''), COALESCE(CAST(value AS TEXT),''), COALESCE(firstUsed,0), %s, %s FROM moz_formhistory ORDER BY id`,
		sel(c, "lastused", "COALESCE(lastUsed,0)", "0"), sel(c, "timesused", "COALESCE(timesUsed,0)", "0")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, first, last, count int64
		var name, value string
		if err := rows.Scan(&id, &name, &value, &first, &last, &count); err != nil {
			return n, err
		}
		fs, fok := timeutil.FromUnixMicro(first, "unix-us")
		ls, lok := timeutil.FromUnixMicro(last, "unix-us")
		m, err := emitForm(ctx, "firefox", fmt.Sprintf("moz_formhistory.id %d", id), name, value, count, fs, fok, ls, lok)
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

func firefoxBookmarks(ctx *Context, db *sql.DB, c map[string]bool) (int, error) {
	folder := "''"
	join := ""
	if c["parent"] && c["title"] {
		folder, join = "COALESCE(pb.title,'')", "LEFT JOIN moz_bookmarks pb ON pb.id = b.parent"
	}
	rows, err := db.Query(fmt.Sprintf(`SELECT b.id, COALESCE(p.url,''), %s, %s, COALESCE(b.dateAdded,0), %s
		FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk %s ORDER BY b.id`,
		sel(c, "title", "COALESCE(b.title,'')", "''"), folder, sel(c, "lastmodified", "COALESCE(b.lastModified,0)", "0"), join))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, added, modified int64
		var u, title, parent string
		if err := rows.Scan(&id, &u, &title, &parent, &added, &modified); err != nil {
			return n, err
		}
		as, aok := timeutil.FromUnixMicro(added, "unix-us")
		ms, mok := timeutil.FromUnixMicro(modified, "unix-us")
		m, err := emitBookmark(ctx, "firefox", fmt.Sprintf("moz_bookmarks.id %d", id), u, title, parent,
			timed{as, aok, "bookmark-added", "Bookmarked "}, timed{ms, mok, "bookmark-modified", "Bookmark changed: "})
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

func emitBookmark(ctx *Context, browser, ref, u, title, folder string, times ...timed) (int, error) {
	u, title = clean(u), clean(title)
	fields := map[string]any{"browser": browser, "url": u, "title": title}
	if folder != "" {
		fields["folder"] = clean(folder)
	}
	return emitTimes(ctx, times, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: u,
		Message: trunc(u, 400) + titleSuffix(title), Fields: fields, Ref: ref})
}
