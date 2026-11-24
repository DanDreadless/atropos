package parsers

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/DanDreadless/atropos/internal/timeutil"

	_ "modernc.org/sqlite"
)

// ErrNothingExtracted tells the pipeline a parser recognised the container
// but found nothing it knows how to turn into events, so generic handling
// should take over.
var ErrNothingExtracted = errors.New("recognised, but no known content to extract")

type sqliteParser struct{}

func (sqliteParser) Name() string { return "sqlite" }
func (sqliteParser) Version() string {
	return "9 (native, write-ahead log applied when one in the case fits: windows search index; onedrive sync and SafeDelete databases; chromium history with referrers, search terms, sync origin and download detail, synced visits as their own source, automatic loads apart, how each page was reached, domains, visit ids, the profile owner from the folder path; firefox places with downloads; cookies, form values, saved logins without passwords, address-bar shortcuts, page icons, bookmarks)"
}

// maxSideRows bounds the small tables read whole into memory (search terms,
// download redirect chains, Firefox annotations).
const maxSideRows = 500000

func (sqliteParser) Parse(ctx *Context) error {
	// A write-ahead log that fits this database is applied to a working
	// copy, never to the evidence, and the copy is what is read.
	path := ctx.File.Name()
	walNote := ""
	head := make([]byte, 20)
	if _, err := ctx.File.ReadAt(head, 0); err == nil && head[18] == 2 {
		walNote = "the database is in write-ahead log mode, and no log in the case fits it: if it was copied from a running program, its newest changes may be in a -wal file beside it, which should be added too"
		w, wpath, why := pickWAL(ctx)
		if why != "" {
			walNote = why
		}
		if w != nil {
			dir := ctx.WorkDir
			if dir == "" {
				dir = os.TempDir()
			}
			merged, err := applyWAL(ctx, w, dir)
			w.file.Close()
			if err != nil {
				ctx.Warn("the write-ahead log that fits this database could not be applied: %v; the database was read without it", err)
				walNote = ""
			} else {
				defer os.Remove(merged)
				path = merged
				walNote = walDescribe(w, wpath)
				ctx.Fact("sqlite.wal_applied", filepath.Base(wpath), "SHA-256 of the write-ahead log applied to this database before it was read")
			}
		}
	}
	// immutable=1 guarantees SQLite neither writes to nor locks the evidence.
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?mode=ro&immutable=1&_pragma=trusted_schema(0)&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return fmt.Errorf("reading schema: %w", err)
	}
	tables := map[string]bool{}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		tables[strings.ToLower(n)] = true
		names = append(names, n)
	}
	rows.Close()
	ctx.Fact("sqlite.tables", strings.Join(names, ", "), "tables present in the database")
	if walNote != "" {
		ctx.Note("%s", walNote)
	}

	done := 0
	if tables["urls"] && tables["visits"] {
		if tables["meta"] {
			var v string
			if db.QueryRow(`SELECT CAST(value AS TEXT) FROM meta WHERE key='version'`).Scan(&v) == nil && v != "" {
				ctx.Fact("browser.history_schema_version", clean(trunc(v, 40)), "Chromium history database version")
			}
		}
		n, err := chromiumVisits(ctx, db, tables)
		if err != nil {
			ctx.Warn("chromium visits: %v", err)
		}
		done += n
		n, err = chromiumExpired(ctx, db)
		if err != nil {
			ctx.Warn("chromium addresses without visit records: %v", err)
		}
		done += n
		if tables["downloads"] {
			n, err := chromiumDownloads(ctx, db, tables)
			if err != nil {
				ctx.Warn("chromium downloads: %v", err)
			}
			done += n
		}
	}
	if tables["systemindex_1_propertystore"] && tables["systemindex_1_propertystore_metadata"] {
		n, err := windowsSearch(ctx, db)
		if err != nil {
			ctx.Warn("windows search index: %v", err)
		}
		done += n
	}
	if tables["od_clientfile_records"] && tables["od_clientfolder_records"] {
		n, err := oneDriveSync(ctx, db)
		if err != nil {
			ctx.Warn("onedrive sync database: %v", err)
		}
		done += n
	}
	if tables["filter_delete_info"] || tables["deletes_last_touched_by_sync_engine"] {
		n, err := oneDriveSafeDelete(ctx, db)
		if err != nil {
			ctx.Warn("onedrive SafeDelete database: %v", err)
		}
		done += n
	}
	if tables["moz_places"] && tables["moz_historyvisits"] {
		n, err := firefoxVisits(ctx, db)
		if err != nil {
			ctx.Warn("firefox visits: %v", err)
		}
		done += n
		if tables["moz_annos"] && tables["moz_anno_attributes"] {
			n, err := firefoxDownloads(ctx, db)
			if err != nil {
				ctx.Warn("firefox downloads: %v", err)
			}
			done += n
		}
	}
	done += browserTables(ctx, db, tables)
	if done == 0 {
		return ErrNothingExtracted
	}
	return nil
}

// Chromium's page transition: the low byte is how the visit came about, the
// high bits qualify it (ui/base/page_transition_types.h).
var chromiumTransitions = []string{"link", "typed", "auto_bookmark", "auto_subframe", "manual_subframe", "generated",
	"auto_toplevel", "form_submit", "reload", "keyword", "keyword_generated"}

var chromiumQualifiers = []struct {
	bit  int64
	name string
}{
	{0x00800000, "blocked"}, {0x01000000, "forward_back"}, {0x02000000, "from_address_bar"}, {0x04000000, "home_page"},
	{0x08000000, "from_api"}, {0x10000000, "chain_start"}, {0x20000000, "chain_end"},
	{0x40000000, "client_redirect"}, {0x80000000, "server_redirect"},
}

// Where a visit row came from (history_types.h, VisitSource). A visit made
// in this browser has no row at all.
var chromiumSources = map[int64]string{0: "synced", 1: "browsed", 2: "extension", 3: "imported from Firefox", 4: "imported from Internet Explorer", 5: "imported from Safari",
	6: "imported from Chrome or Edge", 7: "imported from EdgeHTML"}

// sel returns expr when the column exists, and a constant otherwise, so one
// query serves every version of a schema.
func sel(cols map[string]bool, col, expr, fallback string) string {
	if cols[col] {
		return expr
	}
	return fallback
}

func seconds(micros int64) float64 { return math.Round(float64(micros)/1000) / 1000 }

func chromiumVisits(ctx *Context, db *sql.DB, tables map[string]bool) (int, error) {
	vc, err := columns(db, "visits")
	if err != nil {
		return 0, err
	}
	uc, err := columns(db, "urls")
	if err != nil {
		return 0, err
	}
	var joins []string
	from, opener := "''", "''"
	fromID := sel(vc, "from_visit", "COALESCE(v.from_visit,0)", "0")
	openerID := sel(vc, "opener_visit", "COALESCE(v.opener_visit,0)", "0")
	if vc["from_visit"] {
		joins = append(joins, "LEFT JOIN visits fv ON fv.id = v.from_visit AND v.from_visit <> 0 LEFT JOIN urls fu ON fu.id = fv.url")
		from = "COALESCE(fu.url,'')"
	}
	if vc["opener_visit"] {
		joins = append(joins, "LEFT JOIN visits ov ON ov.id = v.opener_visit AND v.opener_visit <> 0 LEFT JOIN urls ou ON ou.id = ov.url")
		opener = "COALESCE(ou.url,'')"
	}
	source := "-1"
	if tables["visit_source"] {
		joins = append(joins, "LEFT JOIN visit_source vs ON vs.id = v.id")
		source = "COALESCE(vs.source,-1)"
	}
	caTerms, lang, pw := "''", "''", "0"
	if tables["content_annotations"] {
		cc, err := columns(db, "content_annotations")
		if err != nil {
			return 0, err
		}
		joins = append(joins, "LEFT JOIN content_annotations ca ON ca.visit_id = v.id")
		caTerms = sel(cc, "search_terms", "COALESCE(ca.search_terms,'')", "''")
		lang = sel(cc, "page_language", "COALESCE(ca.page_language,'')", "''")
		pw = sel(cc, "password_state", "COALESCE(ca.password_state,0)", "0")
	}
	resp, fg := "0", "0"
	if tables["context_annotations"] {
		cc, err := columns(db, "context_annotations")
		if err != nil {
			return 0, err
		}
		joins = append(joins, "LEFT JOIN context_annotations cx ON cx.visit_id = v.id")
		resp = sel(cc, "response_code", "COALESCE(cx.response_code,0)", "0")
		fg = sel(cc, "total_foreground_duration", "COALESCE(cx.total_foreground_duration,0)", "0")
	}
	// What was typed into a search box, by address.
	terms := map[int64]string{}
	if tables["keyword_search_terms"] {
		r, err := db.Query(`SELECT url_id, COALESCE(term,'') FROM keyword_search_terms ORDER BY url_id, keyword_id LIMIT ?`, maxSideRows)
		if err != nil {
			ctx.Warn("chromium search terms: %v", err)
		} else {
			for r.Next() {
				var id int64
				var term string
				if r.Scan(&id, &term) == nil && term != "" {
					if _, seen := terms[id]; !seen {
						terms[id] = clean(term)
					}
				}
			}
			r.Close()
		}
	}

	q := fmt.Sprintf(`SELECT v.id, v.visit_time, u.id, COALESCE(u.url,''), COALESCE(u.title,''), COALESCE(v.transition,0), COALESCE(u.visit_count,0),
		%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		FROM visits v JOIN urls u ON u.id = v.url %s ORDER BY v.id`,
		fromID, openerID,
		sel(uc, "typed_count", "COALESCE(u.typed_count,0)", "0"), sel(uc, "hidden", "COALESCE(u.hidden,0)", "0"),
		from, opener,
		sel(vc, "visit_duration", "COALESCE(v.visit_duration,0)", "0"),
		sel(vc, "external_referrer_url", "COALESCE(v.external_referrer_url,'')", "''"),
		sel(vc, "originator_cache_guid", "COALESCE(v.originator_cache_guid,'')", "''"),
		sel(vc, "app_id", "COALESCE(v.app_id,'')", "''"),
		source, caTerms, lang, pw, resp, fg, strings.Join(joins, " "))
	rows, err := db.Query(q)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n, synced := 0, 0
	for rows.Next() {
		var id, ts, urlID, transition, count, fromVisit, openerVisit, typed, hidden, duration, src, pwState, respCode, fgDur int64
		var u, title, fromURL, openerURL, extRef, origin, appID, caTerm, language string
		if err := rows.Scan(&id, &ts, &urlID, &u, &title, &transition, &count, &fromVisit, &openerVisit, &typed, &hidden, &fromURL, &openerURL,
			&duration, &extRef, &origin, &appID, &src, &caTerm, &language, &pwState, &respCode, &fgDur); err != nil {
			return n, err
		}
		stamp, ok := timeutil.FromWebkitMicro(ts)
		if !ok {
			continue
		}
		u, title = clean(u), clean(title)
		core := transition & 0xFF
		fields := map[string]any{"browser": "chromium", "title": title, "url": u, "transition": core, "url_visit_count": count, "visit_id": id}
		if d := urlDomain(u); d != "" {
			fields["domain"] = d
		}
		if fromVisit > 0 {
			fields["from_visit_id"] = fromVisit
		}
		if openerVisit > 0 {
			fields["opener_visit_id"] = openerVisit
		}
		if core >= 0 && int(core) < len(chromiumTransitions) {
			fields["transition_name"] = chromiumTransitions[core]
		}
		var quals []string
		for _, ql := range chromiumQualifiers {
			if transition&ql.bit != 0 {
				quals = append(quals, ql.name)
			}
		}
		if len(quals) > 0 {
			fields["transition_qualifiers"] = quals
		}
		if typed > 0 {
			fields["url_typed_count"] = typed
		}
		if hidden != 0 {
			fields["hidden"] = true
		}
		if fromURL != "" {
			fields["from_url"] = clean(fromURL)
		}
		if openerURL != "" {
			fields["opener_url"] = clean(openerURL)
		}
		if extRef != "" {
			fields["external_referrer_url"] = clean(extRef)
		}
		if duration > 0 {
			fields["visit_duration_seconds"] = seconds(duration)
		}
		if fgDur > 0 {
			fields["foreground_seconds"] = seconds(fgDur)
		}
		if respCode > 0 {
			fields["response_code"] = respCode
		}
		if language != "" {
			fields["page_language"] = clean(language)
		}
		if pwState == 1 {
			fields["page_had_password_field"] = true
		}
		if appID != "" {
			fields["app_id"] = clean(appID)
		}
		term := terms[urlID]
		if term == "" {
			term = clean(caTerm)
		}
		suffix := ""
		if term != "" {
			fields["search_term"] = term
			suffix += "  [searched: " + trunc(term, 200) + "]"
		}
		if name, ok := chromiumSources[src]; ok {
			fields["source"] = name
		}
		// A visit carried here by sync happened on another device signed in
		// to the same account: it is not evidence of use of this machine.
		source := "browser"
		if src == 0 || origin != "" {
			source = "browser-synced"
			synced++
			fields["synced_from_another_device"] = true
			if origin != "" {
				fields["originator_cache_guid"] = clean(origin)
			}
			suffix += "  [synced: recorded on another device]"
		}
		how, auto, why := chromiumNavigation(core, quals)
		fields["navigation"] = "user"
		cat, verb := CatBrowser, "Visited"
		if auto {
			fields["navigation"] = "automatic"
			fields["navigation_reason"] = why
			cat, verb = CatBrowserAuto, "Loaded by the browser ("+why+")"
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "url-visited (" + how + ")", Category: cat, Source: source, Host: ctx.Host, Path: u,
			User:    profileUser(ctx, fields),
			Message: verb + " " + trunc(u, 400) + titleSuffix(title) + suffix,
			Fields:  fields,
			Ref:     fmt.Sprintf("visits.id %d", id),
		}); err != nil {
			return n, err
		}
		n++
	}
	if synced > 0 {
		ctx.Note("%d of %d visits were brought here by browser sync from another device signed in to the same account. They are marked \"synced\" and are not evidence that this machine was used at that time", synced, n)
	}
	return n, rows.Err()
}

// chromiumExpired emits the last visit of addresses whose visit records
// have gone: the browser expires visits and keeps the address for a while.
func chromiumExpired(ctx *Context, db *sql.DB) (int, error) {
	uc, err := columns(db, "urls")
	if err != nil || !uc["last_visit_time"] {
		return 0, err
	}
	rows, err := db.Query(`SELECT u.id, COALESCE(u.url,''), COALESCE(u.title,''), u.last_visit_time, COALESCE(u.visit_count,0)
		FROM urls u LEFT JOIN visits v ON v.url = u.id WHERE v.id IS NULL AND u.last_visit_time > 0 ORDER BY u.id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, ts, count int64
		var u, title string
		if err := rows.Scan(&id, &u, &title, &ts, &count); err != nil {
			return n, err
		}
		stamp, ok := timeutil.FromWebkitMicro(ts)
		if !ok {
			continue
		}
		u, title = clean(u), clean(title)
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "url-last-visited", Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: u,
			Message: "Last visit of " + trunc(u, 400) + titleSuffix(title) + "  [the visit records themselves are gone]",
			Fields:  map[string]any{"browser": "chromium", "title": title, "url": u, "url_visit_count": count, "visit_records": "none left"},
			Ref:     fmt.Sprintf("urls.id %d", id),
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// components/download/public/common: DownloadItem::DownloadState as stored,
// download_danger_type.h and download_interrupt_reason_values.h.
var (
	downloadStates  = map[int64]string{0: "in progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}
	downloadDangers = map[int64]string{
		0: "not dangerous", 1: "dangerous file", 2: "dangerous URL", 3: "dangerous content", 4: "possibly dangerous content",
		5: "uncommon content", 6: "dangerous, kept by the user", 7: "dangerous host", 8: "potentially unwanted",
		9: "allowed by policy", 10: "being scanned", 11: "blocked: password protected", 12: "blocked: too large",
		13: "sensitive content warning", 14: "sensitive content blocked", 15: "scanned: safe", 16: "scanned: opened though dangerous",
		17: "offered for scanning", 18: "blocked: unsupported type", 19: "dangerous: account compromise", 20: "deep scan failed",
		21: "encrypted: password asked for to scan locally", 22: "encrypted: awaiting verdict after local scan", 23: "blocked: scan failed",
	}
	downloadInterrupts = map[int64]string{
		1: "file error", 2: "access denied", 3: "no space", 5: "name too long", 6: "file too large", 7: "virus found",
		10: "transient file error", 11: "blocked", 12: "security check failed", 13: "file too short", 14: "hash mismatch",
		15: "same as source", 20: "network failed", 21: "network timeout", 22: "network disconnected", 23: "server down",
		24: "invalid request", 30: "server failed", 31: "server does not support ranges", 32: "server precondition failed", 33: "bad content",
		34: "unauthorised", 35: "certificate problem", 36: "forbidden", 37: "server unreachable",
		38: "content length mismatch", 39: "cross-origin redirect", 40: "cancelled by the user", 41: "browser shut down", 50: "browser crashed",
	}
)

func chromiumDownloads(ctx *Context, db *sql.DB, tables map[string]bool) (int, error) {
	cols, err := columns(db, "downloads")
	if err != nil {
		return 0, err
	}
	text := func(c string) string { return sel(cols, c, "COALESCE(CAST("+c+" AS TEXT),'')", "''") }
	num := func(c, fallback string) string { return sel(cols, c, "COALESCE("+c+","+fallback+")", fallback) }

	// Every address a download passed through, in order: the last is where
	// the file actually came from.
	chains := map[int64][]string{}
	if tables["downloads_url_chains"] {
		r, err := db.Query(`SELECT id, COALESCE(url,'') FROM downloads_url_chains ORDER BY id, chain_index LIMIT ?`, maxSideRows)
		if err != nil {
			ctx.Warn("chromium download addresses: %v", err)
		} else {
			for r.Next() {
				var id int64
				var u string
				if r.Scan(&id, &u) == nil && u != "" && len(chains[id]) < 50 {
					chains[id] = append(chains[id], clean(trunc(u, 2000)))
				}
			}
			r.Close()
		}
	}

	q := fmt.Sprintf(`SELECT id, COALESCE(start_time,0), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		FROM downloads ORDER BY id`,
		num("end_time", "0"), text("target_path"), text("current_path"), num("total_bytes", "0"), num("received_bytes", "-1"),
		num("state", "-1"), num("danger_type", "-1"), num("interrupt_reason", "0"), num("opened", "0"), num("last_access_time", "0"),
		text("tab_url"), text("tab_referrer_url"), text("referrer"), text("site_url"), text("mime_type"), text("original_mime_type"),
		text("last_modified"), text("by_ext_id"), text("by_ext_name"), sel(cols, "hash", "COALESCE(hex(hash),'')", "''"))
	rows, err := db.Query(q)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, start, end, size, received, state, danger, interrupt, opened, access int64
		var target, current, tab, tabRef, referrer, site, mime, origMime, lastMod, extID, extName, hash string
		if err := rows.Scan(&id, &start, &end, &target, &current, &size, &received, &state, &danger, &interrupt, &opened, &access,
			&tab, &tabRef, &referrer, &site, &mime, &origMime, &lastMod, &extID, &extName, &hash); err != nil {
			return n, err
		}
		target, current, tab = clean(target), clean(current), clean(tab)
		path := target
		if path == "" {
			path = current
		}
		fields := map[string]any{"browser": "chromium", "target_path": target, "total_bytes": size, "tab_url": tab}
		put := func(k, v string) {
			if v != "" {
				fields[k] = clean(trunc(v, 2000))
			}
		}
		if current != target {
			put("current_path", current)
		}
		put("tab_referrer_url", tabRef)
		put("referrer", referrer)
		put("site_url", site)
		put("mime_type", mime)
		if origMime != mime {
			put("original_mime_type", origMime)
		}
		put("server_last_modified", lastMod)
		put("by_extension_id", extID)
		put("by_extension_name", extName)
		if len(hash) == 64 {
			if _, err := hex.DecodeString(hash); err == nil {
				fields["sha256"] = strings.ToLower(hash)
			}
		}
		if received >= 0 {
			fields["received_bytes"] = received
		}
		from := tab
		if chain := chains[id]; len(chain) > 0 {
			fields["url_chain"] = chain
			from = chain[len(chain)-1]
			fields["url"] = from
		}
		suffix := ""
		if state >= 0 {
			fields["state_code"] = state
			if name, ok := downloadStates[state]; ok {
				fields["state"] = name
				if state != 1 {
					suffix += "  [" + name + "]"
				}
			}
		}
		if danger >= 0 {
			fields["danger_code"] = danger
			if name, ok := downloadDangers[danger]; ok {
				fields["danger"] = name
			}
			if danger > 0 {
				name := downloadDangers[danger]
				if name == "" {
					name = fmt.Sprintf("danger type %d", danger)
				}
				suffix += "  [the browser's verdict: " + name + "]"
			}
		}
		if interrupt != 0 {
			fields["interrupt_code"] = interrupt
			name := downloadInterrupts[interrupt]
			if name == "" {
				name = fmt.Sprintf("reason %d", interrupt)
			}
			fields["interrupt_reason"] = name
			suffix += "  [interrupted at some point: " + name + "]"
		}
		if cols["opened"] {
			fields["opened_from_browser"] = opened != 0
		}
		for _, t := range []struct {
			ts   int64
			kind string
			word string
		}{{start, "download-started", "Download started"}, {end, "download-finished", "Download finished"},
			{access, "download-last-opened", "Download last opened from the browser"}} {
			stamp, ok := timeutil.FromWebkitMicro(t.ts)
			if !ok {
				continue
			}
			if d := urlDomain(from); d != "" {
				fields["domain"] = d
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: t.kind, Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: path,
				User:    profileUser(ctx, fields),
				Message: fmt.Sprintf("%s: %s (%d bytes) from %s%s", t.word, path, size, trunc(from, 300), suffix),
				Fields:  fields, Ref: fmt.Sprintf("downloads.id %d", id),
			}); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, rows.Err()
}

// Firefox's visit types (nsINavHistoryService TRANSITION_*).
var firefoxVisitTypes = map[int64]string{1: "link", 2: "typed", 3: "bookmark", 4: "embed", 5: "redirect_permanent",
	6: "redirect_temporary", 7: "download", 8: "framed_link", 9: "reload"}

func firefoxVisits(ctx *Context, db *sql.DB) (int, error) {
	vc, err := columns(db, "moz_historyvisits")
	if err != nil {
		return 0, err
	}
	pc, err := columns(db, "moz_places")
	if err != nil {
		return 0, err
	}
	join, from := "", "''"
	if vc["from_visit"] {
		join = "LEFT JOIN moz_historyvisits fv ON fv.id = v.from_visit AND v.from_visit <> 0 LEFT JOIN moz_places fp ON fp.id = fv.place_id"
		from = "COALESCE(fp.url,'')"
	}
	rows, err := db.Query(fmt.Sprintf(`SELECT v.id, v.visit_date, COALESCE(p.url,''), COALESCE(p.title,''), COALESCE(v.visit_type,0), %s, %s, %s, %s, %s
		FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id %s ORDER BY v.id`,
		sel(vc, "from_visit", "COALESCE(v.from_visit,0)", "0"), from, sel(pc, "visit_count", "COALESCE(p.visit_count,0)", "0"), sel(pc, "typed", "COALESCE(p.typed,0)", "0"),
		sel(pc, "hidden", "COALESCE(p.hidden,0)", "0"), join))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, ts, vt, fromVisit, count, typed, hidden int64
		var u, title, fromURL string
		if err := rows.Scan(&id, &ts, &u, &title, &vt, &fromVisit, &fromURL, &count, &typed, &hidden); err != nil {
			return n, err
		}
		stamp, ok := timeutil.FromUnixMicro(ts, "unix-us")
		if !ok {
			continue
		}
		u, title = clean(u), clean(title)
		fields := map[string]any{"browser": "firefox", "title": title, "url": u, "visit_type": vt, "visit_id": id}
		if name, ok := firefoxVisitTypes[vt]; ok {
			fields["visit_type_name"] = name
		}
		if d := urlDomain(u); d != "" {
			fields["domain"] = d
		}
		if fromVisit > 0 {
			fields["from_visit_id"] = fromVisit
		}
		how := map[int64]string{1: "link", 2: "typed", 3: "bookmark", 4: "embedded", 5: "link, after a permanent redirect",
			6: "link, after a temporary redirect", 7: "download", 8: "link in a frame", 9: "reload"}[vt]
		if how == "" {
			how = fmt.Sprintf("visit type %d", vt)
		}
		cat, verb := CatBrowser, "Visited"
		fields["navigation"] = "user"
		if vt == 4 {
			// Content embedded in a page (an image, a frame), not a page opened.
			fields["navigation"], fields["navigation_reason"] = "automatic", "embedded in a page"
			cat, verb = CatBrowserAuto, "Loaded by the browser (embedded in a page)"
		}
		if fromURL != "" {
			fields["from_url"] = clean(fromURL)
		}
		if count > 0 {
			fields["url_visit_count"] = count
		}
		if typed != 0 {
			fields["url_typed"] = true
		}
		if hidden != 0 {
			fields["hidden"] = true
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "url-visited (" + how + ")", Category: cat, Source: "browser", Host: ctx.Host, Path: u,
			User:    profileUser(ctx, fields),
			Message: verb + " " + trunc(u, 400) + titleSuffix(title),
			Fields:  fields,
			Ref:     fmt.Sprintf("moz_historyvisits.id %d", id),
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// firefoxDownloads reads the annotations Firefox attaches to a downloaded
// address: where the file was saved (added when the download began) and a
// small JSON record of how it ended.
func firefoxDownloads(ctx *Context, db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT a.place_id, COALESCE(p.url,''), n.name, COALESCE(CAST(a.content AS TEXT),''), COALESCE(a.dateAdded,0)
		FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id
		WHERE n.name IN ('downloads/destinationFileURI','downloads/metaData') ORDER BY a.place_id, n.name LIMIT ?`, maxSideRows)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type dl struct {
		place       int64
		url, target string
		started     int64
		meta        string
	}
	var all []*dl
	var cur *dl
	for rows.Next() {
		var place, added int64
		var u, name, content string
		if err := rows.Scan(&place, &u, &name, &content, &added); err != nil {
			return 0, err
		}
		if cur == nil || cur.place != place {
			cur = &dl{place: place, url: clean(u)}
			all = append(all, cur)
		}
		if name == "downloads/destinationFileURI" {
			cur.target, cur.started = clean(content), added
		} else if len(content) <= 64<<10 {
			cur.meta = content
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, d := range all {
		path := d.target
		if p, err := url.Parse(d.target); err == nil && p.Scheme == "file" && p.Path != "" {
			path = strings.TrimPrefix(p.Path, "/")
			if len(path) < 2 || path[1] != ':' {
				path = p.Path
			}
		}
		fields := map[string]any{"browser": "firefox", "url": d.url, "target_path": path}
		var meta struct {
			State    *int64   `json:"state"`
			EndTime  *float64 `json:"endTime"`
			FileSize *float64 `json:"fileSize"`
		}
		var end int64
		if d.meta != "" && json.Unmarshal([]byte(d.meta), &meta) == nil {
			if meta.State != nil {
				fields["state_code"] = *meta.State
			}
			if meta.FileSize != nil && *meta.FileSize >= 0 && *meta.FileSize < 1<<53 {
				fields["total_bytes"] = int64(*meta.FileSize)
			}
			if meta.EndTime != nil && *meta.EndTime > 0 && *meta.EndTime < 1e14 {
				end = int64(*meta.EndTime) * 1000 // milliseconds in the record
			}
		}
		for _, t := range []struct {
			ts   int64
			kind string
			word string
		}{{d.started, "download-started", "Download started"}, {end, "download-finished", "Download ended"}} {
			if t.ts <= 0 {
				continue
			}
			stamp, ok := timeutil.FromUnixMicro(t.ts, "unix-us")
			if !ok {
				continue
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: t.kind, Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: path,
				Message: fmt.Sprintf("%s: %s from %s", t.word, path, trunc(d.url, 300)),
				Fields:  fields, Ref: fmt.Sprintf("moz_annos place_id %d", d.place),
			}); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func titleSuffix(t string) string {
	if t == "" {
		return ""
	}
	return "  (" + trunc(t, 200) + ")"
}

func columns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[strings.ToLower(n)] = true
	}
	return out, rows.Err()
}

// chromiumNavigation says how a visit came about, in words for the
// timeline's Meaning column, and whether the browser rather than the person
// made it: a hop in a redirect chain (any visit of a chain but its end), a
// frame loaded inside a page, or a page opened at start-up.
func chromiumNavigation(core int64, quals []string) (how string, automatic bool, why string) {
	has := func(q string) bool {
		for _, x := range quals {
			if x == q {
				return true
			}
		}
		return false
	}
	words := map[int64]string{0: "link", 1: "typed", 2: "bookmark", 3: "frame", 4: "frame, clicked", 5: "address bar suggestion",
		6: "start-up page", 7: "form submitted", 8: "reload", 9: "keyword search", 10: "keyword search, generated"}
	how = words[core]
	if how == "" {
		how = fmt.Sprintf("transition %d", core)
	}
	inChain := has("chain_start") || has("server_redirect") || has("client_redirect")
	switch {
	case inChain && !has("chain_end"):
		return "redirected through", true, "a hop in a redirect chain, not the page that was shown"
	case core == 3:
		return how, true, "a frame inside a page"
	case core == 6:
		return how, true, "a page opened at start-up"
	}
	if has("server_redirect") || has("client_redirect") {
		how += ", after a redirect"
	}
	if has("forward_back") {
		how += ", back or forward"
	}
	return how, false, ""
}

// urlDomain is the host name in an address, lower-cased; "" for one with none.
func urlDomain(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return strings.ToLower(p.Hostname())
}

// profileUser is the account whose profile folder the database came from, if
// its origin names one; it says so in the event's fields.
func profileUser(ctx *Context, fields map[string]any) string {
	u := ProfileUser(ctx.Origin)
	if u != "" {
		fields["user_from"] = "the profile folder the file was taken from (inferred from its path)"
	}
	return u
}
