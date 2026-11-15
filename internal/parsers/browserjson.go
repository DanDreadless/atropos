package parsers

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Browser profile files kept as JSON: Chromium's Bookmarks and Preferences
// (and Secure Preferences), Firefox's extensions.json, and Firefox's session
// and bookmark-backup files, which are JSON inside Mozilla's LZ4 wrapper.
// Each is recognised by the keys at the top of the document.

const maxBookmarkDepth = 64

// browserJSON handles doc if it is one of the browser files. handled is
// false when it is some other JSON, which is then left to the log reader.
func browserJSON(ctx *Context, doc []byte) (handled bool, err error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(doc, &top) != nil {
		return false, nil
	}
	has := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := top[k]; !ok {
				return false
			}
		}
		return true
	}
	var n int
	switch {
	case has("roots", "checksum"):
		ctx.Fact("browser.file", "chromium bookmarks", "recognised by its \"roots\" and \"checksum\" keys")
		n, err = chromiumBookmarks(ctx, top["roots"])
	case has("extensions") && (has("profile") || has("protection") || has("browser")):
		ctx.Fact("browser.file", "chromium preferences", "recognised by its \"extensions\" key beside \"profile\", \"browser\" or \"protection\"")
		n, err = chromiumPreferences(ctx, top)
	case has("addons", "schemaVersion"):
		ctx.Fact("browser.file", "firefox extensions", "recognised by its \"addons\" and \"schemaVersion\" keys")
		n, err = firefoxExtensions(ctx, top["addons"])
	case has("windows") && (has("session") || has("selectedWindow") || has("_closedWindows")):
		ctx.Fact("browser.file", "firefox session", "recognised by its \"windows\" key beside \"session\", \"selectedWindow\" or \"_closedWindows\"")
		n, err = firefoxSession(ctx, top)
	case has("children", "guid") && (has("root") || has("typeCode") || has("type")):
		ctx.Fact("browser.file", "firefox bookmark backup", "recognised by its \"guid\" and \"children\" keys")
		var root ffBookmark
		if err := json.Unmarshal(doc, &root); err != nil {
			return true, fmt.Errorf("firefox bookmark backup: %w", err)
		}
		n, err = firefoxBackupNode(ctx, &root, "", 0, new(int))
	default:
		return false, nil
	}
	body := clean(string(doc))
	ctx.Text("full text", len(body) > maxText, trunc(body, maxText))
	if err == nil && n == 0 {
		ctx.Note("the file holds no dated entries; its text is indexed")
	}
	return true, err
}

// jsonInt reads a number that may be written as a number or as a string.
type jsonInt int64

func (j *jsonInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*j = jsonInt(v)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f > -9e18 && f < 9e18 {
		*j = jsonInt(f)
	}
	return nil // a value that is not a number is treated as absent
}

type crBookmark struct {
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	URL          string       `json:"url"`
	ID           string       `json:"id"`
	DateAdded    jsonInt      `json:"date_added"`
	DateLastUsed jsonInt      `json:"date_last_used"`
	DateModified jsonInt      `json:"date_modified"`
	Children     []crBookmark `json:"children"`
}

func chromiumBookmarks(ctx *Context, roots json.RawMessage) (int, error) {
	var r map[string]json.RawMessage
	if err := json.Unmarshal(roots, &r); err != nil {
		return 0, fmt.Errorf("chromium bookmarks: %w", err)
	}
	names := make([]string, 0, len(r))
	for k := range r {
		names = append(names, k)
	}
	sort.Strings(names)
	total := 0
	for _, k := range names {
		var node crBookmark
		if json.Unmarshal(r[k], &node) != nil {
			continue // "sync_transaction_version" and the like are not folders
		}
		n, err := chromiumBookmarkNode(ctx, &node, k, 0)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func chromiumBookmarkNode(ctx *Context, b *crBookmark, folder string, depth int) (int, error) {
	if depth > maxBookmarkDepth {
		ctx.Warn("bookmark folders nested deeper than %d were not followed", maxBookmarkDepth)
		return 0, nil
	}
	total := 0
	if b.URL != "" {
		as, aok := timeutil.FromWebkitMicro(int64(b.DateAdded))
		us, uok := timeutil.FromWebkitMicro(int64(b.DateLastUsed))
		n, err := emitBookmark(ctx, "chromium", "bookmark id "+clean(trunc(b.ID, 40)), b.URL, b.Name, folder,
			timed{as, aok, "bookmark-added", "Bookmarked "}, timed{us, uok, "bookmark-last-used", "Bookmark opened: "})
		total += n
		if err != nil {
			return total, err
		}
	}
	for i := range b.Children {
		sub := folder
		if b.URL == "" && b.Name != "" && depth > 0 {
			sub = folder + "/" + b.Name
		}
		n, err := chromiumBookmarkNode(ctx, &b.Children[i], sub, depth+1)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Where Chromium says an extension came from (extensions/common/mojom/manifest.mojom).
var chromiumExtLocations = map[int64]string{1: "installed by the user or the web store", 2: "external (preferences file)", 3: "external (registry)",
	4: "unpacked (loaded from a folder in developer mode)", 5: "component of the browser", 6: "external (preferences file, downloaded)",
	7: "policy (downloaded)", 8: "command line", 9: "policy", 10: "external component"}

func chromiumPreferences(ctx *Context, top map[string]json.RawMessage) (int, error) {
	var accounts []struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(top["account_info"], &accounts) == nil {
		var emails []string
		for _, a := range accounts {
			if a.Email != "" {
				emails = append(emails, clean(trunc(a.Email, 200)))
			}
		}
		if len(emails) > 0 {
			ctx.Fact("browser.signed_in_account", strings.Join(emails, ", "), "account the browser profile is signed in to")
		}
	}
	var profile struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(top["profile"], &profile) == nil && profile.Name != "" {
		ctx.Fact("browser.profile_name", clean(trunc(profile.Name, 200)), "name of the browser profile")
	}
	var ext struct {
		Settings map[string]struct {
			InstallTime      jsonInt `json:"install_time"`
			FirstInstallTime jsonInt `json:"first_install_time"`
			LastUpdateTime   jsonInt `json:"last_update_time"`
			Location         jsonInt `json:"location"`
			Path             string  `json:"path"`
			FromWebstore     *bool   `json:"from_webstore"`
			State            *int64  `json:"state"`
			DisableReasons   any     `json:"disable_reasons"`
			Manifest         struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				Permissions []any  `json:"permissions"`
			} `json:"manifest"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(top["extensions"], &ext); err != nil {
		return 0, fmt.Errorf("chromium preferences, extensions: %w", err)
	}
	ids := make([]string, 0, len(ext.Settings))
	for id := range ext.Settings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	total := 0
	for _, id := range ids {
		x := ext.Settings[id]
		name := clean(trunc(x.Manifest.Name, 300))
		fields := map[string]any{"browser": "chromium", "extension_id": clean(trunc(id, 100))}
		if name != "" {
			fields["name"] = name
		}
		if x.Manifest.Version != "" {
			fields["version"] = clean(trunc(x.Manifest.Version, 100))
		}
		if x.Path != "" {
			fields["path"] = clean(trunc(x.Path, 1000))
		}
		if x.Location != 0 {
			fields["location"] = int64(x.Location)
			if n, ok := chromiumExtLocations[int64(x.Location)]; ok {
				fields["location_name"] = n
			}
		}
		if x.FromWebstore != nil {
			fields["from_webstore"] = *x.FromWebstore
		}
		if x.State != nil && *x.State == 0 {
			fields["disabled"] = true
		}
		var perms []string
		for _, p := range x.Manifest.Permissions {
			if s, ok := p.(string); ok && len(perms) < 100 {
				perms = append(perms, clean(trunc(s, 200)))
			}
		}
		if len(perms) > 0 {
			fields["permissions"] = perms
		}
		label := name
		if label == "" {
			label = id
		}
		first := x.FirstInstallTime
		if first == 0 {
			first = x.InstallTime
		}
		fs, fok := timeutil.FromWebkitMicro(int64(first))
		is, iok := timeutil.FromWebkitMicro(int64(x.InstallTime))
		us, uok := timeutil.FromWebkitMicro(int64(x.LastUpdateTime))
		n, err := emitTimes(ctx, []timed{
			{fs, fok, "browser-extension-installed", "Browser extension installed: "},
			{is, iok, "browser-extension-updated", "Browser extension version installed: "},
			{us, uok, "browser-extension-updated", "Browser extension updated: "},
		}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: clean(trunc(x.Path, 1000)),
			Message: trunc(label, 200), Fields: fields, Ref: "extensions.settings." + clean(trunc(id, 100))})
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func firefoxExtensions(ctx *Context, raw json.RawMessage) (int, error) {
	var addons []struct {
		ID            string  `json:"id"`
		Version       string  `json:"version"`
		Type          string  `json:"type"`
		InstallDate   jsonInt `json:"installDate"`
		UpdateDate    jsonInt `json:"updateDate"`
		Active        *bool   `json:"active"`
		Path          string  `json:"path"`
		Location      string  `json:"location"`
		SourceURI     string  `json:"sourceURI"`
		DefaultLocale struct {
			Name string `json:"name"`
		} `json:"defaultLocale"`
	}
	if err := json.Unmarshal(raw, &addons); err != nil {
		return 0, fmt.Errorf("firefox extensions: %w", err)
	}
	total := 0
	for i, a := range addons {
		name := clean(trunc(a.DefaultLocale.Name, 300))
		fields := map[string]any{"browser": "firefox", "extension_id": clean(trunc(a.ID, 200))}
		for k, v := range map[string]string{"name": name, "version": a.Version, "type": a.Type, "path": a.Path, "location_name": a.Location, "source_url": a.SourceURI} {
			if v != "" {
				fields[k] = clean(trunc(v, 1000))
			}
		}
		if a.Active != nil && !*a.Active {
			fields["disabled"] = true
		}
		label := name
		if label == "" {
			label = clean(trunc(a.ID, 200))
		}
		is, iok := unixMillis(int64(a.InstallDate))
		us, uok := unixMillis(int64(a.UpdateDate))
		n, err := emitTimes(ctx, []timed{
			{is, iok, "browser-extension-installed", "Browser extension installed: "},
			{us, uok, "browser-extension-updated", "Browser extension updated: "},
		}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: clean(trunc(a.Path, 1000)),
			Message: label, Fields: fields, Ref: fmt.Sprintf("addons[%d]", i)})
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

type ffTab struct {
	Entries []struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	} `json:"entries"`
	Index        int     `json:"index"`
	LastAccessed jsonInt `json:"lastAccessed"`
}

type ffWindow struct {
	Tabs       []ffTab `json:"tabs"`
	ClosedTabs []struct {
		State    ffTab   `json:"state"`
		ClosedAt jsonInt `json:"closedAt"`
	} `json:"_closedTabs"`
	ClosedAt jsonInt `json:"closedAt"`
}

// firefoxSession reads the tabs Firefox had open, and those it remembers
// closing, from its session store.
func firefoxSession(ctx *Context, top map[string]json.RawMessage) (int, error) {
	var open, closed []ffWindow
	if err := json.Unmarshal(top["windows"], &open); err != nil {
		return 0, fmt.Errorf("firefox session: %w", err)
	}
	_ = json.Unmarshal(top["_closedWindows"], &closed)
	total := 0
	var session struct {
		StartTime  jsonInt `json:"startTime"`
		LastUpdate jsonInt `json:"lastUpdate"`
	}
	if json.Unmarshal(top["session"], &session) == nil {
		ss, sok := unixMillis(int64(session.StartTime))
		ls, lok := unixMillis(int64(session.LastUpdate))
		n, err := emitTimes(ctx, []timed{
			{ss, sok, "browser-session-started", "Firefox session started"},
			{ls, lok, "browser-session-saved", "Firefox session last saved"},
		}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, Fields: map[string]any{"browser": "firefox"}, Ref: "session"})
		total += n
		if err != nil {
			return total, err
		}
	}
	tab := func(t *ffTab, ref, state string, closedAt jsonInt) error {
		if len(t.Entries) == 0 {
			return nil
		}
		i := t.Index - 1
		if i < 0 || i >= len(t.Entries) {
			i = len(t.Entries) - 1
		}
		u, title := clean(t.Entries[i].URL), clean(t.Entries[i].Title)
		fields := map[string]any{"browser": "firefox", "url": u, "title": title, "tab_state": state}
		if len(t.Entries) > 1 {
			// The tab's back and forward history, which has no times of its own.
			var hist []string
			for k, e := range t.Entries {
				if k < 50 {
					hist = append(hist, clean(trunc(e.URL, 1000)))
				}
			}
			fields["tab_history"] = hist
			fields["tab_history_note"] = "earlier pages in this tab, oldest first; they carry no time"
		}
		as, aok := unixMillis(int64(t.LastAccessed))
		cs, cok := unixMillis(int64(closedAt))
		n, err := emitTimes(ctx, []timed{
			{as, aok, "tab-last-active (session)", "Tab last active: "},
			{cs, cok, "tab-closed (session)", "Tab closed: "},
		}, Event{Category: CatBrowser, Source: "browser", Host: ctx.Host, Path: u,
			Message: trunc(u, 400) + titleSuffix(title), Fields: fields, Ref: ref})
		total += n
		return err
	}
	for kind, wins := range [][]ffWindow{open, closed} {
		prefix, state := "windows", "open"
		if kind == 1 {
			prefix, state = "_closedWindows", "in a closed window"
		}
		for wi := range wins {
			w := &wins[wi]
			for ti := range w.Tabs {
				closedAt := jsonInt(0)
				if kind == 1 {
					closedAt = w.ClosedAt
				}
				if err := tab(&w.Tabs[ti], fmt.Sprintf("%s[%d].tabs[%d]", prefix, wi, ti), state, closedAt); err != nil {
					return total, err
				}
			}
			for ci := range w.ClosedTabs {
				c := &w.ClosedTabs[ci]
				if err := tab(&c.State, fmt.Sprintf("%s[%d]._closedTabs[%d]", prefix, wi, ci), "closed", c.ClosedAt); err != nil {
					return total, err
				}
			}
		}
	}
	return total, nil
}

type ffBookmark struct {
	Title        string       `json:"title"`
	URI          string       `json:"uri"`
	ID           jsonInt      `json:"id"`
	DateAdded    jsonInt      `json:"dateAdded"`
	LastModified jsonInt      `json:"lastModified"`
	Children     []ffBookmark `json:"children"`
}

func firefoxBackupNode(ctx *Context, b *ffBookmark, folder string, depth int, seq *int) (int, error) {
	if depth > maxBookmarkDepth {
		ctx.Warn("bookmark folders nested deeper than %d were not followed", maxBookmarkDepth)
		return 0, nil
	}
	total := 0
	*seq++
	if b.URI != "" {
		as, aok := timeutil.FromUnixMicro(int64(b.DateAdded), "unix-us")
		ms, mok := timeutil.FromUnixMicro(int64(b.LastModified), "unix-us")
		n, err := emitBookmark(ctx, "firefox", fmt.Sprintf("bookmark %d (id %d)", *seq, int64(b.ID)), b.URI, b.Title, folder,
			timed{as, aok, "bookmark-added", "Bookmarked "}, timed{ms, mok, "bookmark-modified", "Bookmark changed: "})
		total += n
		if err != nil {
			return total, err
		}
	}
	for i := range b.Children {
		sub := folder
		if b.URI == "" && b.Title != "" {
			sub = strings.TrimPrefix(folder+"/"+b.Title, "/")
		}
		n, err := firefoxBackupNode(ctx, &b.Children[i], sub, depth+1, seq)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ---------------------------------------------------------------------------
// Mozilla's LZ4 wrapper: "mozLz40\0", the decompressed size as a 32-bit
// number, then one LZ4 block.

const (
	mozLz4Magic    = "mozLz40\x00"
	maxMozLz4In    = 128 << 20
	maxMozLz4Out   = 512 << 20
	lz4MaxRatio    = 255 // an LZ4 block cannot expand by more than this
	lz4InitialCap  = 1 << 20
	lz4MinMatchLen = 4
)

type mozLz4Parser struct{}

func (mozLz4Parser) Name() string    { return "mozilla-lz4" }
func (mozLz4Parser) Version() string { return "1 (native: firefox session store, bookmark backup)" }

func (mozLz4Parser) Parse(ctx *Context) error {
	if ctx.Size > maxMozLz4In {
		return fmt.Errorf("a Mozilla LZ4 file larger than %d bytes is not decompressed", maxMozLz4In)
	}
	raw, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return err
	}
	if len(raw) < 12 || string(raw[:8]) != mozLz4Magic {
		return errors.New("not a Mozilla LZ4 file")
	}
	size := int64(binary.LittleEndian.Uint32(raw[8:]))
	if size > maxMozLz4Out || size > int64(len(raw)-12)*lz4MaxRatio {
		return fmt.Errorf("the header declares %d bytes of content, which %d compressed bytes cannot hold", size, len(raw)-12)
	}
	doc, err := lz4Block(raw[12:], int(size))
	if err != nil {
		// What was decompressed before the fault is still worth indexing.
		ctx.Warn("decompression stopped after %d of %d bytes: %v", len(doc), size, err)
	}
	ctx.Fact("mozlz4.decompressed_size", fmt.Sprint(len(doc)), "bytes of content after decompression")
	if err == nil {
		if handled, perr := browserJSON(ctx, bytes.TrimPrefix(doc, []byte{0xEF, 0xBB, 0xBF})); handled {
			return perr
		}
	}
	body := clean(string(doc))
	ctx.Text("decompressed text", len(body) > maxText, trunc(body, maxText))
	ctx.Note("the content was decompressed and indexed as text; it is not a file whose records are understood")
	return nil
}

// lz4Block decompresses one LZ4 block into at most size bytes. On an error
// it returns what it had produced.
func lz4Block(src []byte, size int) ([]byte, error) {
	c := size
	if c > lz4InitialCap {
		c = lz4InitialCap
	}
	dst := make([]byte, 0, c)
	length := func(i *int, n int) (int, error) {
		if n != 15 {
			return n, nil
		}
		for {
			if *i >= len(src) {
				return 0, errors.New("a length runs past the end of the data")
			}
			b := src[*i]
			*i++
			n += int(b)
			if n > size+lz4MinMatchLen {
				return 0, errors.New("a length exceeds the declared size")
			}
			if b != 255 {
				return n, nil
			}
		}
	}
	i := 0
	for i < len(src) {
		tok := src[i]
		i++
		lit, err := length(&i, int(tok>>4))
		if err != nil {
			return dst, err
		}
		if lit > len(src)-i || len(dst)+lit > size {
			return dst, errors.New("literal bytes run past the end of the data or the declared size")
		}
		dst = append(dst, src[i:i+lit]...)
		i += lit
		if i >= len(src) {
			break // the last sequence has literals only
		}
		if i+2 > len(src) {
			return dst, errors.New("a match offset is cut short")
		}
		off := int(src[i]) | int(src[i+1])<<8
		i += 2
		if off == 0 || off > len(dst) {
			return dst, errors.New("a match points before the start of the data")
		}
		ml, err := length(&i, int(tok&15))
		if err != nil {
			return dst, err
		}
		ml += lz4MinMatchLen
		if len(dst)+ml > size {
			return dst, errors.New("a match runs past the declared size")
		}
		for k := 0; k < ml; k++ {
			dst = append(dst, dst[len(dst)-off])
		}
	}
	if len(dst) != size {
		return dst, fmt.Errorf("%d bytes came out where the header declares %d", len(dst), size)
	}
	return dst, nil
}
