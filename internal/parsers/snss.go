package parsers

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Chromium session files: "Sessions\Session_*" (the tabs and windows open,
// with each tab's back-and-forward history) and "Sessions\Tabs_*" (recently
// closed tabs and windows). Both are "SNSS" command logs.
//
// Written from the Chromium source: components/sessions/core/
// command_storage_backend.cc (the file: "SNSS", a version, then commands
// of a 16-bit size, an 8-bit id and the contents), session_command.cc,
// session_service_commands.cc and tab_restore_service_impl.cc (which ids
// mean what in each kind of file), serialized_navigation_entry.cc (a
// navigation, written as a base::Pickle) and base/pickle.cc (a 32-bit
// payload size, then 4-byte aligned values; strings length-prefixed).
//
// The two kinds of file use different command numbers and are told apart
// by content: whichever reading gives navigations that decode.

const (
	snssMaxFile = 256 << 20
	// Session_ commands.
	snssSessNavigation   = 6
	snssSessSelectedNav  = 7
	snssSessTabClosed    = 16
	snssSessWindowClosed = 17
	snssSessLastActive   = 21
	// Tabs_ commands.
	snssTabsNavigation  = 1
	snssTabsSelectedNav = 4
	snssMarker          = 255
)

type snssParser struct{}

func (snssParser) Name() string { return "chromium-session" }
func (snssParser) Version() string {
	return "1 (native: SNSS session and closed-tab files: navigations, last active and closed times)"
}

type snssCmd struct {
	id   byte
	body []byte
	off  int64
}

type pickle struct {
	b   []byte
	pos int
	ok  bool
}

func newPickle(b []byte) *pickle {
	if len(b) < 4 {
		return &pickle{}
	}
	payload := int(binary.LittleEndian.Uint32(b))
	if payload > len(b)-4 {
		return &pickle{}
	}
	head := len(b) - payload
	if head%4 != 0 {
		return &pickle{}
	}
	return &pickle{b: b, pos: head, ok: true}
}

func (p *pickle) take(n int) []byte {
	if !p.ok || n < 0 || p.pos+n > len(p.b) {
		p.ok = false
		return nil
	}
	v := p.b[p.pos : p.pos+n]
	p.pos += (n + 3) &^ 3
	if p.pos > len(p.b) {
		p.pos = len(p.b)
	}
	return v
}

func (p *pickle) int32() int32 {
	if v := p.take(4); v != nil {
		return int32(binary.LittleEndian.Uint32(v))
	}
	return 0
}

func (p *pickle) int64() int64 {
	if v := p.take(8); v != nil {
		return int64(binary.LittleEndian.Uint64(v))
	}
	return 0
}

func (p *pickle) str() string {
	n := p.int32()
	return string(p.take(int(n)))
}

func (p *pickle) str16() string {
	n := p.int32()
	b := p.take(int(n) * 2)
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

type snssNav struct {
	tab, index      int32
	url, title, ref string
	original        string
	transition      int32
	ts              int64 // microseconds since 1601, UTC
	status          int32
	off             int64
}

// readNav decodes a navigation command: the tab, then the entry. Fields
// added to the format over the years are read only while they are there.
func readNav(c snssCmd) (snssNav, bool) {
	p := newPickle(c.body)
	n := snssNav{off: c.off}
	n.tab, n.index = p.int32(), p.int32()
	n.url, n.title = p.str(), p.str16()
	p.str() // the page state, an opaque blob
	n.transition = p.int32()
	if !p.ok || n.url == "" {
		return n, false
	}
	mark := *p
	_ = p.int32() // type mask
	n.ref = p.str()
	_ = p.int32() // a referrer policy written wrongly and ignored by Chromium
	n.original = p.str()
	_ = p.take(4) // overriding the user agent
	n.ts = p.int64()
	_ = p.str16() // search terms, no longer written
	n.status = p.int32()
	if !p.ok {
		// An older entry: keep what the required fields gave.
		*p = mark
		n.ref, n.original, n.ts, n.status = "", "", 0, 0
	}
	return n, true
}

func readSNSS(b []byte) ([]snssCmd, int32, string) {
	if len(b) < 8 || string(b[:4]) != "SNSS" {
		return nil, 0, "not a Chromium session file"
	}
	version := int32(binary.LittleEndian.Uint32(b[4:]))
	var cmds []snssCmd
	why := ""
	for pos := 8; pos+2 <= len(b); {
		size := int(binary.LittleEndian.Uint16(b[pos:]))
		if size < 1 {
			why = fmt.Sprintf("a command of no length at offset %d ends the file there", pos)
			break
		}
		if pos+2+size > len(b) {
			why = fmt.Sprintf("the last command, at offset %d, was cut short (the browser was writing it)", pos)
			break
		}
		cmds = append(cmds, snssCmd{id: b[pos+2], body: b[pos+3 : pos+2+size], off: int64(pos)})
		pos += 2 + size
	}
	return cmds, version, why
}

func (snssParser) Parse(ctx *Context) error {
	if ctx.Size > snssMaxFile {
		return fmt.Errorf("session file of %d bytes is larger than any real one", ctx.Size)
	}
	b := make([]byte, ctx.Size)
	if _, err := io.ReadFull(io.NewSectionReader(ctx.File, 0, ctx.Size), b); err != nil {
		return err
	}
	cmds, version, why := readSNSS(b)
	switch version {
	case 1, 3:
	case 2, 4, 5:
		ctx.Fact("chromium_session.version", fmt.Sprint(version), "SNSS file version")
		ctx.Note("this session file is encrypted with the browser's key (version %d), which Atropos does not hold; its contents cannot be read", version)
		return nil
	default:
		return fmt.Errorf("session file version %d is not one Chromium writes", version)
	}
	if why != "" {
		ctx.Note("%s", why)
	}
	// Which kind of file: the reading whose navigations decode.
	sess, tabs := 0, 0
	for _, c := range cmds {
		if _, ok := readNav(c); ok {
			switch c.id {
			case snssSessNavigation:
				sess++
			case snssTabsNavigation:
				tabs++
			}
		}
	}
	kind := "session"
	if tabs > sess {
		kind = "closed tabs"
	}
	ctx.Fact("chromium_session.kind", kind, "open tabs and windows (Session_), or recently closed ones (Tabs_), told apart by content")
	ctx.Fact("chromium_session.commands", fmt.Sprint(len(cmds)), "commands in the file")
	if kind == "session" {
		return snssSession(ctx, cmds)
	}
	return snssClosed(ctx, cmds)
}

func navFields(n snssNav, kind string) map[string]any {
	core := int64(n.transition) & 0xFF
	f := map[string]any{"browser": "chromium", "session_file": kind, "tab_id": n.tab, "navigation_index": n.index,
		"title": clean(trunc(n.title, 1000)), "transition": core}
	if core >= 0 && int(core) < len(chromiumTransitions) {
		f["transition_name"] = chromiumTransitions[core]
	}
	if n.ref != "" {
		f["referrer"] = clean(trunc(n.ref, 2000))
	}
	if n.original != "" && n.original != n.url {
		f["original_request_url"] = clean(trunc(n.original, 2000))
	}
	if n.status != 0 {
		f["http_status"] = n.status
	}
	return f
}

func emitNav(ctx *Context, n snssNav, kind, typ, what string) error {
	stamp, ok := timeutil.FromWebkitMicro(n.ts)
	if !ok {
		return nil
	}
	u := clean(trunc(n.url, 2000))
	msg := fmt.Sprintf("%s: %s", what, u)
	if n.title != "" {
		msg += " — " + clean(trunc(n.title, 200))
	}
	return ctx.Emit(Event{Stamp: stamp, Type: typ, Category: CatBrowser, Source: "chromium-session", Host: ctx.Host,
		Path: u, Message: msg, Fields: navFields(n, kind), Ref: fmt.Sprintf("command at offset %d", n.off)})
}

func le16Time(body []byte) (int32, int64, bool) {
	if len(body) != 16 {
		return 0, 0, false
	}
	return int32(binary.LittleEndian.Uint32(body)), int64(binary.LittleEndian.Uint64(body[8:])), true
}

// snssSession reads a Session_ file. The browser rewrites the whole state
// now and then, so the same navigation can appear more than once; each is
// put on the timeline once.
func snssSession(ctx *Context, cmds []snssCmd) error {
	type tab struct {
		navs       map[int32]snssNav
		selected   int32
		hasSel     bool
		lastActive int64
		laOff      int64
		closed     int64
		clOff      int64
	}
	tabs := map[int32]*tab{}
	get := func(id int32) *tab {
		if tabs[id] == nil {
			tabs[id] = &tab{navs: map[int32]snssNav{}}
		}
		return tabs[id]
	}
	seen := map[string]bool{}
	navs, windows := 0, 0
	for _, c := range cmds {
		switch c.id {
		case snssSessNavigation:
			n, ok := readNav(c)
			if !ok {
				continue
			}
			get(n.tab).navs[n.index] = n
			key := fmt.Sprintf("%d/%d/%d/%s", n.tab, n.index, n.ts, n.url)
			if seen[key] {
				continue
			}
			seen[key] = true
			navs++
			if err := emitNav(ctx, n, "session", "session-navigation", "Tab navigated (session file)"); err != nil {
				return err
			}
		case snssSessSelectedNav:
			if len(c.body) == 8 {
				t := get(int32(binary.LittleEndian.Uint32(c.body)))
				t.selected, t.hasSel = int32(binary.LittleEndian.Uint32(c.body[4:])), true
			}
		case snssSessLastActive:
			if id, ts, ok := le16Time(c.body); ok {
				t := get(id)
				t.lastActive, t.laOff = ts, c.off
			}
		case snssSessTabClosed:
			if id, ts, ok := le16Time(c.body); ok {
				t := get(id)
				t.closed, t.clOff = ts, c.off
			}
		case snssSessWindowClosed:
			if _, ts, ok := le16Time(c.body); ok {
				windows++
				if stamp, ok := timeutil.FromWebkitMicro(ts); ok {
					if err := ctx.Emit(Event{Stamp: stamp, Type: "window-closed", Category: CatBrowser, Source: "chromium-session", Host: ctx.Host,
						Message: "Browser window closed (session file)", Fields: map[string]any{"browser": "chromium", "session_file": "session"},
						Ref: fmt.Sprintf("command at offset %d", c.off)}); err != nil {
						return err
					}
				}
			}
		}
	}
	ids := make([]int32, 0, len(tabs))
	for id := range tabs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		t := tabs[id]
		// The page the tab showed: its selected entry, else its newest.
		cur, have := t.navs[t.selected]
		if !t.hasSel || !have {
			var best int32 = -1
			for i := range t.navs {
				if i > best {
					best = i
				}
			}
			cur, have = t.navs[best]
		}
		for _, x := range []struct {
			ts   int64
			off  int64
			typ  string
			what string
		}{{t.lastActive, t.laOff, "tab-last-active", "Tab last active"}, {t.closed, t.clOff, "tab-closed", "Tab closed"}} {
			if x.ts == 0 {
				continue
			}
			n := snssNav{tab: id, ts: x.ts, off: x.off, url: "(page not recorded)"}
			if have {
				n.url, n.title, n.index, n.transition = cur.url, cur.title, cur.index, cur.transition
			}
			if err := emitNav(ctx, n, "session", x.typ, x.what); err != nil {
				return err
			}
		}
	}
	ctx.Note("session file: %d tabs, %d distinct navigations, %d windows closed", len(tabs), navs, windows)
	return nil
}

// snssClosed reads a Tabs_ file: each closed tab begins with a command
// recording when it was closed and which of its entries was showing.
func snssClosed(ctx *Context, cmds []snssCmd) error {
	type closed struct {
		ts       int64
		selected int32
		off      int64
		navs     []snssNav
	}
	var list []*closed
	var cur *closed
	for _, c := range cmds {
		switch c.id {
		case snssTabsSelectedNav:
			cur = &closed{off: c.off}
			switch len(c.body) {
			case 16:
				cur.selected, cur.ts = int32(binary.LittleEndian.Uint32(c.body[4:])), int64(binary.LittleEndian.Uint64(c.body[8:]))
			case 8:
				cur.selected = int32(binary.LittleEndian.Uint32(c.body[4:]))
			default:
				cur = nil
				continue
			}
			list = append(list, cur)
		case snssTabsNavigation:
			if cur == nil {
				continue
			}
			n, ok := readNav(c)
			if !ok {
				continue
			}
			n.index = int32(len(cur.navs))
			cur.navs = append(cur.navs, n)
		}
	}
	navs := 0
	for _, t := range list {
		for _, n := range t.navs {
			navs++
			if err := emitNav(ctx, n, "closed tabs", "closed-tab-navigation", "Navigation in a tab since closed"); err != nil {
				return err
			}
		}
		if t.ts == 0 || len(t.navs) == 0 {
			continue
		}
		sel := t.selected
		if sel < 0 || int(sel) >= len(t.navs) {
			sel = int32(len(t.navs) - 1)
		}
		n := t.navs[sel]
		n.ts, n.off = t.ts, t.off
		if err := emitNav(ctx, n, "closed tabs", "tab-closed", "Tab closed"); err != nil {
			return err
		}
	}
	ctx.Note("recently closed tabs: %d tabs with %d navigations", len(list), navs)
	return nil
}
