package parsers

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf16"
)

// pickleW writes a base::Pickle: a 32-bit payload size, then 4-byte aligned values.
type pickleW struct{ b []byte }

func (p *pickleW) align() {
	for len(p.b)%4 != 0 {
		p.b = append(p.b, 0)
	}
}
func (p *pickleW) i32(v int32) { p.b = binary.LittleEndian.AppendUint32(p.b, uint32(v)) }
func (p *pickleW) i64(v int64) { p.b = binary.LittleEndian.AppendUint64(p.b, uint64(v)) }
func (p *pickleW) str(s string) {
	p.i32(int32(len(s)))
	p.b = append(p.b, s...)
	p.align()
}
func (p *pickleW) str16(s string) {
	u := utf16.Encode([]rune(s))
	p.i32(int32(len(u)))
	for _, c := range u {
		p.b = binary.LittleEndian.AppendUint16(p.b, c)
	}
	p.align()
}
func (p *pickleW) bytes() []byte {
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(p.b))), p.b...)
}

func navPickle(tab, index int32, url, title, ref string, transition int32, ts int64) []byte {
	var p pickleW
	p.i32(tab)
	p.i32(index)
	p.str(url)
	p.str16(title)
	p.str("opaque page state")
	p.i32(transition)
	p.i32(0) // type mask
	p.str(ref)
	p.i32(0)
	p.str(url)
	p.i32(0) // bool, aligned
	p.i64(ts)
	p.str16("")
	p.i32(200)
	p.i32(0)
	return p.bytes()
}

func snssFile(version int32, cmds ...[]byte) []byte {
	b := append([]byte("SNSS"), binary.LittleEndian.AppendUint32(nil, uint32(version))...)
	for _, c := range cmds {
		b = append(b, c...)
	}
	return b
}

func snssCommand(id byte, body []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(1+len(body)))
	return append(append(b, id), body...)
}

func idTime(id int32, ts int64) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(id))
	b = append(b, 0, 0, 0, 0) // padding before the 64-bit time
	return binary.LittleEndian.AppendUint64(b, uint64(ts))
}

func TestChromiumSessionFile(t *testing.T) {
	nav := func(tab, idx int32, url, title string, ts string) []byte {
		return snssCommand(snssSessNavigation, navPickle(tab, idx, url, title, "https://ref.example/", 1, webkit(ts)))
	}
	sel := append(binary.LittleEndian.AppendUint32(nil, 1), binary.LittleEndian.AppendUint32(nil, 1)...)
	f := snssFile(3,
		snssCommand(snssMarker, nil),
		nav(1, 0, "https://a.example/", "A", "2024-05-01T10:00:00Z"),
		nav(1, 1, "https://b.example/", "B", "2024-05-01T10:05:00Z"),
		nav(1, 1, "https://b.example/", "B", "2024-05-01T10:05:00Z"), // rewritten state: the same navigation again
		snssCommand(snssSessSelectedNav, sel),
		snssCommand(snssSessLastActive, idTime(1, webkit("2024-05-01T10:30:00Z"))),
		nav(2, 0, "https://c.example/", "C", "2024-05-01T11:00:00Z"),
		snssCommand(snssSessTabClosed, idTime(2, webkit("2024-05-01T11:10:00Z"))),
		snssCommand(snssSessWindowClosed, idTime(9, webkit("2024-05-01T12:00:00Z"))),
		[]byte{0x40, 0x00, 6, 1, 2}, // a command cut short
	)
	r := run(t, write(t, "Session_13350000000000000", f), nil)
	if r.err != nil || len(r.warns) > 0 || r.facts["chromium_session.kind"] != "session" {
		t.Fatalf("%v %v %v", r.err, r.warns, r.facts)
	}
	got := map[string]string{}
	for _, e := range r.events {
		got[e.Type+" "+utc(e)] = e.Path
		if e.Category != CatBrowser || e.Source != "chromium-session" {
			t.Errorf("event: %+v", e)
		}
	}
	want := map[string]string{
		"session-navigation 2024-05-01T10:00:00Z": "https://a.example/",
		"session-navigation 2024-05-01T10:05:00Z": "https://b.example/",
		"session-navigation 2024-05-01T11:00:00Z": "https://c.example/",
		"tab-last-active 2024-05-01T10:30:00Z":    "https://b.example/", // the selected entry
		"tab-closed 2024-05-01T11:10:00Z":         "https://c.example/",
		"window-closed 2024-05-01T12:00:00Z":      "",
	}
	if len(got) != len(want) || len(r.events) != len(want) {
		t.Errorf("events: %v", got)
	}
	for k, v := range want {
		if p, ok := got[k]; !ok || p != v {
			t.Errorf("%s: %q (have %v)", k, p, got)
		}
	}
	for _, e := range r.events {
		if e.Type == "session-navigation" && (e.Fields["referrer"] != "https://ref.example/" || e.Fields["transition_name"] != "typed" || e.Fields["http_status"] != int32(200)) {
			t.Errorf("navigation fields: %+v", e.Fields)
		}
	}
	if !strings.Contains(strings.Join(r.notes, " "), "cut short") {
		t.Errorf("notes: %v", r.notes)
	}
}

func TestChromiumClosedTabsFile(t *testing.T) {
	start := func(index int32, ts string) []byte {
		b := binary.LittleEndian.AppendUint32(nil, 7)
		b = binary.LittleEndian.AppendUint32(b, uint32(index))
		return snssCommand(snssTabsSelectedNav, binary.LittleEndian.AppendUint64(b, uint64(webkit(ts))))
	}
	nav := func(idx int32, url, ts string) []byte {
		return snssCommand(snssTabsNavigation, navPickle(7, idx, url, "", "", 0, webkit(ts)))
	}
	f := snssFile(3,
		start(1, "2024-06-01T09:00:00Z"),
		nav(4, "https://first.example/", "2024-06-01T08:00:00Z"),
		nav(5, "https://second.example/", "2024-06-01T08:30:00Z"),
	)
	r := run(t, write(t, "Tabs_13350000000000000", f), nil)
	if r.err != nil || r.facts["chromium_session.kind"] != "closed tabs" || len(r.events) != 3 {
		t.Fatalf("%v %v %d %+v", r.err, r.facts, len(r.events), r.events)
	}
	last := r.events[2]
	if last.Type != "tab-closed" || utc(last) != "2024-06-01T09:00:00Z" || last.Path != "https://second.example/" {
		t.Errorf("closed tab: %s %+v", utc(last), last)
	}
}

func TestChromiumSessionEncryptedAndDamaged(t *testing.T) {
	r := run(t, write(t, "Session_1", snssFile(5, []byte{1, 2, 3, 4, 5, 6, 7, 8})), nil)
	if r.err != nil || len(r.events) != 0 || !strings.Contains(strings.Join(r.notes, " "), "encrypted") {
		t.Errorf("encrypted: %v %v", r.err, r.notes)
	}
	// Random bytes and truncated pickles must not crash or hang the reader.
	rng := rand.New(rand.NewSource(1))
	good := snssCommand(snssSessNavigation, navPickle(1, 0, "https://a.example/", "A", "", 1, webkit("2024-05-01T10:00:00Z")))
	for i := 0; i < 300; i++ {
		junk := make([]byte, rng.Intn(400))
		rng.Read(junk)
		cut := good[:rng.Intn(len(good))]
		bad := append([]byte(nil), good...)
		bad[2+rng.Intn(len(bad)-2)] ^= byte(1 + rng.Intn(255))
		for _, f := range [][]byte{snssFile(3, junk), snssFile(3, cut), snssFile(3, bad), snssFile(1, bad, junk)} {
			run(t, write(t, "Session_x", f), nil)
		}
	}
}
