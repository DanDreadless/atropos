// Package evtxw writes Windows event log (EVTX) files. It exists to make test
// and demonstration logs: Remote Desktop between two hosts of a case, say,
// where no real pair of logs can be published. Nothing in Atropos reads
// evidence with it.
//
// The files follow the format as Windows writes it, closely enough for
// Event Viewer's readers and the common parsers: a file header and 64 KiB
// chunks, each with its checksums; each record is a BinXML fragment holding
// a template instance whose template is defined inline, with the values as
// typed substitutions (event ID as a 16-bit number, the time as a FILETIME,
// numbers in EventData as numbers). Strings are never shared between
// records, which Windows does to save space and readers need not rely on.
//
// Reference: the "Windows XML Event Log (EVTX)" format description by
// Joachim Metz (libevtx), and Microsoft's [MS-EVEN6] BinXml grammar.
package evtxw

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Record is one event.
type Record struct {
	Provider     string
	ProviderGUID string // "{...}", optional
	EventID      uint16
	Version      uint8
	Level        uint8 // 0 log always, 4 information
	Task         uint16
	Keywords     uint64
	Time         time.Time
	ProcessID    uint32
	ThreadID     uint32
	Channel      string
	Computer     string
	UserSID      string // "S-1-5-18", optional

	// EventData as <Data Name="...">value</Data>, in order. A value is a
	// string, uint8, uint16, uint32, uint64, Hex64 or nil (an empty value).
	Data []KV
	// UserData, when set, is written instead of EventData:
	// <UserData><{Element} xmlns="{NS}"><Name>value</Name>...</{Element}></UserData>.
	UserData *UserData
}

// KV is a named value.
type KV struct {
	Name  string
	Value any
}

// UserData is an event's provider-defined XML (Terminal Services events use it).
type UserData struct {
	Element string
	NS      string
	Fields  []KV
}

// Hex64 is a 64-bit number written as Windows writes logon IDs and keywords.
type Hex64 uint64

const (
	chunkSize   = 0x10000
	chunkHeader = 512
	fileHeader  = 4096
)

// Write writes recs as an event log, numbered from 1 in the order given.
func Write(w io.Writer, recs []Record) error {
	var chunks [][]byte
	cw := newChunk(1)
	for i, r := range recs {
		id := uint64(i + 1)
		rec, err := cw.record(id, r)
		if err != nil {
			return fmt.Errorf("record %d: %w", id, err)
		}
		if !cw.fits(rec) {
			if cw.count == 0 {
				return fmt.Errorf("record %d is too large for a chunk", id)
			}
			chunks = append(chunks, cw.finish())
			cw = newChunk(id)
			if rec, err = cw.record(id, r); err != nil {
				return err
			}
		}
		cw.add(id, rec)
	}
	if cw.count > 0 || len(chunks) == 0 {
		chunks = append(chunks, cw.finish())
	}
	if len(chunks) > 0xFFFF {
		return errors.New("too many records for one file")
	}

	h := make([]byte, fileHeader)
	copy(h, "ElfFile\x00")
	binary.LittleEndian.PutUint64(h[8:], 0)                      // first chunk
	binary.LittleEndian.PutUint64(h[16:], uint64(len(chunks)-1)) // last chunk
	binary.LittleEndian.PutUint64(h[24:], uint64(len(recs)+1))   // next record
	binary.LittleEndian.PutUint32(h[32:], 128)                   // header size
	binary.LittleEndian.PutUint16(h[36:], 1)                     // minor version
	binary.LittleEndian.PutUint16(h[38:], 3)                     // major version
	binary.LittleEndian.PutUint16(h[40:], fileHeader)            // header block size
	binary.LittleEndian.PutUint16(h[42:], uint16(len(chunks)))   // chunks
	binary.LittleEndian.PutUint32(h[120:], 0)                    // flags: clean
	binary.LittleEndian.PutUint32(h[124:], crc32.ChecksumIEEE(h[:120]))
	if _, err := w.Write(h); err != nil {
		return err
	}
	for _, c := range chunks {
		if _, err := w.Write(c); err != nil {
			return err
		}
	}
	return nil
}

type chunkWriter struct {
	buf        []byte
	first      uint64
	last       uint64
	count      int
	lastOffset int
}

func newChunk(first uint64) *chunkWriter {
	return &chunkWriter{buf: make([]byte, chunkHeader, chunkSize), first: first}
}

func (c *chunkWriter) fits(rec []byte) bool { return len(c.buf)+len(rec) <= chunkSize }

func (c *chunkWriter) add(id uint64, rec []byte) {
	c.lastOffset = len(c.buf)
	c.buf = append(c.buf, rec...)
	c.last = id
	c.count++
}

// record encodes r as it would sit at the chunk's next free offset (names
// in BinXML are addressed by their offset in the chunk).
func (c *chunkWriter) record(id uint64, r Record) ([]byte, error) {
	at := len(c.buf)
	b := &bx{base: at + 24}
	if err := b.recordXML(uint32(id), r); err != nil {
		return nil, err
	}
	body := b.buf.Bytes()
	size := 24 + len(body) + 4
	if pad := (8 - size%8) % 8; pad > 0 {
		body = append(body, make([]byte, pad)...)
		size += pad
	}
	out := make([]byte, size)
	copy(out, "\x2a\x2a\x00\x00")
	binary.LittleEndian.PutUint32(out[4:], uint32(size))
	binary.LittleEndian.PutUint64(out[8:], id)
	binary.LittleEndian.PutUint64(out[16:], filetime(r.Time))
	copy(out[24:], body)
	binary.LittleEndian.PutUint32(out[size-4:], uint32(size))
	return out, nil
}

func (c *chunkWriter) finish() []byte {
	free := len(c.buf)
	out := make([]byte, chunkSize)
	copy(out, c.buf)
	copy(out, "ElfChnk\x00")
	last := c.last
	if c.count == 0 {
		last = c.first - 1
	}
	binary.LittleEndian.PutUint64(out[8:], c.first)
	binary.LittleEndian.PutUint64(out[16:], last)
	binary.LittleEndian.PutUint64(out[24:], c.first)
	binary.LittleEndian.PutUint64(out[32:], last)
	binary.LittleEndian.PutUint32(out[40:], 128)
	binary.LittleEndian.PutUint32(out[44:], uint32(c.lastOffset))
	binary.LittleEndian.PutUint32(out[48:], uint32(free))
	binary.LittleEndian.PutUint32(out[52:], crc32.ChecksumIEEE(out[chunkHeader:free]))
	hc := crc32.NewIEEE()
	hc.Write(out[:120])
	hc.Write(out[128:chunkHeader])
	binary.LittleEndian.PutUint32(out[124:], hc.Sum32())
	return out
}

// ---- BinXML ----

// Value types.
const (
	tNull    = 0x00
	tString  = 0x01
	tUint8   = 0x04
	tUint16  = 0x06
	tUint32  = 0x08
	tUint64  = 0x0A
	tGUID    = 0x0F
	tFiletim = 0x11
	tSID     = 0x13
	tHex64   = 0x15
)

type value struct {
	typ  byte
	data []byte
	decl byte    // the type a null value would have had
	nest *nested // a BinXml fragment: written where the value lands
}

// nested is a fragment carried as a value (type 0x21), as Windows carries
// EventData: a template instance of its own.
type nested struct {
	id   uint32
	tree *node
	vals []value
}

const tBinXML = 0x21

// bytes encodes the fragment as it would sit at chunk offset base.
func (n *nested) bytes(base int) []byte {
	b := &bx{base: base, vals: n.vals}
	b.fragment(n.id, n.tree)
	return b.buf.Bytes()
}

// node is an element of the template: attributes and content are literal
// text or a substitution (sub >= 0).
type node struct {
	name     string
	attrs    []attr
	children []*node
	sub      int // content substitution, or -1
	text     string
}

type attr struct {
	name string
	text string
	sub  int
}

type bx struct {
	buf  bytes.Buffer
	base int // chunk offset of buf[0]
	vals []value
}

func (b *bx) pos() int { return b.base + b.buf.Len() }

func (b *bx) u8(v byte)    { b.buf.WriteByte(v) }
func (b *bx) u16(v uint16) { binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *bx) u32(v uint32) { binary.Write(&b.buf, binary.LittleEndian, v) }

func (b *bx) patch32(at int, v uint32) {
	binary.LittleEndian.PutUint32(b.buf.Bytes()[at-b.base:], v)
}

// sub adds a substitution value and returns its number; a nil value is an
// empty, optional one.
func (b *bx) sub(v any) (int, error) {
	val, err := encode(v)
	if err != nil {
		return 0, err
	}
	b.vals = append(b.vals, val)
	return len(b.vals) - 1, nil
}

func encode(v any) (value, error) {
	le := binary.LittleEndian
	switch x := v.(type) {
	case nil:
		return value{typ: tNull, decl: tString}, nil
	case nullOf:
		return value{typ: tNull, decl: byte(x)}, nil
	case *nested:
		return value{typ: tBinXML, nest: x}, nil
	case string:
		return value{typ: tString, data: utf16le(x)}, nil
	case uint8:
		return value{typ: tUint8, data: []byte{x}}, nil
	case uint16:
		return value{typ: tUint16, data: le.AppendUint16(nil, x)}, nil
	case uint32:
		return value{typ: tUint32, data: le.AppendUint32(nil, x)}, nil
	case int:
		if x < 0 || x > 0xFFFFFFFF {
			return value{}, fmt.Errorf("number %d out of range", x)
		}
		return value{typ: tUint32, data: le.AppendUint32(nil, uint32(x))}, nil
	case uint64:
		return value{typ: tUint64, data: le.AppendUint64(nil, x)}, nil
	case Hex64:
		return value{typ: tHex64, data: le.AppendUint64(nil, uint64(x))}, nil
	case time.Time:
		return value{typ: tFiletim, data: le.AppendUint64(nil, filetime(x))}, nil
	case sidValue:
		return value{typ: tSID, data: x}, nil
	case guidValue:
		return value{typ: tGUID, data: x}, nil
	}
	return value{}, fmt.Errorf("cannot write a %T", v)
}

type sidValue []byte

// nullOf is an empty value of the given type.
type nullOf byte
type guidValue []byte

func parseSID(s string) (sidValue, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("bad SID %q", s)
	}
	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("bad SID %q", s)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("bad SID %q", s)
	}
	out := []byte{byte(rev), byte(len(parts) - 3)}
	for i := 5; i >= 0; i-- {
		out = append(out, byte(auth>>(8*i)))
	}
	for _, p := range parts[3:] {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad SID %q", s)
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(n))
	}
	return out, nil
}

func parseGUID(s string) (guidValue, error) {
	h := strings.NewReplacer("{", "", "}", "", "-", "").Replace(s)
	if len(h) != 32 {
		return nil, fmt.Errorf("bad GUID %q", s)
	}
	raw := make([]byte, 16)
	for i := range raw {
		n, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("bad GUID %q", s)
		}
		raw[i] = byte(n)
	}
	// The first three groups are little-endian.
	out := []byte{raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6]}
	return append(out, raw[8:]...), nil
}

// recordXML writes the record's fragment: a template instance with its
// template defined inline, then the values.
func (b *bx) recordXML(id uint32, r Record) error {
	tree, err := b.eventTree(id, r)
	if err != nil {
		return err
	}
	b.fragment(id, tree)
	b.u8(0x00) // end of the record's fragment
	return nil
}

// fragment writes a fragment holding a template instance, with the template
// (tree, over b.vals) defined inline, then the values.
func (b *bx) fragment(id uint32, tree *node) {
	b.u8(0x0F) // fragment header, version 1.1
	b.u8(1)
	b.u8(1)
	b.u8(0)
	b.u8(0x0C) // template instance
	b.u8(1)
	b.u32(id)
	defAt := b.pos() + 4
	b.u32(uint32(defAt))
	// The template definition.
	b.u32(0) // next template
	guid := make([]byte, 16)
	binary.LittleEndian.PutUint32(guid, id)
	copy(guid[4:], "atroposevtxw")
	b.buf.Write(guid)
	sizeAt := b.pos()
	b.u32(0)
	start := b.pos()
	b.u8(0x0F)
	b.u8(1)
	b.u8(1)
	b.u8(0)
	b.element(tree)
	b.u8(0x00) // end of the template's fragment
	b.patch32(sizeAt, uint32(b.pos()-start))
	// The values: sizes and types, then the data.
	b.u32(uint32(len(b.vals)))
	for _, v := range b.vals {
		n := len(v.data)
		if v.nest != nil {
			n = len(v.nest.bytes(0))
		}
		b.u16(uint16(n))
		b.u8(v.typ)
		b.u8(0)
	}
	for _, v := range b.vals {
		if v.nest != nil {
			b.buf.Write(v.nest.bytes(b.pos()))
			continue
		}
		b.buf.Write(v.data)
	}
}

func (b *bx) eventTree(id uint32, r Record) (*node, error) {
	el := func(name string, children ...*node) *node { return &node{name: name, sub: -1, children: children} }
	subEl := func(name string, v any) (*node, error) {
		n, err := b.sub(v)
		if err != nil {
			return nil, err
		}
		return &node{name: name, sub: n}, nil
	}
	subAttr := func(name string, v any) (attr, error) {
		n, err := b.sub(v)
		return attr{name: name, sub: n}, err
	}
	var errs []error
	must := func(n *node, err error) *node { errs = append(errs, err); return n }
	mustA := func(a attr, err error) attr { errs = append(errs, err); return a }

	provider := el("Provider")
	provider.attrs = append(provider.attrs, mustA(subAttr("Name", r.Provider)))
	if r.ProviderGUID != "" {
		g, err := parseGUID(r.ProviderGUID)
		if err != nil {
			return nil, err
		}
		provider.attrs = append(provider.attrs, mustA(subAttr("Guid", g)))
	}
	created := el("TimeCreated")
	created.attrs = []attr{mustA(subAttr("SystemTime", r.Time.UTC()))}
	// Windows gives Correlation an ActivityID even when empty; an element
	// with neither attributes nor content is read wrongly by some readers.
	correlation := el("Correlation")
	correlation.attrs = []attr{mustA(subAttr("ActivityID", nullOf(tGUID)))}
	exec := el("Execution")
	exec.attrs = []attr{mustA(subAttr("ProcessID", r.ProcessID)), mustA(subAttr("ThreadID", r.ThreadID))}
	system := el("System",
		provider,
		must(subEl("EventID", r.EventID)),
		must(subEl("Version", r.Version)),
		must(subEl("Level", r.Level)),
		must(subEl("Task", r.Task)),
		must(subEl("Opcode", uint8(0))),
		must(subEl("Keywords", Hex64(r.Keywords))),
		created,
		must(subEl("EventRecordID", uint64(id))),
		correlation,
		exec,
		must(subEl("Channel", r.Channel)),
		must(subEl("Computer", r.Computer)),
	)
	if r.UserSID != "" {
		sid, err := parseSID(r.UserSID)
		if err != nil {
			return nil, err
		}
		sec := el("Security")
		sec.attrs = []attr{mustA(subAttr("UserID", sid))}
		system.children = append(system.children, sec)
	}
	event := el("Event", system)
	event.attrs = []attr{{name: "xmlns", text: "http://schemas.microsoft.com/win/2004/08/events/event", sub: -1}}
	if r.UserData != nil {
		inner := el(r.UserData.Element)
		if r.UserData.NS != "" {
			inner.attrs = []attr{{name: "xmlns", text: r.UserData.NS, sub: -1}}
		}
		for _, f := range r.UserData.Fields {
			inner.children = append(inner.children, must(subEl(f.Name, f.Value)))
		}
		event.children = append(event.children, el("UserData", inner))
	} else {
		// EventData is a fragment of its own, as Windows writes it.
		inner := &bx{}
		data := &node{name: "EventData", sub: -1}
		for _, f := range r.Data {
			v := f.Value
			if v == nil {
				v = "" // an empty Data element reads as an empty string
			}
			n, err := inner.sub(v)
			if err != nil {
				return nil, err
			}
			d := &node{name: "Data", sub: n, attrs: []attr{{name: "Name", text: f.Name, sub: -1}}}
			data.children = append(data.children, d)
		}
		n, err := b.sub(&nested{id: id | 0x80000000, tree: data, vals: inner.vals})
		if err != nil {
			return nil, err
		}
		event.sub = n
	}
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return event, nil
}

func (b *bx) element(n *node) {
	if len(n.attrs) > 0 {
		b.u8(0x41)
	} else {
		b.u8(0x01)
	}
	b.u16(0xFFFF) // dependency: none
	sizeAt := b.pos()
	b.u32(0)
	start := b.pos()
	b.name(n.name)
	if len(n.attrs) > 0 {
		listAt := b.pos()
		b.u32(0)
		ls := b.pos()
		for i, a := range n.attrs {
			if i < len(n.attrs)-1 {
				b.u8(0x46)
			} else {
				b.u8(0x06)
			}
			b.name(a.name)
			b.content(a.text, a.sub)
		}
		b.patch32(listAt, uint32(b.pos()-ls))
	}
	if n.sub < 0 && n.text == "" && len(n.children) == 0 {
		b.u8(0x03) // close empty element
	} else {
		b.u8(0x02) // close start element
		for _, c := range n.children {
			b.element(c)
		}
		if n.sub >= 0 || n.text != "" {
			b.content(n.text, n.sub) // after any children: EventData follows System
		}
		b.u8(0x04) // close element
	}
	b.patch32(sizeAt, uint32(b.pos()-start))
}

func (b *bx) content(text string, sub int) {
	if sub >= 0 {
		b.u8(0x0E) // optional substitution
		b.u16(uint16(sub))
		if v := b.vals[sub]; v.typ == tNull {
			b.u8(v.decl) // the template states the type; the value is empty
		} else {
			b.u8(v.typ)
		}
		return
	}
	b.u8(0x05) // value text
	b.u8(tString)
	u := utf16.Encode([]rune(text))
	b.u16(uint16(len(u)))
	for _, c := range u {
		b.u16(c)
	}
}

// name writes a name in place: its offset, then the name itself.
func (b *bx) name(s string) {
	b.u32(uint32(b.pos() + 4))
	u := utf16.Encode([]rune(s))
	var hash uint32
	for _, c := range u {
		hash = hash*65599 + uint32(c)
	}
	b.u32(0) // next name in the hash bucket
	b.u16(uint16(hash))
	b.u16(uint16(len(u)))
	for _, c := range u {
		b.u16(c)
	}
	b.u16(0)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:], c)
	}
	return out
}

func filetime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UTC().UnixNano()/100) + 116444736000000000
}
