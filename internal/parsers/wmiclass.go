package parsers

import (
	"encoding/binary"
	"io"
	"math"
	"regexp"
	"sort"
	"unicode/utf16"
)

// Naming the values of WMI instances. An instance record holds its values
// in the order of its class's properties, and only the class definition
// names them. Class definitions are carved from the same file as the
// instances: each begins with its superclass's name in UTF-16, after its
// length and before a FILETIME; its own properties follow in a data area,
// each with a type and an on-disk index. A class's properties are its
// ancestors' and its own, and an instance stores a table of their values in
// index order, strings and arrays as offsets into the instance's data.
//
// Written from the structures in Mandiant's python-cim (flare-wmi,
// cim/objects.py: ClassDefinitionHeader, ClassDefinition, PropertyReference,
// _ClassDefinitionProperty, ClassInstance, DataRegion), and checked against
// what Get-CimInstance gives for the subscription objects of a real
// Windows 11 repository.

type wmiProp struct {
	name  string
	typ   byte
	array bool
	index int
}

type wmiClass struct {
	name, super string
	props       []wmiProp // its own, not inherited
	ts          uint64
}

// reUTF16Ident is a class name in UTF-16: where a class definition's
// superclass is written.
var reUTF16Ident = regexp.MustCompile(`(?:[A-Za-z_]\x00)(?:[A-Za-z0-9_]\x00){2,127}`)

// wmiStr reads a string from a data area: a flag byte (0: one byte a
// character, 1: UTF-16), the text, a terminator.
func wmiStr(d []byte, ref uint32) (string, bool) {
	i := int(ref)
	if i < 0 || i >= len(d) {
		return "", false
	}
	switch d[i] {
	case 0:
		for j := i + 1; j < len(d); j++ {
			if d[j] == 0 {
				return latin1(d[i+1 : j]), true
			}
		}
	case 1:
		var u []uint16
		for j := i + 1; j+1 < len(d); j += 2 {
			c := binary.LittleEndian.Uint16(d[j:])
			if c == 0 {
				return string(utf16.Decode(u)), true
			}
			u = append(u, c)
		}
	}
	return "", false
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// parseClassDef reads a class definition starting at b[0], whose superclass
// name is sup (already matched). It returns nil if the bytes are not one.
func parseClassDef(b []byte) *wmiClass {
	le := binary.LittleEndian
	need := func(o, n int) bool { return o >= 0 && n >= 0 && o+n <= len(b) }
	if !need(0, 4) {
		return nil
	}
	sl := int(le.Uint32(b))
	o := 4 + 2*sl
	if !need(o, 25) {
		return nil
	}
	u := make([]uint16, sl)
	for i := range u {
		u[i] = le.Uint16(b[4+2*i:])
	}
	c := &wmiClass{super: string(utf16.Decode(u)), ts: le.Uint64(b[o:])}
	if !plausibleFiletime(c.ts) {
		return nil
	}
	o += 12 + 1 // FILETIME, data length, a byte
	offName, defaults, sal := le.Uint32(b[o:]), int(le.Uint32(b[o+4:])), int(le.Uint32(b[o+8:]))
	o += 12
	if sal != 4 {
		// The superclass again, as a string, then its length.
		if !need(o, 1) || b[o] != 0 {
			return nil
		}
		j := o + 1
		for j < len(b) && b[j] != 0 {
			j++
		}
		o = j + 1 + 4
	}
	if !need(o, 4) {
		return nil
	}
	qs := int(le.Uint32(b[o:]))
	if qs < 4 || !need(o, qs+4) {
		return nil
	}
	o += qs
	count := int(le.Uint32(b[o:]))
	o += 4
	if count > 1024 || !need(o, 8*count) {
		return nil
	}
	refs := b[o : o+8*count]
	o += 8 * count
	if defaults < 0 || !need(o, defaults+4) {
		return nil
	}
	o += defaults
	ps := int(le.Uint32(b[o:]) & 0x7FFFFFFF)
	if !need(o+4, ps) {
		return nil
	}
	pd := b[o+4 : o+4+ps]
	name, ok := wmiStr(pd, offName)
	if !ok || name == "" {
		return nil
	}
	c.name = name
	for i := 0; i < count; i++ {
		nref, sref := le.Uint32(refs[8*i:]), int(le.Uint32(refs[8*i+4:]))
		if nref&0x80000000 != 0 || sref < 0 || sref+14 > len(pd) {
			return nil // built-in property names do not occur in the classes read here
		}
		pn, ok := wmiStr(pd, nref)
		if !ok || pn == "" {
			return nil
		}
		c.props = append(c.props, wmiProp{name: pn, typ: pd[sref], array: pd[sref+1]&0x20 != 0, index: int(le.Uint16(pd[sref+4:]))})
	}
	return c
}

// carveClasses finds the definitions of the classes wanted and of their
// ancestors. Every version found is kept; the newest is tried first.
func carveClasses(r io.ReaderAt, size int64, want map[string]bool) map[string][]*wmiClass {
	found := map[string][]*wmiClass{}
	buf := make([]byte, wmiWindow+maxWMIRecord+256)
	all := map[string][]*wmiClass{}
	for base := int64(0); base < size; base += wmiWindow {
		n, _ := r.ReadAt(buf, base)
		if n == 0 {
			break
		}
		b := buf[:n]
		for _, m := range reUTF16Ident.FindAllIndex(b, -1) {
			if m[0] < 4 || m[0] >= wmiWindow+4 {
				continue
			}
			if int(binary.LittleEndian.Uint32(b[m[0]-4:])) != (m[1]-m[0])/2 {
				continue
			}
			end := m[0] - 4 + maxWMIRecord
			if end > len(b) {
				end = len(b)
			}
			if c := parseClassDef(b[m[0]-4 : end]); c != nil {
				all[c.name] = append(all[c.name], c)
			}
		}
	}
	// The wanted classes and, transitively, their superclasses.
	queue := make([]string, 0, len(want))
	for k := range want {
		queue = append(queue, k)
	}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if _, done := found[k]; done {
			continue
		}
		vs := all[k]
		sort.SliceStable(vs, func(i, j int) bool { return vs[i].ts > vs[j].ts })
		found[k] = vs
		for _, v := range vs {
			if v.super != "" {
				queue = append(queue, v.super)
			}
		}
	}
	return found
}

// layouts returns the possible property layouts of a class: its versions,
// each with its ancestors' newest version, root first.
func wmiLayouts(classes map[string][]*wmiClass, name string) [][]wmiProp {
	var out [][]wmiProp
	for _, leaf := range classes[name] {
		props := append([]wmiProp(nil), leaf.props...)
		sup, ok := leaf.super, true
		for depth := 0; sup != "" && depth < 16; depth++ {
			vs := classes[sup]
			if len(vs) == 0 {
				// The root of every class has no stored properties.
				if sup != "__SystemClass" {
					ok = false
				}
				break
			}
			props = append(props, vs[0].props...)
			sup = vs[0].super
		}
		if !ok {
			continue
		}
		sort.Slice(props, func(i, j int) bool { return props[i].index < props[j].index })
		good := true
		for i, p := range props {
			if p.index != i {
				good = false
				break
			}
		}
		if good {
			out = append(out, props)
		}
	}
	return out
}

func wmiTypeSize(p wmiProp) int {
	if p.array {
		return 4
	}
	switch p.typ {
	case 0x10, 0x11: // int8, uint8
		return 1
	case 0x02, 0x0B, 0x12: // int16, boolean, uint16
		return 2
	case 0x05, 0x14, 0x15: // real64, int64, uint64
		return 8
	}
	return 4
}

func wmiScalar(p wmiProp, v []byte, region []byte) (any, bool) {
	le := binary.LittleEndian
	switch p.typ {
	case 0x08, 0x65, 0x66: // string, datetime, reference
		s, ok := wmiStr(region, le.Uint32(v))
		return s, ok
	case 0x0B:
		return le.Uint16(v) != 0, true
	case 0x10:
		return int8(v[0]), true
	case 0x11:
		return v[0], true
	case 0x02:
		return int16(le.Uint16(v)), true
	case 0x12:
		return le.Uint16(v), true
	case 0x03:
		return int32(le.Uint32(v)), true
	case 0x13:
		return le.Uint32(v), true
	case 0x14:
		return int64(le.Uint64(v)), true
	case 0x15:
		return le.Uint64(v), true
	case 0x04:
		return math.Float32frombits(le.Uint32(v)), true
	case 0x05:
		return math.Float64frombits(le.Uint64(v)), true
	}
	return nil, false
}

// decodeInstance names an instance's values. rec is the record after the
// class-name hash: two FILETIMEs, the data length, and the rest. It returns
// nil if the layout does not fit the record.
func decodeInstance(rec []byte, class string, layout []wmiProp) map[string]any {
	le := binary.LittleEndian
	n := len(layout)
	o := 16 + 4 + 4 + 1
	stateLen := (2*n + 7) / 8
	if o+stateLen > len(rec) {
		return nil
	}
	state := rec[o : o+stateLen]
	o += stateLen
	toc := make([][]byte, n)
	for i, p := range layout {
		s := wmiTypeSize(p)
		if o+s > len(rec) {
			return nil
		}
		toc[i] = rec[o : o+s]
		o += s
	}
	if o+4 > len(rec) {
		return nil
	}
	qs := int(le.Uint32(rec[o:]))
	if qs < 4 || o+qs+1 > len(rec) {
		return nil
	}
	o += qs
	if rec[o] != 1 {
		return nil // dynamic properties: not read
	}
	o++
	if o+4 > len(rec) {
		return nil
	}
	ds := int(le.Uint32(rec[o:]) & 0x7FFFFFFF)
	if o+4+ds > len(rec) {
		return nil
	}
	region := rec[o+4 : o+4+ds]
	if name, ok := wmiStr(region, 0); !ok || name != class {
		return nil
	}
	out := map[string]any{}
	for i, p := range layout {
		st := state[i/4] >> (2 * (i % 4)) & 3
		if st&1 != 0 || st&2 != 0 {
			continue // not set, or the class's default
		}
		if !p.array {
			v, ok := wmiScalar(p, toc[i], region)
			if !ok {
				return nil
			}
			out[p.name] = v
			continue
		}
		ref := int(le.Uint32(toc[i]))
		if ref+4 > len(region) {
			return nil
		}
		count := int(le.Uint32(region[ref:]))
		elem := wmiTypeSize(wmiProp{typ: p.typ})
		if count > 4096 || ref+4+count*elem > len(region) {
			return nil
		}
		items := make([]any, 0, count)
		for k := 0; k < count; k++ {
			v, ok := wmiScalar(wmiProp{typ: p.typ}, region[ref+4+k*elem:ref+4+(k+1)*elem], region)
			if !ok {
				return nil
			}
			items = append(items, v)
		}
		out[p.name] = items
	}
	return out
}
