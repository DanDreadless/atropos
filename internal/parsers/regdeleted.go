package parsers

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Deleted keys and values. When Windows deletes a key or a value, or
// rewrites one somewhere else in the hive, the cell it occupied is marked
// unallocated and its bytes stay until something reuses the space. Adjacent
// unallocated cells are merged, so one unallocated cell can hold several
// old records. This walks every cell of every hive bin itself (the parsing
// library does not expose cells) and recovers what still parses as a key
// node (nk) or a key value (vk).
//
// Layouts are from Maxim Suhanov's "Windows registry file format
// specification"; expected results from yarp's test hives.

const (
	maxRecoveredKeys = 200000
	maxHbinSize      = 64 << 20
	maxValueShown    = 400
)

type cellNK struct {
	off      uint32 // of the cell, relative to the hive bins
	name     string
	parent   uint32
	written  uint64
	subkeys  uint32
	values   uint32
	valueOff uint32
	flags    uint16
}

type cellVK struct {
	off   uint32
	name  string
	typ   uint32
	data  string
	inUse bool // referenced by a recovered key's values list
}

type hiveCells struct {
	r       io.ReaderAt
	size    int64
	minor   uint32
	live    map[uint32]cellNK
	dead    map[uint32]cellNK
	deadVK  map[uint32]*cellVK
	root    uint32
	bins    int
	stopped string
}

// readCell returns the data of the cell at a hive-bins-relative offset,
// without its size field, whether it is allocated or not.
func (h *hiveCells) readCell(off uint32, limit int) []byte {
	if off == 0xFFFFFFFF {
		return nil
	}
	at := int64(off) + 4096
	var sz [4]byte
	if n, _ := h.r.ReadAt(sz[:], at); n < 4 || at+4 > h.size {
		return nil
	}
	n := int64(int32(binary.LittleEndian.Uint32(sz[:])))
	if n < 0 {
		n = -n
	}
	if n < 8 || at+n > h.size {
		return nil
	}
	n -= 4
	if limit > 0 && n > int64(limit) {
		n = int64(limit)
	}
	b := make([]byte, n)
	k, _ := h.r.ReadAt(b, at+4)
	return b[:k]
}

func regName(b []byte, compressed bool) string {
	if compressed {
		return storedName(string(b), true)
	}
	return storedName(string(b), false)
}

// parseNK reads a key node from cell data (after the size field).
func parseNK(d []byte) (cellNK, bool) {
	le := binary.LittleEndian
	if len(d) < 76 || d[0] != 'n' || d[1] != 'k' {
		return cellNK{}, false
	}
	k := cellNK{flags: le.Uint16(d[2:]), written: le.Uint64(d[4:]), parent: le.Uint32(d[16:]),
		subkeys: le.Uint32(d[20:]), values: le.Uint32(d[36:]), valueOff: le.Uint32(d[40:])}
	nl := int(le.Uint16(d[72:]))
	if nl == 0 || 76+nl > len(d) || k.subkeys > 1<<20 || k.values > 1<<20 {
		return cellNK{}, false
	}
	k.name = regName(d[76:76+nl], k.flags&0x20 != 0)
	if strings.ContainsAny(k.name, "\\\x00") {
		return cellNK{}, false
	}
	return k, true
}

// walk reads every hive bin: live key nodes, and every key node and value
// left in unallocated space.
func (h *hiveCells) walk(hbinsSize uint32) {
	end := int64(4096) + int64(hbinsSize)
	if end > h.size {
		end = h.size
	}
	for at := int64(4096); at+32 <= end; {
		var hdr [32]byte
		if n, _ := h.r.ReadAt(hdr[:], at); n < 32 || string(hdr[:4]) != "hbin" {
			h.stopped = fmt.Sprintf("no hive bin at offset %#x", at)
			h.tail(at)
			return
		}
		size := int64(binary.LittleEndian.Uint32(hdr[8:]))
		if size < 4096 || size%4096 != 0 || size > maxHbinSize || at+size > end {
			h.stopped = fmt.Sprintf("the hive bin at offset %#x has an impossible size", at)
			return
		}
		bin := make([]byte, size)
		if n, _ := h.r.ReadAt(bin, at); int64(n) < size {
			h.stopped = fmt.Sprintf("the hive bin at offset %#x is cut short", at)
			return
		}
		h.bins++
		h.cells(bin, uint32(at-4096))
		at += size
	}
	h.tail(end)
}

// tail looks through the file after the last hive bin. A hive that shrank
// leaves its old bins there, and with them old records, sometimes without
// the cell around them.
func (h *hiveCells) tail(from int64) {
	to := h.size
	if to-from > maxHbinSize {
		to = from + maxHbinSize
	}
	if to-from < 24 {
		return
	}
	b := make([]byte, to-from)
	n, _ := h.r.ReadAt(b, from)
	b = b[:n]
	for s := 0; s+6 <= len(b); s += 4 {
		sig := string(b[s : s+2])
		if sig != "nk" && sig != "vk" {
			continue
		}
		end := len(b)
		if end-s > 1<<16 {
			end = s + 1<<16
		}
		off := uint32(from - 4096 + int64(s) - 4) // where its cell would begin
		if sig == "nk" {
			if k, ok := parseNK(b[s:end]); ok && len(h.dead) < maxRecoveredKeys {
				k.off = off
				h.dead[off] = k
			}
		} else if v, ok := h.parseVK(b[s:end]); ok {
			v.off = off
			h.deadVK[off] = &v
		}
	}
}

func (h *hiveCells) cells(bin []byte, base uint32) {
	le := binary.LittleEndian
	for p := 32; p+8 <= len(bin); {
		raw := int32(le.Uint32(bin[p:]))
		n := int(raw)
		if n < 0 {
			n = -n
		}
		if n < 8 || n%8 != 0 || p+n > len(bin) {
			return // the rest of this bin is not cells
		}
		if raw < 0 {
			if k, ok := parseNK(bin[p+4 : p+n]); ok {
				k.off = base + uint32(p)
				h.live[k.off] = k
			}
		} else {
			h.remnants(bin[p:p+n], base+uint32(p))
		}
		p += n
	}
}

// remnants looks through one unallocated cell for old records, at every
// 8-byte boundary: merged cells keep their records where they were.
func (h *hiveCells) remnants(free []byte, base uint32) {
	le := binary.LittleEndian
	for q := 0; q+8 <= len(free); q += 8 {
		sig := string(free[q+4 : q+6])
		if sig != "nk" && sig != "vk" {
			continue
		}
		// The first record's size is the merged cell's; any other keeps its own old (allocated) size.
		n := int(int32(le.Uint32(free[q:])))
		if n < 0 {
			n = -n
		}
		if q == 0 || n < 8 || q+n > len(free) {
			n = len(free) - q
		}
		d := free[q+4 : q+n]
		off := base + uint32(q)
		if sig == "nk" {
			if k, ok := parseNK(d); ok && len(h.dead) < maxRecoveredKeys {
				k.off = off
				h.dead[off] = k
			}
		} else if v, ok := h.parseVK(d); ok {
			v.off = off
			h.deadVK[off] = &v
		}
	}
}

// parseVK reads a key value and its data, where the data can still be found.
func (h *hiveCells) parseVK(d []byte) (cellVK, bool) {
	le := binary.LittleEndian
	if len(d) < 20 || d[0] != 'v' || d[1] != 'k' {
		return cellVK{}, false
	}
	nl := int(le.Uint16(d[2:]))
	size, dataOff := le.Uint32(d[4:]), le.Uint32(d[8:])
	v := cellVK{typ: le.Uint32(d[12:])}
	flags := le.Uint16(d[16:])
	if 20+nl > len(d) || flags&^3 != 0 || v.typ > 0xFFFF && v.typ != 0xFFFF0010 {
		return cellVK{}, false
	}
	v.name = regName(d[20:20+nl], flags&1 != 0)
	var data []byte
	switch {
	case size&0x80000000 != 0:
		n := size &^ 0x80000000
		if n > 4 {
			return cellVK{}, false
		}
		data = d[8 : 8+n]
	case size == 0:
	case size > 64<<20:
		return cellVK{}, false
	default:
		cell := h.readCell(dataOff, 0)
		if h.minor > 3 && size > 16344 && len(cell) >= 8 && cell[0] == 'd' && cell[1] == 'b' {
			cell = h.bigData(cell, size)
		}
		if uint32(len(cell)) >= size {
			data = cell[:size]
		} else {
			data = cell // what is left of it
		}
	}
	v.data = valueText(v.typ, data)
	return v, true
}

func (h *hiveCells) bigData(db []byte, size uint32) []byte {
	le := binary.LittleEndian
	count := int(le.Uint16(db[2:]))
	list := h.readCell(le.Uint32(db[4:]), count*4)
	var out []byte
	for i := 0; i+4 <= len(list) && uint32(len(out)) < size && i < count*4; i += 4 {
		out = append(out, h.readCell(le.Uint32(list[i:]), 16344)...)
	}
	return out
}

// valueText renders value data for the examiner.
func valueText(typ uint32, d []byte) string {
	le := binary.LittleEndian
	switch typ {
	case 1, 2, 6, 7:
		u := make([]uint16, 0, len(d)/2)
		for i := 0; i+1 < len(d); i += 2 {
			u = append(u, le.Uint16(d[i:]))
		}
		s := string(utf16.Decode(u))
		if typ == 7 {
			s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == 0 }), "; ")
		}
		return clean(strings.TrimRight(s, "\x00"))
	case 4:
		if len(d) >= 4 {
			return fmt.Sprint(le.Uint32(d))
		}
	case 5:
		if len(d) >= 4 {
			return fmt.Sprint(binary.BigEndian.Uint32(d))
		}
	case 11:
		if len(d) >= 8 {
			return fmt.Sprint(le.Uint64(d))
		}
	}
	if len(d) > 64 {
		return fmt.Sprintf("%x… (%d bytes)", d[:64], len(d))
	}
	return fmt.Sprintf("%x", d)
}

var regTypes = map[uint32]string{0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
	6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}

// path builds a key's path from its parents, as far as they can be traced.
// complete is false when a parent is gone.
func (h *hiveCells) path(k cellNK) (string, bool) {
	parts := []string{k.name}
	seen := map[uint32]bool{k.off: true}
	for p := k.parent; len(parts) < 512; {
		if p == h.root {
			break
		}
		next, ok := h.live[p]
		if !ok {
			next, ok = h.dead[p]
		}
		if !ok || seen[p] {
			return strings.Join(reverse(parts), `\`), false
		}
		seen[p] = true
		parts = append(parts, next.name)
		p = next.parent
	}
	return `\` + strings.Join(reverse(parts), `\`), true
}

func reverse(s []string) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[len(s)-1-i] = x
	}
	return out
}

// recoverDeleted emits each key recovered from unallocated space, with its
// values where they survive, and lists values whose key is gone.
func recoverDeleted(ctx *Context, r io.ReaderAt, size int64, host, kind string) error {
	head := make([]byte, 4096)
	if n, _ := r.ReadAt(head, 0); n < 4096 {
		return nil
	}
	le := binary.LittleEndian
	h := &hiveCells{r: r, size: size, minor: le.Uint32(head[24:]), root: le.Uint32(head[36:]),
		live: map[uint32]cellNK{}, dead: map[uint32]cellNK{}, deadVK: map[uint32]*cellVK{}}
	h.walk(le.Uint32(head[40:]))
	if h.stopped != "" {
		ctx.Note("looking for deleted keys, the walk of the hive's cells stopped early: %s", h.stopped)
	}
	livePaths := map[string]bool{}
	for _, k := range h.live {
		if p, ok := h.path(k); ok {
			livePaths[strings.ToLower(p)] = true
		}
	}
	offs := make([]uint32, 0, len(h.dead))
	for o := range h.dead {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	deleted, earlier, values := 0, 0, 0
	for _, o := range offs {
		k := h.dead[o]
		stamp, ok := timeutil.FromFiletime(k.written)
		if !ok {
			continue
		}
		path, complete := h.path(k)
		var vals []string
		if k.values > 0 && k.values < 10000 {
			list := h.readCell(k.valueOff, int(k.values)*4)
			for i := 0; i+4 <= len(list) && len(vals) < 50; i += 4 {
				vo := le.Uint32(list[i:])
				var v *cellVK
				if dv, ok := h.deadVK[vo]; ok {
					v = dv
				} else if c := h.readCell(vo, 1<<16); c != nil {
					if pv, ok := h.parseVK(c); ok {
						v = &pv
					}
				}
				if v == nil {
					continue
				}
				v.inUse = true
				name := v.name
				if name == "" {
					name = "(Default)"
				}
				vals = append(vals, fmt.Sprintf("%s = %s (%s)", name, trunc(v.data, maxValueShown), regTypeName(v.typ)))
			}
		}
		fields := map[string]any{"hive": kind, "key": path, "name": k.name, "path_complete": complete,
			"recovered_from": fmt.Sprintf("unallocated cell at hive offset %#x", int64(o)+4096),
			"time_meaning":   "when the key was last written before its cell was freed, not when it was deleted"}
		if k.subkeys > 0 {
			fields["subkeys_recorded"] = k.subkeys
		}
		if len(vals) > 0 {
			fields["values"] = vals
		}
		typ, what := "registry-key-deleted (last written)", "Deleted key"
		if complete && livePaths[strings.ToLower(path)] {
			// The key still exists: this is the cell of an earlier version of it.
			typ, what = "registry-key-earlier-version (last written)", "Earlier version of key"
			fields["earlier_version"] = true
			earlier++
		} else {
			fields["deleted"] = true
			deleted++
		}
		shown := path
		if !complete {
			shown = `…\` + path
		}
		msg := fmt.Sprintf("%s, recovered from unallocated space: %s", what, shown)
		if len(vals) > 0 {
			msg += fmt.Sprintf(" [%d value(s): %s]", len(vals), trunc(strings.Join(vals, "; "), 600))
		}
		if err := ctx.Emit(Event{Stamp: stamp, Type: typ, Category: CatRegistry, Source: "registry", Host: host, Path: shown,
			Message: msg, Fields: fields, Ref: fmt.Sprintf("unallocated cell at hive offset %#x", int64(o)+4096)}); err != nil {
			return err
		}
	}
	// Values whose key is gone have no time of their own: they are text.
	var loose []string
	voffs := make([]uint32, 0, len(h.deadVK))
	for o, v := range h.deadVK {
		if !v.inUse {
			voffs = append(voffs, o)
		}
	}
	sort.Slice(voffs, func(i, j int) bool { return voffs[i] < voffs[j] })
	for _, o := range voffs {
		v := h.deadVK[o]
		name := v.name
		if name == "" {
			name = "(Default)"
		}
		loose = append(loose, fmt.Sprintf("offset %#x: %s = %s (%s)", int64(o)+4096, name, trunc(v.data, maxValueShown), regTypeName(v.typ)))
		values++
	}
	if len(h.dead) >= maxRecoveredKeys {
		ctx.Warn("more than %d key records were found in unallocated space; the rest were not recovered", maxRecoveredKeys)
	}
	ctx.Fact("registry.deleted_keys", fmt.Sprint(deleted), "keys recovered from unallocated space that no longer exist in the hive")
	ctx.Fact("registry.earlier_key_versions", fmt.Sprint(earlier), "earlier copies of keys that still exist, recovered from unallocated space")
	ctx.Fact("registry.deleted_values", fmt.Sprint(values), "values recovered from unallocated space whose key could not be found")
	if len(loose) > 0 {
		body := "Values recovered from unallocated space in the hive, whose key could not be found. They have no time of their own.\n" + strings.Join(loose, "\n")
		ctx.Text("deleted registry values", len(body) > maxText, trunc(body, maxText))
	}
	if deleted+earlier+values > 0 {
		ctx.Note("from unallocated space in the hive: %d deleted keys, %d earlier versions of keys that still exist, and %d values whose key is gone (indexed as text). A recovered key's time is when it was last written before it was freed, not when it was deleted", deleted, earlier, values)
	}
	return nil
}

func regTypeName(t uint32) string {
	if n, ok := regTypes[t]; ok {
		return n
	}
	return fmt.Sprintf("type %#x", t)
}

// valueSlack returns the bytes of the registry cells holding a value's data
// that lie beyond the data: space left from when the value was longer.
// vkOff is the file offset the parsing library gives for the value.
func valueSlack(r io.ReaderAt, size int64, vkOff int64) []byte {
	if r == nil {
		return nil
	}
	head := make([]byte, 28)
	if n, _ := r.ReadAt(head, 0); n < 28 {
		return nil
	}
	h := &hiveCells{r: r, size: size, minor: binary.LittleEndian.Uint32(head[24:])}
	// The library's offset is that of the record; its cell begins four bytes before.
	var sig [2]byte
	r.ReadAt(sig[:], vkOff)
	cell := vkOff - 4
	if string(sig[:]) != "vk" {
		r.ReadAt(sig[:], vkOff+4)
		if string(sig[:]) != "vk" {
			return nil
		}
		cell = vkOff
	}
	if cell < 4096 {
		return nil
	}
	vk := h.readCell(uint32(cell-4096), 20)
	if len(vk) < 12 {
		return nil
	}
	le := binary.LittleEndian
	dsize, doff := le.Uint32(vk[4:]), le.Uint32(vk[8:])
	if dsize&0x80000000 != 0 || dsize == 0 {
		return nil
	}
	data := h.readCell(doff, 0)
	if h.minor > 3 && dsize > 16344 && len(data) >= 8 && data[0] == 'd' && data[1] == 'b' {
		count := int(le.Uint16(data[2:]))
		list := h.readCell(le.Uint32(data[4:]), count*4)
		var out []byte
		left := int64(dsize)
		for i := 0; i+4 <= len(list) && i < count*4; i += 4 {
			seg := h.readCell(le.Uint32(list[i:]), 0)
			used := int64(16344)
			if left < used {
				used = left
			}
			if used < int64(len(seg)) {
				out = append(out, seg[used:]...)
			}
			left -= used
		}
		return out
	}
	if int64(len(data)) > int64(dsize) {
		return data[dsize:]
	}
	return nil
}
