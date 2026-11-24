// Package artw writes small Windows artefacts for test data: a registry hive
// and an automatic jump list, as Windows lays them out. Like evtxw it exists
// so a made-up story can be told across a case's hosts and read back by the
// real parsers; nothing here is used when reading evidence.
package artw

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Registry value types.
const (
	RegSZ     = 1
	RegBinary = 3
	RegDWORD  = 4
)

// Key is a registry key with its values and subkeys.
type Key struct {
	Name    string
	Written time.Time // the key's last-write time
	Values  []Value
	Subkeys []*Key
}

// Value is one registry value.
type Value struct {
	Name string
	Type uint32
	Data []byte
}

// SZ is a string value.
func SZ(name, s string) Value {
	u := utf16.Encode([]rune(s + "\x00"))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return Value{name, RegSZ, b}
}

// DWORD is a 32-bit number value.
func DWORD(name string, v uint32) Value {
	return Value{name, RegDWORD, binary.LittleEndian.AppendUint32(nil, v)}
}

// Path returns the key at the backslash-separated path below k, made where
// missing, each new key written at t.
func (k *Key) Path(path string, t time.Time) *Key {
	cur := k
next:
	for _, name := range strings.Split(strings.Trim(path, `\`), `\`) {
		if name == "" {
			continue
		}
		for _, sk := range cur.Subkeys {
			if strings.EqualFold(sk.Name, name) {
				cur = sk
				continue next
			}
		}
		nk := &Key{Name: name, Written: t}
		cur.Subkeys = append(cur.Subkeys, nk)
		cur = nk
	}
	return cur
}

func filetime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func ascii(s string) bool {
	for _, r := range s {
		if r >= 0x80 {
			return false
		}
	}
	return true
}

// name is a key or value name as stored: ASCII when it can be (the
// "compressed" flag), else UTF-16.
func name(s string) ([]byte, bool) {
	if ascii(s) {
		return []byte(s), true
	}
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b, false
}

// Hive lays out a hive whose root key is root: a base block and one hive
// bin holding every cell, with a shared security cell and subkey lists in
// "lf" form, sorted as Windows sorts them.
func Hive(root *Key, fileName string, written time.Time) ([]byte, error) {
	le := binary.LittleEndian
	var bin []byte // cells, from offset 0x20 of the first bin
	bin = make([]byte, 0x20)
	alloc := func(data []byte) uint32 {
		off := uint32(len(bin))
		size := (4 + len(data) + 7) &^ 7
		cell := make([]byte, size)
		le.PutUint32(cell, uint32(-int32(size)))
		copy(cell[4:], data)
		bin = append(bin, cell...)
		return off
	}
	// One security descriptor for every key: self-relative, with no owner,
	// group or lists. Its cell is linked to itself, and comes right after
	// the root key: the root is the first cell, as Windows writes it, and
	// some readers (regipy) take the first cell as the root.
	sd := []byte{1, 0, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	skData := make([]byte, 20+len(sd))
	copy(skData, "sk")
	le.PutUint32(skData[16:], uint32(len(sd)))
	copy(skData[20:], sd)
	var sk uint32
	refs := uint32(0)

	var emit func(k *Key, parent uint32, isRoot bool) (uint32, error)
	emit = func(k *Key, parent uint32, isRoot bool) (uint32, error) {
		if k.Name == "" {
			return 0, errors.New("a key needs a name")
		}
		nb, comp := name(k.Name)
		nk := make([]byte, 76+len(nb))
		copy(nk, "nk")
		flags := uint16(0)
		if comp {
			flags |= 0x20
		}
		if isRoot {
			flags |= 0x04 | 0x08
		}
		le.PutUint16(nk[2:], flags)
		le.PutUint64(nk[4:], filetime(k.Written))
		le.PutUint32(nk[16:], parent)
		le.PutUint32(nk[28:], 0xFFFFFFFF)
		le.PutUint32(nk[32:], 0xFFFFFFFF)
		le.PutUint32(nk[40:], 0xFFFFFFFF)
		le.PutUint32(nk[48:], 0xFFFFFFFF)
		le.PutUint16(nk[72:], uint16(len(nb)))
		copy(nk[76:], nb)
		off := alloc(nk)
		if sk == 0 {
			sk = alloc(skData)
		}
		le.PutUint32(bin[off+4+44:], sk)
		refs++
		at := func(field int) []byte { return bin[off+4+uint32(field):] }

		subs := append([]*Key(nil), k.Subkeys...)
		sort.SliceStable(subs, func(a, b int) bool { return strings.ToUpper(subs[a].Name) < strings.ToUpper(subs[b].Name) })
		var children []uint32
		maxName := 0
		for _, sk := range subs {
			c, err := emit(sk, off, false)
			if err != nil {
				return 0, err
			}
			children = append(children, c)
			if n := len(utf16.Encode([]rune(sk.Name))) * 2; n > maxName {
				maxName = n
			}
		}
		if len(children) > 0 {
			lf := make([]byte, 4+8*len(children))
			copy(lf, "lf")
			le.PutUint16(lf[2:], uint16(len(children)))
			for i, c := range children {
				le.PutUint32(lf[4+8*i:], c)
				hint := []byte(subs[i].Name)
				if len(hint) > 4 {
					hint = hint[:4]
				}
				copy(lf[8+8*i:], hint)
			}
			lo := alloc(lf)
			le.PutUint32(at(20), uint32(len(children)))
			le.PutUint32(at(28), lo)
			le.PutUint32(at(52), uint32(maxName))
		}
		if len(k.Values) > 0 {
			list := make([]byte, 4*len(k.Values))
			maxVName, maxData := 0, 0
			for i, v := range k.Values {
				vb, vcomp := name(v.Name)
				vk := make([]byte, 20+len(vb))
				copy(vk, "vk")
				le.PutUint16(vk[2:], uint16(len(vb)))
				if len(v.Data) <= 4 {
					le.PutUint32(vk[4:], uint32(len(v.Data))|0x80000000)
					copy(vk[8:12], v.Data)
				} else {
					le.PutUint32(vk[4:], uint32(len(v.Data)))
					le.PutUint32(vk[8:], alloc(v.Data))
				}
				le.PutUint32(vk[12:], v.Type)
				if vcomp && v.Name != "" {
					le.PutUint16(vk[16:], 1)
				}
				copy(vk[20:], vb)
				le.PutUint32(list[4*i:], alloc(vk))
				if n := len(utf16.Encode([]rune(v.Name))) * 2; n > maxVName {
					maxVName = n
				}
				if len(v.Data) > maxData {
					maxData = len(v.Data)
				}
			}
			lo := alloc(list)
			le.PutUint32(at(36), uint32(len(k.Values)))
			le.PutUint32(at(40), lo)
			le.PutUint32(at(60), uint32(maxVName))
			le.PutUint32(at(64), uint32(maxData))
		}
		return off, nil
	}
	rootOff, err := emit(root, 0xFFFFFFFF, true)
	if err != nil {
		return nil, err
	}
	// The security cell: linked to itself, used by every key.
	le.PutUint32(bin[sk+4+4:], sk)
	le.PutUint32(bin[sk+4+8:], sk)
	le.PutUint32(bin[sk+4+12:], refs)

	// The rest of the bin is one free cell.
	size := (len(bin) + 4095) &^ 4095
	if size-len(bin) < 8 {
		size += 4096
	}
	free := size - len(bin)
	bin = append(bin, make([]byte, free)...)
	le.PutUint32(bin[size-free:], uint32(free))
	copy(bin, "hbin")
	le.PutUint32(bin[8:], uint32(size))
	le.PutUint64(bin[20:], filetime(written))

	base := make([]byte, 4096)
	copy(base, "regf")
	le.PutUint32(base[4:], 1)
	le.PutUint32(base[8:], 1)
	le.PutUint64(base[12:], filetime(written))
	le.PutUint32(base[20:], 1)
	le.PutUint32(base[24:], 5)
	le.PutUint32(base[32:], 1)
	le.PutUint32(base[36:], rootOff)
	le.PutUint32(base[40:], uint32(size))
	le.PutUint32(base[44:], 1)
	fn := utf16.Encode([]rune(fileName))
	if len(fn) > 31 {
		fn = fn[len(fn)-31:]
	}
	for i, c := range fn {
		le.PutUint16(base[48+2*i:], c)
	}
	var sum uint32
	for i := 0; i < 127; i++ {
		sum ^= le.Uint32(base[4*i:])
	}
	switch sum {
	case 0:
		sum = 1
	case 0xFFFFFFFF:
		sum = 0xFFFFFFFE
	}
	le.PutUint32(base[508:], sum)
	return append(base, bin...), nil
}
