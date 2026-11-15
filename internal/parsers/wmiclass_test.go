package parsers

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

type testProp struct {
	name  string
	typ   byte
	array bool
	index int
}

func wmiString(b *bytes.Buffer, s string) uint32 {
	at := uint32(b.Len())
	b.WriteByte(0)
	b.WriteString(s)
	b.WriteByte(0)
	return at
}

// wmiClassDef builds a class definition as python-cim describes it and a
// real Windows 11 repository holds it.
func wmiClassDef(name, super string, props []testProp) []byte {
	le := binary.LittleEndian
	var pd bytes.Buffer
	pd.WriteByte(0xEE) // offsets are never 0 in a real definition
	nameAt := wmiString(&pd, name)
	var refs []uint32
	for _, p := range props {
		n := wmiString(&pd, p.name)
		st := uint32(pd.Len())
		arr := byte(0)
		if p.array {
			arr = 0x20
		}
		pd.Write([]byte{p.typ, arr, 0, 0})
		binary.Write(&pd, le, uint16(p.index))
		binary.Write(&pd, le, uint32(0))
		binary.Write(&pd, le, uint32(2))
		binary.Write(&pd, le, uint32(4)) // an empty qualifier list
		refs = append(refs, n, st)
	}
	var b bytes.Buffer
	u := utf16.Encode([]rune(super))
	binary.Write(&b, le, uint32(len(u)))
	for _, c := range u {
		binary.Write(&b, le, c)
	}
	binary.Write(&b, le, filetime("2019-12-07T09:00:00Z"))
	binary.Write(&b, le, uint32(0))
	b.WriteByte(0)
	binary.Write(&b, le, nameAt)
	binary.Write(&b, le, uint32(3)) // default values
	if super == "" {
		binary.Write(&b, le, uint32(4))
	} else {
		binary.Write(&b, le, uint32(len(super)+8))
		b.WriteByte(0)
		b.WriteString(super)
		b.WriteByte(0)
		binary.Write(&b, le, uint32(len(super)))
	}
	binary.Write(&b, le, uint32(4)) // class qualifiers: none
	binary.Write(&b, le, uint32(len(props)))
	for _, r := range refs {
		binary.Write(&b, le, r)
	}
	b.Write([]byte{0, 0, 0})
	binary.Write(&b, le, uint32(pd.Len()))
	b.Write(pd.Bytes())
	binary.Write(&b, le, uint32(0)) // methods
	return b.Bytes()
}

// wmiTypedInstance builds an instance record whose values sit in a table
// in property order, as ClassInstance in python-cim reads it. values maps
// a property's index to its value; a missing index is left at the default.
func wmiTypedInstance(class, written string, layout []testProp, values map[int]any) []byte {
	le := binary.LittleEndian
	var data bytes.Buffer
	wmiString(&data, class)
	state := make([]byte, (2*len(layout)+7)/8)
	var toc bytes.Buffer
	for i, p := range layout {
		v, set := values[i]
		if !set {
			state[i/4] |= 2 << (2 * (i % 4)) // the class default
		}
		switch {
		case p.array:
			at := uint32(data.Len())
			items, _ := v.([]byte)
			binary.Write(&data, le, uint32(len(items)))
			data.Write(items)
			binary.Write(&toc, le, at)
		case p.typ == 0x08 || p.typ == 0x66:
			var at uint32
			if s, ok := v.(string); ok {
				at = wmiString(&data, s)
			}
			binary.Write(&toc, le, at)
		case p.typ == 0x0B:
			b, _ := v.(bool)
			x := uint16(0)
			if b {
				x = 0xFFFF
			}
			binary.Write(&toc, le, x)
		default:
			n, _ := v.(uint32)
			binary.Write(&toc, le, n)
		}
	}
	var rec bytes.Buffer
	binary.Write(&rec, le, uint32(0)) // offset of the class name
	rec.WriteByte(0)
	rec.Write(state)
	rec.Write(toc.Bytes())
	binary.Write(&rec, le, uint32(4)) // qualifiers: none
	rec.WriteByte(1)                  // no dynamic properties
	binary.Write(&rec, le, uint32(data.Len())|0x80000000)
	rec.Write(data.Bytes())

	var out bytes.Buffer
	sum := sha256.Sum256([]byte(strings.ToUpper(class)))
	for _, c := range fmt.Sprintf("%X", sum[:]) {
		out.Write([]byte{byte(c), 0})
	}
	binary.Write(&out, le, filetime(written))
	binary.Write(&out, le, filetime("2019-12-07T09:00:00Z"))
	binary.Write(&out, le, uint32(rec.Len()+4))
	out.Write(rec.Bytes())
	return out.Bytes()
}

func TestWMIValuesNamedFromClassDefinitions(t *testing.T) {
	base := []testProp{{"MachineName", 0x08, false, 0}, {"MaximumQueueSize", 0x13, false, 1}, {"CreatorSID", 0x11, true, 2}}
	own := []testProp{{"Name", 0x08, false, 3}, {"ExecutablePath", 0x08, false, 4}, {"CommandLineTemplate", 0x08, false, 5}, {"KillTimeout", 0x13, false, 6}}
	layout := append(append([]testProp{}, base...), own...)
	inst := wmiTypedInstance("CommandLineEventConsumer", "2024-05-05T03:00:00Z", layout, map[int]any{
		2: []byte{1, 2, 0, 0, 0, 0, 0, 5}, 3: "Updater", 5: `powershell.exe -nop -enc SQBFAFgA`,
	})
	// An older version of the class, without Name, is in the file too: it
	// does not fit the instance and is passed over.
	old := wmiClassDef("CommandLineEventConsumer", "__EventConsumer", []testProp{{"ExecutablePath", 0x08, false, 3}, {"CommandLineTemplate", 0x08, false, 4}})
	repo := wmiRepo(
		wmiClassDef("__IndicationRelated", "__SystemClass", nil),
		wmiClassDef("__EventConsumer", "__IndicationRelated", base),
		old,
		wmiClassDef("CommandLineEventConsumer", "__EventConsumer", own),
		inst,
	)
	r := run(t, write(t, "OBJECTS.DATA", repo), nil)
	if r.err != nil || len(r.warns) != 0 || len(r.events) != 1 {
		t.Fatalf("%v %v %d", r.err, r.warns, len(r.events))
	}
	e := r.events[0]
	p, _ := e.Fields["properties"].(map[string]any)
	if p == nil || p["Name"] != "Updater" || p["CommandLineTemplate"] != `powershell.exe -nop -enc SQBFAFgA` || e.Fields["name"] != "Updater" {
		t.Fatalf("properties: %+v", e.Fields)
	}
	if sid, _ := p["CreatorSID"].([]any); len(sid) != 8 || sid[7] != uint8(5) {
		t.Errorf("an array: %#v", p["CreatorSID"])
	}
	if _, set := p["KillTimeout"]; set {
		t.Error("a property left at the class default was given a value")
	}
	if e.Fields["values"] != nil || !strings.Contains(e.Message, "CommandLineTemplate=powershell.exe -nop -enc SQBFAFgA") {
		t.Errorf("message %q fields %+v", e.Message, e.Fields)
	}
	if !strings.Contains(strings.Join(r.notes, " "), "1 of 1 subscription records had their values named") {
		t.Errorf("notes: %v", r.notes)
	}

	// Without the class definitions the values are still given, unnamed.
	r = run(t, write(t, "OBJECTS.DATA", wmiRepo(inst)), nil)
	if len(r.events) != 1 || r.events[0].Fields["properties"] != nil || r.events[0].Fields["values"] == nil {
		t.Errorf("without definitions: %+v", r.events)
	}
}
