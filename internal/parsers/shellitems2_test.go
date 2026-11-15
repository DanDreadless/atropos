package parsers

import (
	"encoding/binary"
	"testing"
)

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// item builds a shell item: its size, then the bytes given.
func item(body ...[]byte) []byte {
	var b []byte
	for _, x := range body {
		b = append(b, x...)
	}
	return append(binary.LittleEndian.AppendUint16(nil, uint16(len(b)+2)), b...)
}

func at(n int, parts map[int][]byte) []byte {
	b := make([]byte, n)
	for off, p := range parts {
		copy(b[off:], p)
	}
	return b
}

func TestSignedShellItems(t *testing.T) {
	name := wide("Pixel Test")
	cases := []struct {
		raw        []byte
		kind, name string
	}{
		// A phone: its name's length in characters (with the terminator) at 0x1E, the name at 0x28.
		{at(0x28+len(name)+2, map[int][]byte{2: {0x2E}, 6: le32(sigMTPDevice), 0x1E: le32(11), 0x28: name}), "portable device", "Pixel Test"},
		// Its storage: the length at 0x26, the name at 0x36.
		{at(0x36+len(wide("Internal"))+2, map[int][]byte{6: le32(sigMTPStorage), 0x26: le32(9), 0x36: wide("Internal")}), "portable device storage", "Internal"},
		// A folder on it: two names and an identifier from 0x4A; the second name is shown.
		{at(0x4A+2*5+2*6+2*3, map[int][]byte{6: le32(sigMTPFolder), 0x3E: le32(5), 0x42: le32(6), 0x46: le32(3), 0x4A: append(wide("DCIM"), append([]byte{0, 0}, wide("Photo")...)...)}), "portable device folder", "Photo"},
		// A OneDrive folder: its name, URL-escaped, as text at 0x18.
		{at(0x18+len(wide("My%20Docs"))+2, map[int][]byte{4: le32(sigWebFolder), 0x14: le32(uint32(len(wide("My%20Docs")))), 0x18: wide("My%20Docs")}), "web folder (OneDrive or SharePoint)", "My Docs"},
		// A Control Panel category.
		{at(14, map[int][]byte{0: {12}, 2: {0x01}, 4: le32(sigCPCategory), 8: le32(3)}), "control panel category", "Network and Internet"},
	}
	for _, c := range cases {
		it := parseShellItem(c.raw)
		if it.kind != c.kind || it.name != c.name {
			t.Errorf("got %q %q, want %q %q", it.kind, it.name, c.kind, c.name)
		}
	}
}

// A property store with System.ItemNameDisplay (property 10 of b725f130-…).
func propertyStore(name string) []byte {
	var rec []byte
	v := append([]byte{0x1F, 0, 0, 0}, le32(uint32(len([]rune(name))+1))...)
	v = append(v, wide(name)...)
	v = append(v, 0, 0)
	rec = append(le32(uint32(9+len(v))), le32(10)...)
	rec = append(rec, 0)
	rec = append(rec, v...)
	set := append([]byte("1SPS"), 0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC)
	set = append(set, rec...)
	set = append(set, 0, 0, 0, 0)
	return append(append(le32(uint32(len(set)+4)), set...), 0, 0, 0, 0)
}

func TestPropertyViewItems(t *testing.T) {
	store := propertyStore("Search Results in Pictures")
	body := append([]byte{0x1F, 0x00, 0, 0}, le32(0x23A3DFD5)...)
	body = append(body, byte(len(store)), byte(len(store)>>8), 4, 0, 0, 0, 0, 0)
	body = append(body, store...)
	if it := parseShellItem(item(body)); it.kind != "property view" || it.name != "Search Results in Pictures" {
		t.Errorf("property view: %q %q", it.kind, it.name)
	}
	// A known folder named by its identifier, with no property store.
	kf := append([]byte{0x00, 0x00, 0, 0}, le32(0x23FEBBEE)...)
	kf = append(kf, 0, 0, 16, 0)
	kf = append(kf, 0x3a, 0xcc, 0xbf, 0xb4, 0x2c, 0xdb, 0x4c, 0x42, 0xb0, 0x29, 0x7f, 0xe9, 0x9a, 0x87, 0xc6, 0x41) // Desktop
	kf = append(kf, 0, 0, 0, 0, 0, 0)
	if it := parseShellItem(item(kf)); it.kind != "property view" || it.name != "Desktop" {
		t.Errorf("known folder view: %q %q", it.kind, it.name)
	}
	// A drive in a property view: "/" at offset 4, the letter at 13.
	drive := at(0x55, map[int][]byte{0: {0x55}, 2: {0x1F}, 4: {0x2F}, 13: []byte(`E:\`)})
	if it := parseShellItem(drive); it.kind != "volume" || it.name != "E:" {
		t.Errorf("drive: %q %q", it.kind, it.name)
	}
	// Damage: no panic.
	full := item(body)
	for i := range full {
		for _, v := range []byte{0, 0xFF} {
			bad := append([]byte(nil), full...)
			bad[i] = v
			parseShellItem(bad)
		}
		parseShellItem(full[:i])
	}
}
