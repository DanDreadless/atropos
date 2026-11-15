package parsers

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf16"
)

// Shell items recognised by a signature rather than by their type byte:
// portable (MTP) devices, their storage and folders; OneDrive and
// SharePoint folders; Control Panel categories; and "property view" items,
// which name a folder through a property store.
//
// Layouts are from Joachim Metz's "Windows Shell Item format" and "Windows
// Property Store format" (libfwsi, libfwps), and, where those leave a field
// unknown, from the offsets in Eric Zimmerman's ExtensionBlocks library
// (MIT), which SBECmd uses; the results are compared with SBECmd's.

const (
	sigMTPDevice  = 0x08312006
	sigMTPStorage = 0x10312005
	sigMTPFolder  = 0x07192006
	sigWebFolder  = 0xC001B000
	sigCPCategory = 0x39DE2184
)

// Property view data signatures (libfwsi, "users property view data").
var propertyViewSigs = map[uint32]bool{0x23A3DFD5: true, 0x3B93AFBB: true, 0xBEEBEE00: true, 0x23FEBBEE: true, 0x10141981: true, 0x49505241: true}

var controlPanelCategories = []string{"All Control Panel Items", "Appearance and Personalization", "Hardware and Sound",
	"Network and Internet", "Sounds, Speech, and Audio Devices", "System and Security", "Clock, Language, and Region",
	"Ease of Access", "Programs", "User Accounts", "Security Center", "Mobile PC"}

// utf16At reads n UTF-16 characters at off, or "" when they are not all there.
func utf16At(b []byte, off, n int) string {
	if off < 0 || n <= 0 || n > 4096 || off+2*n > len(b) {
		return ""
	}
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		c := binary.LittleEndian.Uint16(b[off+2*i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// signedShellItem names an item recognised by its signature, whatever its type byte.
func signedShellItem(b []byte) (shellItem, bool) {
	le := binary.LittleEndian
	if len(b) < 10 {
		return shellItem{}, false
	}
	u32 := func(off int) int {
		if off+4 > len(b) {
			return -1
		}
		return int(le.Uint32(b[off:]))
	}
	switch le.Uint32(b[6:]) {
	case sigMTPDevice:
		if name := utf16At(b, 0x28, u32(0x1E)); name != "" {
			return shellItem{kind: "portable device", name: name}, true
		}
	case sigMTPStorage:
		if name := utf16At(b, 0x36, u32(0x26)); name != "" {
			return shellItem{kind: "portable device storage", name: name}, true
		}
	case sigMTPFolder:
		// Three strings follow: a name, the name again as shown, and an identifier.
		n1, n2 := u32(0x3E), u32(0x42)
		if n1 >= 0 && n1 <= 4096 {
			if name := utf16At(b, 0x4A+2*n1, n2); name != "" {
				return shellItem{kind: "portable device folder", name: name}, true
			}
			if name := utf16At(b, 0x4A, n1); name != "" {
				return shellItem{kind: "portable device folder", name: name}, true
			}
		}
	}
	switch le.Uint32(b[4:]) {
	case sigWebFolder:
		// A OneDrive or SharePoint folder: the name or address as text at 0x18.
		if n := u32(0x14); n > 0 && n%2 == 0 {
			if s := utf16At(b, 0x18, n/2); s != "" {
				if un, err := url.PathUnescape(s); err == nil {
					s = un
				}
				return shellItem{kind: "web folder (OneDrive or SharePoint)", name: s}, true
			}
		}
	case sigCPCategory:
		if b[2] == 0x01 {
			c := u32(8)
			if c >= 0 && c < len(controlPanelCategories) {
				return shellItem{kind: "control panel category", name: controlPanelCategories[c]}, true
			}
			return shellItem{kind: "control panel category", name: fmt.Sprintf("Control Panel category %d", c)}, true
		}
	}
	return shellItem{}, false
}

// propertyViewItem names an item that carries a property view: a property
// store, and sometimes an identifier, after a data signature at offset 6.
func propertyViewItem(b []byte) (shellItem, bool) {
	le := binary.LittleEndian
	if len(b) < 18 || !propertyViewSigs[le.Uint32(b[6:])] {
		return shellItem{}, false
	}
	storeSize, idSize := int(le.Uint16(b[10:])), int(le.Uint16(b[12:]))
	if 14+idSize > len(b) {
		return shellItem{}, false
	}
	it := shellItem{kind: "property view"}
	if storeSize > 0 && 14+idSize+storeSize <= len(b) {
		it.name = propertyStoreName(b[14+idSize : 14+idSize+storeSize])
	}
	// A known folder named by its identifier.
	if it.name == "" && idSize == 16 {
		g := guidAt(b[14:])
		if n, ok := knownFolders[g]; ok {
			it.name = n
		} else if n, ok := knownFolderPath("{" + g + "}"); ok {
			it.name = n
		}
	}
	return it, true
}

// propertyStoreName returns the display name a property store gives an
// item (property 10 of b725f130-…, System.ItemNameDisplay), or failing
// that every text value in it joined with "::", as SBECmd shows them.
func propertyStoreName(store []byte) string {
	le := binary.LittleEndian
	var all []string
	name := ""
	for off := 0; off+24 <= len(store); {
		size := int(le.Uint32(store[off:]))
		if size == 0 {
			break
		}
		if size < 24 || off+size > len(store) || string(store[off+4:off+8]) != "1SPS" {
			break
		}
		set := store[off : off+size]
		named := guidAt(set[8:]) == "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
		for r := 24; r+9 <= len(set); {
			rsize := int(le.Uint32(set[r:]))
			if rsize == 0 || rsize < 9 || r+rsize > len(set) {
				break
			}
			rec := set[r : r+rsize]
			id := le.Uint32(rec[4:])
			v := 9
			if named {
				// The name, UTF-16 with its terminator, comes before the value.
				v = 9 + int(id)
			}
			if v+8 <= len(rec) {
				if s := typedString(rec[v:]); s != "" {
					all = append(all, s)
					if !named && id == 10 && name == "" {
						name = s
					}
				}
			}
			r += rsize
		}
		off += size
	}
	if name != "" {
		return name
	}
	return strings.Join(all, "::")
}

// typedString reads a typed property value that is text.
func typedString(v []byte) string {
	le := binary.LittleEndian
	if len(v) < 8 {
		return ""
	}
	n := int(le.Uint32(v[4:]))
	switch le.Uint16(v) {
	case 0x1F: // VT_LPWSTR: a count of characters, with the terminator
		return utf16At(v, 8, n)
	case 0x08: // VT_BSTR: a count of bytes
		return utf16At(v, 8, n/2)
	case 0x1E: // VT_LPSTR
		if n > 0 && 8+n <= len(v) {
			return strings.TrimRight(string(v[8:8+n]), "\x00")
		}
	}
	return ""
}
