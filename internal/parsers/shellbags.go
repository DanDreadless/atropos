package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"

	"www.velocidex.com/golang/regparser"
)

// Shellbags are Explorer's memory of every folder a user has opened in a
// window: local folders, removable drives, network shares and folders inside
// zip files, including ones that no longer exist. They live in the user's
// hives under ...\Shell\BagMRU as a tree. Each key is a folder; each numbered
// value in a key is a "shell item" naming one of its sub-folders, and the
// sub-key with the same number is that sub-folder's own node.
//
// A node's key is written when Explorer first records the folder and again
// when the list of its children changes, so its last-write time is evidence
// the folder was open in Explorer at or before that moment. The shell item
// also carries the folder's own created, modified and accessed times as they
// were when it was recorded.

const (
	shellbagMaxDepth = 64
	shellbagMaxNodes = 200000
)

// knownFolders names the root items that appear as class identifiers.
var knownFolders = map[string]string{
	"20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC",
	"12f0008f-2113-482a-80b3-fd5e91c12313": "OneNote", // as SBECmd's GUID list names it
	"59031a47-3f72-44a7-89c5-5595fe6b30ee": "User folder",
	"450d8fba-ad25-11d0-98a8-0800361b1103": "Documents",
	"208d2c60-3aea-1069-a2d7-08002b30309d": "Network",
	"f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
	"645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
	"031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
	"679f85cb-0220-4080-b29b-5540cc05aab6": "Quick access",
	"018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
	"b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
	"374de290-123f-4565-9164-39c4925e467b": "Downloads",
	"088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
	"a8cdff1c-4878-43be-b5fd-f8091c1c60d0": "Documents",
	"d3162b92-9365-467a-956b-92703aca08af": "Documents",
	"3add1653-eb32-4cb0-bbd7-dfa0abb5acca": "Pictures",
	"24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
	"1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music",
	"3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
	"a0953c92-50dc-43bf-be83-3742fed03c9c": "Videos",
	"f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
	"0db7e03f-fc29-4dc6-9020-ff41b59e513a": "3D Objects",
	"26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
	"21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
	"871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer",
	"f3364ba0-65b9-11ce-a9ba-00aa004ae837": "Shared documents",
	"9343812e-1c37-4a49-a12e-4b2d810d956b": "Search results",
	"4234d49b-0245-4df3-b780-3893943456e1": "Applications",
	"b2b4a4d1-2754-4140-a2eb-9a76d9d7cdc6": "Linux",
	"f874310e-b6b7-47dc-bc84-b9e6b38f5903": "Home",
	"7b81be6a-ce2b-4676-a29e-eb907a5126c5": "Programs and Features",
	"8e908fc9-becc-40f6-915b-f4ca0e70d03d": "Network and Sharing Center",
	"4026492f-2f69-46b8-b9bf-5654fc07e423": "Windows Defender Firewall",
	"025a5937-a6be-4686-a844-36fe4bec8b6d": "Power Options",
	"7007acc7-3202-11d1-aad2-00805fc1270e": "Network Connections",
	"241d7c96-f8bf-4f85-b01f-e2b043341a4b": "RemoteApp and Desktop Connections",
}

// guidAt renders the 16 bytes at b as a class identifier, lower case.
func guidAt(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	le := binary.LittleEndian
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		le.Uint32(b), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// dosTime converts the 16-bit date and time pair used inside shell items.
// The pair has two-second precision and no zone.
func dosTime(date, tm uint16) (time.Time, bool) {
	if date == 0 {
		return time.Time{}, false
	}
	y, m, d := int(date>>9)+1980, int(date>>5&0xF), int(date&0x1F)
	h, min, s := int(tm>>11), int(tm>>5&0x3F), int(tm&0x1F)*2
	if m < 1 || m > 12 || d < 1 || d > 31 || h > 23 || min > 59 || s > 59 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(m), d, h, min, s, 0, time.UTC), true
}

func utf16zAt(b []byte) string {
	u := make([]uint16, 0, 64)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// shellItem is what one item says about the folder it names.
type shellItem struct {
	name                        string
	kind                        string // what sort of item, for the examiner
	created, modified, accessed time.Time
	mftEntry                    uint64
	mftSeq                      uint16
}

var beef0004 = []byte{0x04, 0x00, 0xEF, 0xBE}

// archiveItemName recognises the two layouts Windows uses for a folder
// browsed inside an archive, and returns the folder's name.
//
// The zip layout (seen on Windows 7 to 11): bytes 12 to 31 are zero, a date
// as text or "N/A" sits at 0x24, the name's length in characters is the
// 32-bit number at 0x54, and the name itself starts at 0x5C.
//
// The layout Windows 11 uses for the other archive kinds it opens (7z, tar,
// rar): 0xFFFFFFFF at 0x18, then two 16-bit lengths, then at 0x20 the path
// inside the archive, of which the last part is the folder.
func archiveItemName(b []byte) (string, bool) {
	le := binary.LittleEndian
	zero := func(lo, hi int) bool {
		for _, c := range b[lo:hi] {
			if c != 0 {
				return false
			}
		}
		return true
	}
	if len(b) >= 0x5E && zero(12, 32) {
		n := int(le.Uint32(b[0x54:]))
		if n >= 1 && n <= 260 && 0x5C+2*n+2 <= len(b) && le.Uint16(b[0x5C+2*n:]) == 0 {
			if name := utf16zAt(b[0x5C:]); len(utf16.Encode([]rune(name))) == n {
				return name, true
			}
		}
	}
	if len(b) >= 0x24 && le.Uint32(b[0x18:]) == 0xFFFFFFFF && zero(6, 16) {
		nameLen, parentLen := int(le.Uint16(b[0x1C:])), int(le.Uint16(b[0x1E:]))
		p := utf16zAt(b[0x20:])
		if nameLen >= 1 && len(utf16.Encode([]rune(p))) == nameLen+parentLen {
			if i := strings.LastIndexAny(p, `\/`); i >= 0 && i+1 < len(p) {
				p = p[i+1:]
			}
			return p, true
		}
	}
	return "", false
}

// nestedDrive finds a drive item ("E:\") wrapped inside another item, which
// is how some removable and portable devices are recorded.
func nestedDrive(b []byte) string {
	for i := 4; i+4 <= len(b); i++ {
		c := b[i+1]
		if b[i] == 0x2F && b[i+2] == ':' && b[i+3] == '\\' && (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return string(b[i+1 : i+3])
		}
	}
	return ""
}

// parseShellItem reads one item: the two-byte size is at b[0:2].
func parseShellItem(b []byte) shellItem {
	le := binary.LittleEndian
	it := shellItem{kind: "unknown"}
	if len(b) < 4 {
		return it
	}
	if size := int(le.Uint16(b)); size >= 4 && size <= len(b) {
		b = b[:size]
	}
	typ := b[2]
	// The extension block, where present, has the long name and two of the
	// times, whatever kind of item carries it. Its signature sits four bytes
	// into the block.
	ext := -1
	if i := bytes.Index(b, beef0004); i >= 4 {
		ext = i - 4
	}
	fromExtension := func() {
		if ext < 0 || ext+18 > len(b) {
			return
		}
		e := b[ext:]
		version := le.Uint16(e[2:])
		if t, ok := dosTime(le.Uint16(e[8:]), le.Uint16(e[10:])); ok {
			it.created = t
		}
		if t, ok := dosTime(le.Uint16(e[12:]), le.Uint16(e[14:])); ok {
			it.accessed = t
		}
		// Where the long name starts depends on the version of the block.
		off := map[bool]int{true: 0x14, false: 0}[version >= 3]
		switch {
		case version >= 9:
			off = 0x2E
		case version >= 8:
			off = 0x2A
		case version >= 7:
			off = 0x26
		}
		if version >= 7 && len(e) >= 28 {
			it.mftEntry = le.Uint64(e[20:]) & 0xFFFFFFFFFFFF
			it.mftSeq = le.Uint16(e[26:])
		}
		if off > 0 && off < len(e) {
			if n := utf16zAt(e[off:]); n != "" {
				it.name = n
			}
		}
	}
	// Portable devices, web folders and Control Panel categories are
	// recognised by their signatures, whatever their type byte.
	if si, ok := signedShellItem(b); ok {
		si.name = clean(si.name)
		return si
	}
	// An item with a property view names its folder through a property store.
	if (typ == 0x1F || typ == 0x00) && len(b) > 20 && !(typ == 0x1F && b[4] == 0x2F) {
		if pv, ok := propertyViewItem(b); ok {
			pv.name = clean(pv.name)
			if pv.name == "" {
				pv.name = fmt.Sprintf("(property view, type 0x%02X)", typ)
			}
			return pv
		}
	}
	// A folder opened inside an archive has no dependable type byte (it is
	// whatever was in memory), so these are recognised by layout, first.
	if name, ok := archiveItemName(b); ok {
		it.kind = "folder inside an archive"
		it.name = clean(name)
		if it.name != "" {
			return it
		}
	}
	switch {
	case typ == 0x1F && len(b) > 20 && b[4] == 0x2F && len(b) >= 16:
		// A drive in a property view: its letter at offset 13.
		it.kind = "volume"
		it.name = strings.TrimRight(cstr(b[13:16]), `\`)
	case typ == 0x1F && len(b) >= 20:
		it.kind = "root folder"
		g := guidAt(b[4:])
		if n, ok := knownFolders[g]; ok {
			it.name = n
		} else {
			it.name = "{" + g + "}"
		}
	case typ&0x70 == 0x20:
		it.kind = "volume"
		if typ&0x01 != 0 && len(b) > 5 {
			it.name = strings.TrimRight(cstr(b[3:]), `\`)
		} else if d := nestedDrive(b); d != "" {
			it.name = d
		} else if len(b) >= 20 {
			g := guidAt(b[4:])
			if n, ok := knownFolders[g]; ok {
				it.name = n
			} else {
				it.name = "{" + g + "}"
			}
		}
	case typ&0x70 == 0x30 && len(b) >= 16:
		it.kind = "folder"
		if typ&0x02 != 0 && typ&0x01 == 0 {
			it.kind = "file"
		}
		if t, ok := dosTime(le.Uint16(b[8:]), le.Uint16(b[10:])); ok {
			it.modified = t
		}
		if typ&0x04 != 0 {
			it.name = utf16zAt(b[14:])
		} else {
			it.name = cstr(b[14:])
		}
		fromExtension()
	case typ&0x70 == 0x40 && len(b) > 6:
		it.kind = "network location"
		it.name = cstr(b[5:])
	case typ == 0x71 && len(b) >= 30:
		it.kind = "control panel item"
		if n, ok := knownFolders[guidAt(b[14:])]; ok {
			it.name = n
		} else {
			it.name = "{" + guidAt(b[14:]) + "}"
		}
	default:
		// Items wrapped by a delegate folder, MTP devices and others: if an
		// extension block is inside, it names the folder.
		if ext >= 0 {
			it.kind = "folder"
			fromExtension()
			// A delegate item ("CFSF" at offset 6) wraps an ordinary file
			// entry that begins at offset 12: its size at 14 and its
			// modified date and time at 18. Found by comparison with SBECmd,
			// which showed a modified time on these where Atropos had none.
			if len(b) >= 22 && string(b[6:10]) == "CFSF" {
				if t, ok := dosTime(le.Uint16(b[18:]), le.Uint16(b[20:])); ok {
					it.modified = t
				}
			}
		}
	}
	it.name = clean(it.name)
	if it.name == "" {
		it.name = fmt.Sprintf("(shell item type 0x%02X)", typ)
	}
	return it
}

type shellbagWalk struct {
	ctx   *Context
	host  string
	hive  string
	nodes int
}

// shellBags walks one BagMRU tree. root is the BagMRU key itself, which
// stands for the desktop.
func shellBags(ctx *Context, host, hive, rootPath string, root *regparser.CM_KEY_NODE) error {
	w := &shellbagWalk{ctx: ctx, host: host, hive: hive}
	return w.walk(root, rootPath, "Desktop", 0)
}

func (w *shellbagWalk) walk(key *regparser.CM_KEY_NODE, keyPath, folder string, depth int) error {
	if depth > shellbagMaxDepth {
		w.ctx.Warn("shellbag tree deeper than %d levels at %s; not followed further", shellbagMaxDepth, keyPath)
		return nil
	}
	items := map[string][]byte{}
	for _, v := range key.Values() {
		name := valueName(v)
		if name == "" || strings.Trim(name, "0123456789") != "" {
			continue // MRUListEx, NodeSlot and the like
		}
		if d := safeData(v); d != nil && len(d.Data) >= 4 {
			items[name] = d.Data
		}
	}
	for _, sub := range key.Subkeys() {
		name := keyName(sub)
		data, ok := items[name]
		if !ok {
			continue
		}
		if w.nodes++; w.nodes > shellbagMaxNodes {
			w.ctx.Warn("more than %d shellbag folders; the rest were not read", shellbagMaxNodes)
			return nil
		}
		it := parseShellItem(data)
		path := folder + `\` + it.name
		subPath := keyPath + `\` + clean(name)
		fields := map[string]any{"folder": path, "key": subPath, "item_kind": it.kind, "hive": w.hive}
		if it.mftEntry != 0 {
			fields["mft_entry"] = it.mftEntry
		}
		if stamp, ok := keyStamp(sub); ok {
			if err := w.ctx.Emit(Event{
				Stamp: stamp, Type: "shellbag-folder-recorded", Category: CatFileOpening, Source: "shellbags",
				Host: w.host, Path: path,
				Message: "Shellbag: folder open in Explorer at or before this time: " + path,
				Fields:  fields, Ref: "shellbag key " + subPath,
			}); err != nil {
				return err
			}
		}
		for _, t := range []struct {
			when      time.Time
			typ, macb string
			word      string
		}{{it.created, "folder-created (shellbag)", "...B", "created"}, {it.modified, "folder-modified (shellbag)", "M...", "modified"}, {it.accessed, "folder-accessed (shellbag)", ".A..", "accessed"}} {
			stamp, ok := timeutil.FromTimeNative(t.when, "")
			if !ok {
				continue
			}
			stamp.Raw = "DOS date and time " + t.when.Format("2006-01-02 15:04:05")
			stamp.Caveat = "shell item times have two-second precision and no zone: they are UTC when the folder was on an NTFS volume, and local time when it was on FAT or exFAT media"
			if err := w.ctx.Emit(Event{
				Stamp: stamp, Type: t.typ, MACB: t.macb, Category: CatFileOpening, Source: "shellbags",
				Host: w.host, Path: path,
				Message: fmt.Sprintf("Shellbag: %s was %s (as recorded when Explorer last saw it)", path, t.word),
				Fields:  fields, Ref: "shell item in value " + clean(name) + " of " + keyPath,
			}); err != nil {
				return err
			}
		}
		if err := w.walk(sub, subPath, path, depth+1); err != nil {
			return err
		}
	}
	return nil
}
