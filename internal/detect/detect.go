// Package detect identifies an artefact from its content. File names are
// never trusted for identification: evidence is routinely renamed, and a name
// proves nothing about what a file is.
package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/DanDreadless/atropos/internal/winnotepad"
)

// Artefact kinds. Kinds with a dedicated parser are routed to it; the rest
// are recognised, recorded and given generic handling.
const (
	EVTX     = "windows-event-log"
	Registry = "windows-registry-hive"
	// RegistryLog is a hive's transaction log (.LOG, .LOG1, .LOG2): it
	// begins with a copy of the hive's base block, marked as a log.
	RegistryLog = "windows-registry-log"
	Prefetch    = "windows-prefetch"
	LNK         = "windows-shortcut"
	MFT         = "ntfs-mft"
	NTFSVolume  = "ntfs-volume-image"
	NTFSIndex   = "ntfs-directory-index"
	NTFSLog     = "ntfs-transaction-log"
	SQLite      = "sqlite-database"
	Text        = "text"
	TextUTF16   = "text-utf16"
	Zip         = "zip-archive"
	Gzip        = "gzip"
	Tar         = "tar-archive"
	ESE         = "ese-database"
	EWF         = "ewf-image"
	VHDX        = "vhdx-image"
	VMDK        = "vmdk-image"
	VHD         = "vhd-image"
	MBRDisk     = "disk-image"
	ISO         = "iso-image"
	RecycleI    = "recycle-bin-record"
	WinNotepad  = "windows-notepad-state"
	DefenderDH  = "defender-detection-record"
	MozLz4      = "mozilla-lz4"
	WMIRepo     = "wmi-repository"
	USN         = "ntfs-usn-journal"
	JumpList    = "jump-list-custom"
	SevenZip    = "7z-archive"
	PE          = "pe-executable"
	ELF         = "elf-executable"
	PDF         = "pdf"
	OLE         = "ole-compound-file"
	PCAP        = "packet-capture"
	Empty       = "empty"
	Unknown     = "unknown"
)

type Result struct {
	Kind   string
	Reason string
}

type sig struct {
	off    int
	magic  []byte
	kind   string
	reason string
}

var sigs = []sig{
	{0, []byte("ElfFile\x00"), EVTX, `signature "ElfFile" at offset 0`},
	{0, []byte("regf"), Registry, `signature "regf" at offset 0`},
	{0, []byte("MAM\x04"), Prefetch, `compressed prefetch signature "MAM\x04" at offset 0`},
	{4, []byte("SCCA"), Prefetch, `signature "SCCA" at offset 4`},
	{0, []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}, LNK, "shell link header size and class identifier at offset 0"},
	{3, []byte("NTFS    "), NTFSVolume, `NTFS boot sector signature at offset 3`},
	{0, []byte("SQLite format 3\x00"), SQLite, `signature "SQLite format 3" at offset 0`},
	{4, []byte{0xEF, 0xCD, 0xAB, 0x89}, ESE, "ESE database signature at offset 4"},
	{0, []byte("EVF\x09\x0d\x0a\xff\x00"), EWF, "Expert Witness Format signature at offset 0"},
	{0, []byte("mozLz40\x00"), MozLz4, `Mozilla LZ4 signature "mozLz40" at offset 0`},
	{0, []byte("vhdxfile"), VHDX, `signature "vhdxfile" at offset 0`},
	{0, []byte("KDMV"), VMDK, `signature "KDMV" at offset 0`},
	{0, []byte("conectix"), VHD, `VHD footer copy "conectix" at offset 0 (a dynamic or differencing VHD)`},
	{0, []byte("PK\x03\x04"), Zip, "ZIP local file header at offset 0"},
	{0, []byte("PK\x05\x06"), Zip, "empty ZIP end-of-directory record at offset 0"},
	{0, []byte{0x1f, 0x8b}, Gzip, "gzip signature at offset 0"},
	{257, []byte("ustar"), Tar, `tar signature "ustar" at offset 257`},
	{0, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, SevenZip, "7z signature at offset 0"},
	{0, []byte("%PDF-"), PDF, `signature "%PDF-" at offset 0`},
	{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, OLE, "OLE compound file signature at offset 0"},
	{0, []byte{0x7F, 'E', 'L', 'F'}, ELF, "ELF signature at offset 0"},
	{0, []byte{0xD4, 0xC3, 0xB2, 0xA1}, PCAP, "pcap signature at offset 0"},
	{0, []byte{0xA1, 0xB2, 0xC3, 0xD4}, PCAP, "pcap signature at offset 0"},
	{0, []byte{0x0A, 0x0D, 0x0D, 0x0A}, PCAP, "pcapng section header at offset 0"},
}

// Identify inspects the start of a file.
func Identify(r io.ReaderAt, size int64) Result {
	if size == 0 {
		return Result{Empty, "file has no content"}
	}
	head := make([]byte, 4096)
	n, _ := r.ReadAt(head, 0)
	head = head[:n]

	for _, s := range sigs {
		if len(head) >= s.off+len(s.magic) && bytes.Equal(head[s.off:s.off+len(s.magic)], s.magic) {
			// A transaction log starts with "regf" too; its file type says it is a log.
			if s.kind == Registry && len(head) >= 32 {
				switch binary.LittleEndian.Uint32(head[28:]) {
				case 1, 2, 6:
					return Result{RegistryLog, `signature "regf" at offset 0 with file type ` + fmt.Sprint(binary.LittleEndian.Uint32(head[28:])) + ` (a transaction log)`}
				}
			}
			return Result{s.kind, s.reason}
		}
	}
	// An optical disc image keeps its signature at sector 16, past anything
	// else looked at here. It is checked before the boot sector test because
	// many discs carry a boot sector too.
	iso := make([]byte, 5)
	if n, _ := r.ReadAt(iso, 32769); n == 5 && string(iso) == "CD001" {
		return Result{ISO, `ISO 9660 signature "CD001" at offset 32769`}
	}
	// A raw $MFT is a run of 1024-byte FILE records.
	if len(head) >= 1028 && (bytes.HasPrefix(head, []byte("FILE")) || bytes.HasPrefix(head, []byte("BAAD"))) {
		next := head[1024:1028]
		if bytes.Equal(next, []byte("FILE")) || bytes.Equal(next, []byte("BAAD")) {
			return Result{MFT, `"FILE" record signatures at offsets 0 and 1024`}
		}
	}
	// A directory index saved on its own is a run of 4096-byte INDX records,
	// each protected by an eight-sector check array.
	if len(head) >= 0x40 && bytes.HasPrefix(head, []byte("INDX")) {
		if off, n := binary.LittleEndian.Uint16(head[4:]), binary.LittleEndian.Uint16(head[6:]); off >= 0x28 && off <= 0x40 && n == 9 {
			return Result{NTFSIndex, `NTFS directory index: "INDX" record with an eight-sector check array at offset 0`}
		}
	}
	// The NTFS transaction log opens with two restart pages.
	if len(head) >= 0x30 && bytes.HasPrefix(head, []byte("RSTR")) {
		sys := int64(binary.LittleEndian.Uint32(head[0x10:]))
		second := make([]byte, 4)
		if n, _ := r.ReadAt(second, sys); sys >= 0x200 && sys <= 0x10000 && n == 4 && (string(second) == "RSTR" || string(second) == "RCRD") {
			return Result{NTFSLog, `NTFS transaction log: "RSTR" restart pages at offset 0 and one page on`}
		}
	}
	// Windows Notepad's state files begin "NP", which proves nothing. They
	// are accepted only when a known layout's checksum agrees.
	if winnotepad.Signature(head) && size <= 64<<20 {
		whole := make([]byte, size)
		if n, _ := r.ReadAt(whole, 0); int64(n) == size {
			if f, err := winnotepad.Decode(whole); err == nil {
				return Result{WinNotepad, `Windows Notepad state file (` + f.Kind + `): "NP" at offset 0 and a matching CRC-32`}
			}
		}
	}
	if defenderDetection(head) {
		return Result{DefenderDH, `Microsoft Defender detection record: a number, a GUID and "Magic.Version:" as the first three values`}
	}
	// Two letters are a weak signature: prose can begin "MZ". A DOS header is
	// binary, so text is ruled out first.
	if recycleRecord(head, size) {
		return Result{RecycleI, "Recycle Bin $I record: version, size and deletion time are consistent with the file's length"}
	}
	if usnJournal(head) {
		return Result{USN, "NTFS change journal: a valid USN record follows the leading padding"}
	}
	if i := bytes.Index(head, lnkClass); i >= 16 && i <= 64 && binary.LittleEndian.Uint32(head) <= 16 {
		return Result{JumpList, "custom jump list: a short header followed by a shell link"}
	}
	// A change journal copied out whole begins with a long run of zeros. Look
	// further in before giving up, but only when the start is entirely empty.
	if size > int64(len(head)) && allZero(head) {
		buf := make([]byte, 1<<20)
		for off := int64(len(head)) &^ 7; off < size && off < 64<<20; off += int64(len(buf)) {
			n, _ := r.ReadAt(buf, off)
			if n == 0 {
				break
			}
			if !allZero(buf[:n]) {
				if usnJournal(buf[:n]) {
					return Result{USN, "NTFS change journal: a valid USN record follows the leading padding"}
				}
				break
			}
		}
	}
	if len(head) >= 0x40 && head[0] == 'M' && head[1] == 'Z' && !looksText(head) {
		return Result{PE, `"MZ" signature at offset 0`}
	}
	if len(head) >= 512 && head[510] == 0x55 && head[511] == 0xAA && !looksText(head) {
		return Result{MBRDisk, "boot sector signature 55AA at offset 510"}
	}
	if wmiRepository(r, size) {
		return Result{WMIRepo, "WMI repository (OBJECTS.DATA): 8 KiB pages whose first megabyte holds many records that begin with a class-name hash, and WMI's system class names"}
	}
	if len(head) >= 2 && head[0] == 0xFF && head[1] == 0xFE {
		return Result{TextUTF16, "UTF-16 little-endian byte order mark"}
	}
	if looksUTF16(head) {
		return Result{TextUTF16, "content is consistent with UTF-16 little-endian text"}
	}
	if looksText(head) {
		return Result{Text, "content is printable text"}
	}
	return Result{Unknown, "no known signature matched"}
}

var lnkClass = []byte{0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// filetimePlausible accepts times between 1980 and 2100, as the rest of
// Atropos does.
func filetimePlausible(ft uint64) bool {
	const y1980, y2100 = 119600064000000000, 157469184000000000
	return ft >= y1980 && ft < y2100
}

// defenderDetection recognises a file from Defender's DetectionHistory
// folder. It is a run of sized, typed values: the threat's number (8 bytes),
// the detection's GUID (16 bytes, type 0x1E), then a UTF-16 string (type
// 0x15) beginning "Magic.Version:".
func defenderDetection(b []byte) bool {
	if len(b) < 0x30+28 {
		return false
	}
	le := binary.LittleEndian
	if le.Uint32(b) != 8 || le.Uint32(b[0x10:]) != 16 || le.Uint32(b[0x14:]) != 0x1E || le.Uint32(b[0x2C:]) != 0x15 {
		return false
	}
	for i, c := range "Magic.Version:" {
		if b[0x30+2*i] != byte(c) || b[0x30+2*i+1] != 0 {
			return false
		}
	}
	return true
}

// recycleRecord recognises a Recycle Bin $I record. Version 1 is a fixed
// 544 bytes; version 2 states the length of its path.
func recycleRecord(b []byte, size int64) bool {
	if len(b) < 28 {
		return false
	}
	le := binary.LittleEndian
	switch le.Uint64(b) {
	case 1:
		if size != 544 {
			return false
		}
	case 2:
		if n := int64(le.Uint32(b[24:])); n == 0 || n > 32768 || size != 28+2*n {
			return false
		}
	default:
		return false
	}
	return filetimePlausible(le.Uint64(b[16:]))
}

// usnJournal recognises an NTFS change journal: zero padding, then a
// well-formed version 2 record.
func usnJournal(b []byte) bool {
	le := binary.LittleEndian
	for i := 0; i+60 <= len(b); i += 8 {
		if le.Uint64(b[i:]) == 0 {
			continue
		}
		r := b[i:]
		n, nameLen := int(le.Uint32(r)), int(le.Uint16(r[56:]))
		return n >= 60 && n <= 1024 && n%8 == 0 && le.Uint16(r[4:]) == 2 && le.Uint16(r[6:]) == 0 &&
			le.Uint16(r[58:]) == 60 && nameLen > 0 && nameLen%2 == 0 && 60+nameLen <= n && filetimePlausible(le.Uint64(r[32:]))
	}
	return false
}

func looksText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	// A sample may end mid-rune; trim up to three trailing bytes before judging.
	for i := 0; i < 3 && len(b) > 0 && !utf8.Valid(b); i++ {
		b = b[:len(b)-1]
	}
	if !utf8.Valid(b) {
		return false
	}
	ctrl := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			ctrl++
		}
	}
	return ctrl*50 < len(b)
}

func looksUTF16(b []byte) bool {
	if len(b) < 64 {
		return false
	}
	zeros, printable := 0, 0
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 {
			zeros++
			if b[i] >= 0x20 && b[i] < 0x7F || b[i] == '\n' || b[i] == '\r' || b[i] == '\t' {
				printable++
			}
		}
	}
	pairs := len(b) / 2
	return zeros*10 >= pairs*9 && printable*10 >= pairs*9
}

// wmiRepository recognises the WMI repository's object store. The file has
// no signature: it is a run of 8 KiB pages. What marks it is what it holds:
// records that each begin with a SHA-256 written as 64 hexadecimal
// characters in UTF-16, and the names of WMI's own system classes.
func wmiRepository(r io.ReaderAt, size int64) bool {
	if size < 8192 || size%8192 != 0 {
		return false
	}
	buf := make([]byte, 1<<20)
	n, _ := r.ReadAt(buf, 0)
	buf = buf[:n]
	if !bytes.Contains(buf, []byte("__NAMESPACE")) && !bytes.Contains(buf, []byte("__SystemSecurity")) && !bytes.Contains(buf, []byte("__PARAMETERS")) {
		return false
	}
	runs, run := 0, 0
	for i := 0; i+1 < len(buf); i += 2 {
		c := buf[i]
		if buf[i+1] == 0 && (c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			run++
			continue
		}
		if run >= 64 {
			runs++
		}
		run = 0
	}
	// Hashes may start on an odd byte as well.
	run = 0
	for i := 1; i+1 < len(buf); i += 2 {
		c := buf[i]
		if buf[i+1] == 0 && (c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			run++
			continue
		}
		if run >= 64 {
			runs++
		}
		run = 0
	}
	return runs >= 8
}
