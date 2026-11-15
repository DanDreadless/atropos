package parsers

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// usnParser reads the NTFS change journal ($Extend\$UsnJrnl:$J): one record
// for every change to every file, including files since deleted. It is often
// the only surviving evidence that a file existed, was renamed or was
// removed.
//
// A record names the file and gives the file-table reference of its parent
// directory, not a full path. The reference is in the event's fields so the
// path can be found from the same volume's $MFT events.
type usnParser struct{}

func (usnParser) Name() string    { return "usn-journal" }
func (usnParser) Version() string { return "1 (native, USN_RECORD_V2)" }

var usnReasons = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "DATA_OVERWRITE"}, {0x00000002, "DATA_EXTEND"}, {0x00000004, "DATA_TRUNCATION"},
	{0x00000010, "NAMED_DATA_OVERWRITE"}, {0x00000020, "NAMED_DATA_EXTEND"}, {0x00000040, "NAMED_DATA_TRUNCATION"},
	{0x00000100, "FILE_CREATE"}, {0x00000200, "FILE_DELETE"}, {0x00000400, "EA_CHANGE"}, {0x00000800, "SECURITY_CHANGE"},
	{0x00001000, "RENAME_OLD_NAME"}, {0x00002000, "RENAME_NEW_NAME"}, {0x00004000, "INDEXABLE_CHANGE"},
	{0x00008000, "BASIC_INFO_CHANGE"}, {0x00010000, "HARD_LINK_CHANGE"}, {0x00020000, "COMPRESSION_CHANGE"},
	{0x00040000, "ENCRYPTION_CHANGE"}, {0x00080000, "OBJECT_ID_CHANGE"}, {0x00100000, "REPARSE_POINT_CHANGE"},
	{0x00200000, "STREAM_CHANGE"}, {0x00400000, "TRANSACTED_CHANGE"}, {0x00800000, "INTEGRITY_CHANGE"},
	{0x80000000, "CLOSE"},
}

// usnRecordAt reports whether b begins with a plausible version 2 record,
// and its length.
func usnRecordAt(b []byte) (int, bool) {
	if len(b) < 60 {
		return 0, false
	}
	le := binary.LittleEndian
	n := int(le.Uint32(b))
	nameLen, nameOff := int(le.Uint16(b[56:])), int(le.Uint16(b[58:]))
	if n < 60 || n > 1024 || n%8 != 0 || le.Uint16(b[4:]) != 2 || le.Uint16(b[6:]) != 0 ||
		nameOff != 60 || nameLen == 0 || nameLen%2 != 0 || 60+nameLen > n {
		return 0, false
	}
	if _, ok := timeutil.FromFiletime(le.Uint64(b[32:])); !ok {
		return 0, false
	}
	return n, true
}

// USNJournal reports whether head, the start of a file, looks like a change
// journal: nothing but zero padding and then a valid record.
func USNJournal(head []byte) bool {
	for i := 0; i+60 <= len(head); i += 8 {
		if binary.LittleEndian.Uint64(head[i:]) == 0 {
			continue
		}
		_, ok := usnRecordAt(head[i:])
		return ok
	}
	return false
}

func (usnParser) Parse(ctx *Context) error {
	r := bufio.NewReaderSize(io.NewSectionReader(ctx.File, 0, ctx.Size), 4<<20)
	le := binary.LittleEndian
	var offset int64
	skipped, emitted := int64(0), 0
	for {
		head, err := r.Peek(8)
		if err != nil {
			break
		}
		if le.Uint64(head) == 0 { // padding between runs of records
			r.Discard(8)
			offset += 8
			continue
		}
		b, _ := r.Peek(1024)
		n, ok := usnRecordAt(b)
		if !ok || n > len(b) {
			// Not a record: damaged, or a version this parser does not read.
			r.Discard(8)
			offset += 8
			skipped += 8
			continue
		}
		rec := b[:n]
		nameLen := int(le.Uint16(rec[56:]))
		u := make([]uint16, nameLen/2)
		for i := range u {
			u[i] = le.Uint16(rec[60+i*2:])
		}
		name := clean(string(utf16.Decode(u)))
		reason := le.Uint32(rec[40:])
		var reasons []string
		for _, x := range usnReasons {
			if reason&x.bit != 0 {
				reasons = append(reasons, x.name)
			}
		}
		stamp, _ := timeutil.FromFiletime(le.Uint64(rec[32:]))
		frn, parent := le.Uint64(rec[8:]), le.Uint64(rec[16:])
		cat := CatFileSystem
		if reason&0x200 != 0 {
			cat = CatDeletion
		}
		attrs := le.Uint32(rec[52:])
		what := "file"
		if attrs&0x10 != 0 {
			what = "directory"
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "usn-change", Category: cat, Source: "usn", Host: ctx.Host, Path: name,
			Message: fmt.Sprintf("USN: %s %s  %s", what, name, strings.Join(reasons, " ")),
			Fields: map[string]any{
				"name": name, "reasons": reasons, "usn": le.Uint64(rec[24:]),
				"entry": frn & 0xFFFFFFFFFFFF, "sequence": frn >> 48,
				"parent_entry": parent & 0xFFFFFFFFFFFF, "parent_sequence": parent >> 48,
				"is_dir": attrs&0x10 != 0, "attributes": fmt.Sprintf("0x%08X", attrs),
			},
			Ref: fmt.Sprintf("USN record at offset %d", offset),
		}); err != nil {
			return err
		}
		emitted++
		r.Discard(n)
		offset += int64(n)
	}
	if skipped > 0 {
		ctx.Warn("%d bytes were not valid version 2 records and were skipped", skipped)
	}
	if emitted == 0 {
		return ErrNothingExtracted
	}
	ctx.Note("change journal records name a file and its parent directory's file-table entry, not a full path")
	return nil
}
