package parsers

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// NTFS keeps, for every directory, an index of the files in it (the $I30
// index). Each index entry repeats the file's name, size and four timestamps.
// When a file is deleted or renamed its entry is not wiped: later entries are
// moved over it, and what is left beyond the last live entry stays on disk
// until something overwrites it. That leftover space ("slack") is where the
// names and times of files that no longer exist can be recovered from, and
// where an older set of timestamps for a file that still exists can survive.
//
// The same entry layout appears inside the transaction log ($LogFile), which
// records each entry being added to and removed from an index.

// indexEntry is one $I30 entry: a file name and what the directory recorded
// about the file.
type indexEntry struct {
	name                                 string
	entry, sequence                      uint64 // the file's record in the file table
	parentEntry, parentSequence          uint64
	created, modified, changed, accessed time.Time
	size, allocated                      uint64
	flags                                uint32
	namespace                            byte
	slack                                bool
	offset                               int64 // where in the source the entry starts
}

func (e indexEntry) isDir() bool { return e.flags&0x10000000 != 0 }

const indexBlockSize = 4096

// Times outside this window mark bytes that are not an index entry. The
// window is wide on purpose: a backdated file is exactly what is being
// looked for.
var (
	indexTimeMin = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	indexTimeMax = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

func indexTime(v uint64) (time.Time, bool) {
	if v == 0 {
		return time.Time{}, false
	}
	const epochDiff = 116444736000000000
	if v < epochDiff {
		return time.Time{}, false
	}
	t := time.Unix(0, 0).UTC().Add(time.Duration(v-epochDiff) * 100)
	if t.Before(indexTimeMin) || t.After(indexTimeMax) {
		return time.Time{}, false
	}
	return t, true
}

// parseFileName reads the part of an index entry that describes the file:
// its parent directory, four times, sizes, attributes and name. This is a
// copy of the file's $FILE_NAME attribute. strict is for carving: every field
// must be believable, because the bytes may be anything.
func parseFileName(fn []byte, strict bool) (e indexEntry, used int, ok bool) {
	le := binary.LittleEndian
	if len(fn) < 0x44 {
		return e, 0, false
	}
	nameLen := int(fn[0x40])
	e.namespace = fn[0x41]
	used = 0x42 + 2*nameLen
	if nameLen == 0 || e.namespace > 3 || used > len(fn) {
		return e, 0, false
	}
	parent := le.Uint64(fn)
	e.parentEntry, e.parentSequence = parent&0xFFFFFFFFFFFF, parent>>48
	var okC, okM, okX, okA bool
	e.created, okC = indexTime(le.Uint64(fn[0x08:]))
	e.modified, okM = indexTime(le.Uint64(fn[0x10:]))
	e.changed, okX = indexTime(le.Uint64(fn[0x18:]))
	e.accessed, okA = indexTime(le.Uint64(fn[0x20:]))
	if !okC || !okM || !okX || !okA {
		// Windows keeps no times in the index for its own metadata files
		// ($Bitmap, $Boot and the like): a live entry may have none. A
		// carved one must have all four, or anything would pass.
		zero := le.Uint64(fn[0x08:]) == 0 && le.Uint64(fn[0x10:]) == 0 && le.Uint64(fn[0x18:]) == 0 && le.Uint64(fn[0x20:]) == 0
		if strict || !zero {
			return e, 0, false
		}
	}
	e.allocated, e.size = le.Uint64(fn[0x28:]), le.Uint64(fn[0x30:])
	e.flags = le.Uint32(fn[0x38:])
	u := make([]uint16, nameLen)
	for i := range u {
		u[i] = le.Uint16(fn[0x42+2*i:])
		// No control characters, and none of the characters NTFS forbids.
		if u[i] < 0x20 || u[i] == '/' || u[i] == 0xFFFF || u[i] == 0xFFFE {
			return e, 0, false
		}
	}
	e.name = string(utf16.Decode(u))
	if strict {
		// A parent that is a real record, sizes a volume could hold, space
		// allocated in whole sectors, and a name that is not a lone
		// punctuation mark picked out of other data.
		if e.parentSequence == 0 || e.parentEntry > 1<<36 || e.size > 1<<50 || e.allocated > 1<<50 || e.allocated%512 != 0 ||
			nameLen == 1 && !unicode.IsLetter(rune(u[0])) && !unicode.IsDigit(rune(u[0])) {
			return e, 0, false
		}
	}
	return e, used, true
}

// parseIndexEntry reads the whole entry at the start of b: a 16-byte header
// naming the file's record, then the file name part.
func parseIndexEntry(b []byte, strict bool) (e indexEntry, length int, ok bool) {
	le := binary.LittleEndian
	if len(b) < 0x52 {
		return e, 0, false
	}
	ref := le.Uint64(b)
	length = int(le.Uint16(b[8:]))
	content := int(le.Uint16(b[10:]))
	if length < 0x52 || length > len(b) || length%8 != 0 || content < 0x44 || content > length-0x10 {
		return e, 0, false
	}
	e, used, ok := parseFileName(b[0x10:0x10+content], strict)
	if !ok {
		return e, 0, false
	}
	e.entry, e.sequence = ref&0xFFFFFFFFFFFF, ref>>48
	if strict && (e.sequence == 0 || e.entry > 1<<36 || content != used && content != (used+7)&^7) {
		return e, 0, false
	}
	return e, length, true
}

// applyFixups undoes the protection NTFS puts on multi-sector records: the
// last two bytes of each 512-byte sector are swapped for a check value and
// kept in an array near the start. It reports false if the record is torn.
func applyFixups(block []byte) bool {
	le := binary.LittleEndian
	if len(block) < 8 {
		return false
	}
	off, n := int(le.Uint16(block[4:])), int(le.Uint16(block[6:]))
	if n < 2 || off < 8 || off+2*n > len(block) || (n-1)*512 > len(block) {
		return false
	}
	check := block[off : off+2]
	whole := true
	for i := 1; i < n; i++ {
		end := i*512 - 2
		if block[end] != check[0] || block[end+1] != check[1] {
			whole = false
			continue
		}
		copy(block[end:end+2], block[off+2*i:off+2*i+2])
	}
	return whole
}

// parseIndexBlock reads one 4096-byte INDX record: its live entries, and
// whatever entries can still be read in the space after them. base is the
// block's offset in its source, for references.
func parseIndexBlock(block []byte, base int64) (live, slack []indexEntry, err error) {
	le := binary.LittleEndian
	if len(block) < 0x40 || string(block[:4]) != "INDX" {
		return nil, nil, fmt.Errorf("not an index record")
	}
	block = append([]byte(nil), block...)
	torn := !applyFixups(block)
	// The node header sits at 0x18; its offsets are relative to it.
	first := 0x18 + int(le.Uint32(block[0x18:]))
	end := 0x18 + int(le.Uint32(block[0x1C:]))
	if first < 0x28 || first > len(block) || end < first || end > len(block) {
		return nil, nil, fmt.Errorf("index record header is not valid")
	}
	pos := first
	for pos+0x10 <= end {
		length := int(le.Uint16(block[pos+8:]))
		flags := le.Uint16(block[pos+12:])
		if flags&2 != 0 || length < 0x10 { // the last entry carries no file
			break
		}
		if e, n, ok := parseIndexEntry(block[pos:end], false); ok {
			e.offset = base + int64(pos)
			live = append(live, e)
			pos += n
			continue
		}
		pos += length
	}
	// Carve the rest of the block. Entries are 8-byte aligned.
	//
	// The file name part is looked for on its own. When the last entry of a
	// record is removed, the end marker is written over that entry's 16-byte
	// header, so the most common leftover has no header: its name, times and
	// parent survive, and which file record it was does not.
	start := (end + 7) &^ 7
	for p := start; p+0x44 <= len(block); p += 8 {
		e, used, ok := parseFileName(block[p:], true)
		if !ok {
			continue
		}
		e.slack, e.offset = true, base+int64(p)
		if p-0x10 >= start {
			if he, _, hok := parseIndexEntry(block[p-0x10:], true); hok {
				e.entry, e.sequence, e.offset = he.entry, he.sequence, base+int64(p-0x10)
			}
		}
		slack = append(slack, e)
		p += (used+7)&^7 - 8
	}
	if torn {
		err = fmt.Errorf("the record's sector check values do not match (a torn or partly overwritten record); what could be read was kept")
	}
	return live, slack, err
}

// indexKey identifies one state of one name, for telling a leftover copy of
// a live entry from something the directory no longer holds.
func (e indexEntry) key() string {
	// The file's own record number is left out: a carved entry may have lost it.
	return fmt.Sprintf("%d-%d|%s|%d|%d|%d|%d", e.parentEntry, e.parentSequence, e.name,
		e.created.UnixNano(), e.modified.UnixNano(), e.changed.UnixNano(), e.accessed.UnixNano())
}

// readIndexStream parses every record of an index stream. Slack entries that
// are byte-for-byte copies of a live entry in the same stream are dropped:
// they are what index rebalancing leaves behind and say nothing new.
func readIndexStream(r io.ReaderAt, size int64, warn func(string, ...any)) (live, slack []indexEntry) {
	buf := make([]byte, indexBlockSize)
	bad := 0
	for off := int64(0); off+indexBlockSize <= size; off += indexBlockSize {
		if _, err := r.ReadAt(buf, off); err != nil {
			warn("index record at offset %d could not be read: %v", off, err)
			break
		}
		if string(buf[:4]) != "INDX" {
			continue // never used, or zeroed
		}
		l, s, err := parseIndexBlock(buf, off)
		if err != nil {
			bad++
			if bad <= 5 {
				warn("index record at offset %d: %v", off, err)
			}
		}
		live = append(live, l...)
		slack = append(slack, s...)
	}
	if bad > 5 {
		warn("%d index records in all had problems", bad)
	}
	seen := map[string]bool{}
	for _, e := range live {
		seen[e.key()] = true
	}
	kept := slack[:0]
	for _, e := range slack {
		if !seen[e.key()] {
			seen[e.key()] = true // and one copy of each leftover is enough
			kept = append(kept, e)
		}
	}
	return live, kept
}

// joinDir joins a directory path from the file table and a name. The file
// table calls the root "/.".
func joinDir(dir, name string) string {
	if dir == "" || dir == "/" || dir == "/." {
		return "/" + name
	}
	return dir + "/" + name
}

// emitIndexEntry puts an entry's times on the timeline. what says where the
// entry came from, in the examiner's words; typ is the event type prefix.
func emitIndexEntry(ctx *Context, e indexEntry, source, typ, what, path, ref string, extra map[string]any) error {
	fields := map[string]any{
		"name":         e.name,
		"parent_entry": e.parentEntry, "parent_sequence": e.parentSequence,
		"size": e.size, "allocated_size": e.allocated, "is_dir": e.isDir(),
		"attributes": fmt.Sprintf("0x%08X", e.flags), "recovered_from_slack": e.slack,
	}
	// A carved entry whose header was overwritten does not say which file
	// record it belonged to; nothing is put in its place.
	if e.sequence != 0 {
		fields["entry"], fields["sequence"] = e.entry, e.sequence
	} else {
		fields["file_record_unknown"] = true
	}
	for k, v := range extra {
		fields[k] = v
	}
	groups := macb(e.modified, e.accessed, e.changed, e.created)
	keys := make([]time.Time, 0, len(groups))
	for t := range groups {
		keys = append(keys, t)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	kind := "file"
	if e.isDir() {
		kind = "folder"
	}
	for _, t := range keys {
		stamp, ok := timeutil.FromTimeNative(t, "")
		if !ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: typ + " " + groups[t], MACB: groups[t], Category: CatFileSystem, Source: source,
			Host: ctx.Host, Path: path,
			Message: fmt.Sprintf("%s %s  %s %s (%d bytes): %s", typ, groups[t], kind, path, e.size, what),
			Fields:  fields, Ref: ref,
		}); err != nil {
			return err
		}
	}
	return nil
}

// i30Parser reads a directory index saved to a file on its own (an "$I30"
// exported from an image by a forensic tool). The directory's own name is not
// in the index, so paths are the bare file names, with the directory's record
// number in the fields.
type i30Parser struct{}

func (i30Parser) Name() string    { return "ntfs-index" }
func (i30Parser) Version() string { return "1" }

func (i30Parser) Parse(ctx *Context) error {
	live, slack := readIndexStream(ctx.File, ctx.Size, ctx.Warn)
	for _, e := range live {
		if e.namespace == 2 { // the 8.3 short name of an entry already listed
			continue
		}
		if err := emitIndexEntry(ctx, e, "i30", "$I30", "listed in the directory index", e.name,
			fmt.Sprintf("index entry at offset %d", e.offset), nil); err != nil {
			return err
		}
	}
	for _, e := range slack {
		if err := emitIndexEntry(ctx, e, "i30", "$I30-slack",
			"recovered from unused space in the directory index, so the file was deleted, renamed, moved, or had these times before they changed", e.name,
			fmt.Sprintf("slack entry at offset %d", e.offset), nil); err != nil {
			return err
		}
	}
	if len(live)+len(slack) == 0 {
		return ErrNothingExtracted
	}
	ctx.Note("%d live and %d recovered index entries. A recovered entry's times are the file's own times as the directory last recorded them, not the time it was deleted", len(live), len(slack))
	return nil
}
