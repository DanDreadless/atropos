package parsers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// logFileParser reads the NTFS transaction log, $LogFile. NTFS writes every
// change to a volume's metadata into this log before making it, so that an
// interrupted change can be finished or undone. The log is a ring a few tens
// of megabytes long, and on a busy volume holds only the last hours or days.
//
// What it gives an investigation: the names and times of files as they were
// when they were created, added to a directory or removed from one, including
// files that have since gone and times that have since been changed.
//
// What it does not give: the log has no clock. A record says what changed and
// in what order (its log sequence number), never when. Events are therefore
// placed at the file's own timestamps as the record carried them, and each
// event carries the sequence number so the order of operations can be read.
type logFileParser struct{}

func (logFileParser) Name() string    { return "ntfs-logfile" }
func (logFileParser) Version() string { return "1" }

func (logFileParser) Parse(ctx *Context) error {
	n, err := parseLogFile(ctx, ctx.File, ctx.Size, "", nil)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNothingExtracted
	}
	return nil
}

// errLogUnreadable marks a log whose structure could not be read, as opposed
// to an event the store refused.
var errLogUnreadable = errors.New("transaction log unreadable")

// Redo and undo operation codes that carry a file name.
const (
	opInitFileRecord   = 0x02
	opAddIndexRoot     = 0x0C
	opDeleteIndexRoot  = 0x0D
	opAddIndexAlloc    = 0x0E
	opDeleteIndexAlloc = 0x0F
	opMaxKnown         = 0x25
)

type logRecord struct {
	lsn            uint64
	redoOp, undoOp uint16
	redo, undo     []byte
	offset         int64
}

const (
	logRecordHeader = 0x30
	maxLogRecord    = 4 << 20
)

// readLogRecords finds every operation record in the log. A record is
// accepted only where its sequence number points at the very place it was
// found, which the log's own layout guarantees for real records, so stale
// bytes and the middle of long records are not mistaken for records.
func readLogRecords(r io.ReaderAt, size int64, warn func(string, ...any)) ([]logRecord, error) {
	le := binary.LittleEndian
	var pageSize int64
	var seqBits uint32
	var dataOff int
	head := make([]byte, 0x1000)
	for _, at := range []int64{0, 0x1000} {
		if _, err := r.ReadAt(head, at); err != nil || string(head[:4]) != "RSTR" {
			continue
		}
		ra := int(le.Uint16(head[0x18:]))
		if ra+0x28 > len(head) {
			continue
		}
		ps, bits, do := int64(le.Uint32(head[0x14:])), le.Uint32(head[ra+0x10:]), int(le.Uint16(head[ra+0x26:]))
		if (ps == 0x1000 || ps == 0x2000 || ps == 0x200 || ps == 0x400 || ps == 0x800) && bits >= 20 && bits <= 60 && do >= 0x28 && int64(do) < ps && do%8 == 0 {
			pageSize, seqBits, dataOff = ps, bits, do
			break
		}
	}
	if pageSize == 0 {
		return nil, fmt.Errorf("%w: no usable restart page, so this does not look like an NTFS transaction log, or its start is damaged", errLogUnreadable)
	}
	offMask := uint64(1)<<(64-seqBits) - 1
	firstNormal := 4 * pageSize // two restart pages, then two pages holding copies of the newest page
	page := make([]byte, pageSize)
	next := make([]byte, pageSize)
	var out []logRecord
	seen := map[uint64]bool{}
	torn, lost := 0, 0

	loadPage := func(buf []byte, at int64) bool {
		if at+pageSize > size {
			return false
		}
		if _, err := r.ReadAt(buf, at); err != nil || string(buf[:4]) != "RCRD" {
			return false
		}
		if !applyFixups(buf) {
			torn++
		}
		return true
	}
	for at := 2 * pageSize; at+pageSize <= size; at += pageSize {
		if !loadPage(page, at) {
			continue
		}
		for p := dataOff; p+logRecordHeader <= int(pageSize); p += 8 {
			lsn := le.Uint64(page[p:])
			if lsn == 0 {
				continue
			}
			want := int64(lsn&offMask) << 3
			if at >= firstNormal && want != at+int64(p) || at < firstNormal && want%pageSize != int64(p) {
				continue
			}
			dataLen := int(le.Uint32(page[p+0x18:]))
			recType := le.Uint32(page[p+0x20:])
			if recType != 1 && recType != 2 || dataLen < 0x20 || dataLen > maxLogRecord {
				continue
			}
			// Gather the record's data, which may run on into following pages.
			data := make([]byte, 0, dataLen)
			take := int(pageSize) - (p + logRecordHeader)
			if take > dataLen {
				take = dataLen
			}
			data = append(data, page[p+logRecordHeader:p+logRecordHeader+take]...)
			spilled := false
			for cont := at + pageSize; len(data) < dataLen; cont += pageSize {
				spilled = true
				if cont+pageSize > size {
					cont = firstNormal // the log is a ring
				}
				if at < firstNormal || !loadPage(next, cont) {
					data = nil
					break
				}
				take := dataLen - len(data)
				if take > int(pageSize)-dataOff {
					take = int(pageSize) - dataOff
				}
				data = append(data, next[dataOff:dataOff+take]...)
			}
			if data == nil {
				// The two copy pages hold a snapshot of the newest page with
				// older bytes after it; a record running off one of those is
				// stale, not lost.
				if at >= firstNormal {
					lost++
				}
				break
			}
			if recType == 1 && !seen[lsn] {
				if rec, ok := decodeLogRecord(lsn, data, at+int64(p)); ok {
					seen[lsn] = true
					out = append(out, rec)
				}
			}
			if spilled {
				break // the rest of this page belongs to the record
			}
			p += (logRecordHeader+dataLen+7)&^7 - 8
		}
	}
	if torn > 0 {
		warn("%d log pages failed their sector check (torn or partly overwritten); what could be read from them was kept", torn)
	}
	if lost > 0 {
		warn("%d records ran on into pages that have been overwritten and were skipped", lost)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].lsn < out[j].lsn })
	return out, nil
}

func decodeLogRecord(lsn uint64, d []byte, at int64) (logRecord, bool) {
	le := binary.LittleEndian
	rec := logRecord{lsn: lsn, offset: at, redoOp: le.Uint16(d), undoOp: le.Uint16(d[2:])}
	if rec.redoOp > opMaxKnown || rec.undoOp > opMaxKnown {
		return rec, false
	}
	ro, rl := int(le.Uint16(d[4:])), int(le.Uint16(d[6:]))
	uo, ul := int(le.Uint16(d[8:])), int(le.Uint16(d[10:]))
	if ro+rl > len(d) || uo+ul > len(d) {
		return rec, false
	}
	rec.redo, rec.undo = d[ro:ro+rl], d[uo:uo+ul]
	return rec, true
}

// fileRecordEntry reads the name and times out of a file record as the log
// holds it at the moment the record was first written.
func fileRecordEntry(b []byte) (e indexEntry, ok bool) {
	le := binary.LittleEndian
	if len(b) < 0x38 || string(b[:4]) != "FILE" {
		return e, false
	}
	e.sequence = uint64(le.Uint16(b[0x10:]))
	e.entry = uint64(le.Uint32(b[0x2C:]))
	if le.Uint16(b[0x16:])&2 != 0 {
		e.flags = 0x10000000
	}
	var siOK bool
	var si [4]time.Time
	best := -1
	for p := int(le.Uint16(b[0x14:])); p+0x18 <= len(b); {
		typ, alen := le.Uint32(b[p:]), int(le.Uint32(b[p+4:]))
		if typ == 0xFFFFFFFF || alen < 0x18 || p+alen > len(b) {
			break
		}
		if b[p+8] == 0 { // resident
			clen, coff := int(le.Uint32(b[p+0x10:])), int(le.Uint16(b[p+0x14:]))
			if coff+clen <= alen {
				c := b[p+coff : p+coff+clen]
				switch {
				case typ == 0x10 && len(c) >= 0x20:
					var a, b2, c2, d bool
					si[0], a = indexTime(le.Uint64(c))
					si[1], b2 = indexTime(le.Uint64(c[8:]))
					si[2], c2 = indexTime(le.Uint64(c[16:]))
					si[3], d = indexTime(le.Uint64(c[24:]))
					siOK = a && b2 && c2 && d
				case typ == 0x30 && len(c) >= 0x44:
					// Reuse the index entry reader: an entry is a 16-byte
					// header followed by exactly this attribute.
					tmp := make([]byte, 0x10+(len(c)+7)&^7)
					le.PutUint16(tmp[8:], uint16(len(tmp)))
					le.PutUint16(tmp[10:], uint16(len(c)))
					copy(tmp[0x10:], c)
					if fe, _, good := parseIndexEntry(tmp, false); good && int(fe.namespace) != 2 && best < 1 {
						// Prefer the long name over the 8.3 one.
						keepEntry, keepSeq, keepFlags := e.entry, e.sequence, e.flags
						e = fe
						e.entry, e.sequence, e.flags = keepEntry, keepSeq, keepFlags|fe.flags
						best = 1
					}
				}
			}
		}
		p += alen
	}
	if best < 0 {
		return e, false
	}
	if siOK {
		// $STANDARD_INFORMATION is what Explorer shows; prefer it.
		e.created, e.modified, e.changed, e.accessed = si[0], si[1], si[2], si[3]
	}
	return e, true
}

// parseLogFile emits what the log's records say about file names. where
// prefixes each reference ("$LogFile in the volume, "); resolve turns a
// parent directory's record number into its path where the caller knows it.
func parseLogFile(ctx *Context, r io.ReaderAt, size int64, where string, resolve func(entry uint64) string) (int, error) {
	recs, err := readLogRecords(r, size, ctx.Warn)
	if err != nil {
		return 0, err
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	emitted := 0
	for _, rec := range recs {
		var e indexEntry
		var ok bool
		var typ, what string
		switch {
		case rec.redoOp == opAddIndexRoot || rec.redoOp == opAddIndexAlloc:
			e, _, ok = parseIndexEntry(rec.redo, false)
			typ, what = "$LogFile-name-added", "the log records this name being added to a directory (a file created, renamed to this, or moved here)"
		case rec.redoOp == opDeleteIndexRoot || rec.redoOp == opDeleteIndexAlloc:
			e, _, ok = parseIndexEntry(rec.undo, false)
			typ, what = "$LogFile-name-removed", "the log records this name being removed from a directory (a file deleted, renamed away, or moved out)"
		case rec.redoOp == opInitFileRecord:
			e, ok = fileRecordEntry(rec.redo)
			typ, what = "$LogFile-record-created", "the log records this file's record being written for the first time"
		default:
			continue
		}
		if !ok || e.namespace == 2 {
			continue
		}
		key := typ + "|" + e.key()
		if seen[key] {
			continue
		}
		seen[key] = true
		counts[typ]++
		name := clean(e.name)
		path := name
		if resolve != nil {
			if dir := resolve(e.parentEntry); dir != "" {
				path = joinDir(dir, name)
			}
		}
		if err := emitIndexEntry(ctx, e, "logfile", typ, what+". The log has no clock: this is one of the file's own times, not when the operation happened",
			path, fmt.Sprintf("%srecord at offset %d, LSN %d", where, rec.offset, rec.lsn),
			map[string]any{"lsn": rec.lsn, "redo_operation": rec.redoOp, "undo_operation": rec.undoOp}); err != nil {
			return emitted, err
		}
		emitted++
	}
	ctx.Note("transaction log: %d operation records read; %d names added to directories, %d removed, %d file records created. The log has no clock, so each event sits at one of the file's own times; the lsn field of each event gives the order things happened in",
		len(recs), counts["$LogFile-name-added"], counts["$LogFile-name-removed"], counts["$LogFile-record-created"])
	return emitted, nil
}
