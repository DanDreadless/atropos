package parsers

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// SQLite write-ahead logs. A database in WAL mode writes changes to a
// separate "-wal" file first and copies them into the database only now
// and then (a checkpoint), so a database copied from a running browser can
// lack its newest rows, which are in the log.
//
// Written from SQLite's own file format documentation ("The Write-Ahead
// Log File Format", sqlite.org/fileformat2.html#walformat): a 32-byte
// header, then frames of a 24-byte header and one page. A frame counts
// only if its salts match the header's and the running checksum holds; a
// transaction counts only if its last frame (the commit, which records
// the database size) does. Applying the log means writing, for each page,
// its newest committed version over the database.
//
// The log does not name its database, and names are not used to pair
// files. A log is applied to a database only if its pages fit that
// database: the same page size, the database in WAL mode, and each logged
// page of the kind the database has at that position (table or index),
// holding rows with as many columns as the table that owns the page.

const (
	walHeader      = 32
	walFrameHeader = 24
	walMaxFrames   = 1 << 22
)

type walLog struct {
	pageSize   int64
	frames     int   // valid frames, committed or not
	committed  int   // frames up to and including the last commit
	commits    int   // transactions
	dbPages    int64 // database size in pages after the last commit
	pages      map[uint32]int64
	superseded int // committed frames replaced by a later version of their page
	file       *os.File
}

// isWALHeader says whether b begins with a SQLite write-ahead log header.
func isWALHeader(b []byte) bool {
	if len(b) < walHeader {
		return false
	}
	m := binary.BigEndian.Uint32(b)
	ps := binary.BigEndian.Uint32(b[8:])
	return (m == 0x377f0682 || m == 0x377f0683) && binary.BigEndian.Uint32(b[4:]) == 3007000 &&
		(ps == 1 || ps >= 512 && ps <= 32768 && ps&(ps-1) == 0)
}

func walChecksum(b []byte, bigEndian bool, s0, s1 uint32) (uint32, uint32) {
	var bo binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		bo = binary.BigEndian
	}
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += bo.Uint32(b[i:]) + s1
		s1 += bo.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}

// readWAL reads a write-ahead log's committed frames.
func readWAL(r io.ReaderAt, size int64) (*walLog, error) {
	h := make([]byte, walHeader)
	if _, err := r.ReadAt(h, 0); err != nil || !isWALHeader(h) {
		return nil, errors.New("not a SQLite write-ahead log")
	}
	be := binary.BigEndian
	big := be.Uint32(h) == 0x377f0683
	w := &walLog{pageSize: int64(be.Uint32(h[8:])), pages: map[uint32]int64{}}
	if w.pageSize == 1 {
		w.pageSize = 65536
	}
	s0, s1 := walChecksum(h[:24], big, 0, 0)
	if s0 != be.Uint32(h[24:]) || s1 != be.Uint32(h[28:]) {
		return nil, errors.New("the write-ahead log's header checksum does not hold")
	}
	salt1, salt2 := be.Uint32(h[16:]), be.Uint32(h[20:])
	frame := make([]byte, walFrameHeader+w.pageSize)
	pending := map[uint32]int64{}
	pendingFrames := 0
	for off := int64(walHeader); off+int64(len(frame)) <= size && w.frames < walMaxFrames; off += int64(len(frame)) {
		if _, err := r.ReadAt(frame, off); err != nil {
			break
		}
		if be.Uint32(frame[8:]) != salt1 || be.Uint32(frame[12:]) != salt2 {
			break // a frame left from before the log was last restarted
		}
		s0, s1 = walChecksum(frame[:8], big, s0, s1)
		s0, s1 = walChecksum(frame[walFrameHeader:], big, s0, s1)
		if s0 != be.Uint32(frame[16:]) || s1 != be.Uint32(frame[20:]) {
			break
		}
		w.frames++
		pendingFrames++
		pg := be.Uint32(frame)
		if pg == 0 {
			break
		}
		pending[pg] = off + walFrameHeader
		if commit := be.Uint32(frame[4:]); commit != 0 {
			for p, at := range pending {
				if _, ok := w.pages[p]; ok {
					w.superseded++
				}
				w.pages[p] = at
			}
			w.superseded += pendingFrames - len(pending)
			pending, pendingFrames = map[uint32]int64{}, 0
			w.commits++
			w.committed = w.frames
			w.dbPages = int64(commit)
		}
	}
	return w, nil
}

func sqliteVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7F)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// leafColumns returns the column count of each row on a table leaf page
// whose record header lies within the page.
func leafColumns(page []byte, first bool) []int {
	h := 0
	if first {
		h = 100
	}
	if len(page) < h+8 || page[h] != 13 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(page[h+3:]))
	var out []int
	for i := 0; i < n && i < 64; i++ {
		at := h + 8 + 2*i
		if at+2 > len(page) {
			break
		}
		c := int(binary.BigEndian.Uint16(page[at:]))
		if c >= len(page) {
			continue
		}
		_, k1 := sqliteVarint(page[c:]) // payload length
		_, k2 := sqliteVarint(page[c+k1:])
		p := c + k1 + k2
		if k1 == 0 || k2 == 0 || p >= len(page) {
			continue
		}
		hs, k3 := sqliteVarint(page[p:])
		if k3 == 0 || hs < uint64(k3) || p+int(hs) > len(page) {
			continue
		}
		cols := 0
		for q := p + k3; q < p+int(hs); cols++ {
			_, k := sqliteVarint(page[q:])
			if k == 0 {
				break
			}
			q += k
		}
		out = append(out, cols)
	}
	return out
}

// walFit compares a log's pages with a database: how many logged pages
// agree with it and how many contradict it.
func walFit(dbPath string, dbFile *os.File, w *walLog) (agree, disagree int, err error) {
	hdr := make([]byte, 100)
	if _, err := dbFile.ReadAt(hdr, 0); err != nil {
		return 0, 0, err
	}
	ps := int64(binary.BigEndian.Uint16(hdr[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps != w.pageSize {
		return 0, 1, nil
	}
	if hdr[18] != 2 || hdr[19] != 2 {
		return 0, 1, nil // the database is not in WAL mode
	}
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+"?mode=ro&immutable=1&_pragma=trusted_schema(0)&_pragma=query_only(1)")
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()
	// What each page of the database is, and the column count of each table.
	type stat struct {
		name, kind string
		page       uint32
	}
	var stats []stat
	rows, err := db.Query(`SELECT name, pageno, pagetype FROM dbstat`)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var st stat
		if rows.Scan(&st.name, &st.page, &st.kind) == nil {
			stats = append(stats, st)
		}
	}
	rows.Close()
	kinds := map[string]string{"sqlite_master": "table", "sqlite_schema": "table"}
	cols := map[string]int{"sqlite_master": 5, "sqlite_schema": 5}
	rows, err = db.Query(`SELECT type, name FROM sqlite_master WHERE type IN ('table','index')`)
	if err != nil {
		return 0, 0, err
	}
	var tables []string
	for rows.Next() {
		var t, n string
		if rows.Scan(&t, &n) == nil {
			kinds[n] = t
			if t == "table" {
				tables = append(tables, n)
			}
		}
	}
	rows.Close()
	for _, t := range tables {
		if r, err := db.Query(`SELECT * FROM "` + strings.ReplaceAll(t, `"`, `""`) + `" LIMIT 0`); err == nil {
			if c, err := r.Columns(); err == nil {
				cols[t] = len(c)
			}
			r.Close()
		}
	}
	owners := map[uint32]pageOwner{}
	for _, st := range stats {
		if k := kinds[st.name]; k != "" && (st.kind == "leaf" || st.kind == "internal") {
			owners[st.page] = pageOwner{name: st.name, kind: k}
		}
	}
	return walCompare(w, owners, cols)
}

type pageOwner struct {
	name, kind string // kind: table or index
}

func walCompare(w *walLog, owners map[uint32]pageOwner, cols map[string]int) (int, int, error) {
	buf := make([]byte, w.pageSize)
	agree, disagree := 0, 0
	for pg, at := range w.pages {
		o, ok := owners[pg]
		// The schema table is alike in every database: it proves nothing.
		if !ok || o.name == "sqlite_master" || o.name == "sqlite_schema" {
			continue
		}
		if _, err := w.file.ReadAt(buf, at); err != nil {
			return agree, disagree, err
		}
		t := buf[0]
		var kind string
		switch t {
		case 13, 5:
			kind = "table"
		case 10, 2:
			kind = "index"
		default:
			continue // the page has become free or overflow: says nothing
		}
		if kind != o.kind {
			disagree++
			continue
		}
		want, known := cols[o.name]
		if t != 13 || !known {
			continue // an interior or index page of the right kind: too common to count
		}
		exact, more := 0, 0
		for _, c := range leafColumns(buf, false) {
			switch {
			case c == want:
				exact++
			case c > want:
				more++
			}
			// Fewer columns: a row older than a column added later. Neutral.
		}
		switch {
		case more > 0:
			disagree++
		case exact > 0:
			agree++
		}
	}
	return agree, disagree, nil
}

// pickWAL chooses, among the logs offered, the one whose pages fit this
// database. It returns nil, with a reason, when none or more than one does.
func pickWAL(ctx *Context) (*walLog, string, string) {
	var best *walLog
	bestPath, why := "", ""
	bestAgree, tied := 0, false
	for _, p := range ctx.Segments {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		st, _ := f.Stat()
		w, err := readWAL(f, st.Size())
		if err != nil || w.committed == 0 {
			f.Close()
			continue
		}
		w.file = f
		agree, disagree, err := walFit(ctx.File.Name(), ctx.File, w)
		if err != nil || agree == 0 || disagree*10 > agree {
			f.Close()
			continue
		}
		switch {
		case agree > bestAgree:
			if best != nil {
				best.file.Close()
			}
			best, bestPath, bestAgree, tied = w, p, agree, false
		case agree == bestAgree:
			tied = true
			f.Close()
		default:
			f.Close()
		}
	}
	if tied {
		if best != nil {
			best.file.Close()
		}
		return nil, "", "more than one write-ahead log in the case fits this database equally well, so none was applied"
	}
	return best, bestPath, why
}

// applyWAL writes a copy of the database with the log's committed pages
// over it, in dir, and returns its path.
func applyWAL(ctx *Context, w *walLog, dir string) (string, error) {
	out, err := os.CreateTemp(dir, "sqlite-wal-applied-*.db")
	if err != nil {
		return "", err
	}
	name := out.Name()
	fail := func(err error) (string, error) {
		out.Close()
		os.Remove(name)
		return "", err
	}
	if _, err := io.Copy(out, io.NewSectionReader(ctx.File, 0, ctx.Size)); err != nil {
		return fail(err)
	}
	buf := make([]byte, w.pageSize)
	for pg, at := range w.pages {
		if int64(pg) > w.dbPages {
			continue // beyond the database's size after the last commit
		}
		if _, err := w.file.ReadAt(buf, at); err != nil {
			return fail(err)
		}
		if _, err := out.WriteAt(buf, int64(pg-1)*w.pageSize); err != nil {
			return fail(err)
		}
	}
	if err := out.Truncate(w.dbPages * w.pageSize); err != nil {
		return fail(err)
	}
	// The copy no longer needs its log: mark it as a rollback-journal
	// database so SQLite does not look for one beside it.
	if _, err := out.WriteAt([]byte{1, 1}, 18); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func walDescribe(w *walLog, path string) string {
	return fmt.Sprintf("write-ahead log %s applied: %d committed transactions (%d frames, %d of them replaced by later versions of the same page); %d frames after the last commit were not applied",
		filepath.Base(path), w.commits, w.committed, w.superseded, w.frames-w.committed)
}
