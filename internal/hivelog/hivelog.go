// Package hivelog applies registry transaction logs (.LOG, .LOG1, .LOG2) to
// a hive, as Windows does when it loads a hive that was not fully written:
// changes made in the last hour or so before a system was shut down or
// imaged are often in the logs and nowhere else.
//
// Written from Maxim Suhanov's "Windows registry file format specification"
// (github.com/msuhanov/regf), with yarp's recovery code and Microsoft's
// Marvin32 source read alongside. The result is checked against hives that
// Windows itself recovered from the same files.
//
// Nothing is written: the recovered hive is a view (Overlay) that reads the
// original file and puts the logged pages over it.
package hivelog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"
)

const (
	baseBlockSize = 4096
	sector        = 512
	// maxLog bounds how much of one log is read into memory. Real logs are
	// a few megabytes; a log grows only while the hive is not written back.
	maxLog = 512 << 20
	// maxHbins bounds the hive size a log may declare (a hive is limited
	// to 2 GiB by Windows).
	maxHbins = 2 << 30
)

// File types in a base block.
const (
	TypePrimary = 0
	TypeLogOld  = 1 // Windows XP to 8
	TypeLogW2K  = 2 // Windows 2000
	TypeLogNew  = 6 // Windows 8.1 on
)

// Base is what a base block says. A log holds a copy of its hive's base
// block, partly updated, in its first sector.
type Base struct {
	Seq1, Seq2 uint32 // primary and secondary sequence numbers
	Written    uint64 // last written, FILETIME
	Minor      uint32
	Type       uint32
	Root       uint32 // root cell offset
	HbinsSize  uint32
	Name       string // the end of the hive's path, as the hive records it
	RmID       [16]byte
	Flags      uint32
	ChecksumOK bool
	raw        []byte
}

// ParseBase reads a base block from the start of b, which must hold at
// least one sector.
func ParseBase(b []byte) (Base, error) {
	if len(b) < sector || string(b[:4]) != "regf" {
		return Base{}, errors.New(`not a registry file: no "regf" signature`)
	}
	le := binary.LittleEndian
	var x Base
	x.Seq1, x.Seq2 = le.Uint32(b[4:]), le.Uint32(b[8:])
	x.Written = le.Uint64(b[12:])
	x.Minor = le.Uint32(b[24:])
	x.Type = le.Uint32(b[28:])
	x.Root = le.Uint32(b[36:])
	x.HbinsSize = le.Uint32(b[40:])
	u := make([]uint16, 0, 32)
	for i := 48; i < 112; i += 2 {
		c := le.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	x.Name = string(utf16.Decode(u))
	copy(x.RmID[:], b[112:128])
	x.Flags = le.Uint32(b[144:])
	x.ChecksumOK = checksum(b) == le.Uint32(b[508:])
	n := baseBlockSize
	if len(b) < n {
		n = len(b)
	}
	x.raw = append([]byte(nil), b[:n]...)
	return x, nil
}

// checksum is the XOR-32 of the first 508 bytes, with 0 and -1 avoided.
func checksum(b []byte) uint32 {
	var c uint32
	for i := 0; i < 508; i += 4 {
		c ^= binary.LittleEndian.Uint32(b[i:])
	}
	switch c {
	case 0xFFFFFFFF:
		return 0xFFFFFFFE
	case 0:
		return 1
	}
	return c
}

// IsLog says whether the base block is a transaction log's.
func (b Base) IsLog() bool {
	return b.Type == TypeLogOld || b.Type == TypeLogW2K || b.Type == TypeLogNew
}

// Dirty says whether a hive's base block shows that it was not fully
// written: its checksum is wrong, or its two sequence numbers differ.
func (b Base) Dirty() bool { return !b.ChecksumOK || b.Seq1 != b.Seq2 }

// SameHive says whether a log's base block belongs to this hive: the same
// recorded file name and, where Windows set one, the same resource manager
// identifier. Names alone are not enough: every SYSTEM hive is "SYSTEM".
func (b Base) SameHive(log Base) bool {
	return b.Name != "" && b.Name == log.Name && b.RmID == log.RmID
}

// ---------------------------------------------------------------------------
// The recovered hive.

// Overlay reads a hive with logged pages put over it. Pages are 512 bytes.
type Overlay struct {
	r        io.ReaderAt
	rsize    int64
	size     int64
	head     [baseBlockSize]byte
	pages    map[int64][]byte
	modified int
}

func newOverlay(r io.ReaderAt, size int64) *Overlay {
	o := &Overlay{r: r, rsize: size, size: size, pages: map[int64][]byte{}}
	io.ReadFull(io.NewSectionReader(r, 0, baseBlockSize), o.head[:])
	return o
}

// Size is the size of the recovered hive.
func (o *Overlay) Size() int64 { return o.size }

// Pages is how many 512-byte pages of the hive the logs replaced.
func (o *Overlay) Pages() int { return len(o.pages) }

func (o *Overlay) write(off int64, data []byte) {
	for len(data) > 0 {
		page := off &^ (sector - 1)
		p, ok := o.pages[page]
		if !ok {
			p = make([]byte, sector)
			o.readUnder(p, page)
			o.pages[page] = p
		}
		n := copy(p[off-page:], data)
		data, off = data[n:], off+int64(n)
	}
	if off > o.size {
		o.size = off
	}
}

// readUnder reads what lies under the logged pages: the original file, and
// zeros past its end (Windows grows the file to fit).
func (o *Overlay) readUnder(p []byte, off int64) {
	for i := range p {
		p[i] = 0
	}
	if off < o.rsize {
		n := int64(len(p))
		if off+n > o.rsize {
			n = o.rsize - off
		}
		o.r.ReadAt(p[:n], off)
	}
}

// ReadAt reads the recovered hive.
func (o *Overlay) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	done := 0
	for done < len(p) {
		if off >= o.size {
			return done, io.EOF
		}
		var n int
		switch page := off &^ (sector - 1); {
		case off < baseBlockSize:
			n = copy(p[done:], o.head[off:])
		case o.pages[page] != nil:
			n = copy(p[done:], o.pages[page][off-page:])
		default:
			// Up to the next logged page or the end, from beneath.
			end := page + sector
			for end < o.size && o.pages[end] == nil && end-off < int64(len(p)-done) {
				end += sector
			}
			if end > o.size {
				end = o.size
			}
			want := int64(len(p) - done)
			if end-off < want {
				want = end - off
			}
			o.readUnder(p[done:done+int(want)], off)
			n = int(want)
		}
		if n <= 0 {
			return done, io.ErrUnexpectedEOF
		}
		done += n
		off += int64(n)
	}
	return done, nil
}

// ---------------------------------------------------------------------------
// Recovery.

// Log is a transaction log offered for a hive.
type Log struct {
	Name string // for the report only
	R    io.ReaderAt
	Size int64
}

// Applied says what was taken from one log.
type Applied struct {
	Log            string
	Format         string // "new" (Windows 8.1 on) or "old"
	Entries        int
	First, Last    uint32 // sequence numbers of the entries applied (new format)
	Pages          int
	StoppedBecause string // why entries after the last applied were not used
}

// Result is a recovered hive and what went into it.
type Result struct {
	Hive        *Overlay // nil when nothing was applied
	Applied     []Applied
	NotUsed     []string // logs offered and not used, each with the reason
	BaseFromLog bool     // the hive's own base block was damaged; a log's copy was used
	Clean       bool     // the hive was fully written: Windows would apply nothing
}

type candidate struct {
	log  Log
	base Base
	data []byte
}

// Recover applies whichever of the logs belong to the hive, the way Windows
// does. A log that is not this hive's, or that Windows would not apply, is
// listed in NotUsed with the reason. size is the size of the hive file.
func Recover(hive io.ReaderAt, size int64, logs []Log) (*Result, error) {
	head := make([]byte, baseBlockSize)
	if n, _ := hive.ReadAt(head, 0); n < sector {
		return nil, errors.New("the hive is shorter than its base block")
	}
	primary, err := ParseBase(head)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	var olds, news []candidate
	for _, l := range logs {
		if l.Size < sector {
			res.NotUsed = append(res.NotUsed, l.Name+": empty")
			continue
		}
		if l.Size > maxLog {
			res.NotUsed = append(res.NotUsed, fmt.Sprintf("%s: %d bytes, larger than any real log; not read", l.Name, l.Size))
			continue
		}
		data := make([]byte, l.Size)
		if _, err := l.R.ReadAt(data, 0); err != nil && err != io.EOF {
			res.NotUsed = append(res.NotUsed, fmt.Sprintf("%s: %v", l.Name, err))
			continue
		}
		b, err := ParseBase(data)
		switch {
		case err != nil:
			res.NotUsed = append(res.NotUsed, l.Name+": "+err.Error())
		case !b.IsLog():
			res.NotUsed = append(res.NotUsed, l.Name+": not a transaction log")
		case !primary.SameHive(b):
			res.NotUsed = append(res.NotUsed, l.Name+": the log of another hive")
		case b.Type == TypeLogNew:
			news = append(news, candidate{l, b, data})
		default:
			olds = append(olds, candidate{l, b, data})
		}
	}
	if !primary.Dirty() {
		res.Clean = true
		for _, c := range append(olds, news...) {
			res.NotUsed = append(res.NotUsed, c.log.Name+": the hive was fully written, so Windows would not apply it")
		}
		return res, nil
	}
	o := newOverlay(hive, size)
	var newBase []byte
	var seq uint32
	hbins := primary.HbinsSize
	flags := primary.Flags
	switch {
	case len(news) > 0:
		seq, hbins, flags, newBase = recoverNew(res, o, primary, news, hbins, flags)
		for _, c := range olds {
			res.NotUsed = append(res.NotUsed, c.log.Name+": an old-format log beside new-format ones")
		}
	case len(olds) > 0:
		seq, hbins, flags, newBase = recoverOld(res, o, primary, olds, hbins, flags)
	}
	if len(res.Applied) == 0 {
		return res, nil
	}
	// The base block: the hive's own, or a log's copy when the hive's is
	// damaged, brought up to date as Windows writes it after recovery.
	nb := make([]byte, baseBlockSize)
	if primary.ChecksumOK {
		copy(nb, primary.raw)
	} else {
		copy(nb, newBase[:sector])
		res.BaseFromLog = true
	}
	le := binary.LittleEndian
	le.PutUint32(nb[4:], seq)
	le.PutUint32(nb[8:], seq)
	le.PutUint32(nb[28:], TypePrimary)
	le.PutUint32(nb[40:], hbins)
	le.PutUint32(nb[144:], flags)
	le.PutUint32(nb[508:], checksum(nb))
	copy(o.head[:], nb)
	if end := int64(baseBlockSize) + int64(hbins); end > o.size {
		o.size = end
	}
	res.Hive = o
	return res, nil
}

// seqBefore compares sequence numbers that may have wrapped.
func seqBefore(a, b uint32) bool { return a != b && b-a < 0x80000000 }

func recoverNew(res *Result, o *Overlay, primary Base, logs []candidate, hbins, flags uint32) (uint32, uint32, uint32, []byte) {
	// The log whose entries start earlier is applied first.
	// Logs starting at the same sequence are ordered by their bytes, so that
	// nothing below depends on the order the files arrived in.
	sort.SliceStable(logs, func(i, j int) bool {
		a, b := logs[i].base.Seq1, logs[j].base.Seq1
		if a == b {
			return bytes.Compare(logs[i].data, logs[j].data) < 0
		}
		return seqBefore(a, b)
	})
	if len(logs) > 2 {
		// More logs name this hive than Windows keeps (two): copies of the
		// same hive's logs from different times, or from another copy of it.
		// The pair whose entries carry this hive furthest is the one Windows
		// would have had beside it; the others are left, each said why. Ties
		// go to the earlier pair in the sorted order, so the choice does not
		// depend on the order the files arrived in.
		cands := logs
		if len(cands) > maxCandidates {
			for _, extra := range cands[maxCandidates:] {
				res.NotUsed = append(res.NotUsed, extra.log.Name+": more logs of this hive than are tried")
			}
			cands = cands[:maxCandidates]
		}
		bi, bj, best := 0, 1, -1
		for i := range cands {
			for j := i + 1; j < len(cands); j++ {
				if n := reach(primary, []candidate{cands[i], cands[j]}); n > best {
					bi, bj, best = i, j, n
				}
			}
		}
		for k, extra := range cands {
			if k != bi && k != bj {
				res.NotUsed = append(res.NotUsed, extra.log.Name+": a third new-format log of this hive; Windows uses two, and the two whose entries reach furthest were used")
			}
		}
		logs = []candidate{cands[bi], cands[bj]}
	}
	var order []candidate
	if !primary.ChecksumOK {
		// Windows uses only the log with the latest entries.
		order = []candidate{logs[len(logs)-1]}
		if len(logs) > 1 {
			res.NotUsed = append(res.NotUsed, logs[0].log.Name+": the hive's base block is damaged, so only the latest log is used")
		}
	} else {
		order = logs
	}
	var seq uint32
	have := false
	base := order[0].data
	for _, c := range order {
		start := c.base.Seq1
		switch {
		case primary.ChecksumOK && seqBefore(start, primary.Seq2):
			res.NotUsed = append(res.NotUsed, fmt.Sprintf("%s: its entries (from %d) are older than the hive (%d)", c.log.Name, start, primary.Seq2))
			continue
		case have && start != seq+1:
			res.NotUsed = append(res.NotUsed, fmt.Sprintf("%s: its entries start at %d, not at %d where the other log ended", c.log.Name, start, seq+1))
			continue
		}
		a := Applied{Log: c.log.Name, Format: "new"}
		before := len(o.pages)
		expect := start
		for off := sector; off+40 <= len(c.data); {
			e, why := logEntry(c.data[off:], expect)
			if why != "" {
				a.StoppedBecause = why
				break
			}
			for _, p := range e.pages {
				o.write(int64(baseBlockSize)+int64(p.off), p.data)
			}
			if a.Entries == 0 {
				a.First = e.seq
			}
			a.Last, a.Entries = e.seq, a.Entries+1
			hbins = e.hbins
			flags = flags&^1 | e.flags&1
			seq, have = e.seq, true
			expect++
			off += int(e.size)
		}
		a.Pages = len(o.pages) - before
		if a.Entries > 0 {
			res.Applied = append(res.Applied, a)
			base = c.data
		} else {
			res.NotUsed = append(res.NotUsed, fmt.Sprintf("%s: no entry could be applied (%s)", c.log.Name, a.StoppedBecause))
		}
	}
	return seq, hbins, flags, base
}

// maxCandidates bounds the logs of one hive tried in pairs.
const maxCandidates = 8

// reach counts the entries a pair of new-format logs (sorted, earlier first)
// would apply to the hive, by the rules recoverNew applies them by, without
// writing anything.
func reach(primary Base, pair []candidate) int {
	order := pair
	if !primary.ChecksumOK {
		order = pair[len(pair)-1:]
	}
	n, have := 0, false
	var seq uint32
	for _, c := range order {
		start := c.base.Seq1
		if (primary.ChecksumOK && seqBefore(start, primary.Seq2)) || (have && start != seq+1) {
			continue
		}
		expect := start
		for off := sector; off+40 <= len(c.data); {
			e, why := logEntry(c.data[off:], expect)
			if why != "" {
				break
			}
			n++
			seq, have = e.seq, true
			expect++
			off += int(e.size)
		}
	}
	return n
}

type page struct {
	off  uint32
	data []byte
}

type entry struct {
	size, seq, hbins, flags uint32
	pages                   []page
}

// logEntry reads one new-format entry, checking everything Windows checks.
func logEntry(b []byte, expect uint32) (entry, string) {
	le := binary.LittleEndian
	if string(b[:4]) != "HvLE" {
		return entry{}, "no further entry"
	}
	e := entry{size: le.Uint32(b[4:]), flags: le.Uint32(b[8:]), seq: le.Uint32(b[12:]), hbins: le.Uint32(b[16:])}
	count := le.Uint32(b[20:])
	switch {
	case e.size < 40 || e.size%sector != 0 || int64(e.size) > int64(len(b)):
		return entry{}, fmt.Sprintf("entry %d has an impossible size", e.seq)
	case e.hbins == 0 || e.hbins%4096 != 0 || e.hbins > maxHbins:
		return entry{}, fmt.Sprintf("entry %d declares an impossible hive size", e.seq)
	case uint64(count)*8+40 > uint64(e.size):
		return entry{}, fmt.Sprintf("entry %d lists more pages than it holds", e.seq)
	case marvin32(b[40:e.size]) != le.Uint64(b[24:]):
		return entry{}, fmt.Sprintf("entry %d fails its first hash: it was not completely written", e.seq)
	case marvin32(b[:32]) != le.Uint64(b[32:]):
		return entry{}, fmt.Sprintf("entry %d fails its second hash", e.seq)
	case e.seq != expect:
		return entry{}, fmt.Sprintf("entry %d is not the expected %d, so the entries after it are older", e.seq, expect)
	}
	at := 40 + count*8
	for i := uint32(0); i < count; i++ {
		ref := b[40+i*8:]
		off, n := le.Uint32(ref), le.Uint32(ref[4:])
		if n == 0 || n%sector != 0 || uint64(off)+uint64(n) > uint64(e.hbins) || uint64(at)+uint64(n) > uint64(e.size) {
			return entry{}, fmt.Sprintf("entry %d has a page outside the hive or the entry", e.seq)
		}
		e.pages = append(e.pages, page{off, b[at : at+n]})
		at += n
	}
	return e, ""
}

func recoverOld(res *Result, o *Overlay, primary Base, logs []candidate, hbins, flags uint32) (uint32, uint32, uint32, []byte) {
	// A valid old log has equal sequence numbers and a sound checksum, and
	// is as recent as the hive. Of several, the most recent is used.
	var best *candidate
	for i := range logs {
		c := &logs[i]
		switch {
		case !c.base.ChecksumOK || c.base.Seq1 != c.base.Seq2:
			res.NotUsed = append(res.NotUsed, c.log.Name+": its base block shows it was not completely written")
		case primary.ChecksumOK && c.base.Written < primary.Written:
			res.NotUsed = append(res.NotUsed, c.log.Name+": older than the hive")
		case best == nil || c.base.Written > best.base.Written:
			if best != nil {
				res.NotUsed = append(res.NotUsed, best.log.Name+": a more recent log was used")
			}
			best = c
		default:
			res.NotUsed = append(res.NotUsed, c.log.Name+": a more recent log was used")
		}
	}
	if best == nil {
		return 0, hbins, flags, nil
	}
	d := best.data
	hb := best.base.HbinsSize
	if hb == 0 || hb%sector != 0 || hb > maxHbins || len(d) < 2*sector || string(d[sector:sector+4]) != "DIRT" {
		res.NotUsed = append(res.NotUsed, best.log.Name+": no dirty vector after its base block")
		return 0, hbins, flags, nil
	}
	bits := int(hb / sector)
	vec := (bits + 7) / 8
	if sector+4+vec > len(d) {
		res.NotUsed = append(res.NotUsed, best.log.Name+": its dirty vector is cut short")
		return 0, hbins, flags, nil
	}
	bitmap := d[sector+4 : sector+4+vec]
	at := (sector + 4 + vec + sector - 1) / sector * sector
	a := Applied{Log: best.log.Name, Format: "old"}
	for i := 0; i < bits; i++ {
		if bitmap[i/8]&(1<<(i%8)) == 0 {
			continue
		}
		if at+sector > len(d) {
			a.StoppedBecause = "the log ends before its last dirty page"
			break
		}
		o.write(int64(baseBlockSize)+int64(i)*sector, d[at:at+sector])
		at += sector
	}
	a.Pages = len(o.pages)
	if a.Pages == 0 {
		res.NotUsed = append(res.NotUsed, best.log.Name+": it records no changed pages")
		return 0, hbins, flags, nil
	}
	a.Entries = 1
	res.Applied = append(res.Applied, a)
	return best.base.Seq1, hb, best.base.Flags, d
}

// ---------------------------------------------------------------------------

// marvin32 is the 64-bit Marvin32 hash with the seed Windows uses for
// registry log entries. The data is always a whole number of 32-bit words
// here, so only the 0x80 terminator follows them.
func marvin32(b []byte) uint64 {
	const seed uint64 = 0x82EF4D887A4E55C5
	lo, hi := uint32(seed&0xFFFFFFFF), uint32(seed>>32)
	mix := func(v uint32) {
		lo += v
		hi ^= lo
		lo = (lo<<20 | lo>>12) + hi
		hi = (hi<<9 | hi>>23) ^ lo
		lo = (lo<<27 | lo>>5) + hi
		hi = hi<<19 | hi>>13
	}
	n := len(b) &^ 3
	for i := 0; i < n; i += 4 {
		mix(binary.LittleEndian.Uint32(b[i:]))
	}
	final := uint32(0x80)
	for i := len(b) - 1; i >= n; i-- {
		final = final<<8 | uint32(b[i])
	}
	mix(final)
	mix(0)
	return uint64(hi)<<32 | uint64(lo)
}
