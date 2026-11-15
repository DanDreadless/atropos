package imagefs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Reading through a volume shadow copy.
//
// A shadow copy is not a copy: it is the current volume, plus a store of
// the 16 KiB blocks that were about to be overwritten after the copy was
// made. To read the volume as it was at copy k, each block is looked up in
// store k; what that store does not hold is looked up in the next newer
// store, and so on, and what no store holds is read from the volume as it
// is now.
//
// Written from the "Store" and "Reading snapshot data" sections of Joachim
// Metz's "Volume Shadow Snapshot (VSS) format", and, where that document
// says it is incomplete (successive block descriptors, overlays), from
// libvshadow's own implementation of the same rules
// (libvshadow_block_tree_insert, libvshadow_store_descriptor_read_buffer).

const (
	vssFlagForwarder = 0x1
	vssFlagOverlay   = 0x2
	vssFlagNotUsed   = 0x4
	vssBlockHeader   = 128
	vssDescSize      = 32
)

type vssDesc struct {
	orig, rel, off int64
	flags, bitmap  uint32
	overlay        *vssDesc
}

type vssStore struct {
	fwd     map[int64]*vssDesc // by original offset
	rev     map[int64]*vssDesc // forwarders, by relative offset
	cur     []byte             // current bitmap: a set bit is a block the store did not use
	prev    []byte             // previous bitmap, when there is one
	hasPrev bool
}

func bitSet(bits []byte, off int64) bool {
	i := off / vssBlock
	if i < 0 || i/8 >= int64(len(bits)) {
		return false
	}
	return bits[i/8]&(1<<(i%8)) != 0
}

// chain reads a store's chain of 16 KiB blocks of one record type, calling
// fn with each block's data after its header.
func vssChain(r io.ReaderAt, size, off int64, kind uint32, seen map[int64]bool, fn func([]byte) error) error {
	limit := size/vssBlock + 1
	for n := int64(0); off != 0; n++ {
		if n > limit || seen[off] {
			return errors.New("a shadow copy store's block chain loops or is longer than the volume")
		}
		seen[off] = true
		if off < 0 || off%512 != 0 || off > size-vssBlock {
			return fmt.Errorf("a shadow copy store block at offset %d is outside the volume", off)
		}
		b, err := readAt(r, off, vssBlock)
		if err != nil {
			return err
		}
		if !bytes.Equal(b[:16], vssID) || binary.LittleEndian.Uint32(b[20:]) != kind {
			return fmt.Errorf("the shadow copy store block at offset %d is not of the type expected (%d)", off, kind)
		}
		if err := fn(b[vssBlockHeader:]); err != nil {
			return err
		}
		off = int64(binary.LittleEndian.Uint64(b[40:]))
	}
	return nil
}

func loadStore(r io.ReaderAt, size int64, c ShadowCopy) (*vssStore, error) {
	if !c.HasStore || c.BlockList == 0 {
		return nil, errors.New("the catalog does not say where this shadow copy's store is")
	}
	s := &vssStore{fwd: map[int64]*vssDesc{}, rev: map[int64]*vssDesc{}}
	// Every store block is read once: a block met twice is a loop or damage.
	seen := map[int64]bool{}
	if c.Bitmap != 0 {
		if err := vssChain(r, size, c.Bitmap, 6, seen, func(b []byte) error { s.cur = append(s.cur, b...); return nil }); err != nil {
			return nil, fmt.Errorf("store bitmap: %v", err)
		}
	}
	if c.PrevBitmap != 0 {
		s.hasPrev = true
		if err := vssChain(r, size, c.PrevBitmap, 6, seen, func(b []byte) error { s.prev = append(s.prev, b...); return nil }); err != nil {
			return nil, fmt.Errorf("store previous bitmap: %v", err)
		}
	}
	le := binary.LittleEndian
	empty := make([]byte, vssDescSize)
	err := vssChain(r, size, c.BlockList, 3, seen, func(b []byte) error {
		for i := 0; i+vssDescSize <= len(b); i += vssDescSize {
			e := b[i : i+vssDescSize]
			if bytes.Equal(e, empty) {
				continue
			}
			d := &vssDesc{orig: int64(le.Uint64(e)), rel: int64(le.Uint64(e[8:])), off: int64(le.Uint64(e[16:])),
				flags: le.Uint32(e[24:]), bitmap: le.Uint32(e[28:])}
			if d.flags&vssFlagForwarder != 0 && d.off != 0 {
				return fmt.Errorf("a forwarding block descriptor has a store offset (%d)", d.off)
			}
			if d.orig < 0 || d.rel < 0 || d.off < 0 || d.orig > size || d.off > size {
				return errors.New("a block descriptor points outside the volume")
			}
			s.insert(d)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store block list: %v", err)
	}
	return s, nil
}

func blockKey(off int64) int64 { return off &^ (vssBlock - 1) }

// insert applies one block descriptor, in list order, as libvshadow does.
func (s *vssStore) insert(d *vssDesc) {
	if d.flags&vssFlagNotUsed != 0 {
		return
	}
	orig := d.orig
	if d.flags&vssFlagOverlay == 0 {
		// A forwarder that points at this block: the chain ends here.
		if r, ok := s.rev[blockKey(d.orig)]; ok {
			orig = r.orig
			delete(s.rev, blockKey(r.rel))
		}
	}
	if d.flags&vssFlagForwarder != 0 && orig == d.rel {
		return
	}
	nd := *d
	nd.orig = orig
	k := blockKey(orig)
	if e, ok := s.fwd[k]; ok {
		if nd.flags&vssFlagOverlay != 0 {
			ov := e.overlay
			if e.flags&vssFlagOverlay != 0 {
				ov = e
			}
			if ov != nil {
				ov.bitmap |= nd.bitmap
			} else {
				e.overlay = &nd
			}
			return
		}
		if e.flags&vssFlagOverlay != 0 {
			nd.overlay = e
		} else {
			nd.overlay = e.overlay
		}
	}
	s.fwd[k] = &nd
	if nd.flags&vssFlagForwarder != 0 {
		s.rev[blockKey(nd.rel)] = &nd
	}
}

// rangeAt says where the bytes at off come from in this store: the
// descriptor (nil if none applies), how many bytes the answer holds for,
// and the offset to read them from.
func (s *vssStore) rangeAt(off int64, active bool) (*vssDesc, int64, int64) {
	k := blockKey(off)
	rel := off - k
	size := vssBlock - rel
	d := s.fwd[k]
	if d == nil {
		return nil, size, 0
	}
	at := d.off
	if d.flags&vssFlagForwarder != 0 {
		at = d.rel
	}
	ov := d.overlay
	if d.flags&vssFlagOverlay != 0 {
		ov = d
	}
	if ov != nil {
		if !active {
			// Overlays belong to the copy being read, not to newer stores.
			if d == ov {
				return nil, size, 0
			}
		} else {
			// Each bit of the overlay's bitmap is a 512-byte sector of the block.
			sector := (off - blockKey(ov.orig)) / 512
			bits := ov.bitmap >> uint(sector)
			left := 32 - sector
			into := off - (blockKey(ov.orig) + sector*512)
			var run int64
			want := bits&1 != 0
			for left > 0 && (bits&1 != 0) == want {
				run += 512
				bits >>= 1
				left--
			}
			size = run - into
			if want {
				return ov, size, ov.off + rel
			}
			if d == ov {
				return nil, size, 0
			}
		}
	}
	return d, size, at + rel
}

// ShadowVolume reads the volume as it was when one shadow copy was made.
type ShadowVolume struct {
	r      io.ReaderAt
	size   int64 // of the volume now
	stores []*vssStore
	active int
	vsize  int64 // of the volume then
}

// OpenShadowCopy prepares to read copy k of the list ShadowCopies gives
// for the volume r. The stores of every newer copy are read too, since
// the older copy is built on them.
func OpenShadowCopy(r io.ReaderAt, size int64, copies []ShadowCopy, k int) (*ShadowVolume, error) {
	if k < 0 || k >= len(copies) {
		return nil, fmt.Errorf("no shadow copy %d", k+1)
	}
	v := &ShadowVolume{r: r, size: size, active: k, vsize: copies[k].VolumeSize, stores: make([]*vssStore, len(copies))}
	if v.vsize <= 0 || v.vsize > size {
		// The catalog's size is out of bounds (a known corruption): the volume's own is used.
		v.vsize = size
	}
	for i := k; i < len(copies); i++ {
		s, err := loadStore(r, size, copies[i])
		if err != nil {
			return nil, fmt.Errorf("shadow copy %d: %v", i+1, err)
		}
		v.stores[i] = s
	}
	return v, nil
}

// Size is the volume's size when the copy was made.
func (v *ShadowVolume) Size() int64 { return v.vsize }

func (v *ShadowVolume) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= v.vsize {
		return 0, io.EOF
	}
	n := len(p)
	var eof error
	if int64(n) > v.vsize-off {
		n, eof = int(v.vsize-off), io.EOF
	}
	if err := v.read(v.active, p[:n], off, 0); err != nil {
		return 0, err
	}
	return n, eof
}

func (v *ShadowVolume) read(si int, p []byte, off int64, depth int) error {
	if depth > len(v.stores) {
		return errors.New("shadow copy stores forward to each other without end")
	}
	for len(p) > 0 {
		s := v.stores[si]
		d, size, at := s.rangeAt(off, si == v.active)
		if size <= 0 {
			size = 512
		}
		n := int64(len(p))
		if n > size {
			n = size
		}
		next := si+1 < len(v.stores)
		var err error
		switch {
		case d != nil && d.flags&vssFlagForwarder != 0 && next:
			err = v.read(si+1, p[:n], at, depth+1)
		case d != nil:
			err = v.volume(p[:n], at)
		case next:
			err = v.read(si+1, p[:n], off, depth+1)
		case si == v.active && s.rev[blockKey(off)] == nil && bitSet(s.cur, off) && (!s.hasPrev || bitSet(s.prev, off)):
			// A block the store never used, in the newest store: undefined
			// on Windows, zeros here (as libvshadow gives).
			clear(p[:n])
		default:
			err = v.volume(p[:n], off)
		}
		if err != nil {
			return err
		}
		p, off = p[n:], off+n
	}
	return nil
}

func (v *ShadowVolume) volume(p []byte, off int64) error {
	k, err := v.r.ReadAt(p, off)
	if k == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("reading the volume at offset %d: %v", off, err)
}

// shadowSet holds the shadow copies of one volume, opened on demand.
type shadowSet struct {
	r      io.ReaderAt
	size   int64
	copies []ShadowCopy
	mu     sync.Mutex
	open   map[int]FS
	errs   map[int]error
}
