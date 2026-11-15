package imagefs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"
)

// Volume shadow copies: Windows keeps earlier states of an NTFS volume on
// the volume itself. This lists them (when each was made); vssread.go reads
// through them.
//
// Written from Joachim Metz's "Volume Shadow Snapshot (VSS) format" (the
// libvshadow project). A header at offset 0x1E00 of the volume points to a
// catalog of 16 KiB blocks; each block holds 128-byte entries, and an entry
// of type 2 describes one shadow copy.

// vssID is the identifier 3808876b-c176-4e48-b7ae-04046e6cc752 as stored.
var vssID = []byte{0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E, 0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52}

const (
	vssHeaderOffset = 0x1E00
	vssBlock        = 0x4000
	vssEntry        = 128
	vssMaxBlocks    = 4096
)

// ShadowCopy is one earlier state of a volume, as its catalog records it.
type ShadowCopy struct {
	ID         string // the store's identifier, as it appears in the store's file name
	Created    uint64 // FILETIME, UTC
	VolumeSize int64  // size of the volume when the copy was made
	HasStore   bool   // the catalog also says where the copy's data is kept
	Offset     int64  // of the catalog entry, from the start of the volume
	// Where the copy's store is, from the catalog's type 3 entry: its block
	// list, header, range list, bitmap and previous bitmap (0 if none).
	BlockList, StoreHeader, RangeList, Bitmap, PrevBitmap int64
}

// CreatedTime is when the copy was made.
func (s ShadowCopy) CreatedTime() time.Time {
	const delta = 116444736000000000
	t := int64(s.Created) - delta
	return time.Unix(t/1e7, (t%1e7)*100).UTC()
}

func guidString(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%s-%s", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

// ShadowCopies lists the shadow copies of the NTFS volume that r holds from
// its first byte. A volume with none gives an empty list and no error. The
// list is in order of creation.
func ShadowCopies(r io.ReaderAt, size int64) ([]ShadowCopy, error) {
	h, err := readAt(r, vssHeaderOffset, 100)
	if err != nil || !bytes.Equal(h[:16], vssID) {
		return nil, nil // shadow copies were never enabled on this volume
	}
	if rt := binary.LittleEndian.Uint32(h[20:]); rt != 1 {
		return nil, fmt.Errorf("volume shadow copy header has record type %d, not 1", rt)
	}
	off := int64(binary.LittleEndian.Uint64(h[48:]))
	byID := map[string]*ShadowCopy{}
	var order []string
	seen := map[int64]bool{}
	for n := 0; off != 0; n++ {
		if n >= vssMaxBlocks || seen[off] {
			return nil, fmt.Errorf("volume shadow copy catalog loops or is longer than any real one")
		}
		seen[off] = true
		if off < 0 || off%512 != 0 || (size > 0 && off > size-vssBlock) {
			return nil, fmt.Errorf("volume shadow copy catalog block at offset %d is outside the volume", off)
		}
		b, err := readAt(r, off, vssBlock)
		if err != nil {
			return nil, fmt.Errorf("volume shadow copy catalog block at offset %d: %v", off, err)
		}
		if !bytes.Equal(b[:16], vssID) || binary.LittleEndian.Uint32(b[20:]) != 2 {
			return nil, fmt.Errorf("volume shadow copy catalog block at offset %d is not a catalog block", off)
		}
		for e := vssEntry; e+vssEntry <= vssBlock; e += vssEntry {
			ent := b[e : e+vssEntry]
			id := guidString(ent[16:32])
			switch binary.LittleEndian.Uint64(ent) {
			case 2:
				if _, dup := byID[id]; !dup {
					order = append(order, id)
					byID[id] = &ShadowCopy{ID: id}
				}
				s := byID[id]
				s.VolumeSize = int64(binary.LittleEndian.Uint64(ent[8:]))
				s.Created = binary.LittleEndian.Uint64(ent[48:])
				s.Offset = off + int64(e)
			case 3:
				// Where the copy's blocks are; it follows its type 2 entry.
				if s, ok := byID[id]; ok {
					s.HasStore = true
					le := binary.LittleEndian
					s.BlockList, s.StoreHeader, s.RangeList = int64(le.Uint64(ent[8:])), int64(le.Uint64(ent[32:])), int64(le.Uint64(ent[40:]))
					s.Bitmap, s.PrevBitmap = int64(le.Uint64(ent[48:])), int64(le.Uint64(ent[72:]))
				}
			}
		}
		off = int64(binary.LittleEndian.Uint64(b[40:]))
	}
	out := make([]ShadowCopy, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created < out[j].Created })
	return out, nil
}

// shadowSummary is a line for the examiner about a volume's shadow copies.
func shadowSummary(r io.ReaderAt) string {
	copies, err := ShadowCopies(r, 0)
	if err != nil {
		return "; its volume shadow copy catalog could not be read (" + err.Error() + ")"
	}
	if len(copies) == 0 {
		return ""
	}
	const layout = "2006-01-02 15:04 UTC"
	when := "made " + copies[0].CreatedTime().Format(layout)
	if len(copies) > 1 {
		when = "the first made " + copies[0].CreatedTime().Format(layout) + ", the last " + copies[len(copies)-1].CreatedTime().Format(layout)
	}
	return fmt.Sprintf("; holds %d volume shadow copies (%s), each shown as a folder <shadow copy N> at the root", len(copies), when)
}
