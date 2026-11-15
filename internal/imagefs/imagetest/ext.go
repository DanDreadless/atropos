package imagetest

import (
	"encoding/binary"
	"time"
)

// Ext4 returns a 2 MiB ext4 volume (1 KiB blocks, 256-byte inodes, one
// group), labelled "builder", last mounted at /media/usb, holding:
//
//	/docs/             inode 12
//	/docs/report.txt   inode 13, 5000 bytes by extents: blocks 0-1, a hole
//	                   at 2, an unwritten extent at 3, block 4. A written
//	                   block's bytes are 'A'+logical block; the rest zero.
//	/big.bin           inode 14, 14336 bytes by block map: twelve direct
//	                   blocks and two through a single indirect block; each
//	                   block filled with its logical number.
//	/tree.dat          inode 15, 2048 bytes through a one-level extent tree
//	                   ('X' then 'Y').
//	/link              inode 16, symbolic link to docs/report.txt
//	in /docs's unused space, two deleted names: old.txt (inode 17, freed,
//	deleted at 2024-05-01 12:00:00) and reused.txt (inode 14, now big.bin's).
//
// Every inode's times are ExtTimes[inode]: modified, accessed, changed,
// created, with nanoseconds; tree.dat's modified time is in 2040, past
// what 32 bits of seconds can hold.
func Ext4() []byte {
	const bs, blocks, ipg, isz, table = 1024, 2048, 64, 256, 5
	img := make([]byte, bs*blocks)
	le := binary.LittleEndian
	sb := img[1024:2048]
	le.PutUint32(sb[0x0:], ipg)
	le.PutUint32(sb[0x4:], blocks)
	le.PutUint32(sb[0x14:], 1)
	le.PutUint32(sb[0x20:], 8192)
	le.PutUint32(sb[0x28:], ipg)
	le.PutUint16(sb[0x38:], 0xEF53)
	le.PutUint32(sb[0x4C:], 1)
	le.PutUint32(sb[0x54:], 11)
	le.PutUint16(sb[0x58:], isz)
	le.PutUint32(sb[0x5C:], 0x4)      // has a journal
	le.PutUint32(sb[0x60:], 0x2|0x40) // file types in entries, extents
	le.PutUint32(sb[0x64:], 0x1|0x40) // sparse superblocks, large inodes
	copy(sb[0x68:], []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	copy(sb[0x78:], "builder")
	copy(sb[0x88:], "/media/usb")
	gd := img[2*bs:]
	le.PutUint32(gd[0x8:], table)

	inode := func(n uint32) []byte { return img[table*bs+int(n-1)*isz : table*bs+int(n)*isz] }
	setInode := func(n uint32, mode uint16, links uint16, size int64, flags uint32) []byte {
		b := inode(n)
		le.PutUint16(b[0:], mode)
		le.PutUint16(b[0x2:], 1000)
		le.PutUint32(b[0x4:], uint32(size))
		le.PutUint16(b[0x18:], 100)
		le.PutUint16(b[0x1A:], links)
		le.PutUint32(b[0x20:], flags)
		le.PutUint32(b[0x6C:], uint32(size>>32))
		le.PutUint16(b[0x80:], 32)
		if t, ok := ExtTimes[n]; ok {
			for i, at := range [][2]int{{0x10, 0x88}, {0x8, 0x8C}, {0xC, 0x84}, {0x90, 0x94}} {
				sec, ns := t[i].Unix(), t[i].Nanosecond()
				le.PutUint32(b[at[0]:], uint32(sec))
				le.PutUint32(b[at[1]:], uint32(ns)<<2|uint32((sec-int64(int32(uint32(sec))))>>32)&3)
			}
		}
		return b
	}
	extents := func(b []byte, depth uint16, list ...[3]uint32) {
		h := b[0x28:]
		le.PutUint16(h[0:], 0xF30A)
		le.PutUint16(h[2:], uint16(len(list)))
		le.PutUint16(h[4:], 4)
		le.PutUint16(h[6:], depth)
		for i, e := range list {
			x := h[12+12*i:]
			le.PutUint32(x[0:], e[0])
			if depth == 0 {
				le.PutUint16(x[4:], uint16(e[1]))
				le.PutUint32(x[8:], e[2])
			} else {
				le.PutUint32(x[4:], e[2])
			}
		}
	}
	type dirent struct {
		ino   uint32
		name  string
		ftype byte
	}
	dir := func(blk int, list []dirent, slack []dirent) {
		b := img[blk*bs : (blk+1)*bs]
		pos := 0
		for i, d := range list {
			n := 8 + (len(d.name)+3)&^3
			rec := n
			if i == len(list)-1 {
				rec = bs - pos
			}
			le.PutUint32(b[pos:], d.ino)
			le.PutUint16(b[pos+4:], uint16(rec))
			b[pos+6], b[pos+7] = byte(len(d.name)), d.ftype
			copy(b[pos+8:], d.name)
			if i == len(list)-1 {
				// What was removed lies after the last entry, inside its length.
				q := pos + n
				for _, s := range slack {
					m := 8 + (len(s.name)+3)&^3
					le.PutUint32(b[q:], s.ino)
					le.PutUint16(b[q+4:], uint16(m))
					b[q+6], b[q+7] = byte(len(s.name)), s.ftype
					copy(b[q+8:], s.name)
					q += m
				}
			}
			pos += rec
		}
	}

	root := setInode(2, 0o40755, 3, bs, 0x80000)
	extents(root, 0, [3]uint32{0, 1, 21})
	dir(21, []dirent{{2, ".", 2}, {2, "..", 2}, {12, "docs", 2}, {14, "big.bin", 1}, {15, "tree.dat", 1}, {16, "link", 7}}, nil)
	docs := setInode(12, 0o40750, 2, bs, 0x80000)
	extents(docs, 0, [3]uint32{0, 1, 22})
	dir(22, []dirent{{12, ".", 2}, {2, "..", 2}, {13, "report.txt", 1}}, []dirent{{17, "old.txt", 1}, {14, "reused.txt", 1}})

	report := setInode(13, 0o100640, 1, 5000, 0x80000)
	extents(report, 0, [3]uint32{0, 2, 30}, [3]uint32{3, 32768 + 1, 40}, [3]uint32{4, 1, 41})
	for l, blk := range map[int]int{0: 30, 1: 31, 4: 41} {
		for i := 0; i < bs; i++ {
			img[blk*bs+i] = byte('A' + l)
		}
	}
	for i := 0; i < bs; i++ {
		img[40*bs+i] = 0xEE // an unwritten extent's blocks read as zeros, whatever they hold
	}

	big := setInode(14, 0o100600, 1, 14*bs, 0)
	for i := 0; i < 12; i++ {
		le.PutUint32(big[0x28+4*i:], uint32(50+i))
	}
	le.PutUint32(big[0x28+4*12:], 62)
	le.PutUint32(img[62*bs:], 63)
	le.PutUint32(img[62*bs+4:], 64)
	for l := 0; l < 14; l++ {
		blk := 50 + l
		if l >= 12 {
			blk = 63 + l - 12
		}
		for i := 0; i < bs; i++ {
			img[blk*bs+i] = byte(l)
		}
	}

	tree := setInode(15, 0o100644, 1, 2*bs, 0x80000)
	extents(tree, 1, [3]uint32{0, 0, 70})
	node := img[70*bs:]
	le.PutUint16(node[0:], 0xF30A)
	le.PutUint16(node[2:], 2)
	le.PutUint16(node[4:], 84)
	for i, e := range [][3]uint32{{0, 1, 71}, {1, 1, 80}} {
		x := node[12+12*i:]
		le.PutUint32(x[0:], e[0])
		le.PutUint16(x[4:], uint16(e[1]))
		le.PutUint32(x[8:], e[2])
	}
	for i := 0; i < bs; i++ {
		img[71*bs+i], img[80*bs+i] = 'X', 'Y'
	}

	link := setInode(16, 0o120777, 1, 15, 0)
	copy(link[0x28:], "docs/report.txt")

	old := setInode(17, 0o100644, 0, 0, 0x80000)
	le.PutUint32(old[0x14:], uint32(time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC).Unix()))
	return img
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

// ExtTimes are the times Ext4 gives each inode: modified, accessed,
// changed, created.
var ExtTimes = map[uint32][4]time.Time{
	2:  {ts("2024-04-01T09:00:00.1Z"), ts("2024-04-01T09:00:00.2Z"), ts("2024-04-01T09:00:00.3Z"), ts("2024-04-01T09:00:00Z")},
	12: {ts("2024-04-02T10:00:00.123456789Z"), ts("2024-04-02T10:00:01Z"), ts("2024-04-02T10:00:02Z"), ts("2024-04-02T09:59:59Z")},
	13: {ts("2024-04-03T11:11:11.000000001Z"), ts("2024-04-04T11:11:11Z"), ts("2024-04-03T11:11:11.000000001Z"), ts("2024-04-02T10:00:00.5Z")},
	14: {ts("2024-04-05T00:00:00Z"), ts("2024-04-05T00:00:00Z"), ts("2024-04-05T00:00:00Z"), ts("2024-04-05T00:00:00Z")},
	15: {ts("2040-01-01T00:00:00.25Z"), ts("2024-04-06T00:00:00Z"), ts("2024-04-06T00:00:00Z"), ts("2024-04-06T00:00:00Z")},
	16: {ts("2024-04-07T00:00:00Z"), ts("2024-04-07T00:00:00Z"), ts("2024-04-07T00:00:00Z"), ts("2024-04-07T00:00:00Z")},
	17: {ts("2024-05-01T12:00:00Z"), ts("2024-04-20T08:30:00Z"), ts("2024-05-01T12:00:00Z"), ts("2024-03-15T16:45:00Z")},
}
