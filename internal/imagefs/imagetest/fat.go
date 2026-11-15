package imagetest

import (
	"encoding/binary"
	"unicode/utf16"
)

// FAT16 returns a 16 MiB FAT16 volume, labelled TESTSTICK with serial
// 1234-ABCD, holding:
//
//	/Report final.docx   3000 bytes in clusters 3 and 5 (fragmented); its
//	                     bytes are i%251. Created 2023-03-01 10:20:30.50,
//	                     modified 2023-03-02 11:22:44, accessed 2023-03-05.
//	/DCIM/               a directory, created and modified 2023-03-01 09:00:00
//	/DCIM/img_0001.jpg   12 bytes ("JPEGJPEGJPEG"); its 8.3 name is stored
//	                     upper case with Windows NT's lower-case flags set.
//	                     Modified 2022-12-25 18:30:58.
//	a deleted "secret plan.txt" (short name SECRET~1.TXT), 10 bytes, its
//	                     long name deleted with it. Modified 2023-03-03 08:00:00.
func FAT16() []byte {
	const bps, spc, reserved, nfats, rootEntries, total, fatSize = 512, 4, 1, 2, 512, 32768, 32
	img := make([]byte, total*bps)
	le := binary.LittleEndian
	b := img[:512]
	copy(b, []byte{0xEB, 0x3C, 0x90})
	copy(b[3:], "MSDOS5.0")
	le.PutUint16(b[11:], bps)
	b[13] = spc
	le.PutUint16(b[14:], reserved)
	b[16] = nfats
	le.PutUint16(b[17:], rootEntries)
	le.PutUint16(b[19:], total)
	b[21] = 0xF8
	le.PutUint16(b[22:], fatSize)
	b[36], b[38] = 0x80, 0x29
	le.PutUint32(b[39:], 0x1234ABCD)
	copy(b[43:], "TESTSTICK  ")
	copy(b[54:], "FAT16   ")
	b[510], b[511] = 0x55, 0xAA

	fat := map[int]uint16{0: 0xFFF8, 1: 0xFFFF, 2: 0xFFFF, 3: 5, 5: 0xFFFF, 6: 0xFFFF}
	for k := 0; k < nfats; k++ {
		at := (reserved + k*fatSize) * bps
		for c, v := range fat {
			le.PutUint16(img[at+c*2:], v)
		}
	}
	rootOff := (reserved + nfats*fatSize) * bps
	dataOff := rootOff + rootEntries*32
	clusterAt := func(c int) int { return dataOff + (c-2)*spc*bps }

	var root []byte
	label := make([]byte, 32)
	copy(label, "TESTSTICK  ")
	label[11] = 0x08
	root = append(root, label...)
	report := short("REPORT~1DOC", 0x20, 3, 3000, dt(2023, 3, 1, 10, 20, 30), 50, dt(2023, 3, 2, 11, 22, 44), date(2023, 3, 5))
	root = append(root, lfn("Report final.docx", report, false)...)
	root = append(root, report...)
	root = append(root, short("DCIM       ", 0x10, 2, 0, dt(2023, 3, 1, 9, 0, 0), 0, dt(2023, 3, 1, 9, 0, 0), date(2023, 3, 1))...)
	secret := short("SECRET~1TXT", 0x20, 4, 10, dt(2023, 3, 3, 7, 59, 0), 0, dt(2023, 3, 3, 8, 0, 0), date(2023, 3, 3))
	gone := lfn("secret plan.txt", secret, true)
	secret[0] = 0xE5
	root = append(root, gone...)
	root = append(root, secret...)
	copy(img[rootOff:], root)

	// /DCIM, in cluster 2.
	var dcim []byte
	dot := short(".          ", 0x10, 2, 0, dt(2023, 3, 1, 9, 0, 0), 0, dt(2023, 3, 1, 9, 0, 0), date(2023, 3, 1))
	dotdot := short("..         ", 0x10, 0, 0, dt(2023, 3, 1, 9, 0, 0), 0, dt(2023, 3, 1, 9, 0, 0), date(2023, 3, 1))
	jpg := short("IMG_0001JPG", 0x20, 6, 12, dt(2022, 12, 25, 18, 30, 58), 0, dt(2022, 12, 25, 18, 30, 58), date(2022, 12, 25))
	jpg[12] = 0x18
	dcim = append(append(append(dcim, dot...), dotdot...), jpg...)
	copy(img[clusterAt(2):], dcim)

	// File data: the report across clusters 3 and 5, with 4 between them
	// holding the deleted file's old content.
	data := make([]byte, 3000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	n := copy(img[clusterAt(3):clusterAt(3)+spc*bps], data)
	copy(img[clusterAt(5):], data[n:])
	copy(img[clusterAt(4):], "top secret")
	copy(img[clusterAt(6):], "JPEGJPEGJPEG")
	return img
}

type stamp struct{ date, time uint16 }

func dt(y, mo, d, h, mi, s int) stamp {
	return stamp{uint16((y-1980)<<9 | mo<<5 | d), uint16(h<<11 | mi<<5 | s/2)}
}

func date(y, mo, d int) uint16 { return uint16((y-1980)<<9 | mo<<5 | d) }

func short(name string, attr byte, cluster uint16, size uint32, created stamp, tenMs byte, modified stamp, accessed uint16) []byte {
	le := binary.LittleEndian
	e := make([]byte, 32)
	copy(e, name)
	e[11] = attr
	e[13] = tenMs
	le.PutUint16(e[14:], created.time)
	le.PutUint16(e[16:], created.date)
	le.PutUint16(e[18:], accessed)
	le.PutUint16(e[22:], modified.time)
	le.PutUint16(e[24:], modified.date)
	le.PutUint16(e[26:], cluster)
	le.PutUint32(e[28:], size)
	return e
}

// lfn returns the long-name entries that go before the short entry e, last
// part first, as they are stored.
func lfn(name string, e []byte, deleted bool) []byte {
	var sum byte
	for i := 0; i < 11; i++ {
		sum = (sum>>1 | sum<<7) + e[i]
	}
	u := utf16.Encode([]rune(name))
	parts := (len(u) + 12) / 13
	u = append(u, 0)
	for len(u)%13 != 0 {
		u = append(u, 0xFFFF)
	}
	var out []byte
	for p := parts; p >= 1; p-- {
		x := make([]byte, 32)
		x[0] = byte(p)
		if p == parts {
			x[0] |= 0x40
		}
		if deleted {
			x[0] = 0xE5
		}
		x[11], x[13] = 0x0F, sum
		chars := u[(p-1)*13 : p*13]
		k := 0
		for _, r := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
			for at := r[0]; at+1 < r[1]; at += 2 {
				binary.LittleEndian.PutUint16(x[at:], chars[k])
				k++
			}
		}
		out = append(out, x...)
	}
	return out
}

// ExFAT returns a 16 MiB exFAT volume, labelled CAMERA with serial
// C0FF-EE11 and 4 KiB clusters, holding:
//
//	/Holiday photo.jpg  5000 bytes, contiguous (no FAT chain) in clusters
//	                    5 and 6; its bytes are i%241. Clock at UTC+01:00:
//	                    created 2024-07-15 14:30:21.50, modified 14:30:20,
//	                    accessed 2024-07-16 09:00:00 (all local).
//	/Docs/              a directory in cluster 7, through the FAT. Clock at
//	                    UTC-05:00: created and modified 2024-01-02 03:04:06.
//	/Docs/notes.txt     12 bytes ("hello notes\n"), cluster 8. No UTC
//	                    offset recorded: modified 2024-02-03 04:05:06.
//	a deleted gone.txt  10 bytes, once in cluster 9, modified 2024-03-01 12:00:00.
func ExFAT() []byte {
	const bpsShift, spcShift, total, fatOff, fatLen, heap, clusters, rootCluster = 9, 3, 32768, 24, 32, 64, 4088, 4
	const bps, cl = 1 << bpsShift, 1 << (bpsShift + spcShift)
	img := make([]byte, total*bps)
	le := binary.LittleEndian
	b := img[:512]
	copy(b, []byte{0xEB, 0x76, 0x90})
	copy(b[3:], "EXFAT   ")
	le.PutUint64(b[72:], total)
	le.PutUint32(b[80:], fatOff)
	le.PutUint32(b[84:], fatLen)
	le.PutUint32(b[88:], heap)
	le.PutUint32(b[92:], clusters)
	le.PutUint32(b[96:], rootCluster)
	le.PutUint32(b[100:], 0xC0FFEE11)
	le.PutUint16(b[104:], 0x0100)
	b[108], b[109], b[110] = bpsShift, spcShift, 1
	b[510], b[511] = 0x55, 0xAA

	fat := map[int]uint32{0: 0xFFFFFFF8, 1: 0xFFFFFFFF, 2: 0xFFFFFFFF, 3: 0xFFFFFFFF, 4: 0xFFFFFFFF, 7: 0xFFFFFFFF, 8: 0xFFFFFFFF}
	for c, v := range fat {
		le.PutUint32(img[fatOff*bps+c*4:], v)
	}
	clusterAt := func(c int) int { return heap*bps + (c-2)*cl }

	var root []byte
	lab := make([]byte, 32)
	lab[0], lab[1] = 0x83, 6
	for i, r := range utf16.Encode([]rune("CAMERA")) {
		le.PutUint16(lab[2+2*i:], r)
	}
	bitmap := make([]byte, 32)
	bitmap[0] = 0x81
	le.PutUint32(bitmap[20:], 2)
	le.PutUint64(bitmap[24:], (clusters+7)/8)
	upcase := make([]byte, 32)
	upcase[0] = 0x82
	le.PutUint32(upcase[20:], 3)
	le.PutUint64(upcase[24:], 128)
	root = append(append(append(root, lab...), bitmap...), upcase...)
	plus1 := byte(0x80 | 4)
	minus5 := byte(0x80 | (128 - 20))
	root = append(root, exfatSet("Holiday photo.jpg", 0x20, true, true, 5, 5000,
		[3]stamp{dt(2024, 7, 15, 14, 30, 20), dt(2024, 7, 15, 14, 30, 20), dt(2024, 7, 16, 9, 0, 0)}, [2]byte{150, 0}, [3]byte{plus1, plus1, plus1})...)
	root = append(root, exfatSet("Docs", 0x10, true, false, 7, cl,
		[3]stamp{dt(2024, 1, 2, 3, 4, 6), dt(2024, 1, 2, 3, 4, 6), dt(2024, 1, 2, 3, 4, 6)}, [2]byte{}, [3]byte{minus5, minus5, minus5})...)
	root = append(root, exfatSet("gone.txt", 0x20, false, false, 9, 10,
		[3]stamp{dt(2024, 3, 1, 12, 0, 0), dt(2024, 3, 1, 12, 0, 0), dt(2024, 3, 1, 12, 0, 0)}, [2]byte{}, [3]byte{})...)
	copy(img[clusterAt(4):], root)

	docs := exfatSet("notes.txt", 0x20, true, false, 8, 12,
		[3]stamp{dt(2024, 2, 3, 4, 5, 6), dt(2024, 2, 3, 4, 5, 6), dt(2024, 2, 3, 4, 5, 6)}, [2]byte{}, [3]byte{})
	copy(img[clusterAt(7):], docs)

	photo := make([]byte, 5000)
	for i := range photo {
		photo[i] = byte(i % 241)
	}
	copy(img[clusterAt(5):], photo)
	copy(img[clusterAt(8):], "hello notes\n")
	copy(img[clusterAt(9):], "gone gone!")
	return img
}

// exfatSet returns a file directory entry set: file, stream extension and
// file name entries. times are created, modified, accessed.
func exfatSet(name string, attr uint16, inUse, contiguous bool, cluster uint32, size uint64, times [3]stamp, tenMs [2]byte, offsets [3]byte) []byte {
	le := binary.LittleEndian
	u := utf16.Encode([]rune(name))
	names := (len(u) + 14) / 15
	set := make([]byte, 32*(2+names))
	f := set[:32]
	f[0], f[1] = 0x85, byte(1+names)
	le.PutUint16(f[4:], attr)
	for i, at := range []int{8, 12, 16} {
		le.PutUint16(f[at:], times[i].time)
		le.PutUint16(f[at+2:], times[i].date)
	}
	f[20], f[21] = tenMs[0], tenMs[1]
	copy(f[22:25], offsets[:])
	s := set[32:64]
	s[0], s[1], s[3] = 0xC0, 0x01, byte(len(u))
	if contiguous {
		s[1] |= 0x02
	}
	le.PutUint64(s[8:], size)
	le.PutUint32(s[20:], cluster)
	le.PutUint64(s[24:], size)
	for k := 0; k < names; k++ {
		n := set[64+32*k:]
		n[0] = 0xC1
		for j := 0; j < 15 && k*15+j < len(u); j++ {
			le.PutUint16(n[2+2*j:], u[k*15+j])
		}
	}
	// The set checksum, over every byte but its own two.
	var sum uint16
	for i, c := range set {
		if i == 2 || i == 3 {
			continue
		}
		sum = (sum>>1 | sum<<15) + uint16(c)
	}
	le.PutUint16(f[2:], sum)
	if !inUse {
		for k := 0; k < len(set); k += 32 {
			set[k] &^= 0x80
		}
	}
	return set
}

// MBR returns a disk image with one MBR partition, of the given type,
// holding vol and starting at sector 2048.
func MBR(vol []byte, typ byte) []byte {
	const start = 2048
	img := make([]byte, start*512+len(vol))
	e := img[446:]
	e[4] = typ
	binary.LittleEndian.PutUint32(e[8:], start)
	binary.LittleEndian.PutUint32(e[12:], uint32(len(vol)/512))
	img[510], img[511] = 0x55, 0xAA
	copy(img[start*512:], vol)
	return img
}
