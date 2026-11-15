// Package imagetest builds small disc images for tests. It is imported only
// by tests, so none of it is in the Atropos binary.
package imagetest

import "encoding/binary"

const sector = 2048

func record(name string, at, length int, dir bool) []byte {
	id := []byte(name)
	switch name {
	case ".":
		id = []byte{0}
	case "..":
		id = []byte{1}
	default:
		if !dir {
			id = append(id, ';', '1')
		}
	}
	n := 33 + len(id)
	n += n % 2
	r := make([]byte, n)
	r[0] = byte(n)
	binary.LittleEndian.PutUint32(r[2:], uint32(at))
	binary.LittleEndian.PutUint32(r[10:], uint32(length))
	copy(r[18:], []byte{124, 3, 9, 13, 30, 0, 0}) // 2024-03-09 13:30:00 GMT
	if dir {
		r[25] = 2
	}
	r[32] = byte(len(id))
	copy(r[33:], id)
	return r
}

// ISO returns an ISO 9660 image holding the given files in its root
// directory and, if sub is not empty, in a directory called SUB. Names must
// be upper case, as plain ISO 9660 requires. The image also carries a boot
// sector signature, as discs made to start a computer do.
func ISO(root, sub map[string][]byte, order []string) []byte {
	next := 20
	img := make([]byte, next*sector)
	put := func(data []byte) int {
		at := next
		n := (len(data) + sector - 1) / sector
		if n == 0 {
			n = 1
		}
		next += n
		img = append(img, make([]byte, n*sector)...)
		copy(img[at*sector:], data)
		return at
	}
	dir := func(self int, files map[string][]byte, extra []byte) {
		d := append(record(".", self, sector, true), record("..", self, sector, true)...)
		for _, name := range order {
			if data, ok := files[name]; ok {
				d = append(d, record(name, put(data), len(data), false)...)
			}
		}
		copy(img[self*sector:], append(d, extra...))
	}
	rootAt := put(nil)
	var extra []byte
	if len(sub) > 0 {
		subAt := put(nil)
		dir(subAt, sub, nil)
		extra = record("SUB", subAt, sector, true)
	}
	dir(rootAt, root, extra)
	pvd := img[16*sector:]
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	copy(pvd[40:], "ATROPOS_TEST")
	copy(pvd[156:], record(".", rootAt, sector, true))
	img[17*sector] = 255
	copy(img[17*sector+1:], "CD001")
	img[510], img[511] = 0x55, 0xAA
	return img
}
