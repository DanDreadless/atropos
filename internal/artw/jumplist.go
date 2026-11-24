package artw

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// JumpEntry is one entry of an automatic jump list: a file the application
// opened, and when it last did.
type JumpEntry struct {
	Path     string // a local path or \\server\share\file
	LastUsed time.Time
	Count    uint32
	Machine  string // NetBIOS name of the computer the file was on, at most 15 characters
}

func wide(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// JumpList lays out an automatic jump list (DestList version 4, as Windows
// 10 writes it): a compound file with the DestList stream and one shortcut
// stream per entry, named by the entry's number in hexadecimal.
func JumpList(entries []JumpEntry) []byte {
	le := binary.LittleEndian
	dl := make([]byte, 32)
	le.PutUint32(dl, 4)
	le.PutUint32(dl[4:], uint32(len(entries)))
	le.PutUint32(dl[16:], uint32(len(entries))) // the last entry number issued
	streams := map[string][]byte{}
	var order []string
	for i, e := range entries {
		x := make([]byte, 130)
		m := strings.ToUpper(e.Machine)
		if len(m) > 15 {
			m = m[:15]
		}
		copy(x[72:88], m)
		le.PutUint32(x[88:], uint32(i+1))
		le.PutUint64(x[100:], filetime(e.LastUsed))
		le.PutUint32(x[108:], 0xFFFFFFFF) // not pinned
		le.PutUint32(x[116:], e.Count)
		p := wide(e.Path)
		le.PutUint16(x[128:], uint16(len(p)/2))
		dl = append(append(dl, x...), p...)
		dl = le.AppendUint32(dl, 0) // no properties after the path
		name := fmt.Sprintf("%x", i+1)
		streams[name] = Shortcut(e.Path, e.LastUsed)
		order = append(order, name)
	}
	streams["DestList"] = dl
	order = append(order, "DestList")
	return compoundFile(streams, order)
}

// Shortcut lays out a shell link to path, with LinkInfo naming the local
// path or, for \\server\share\rest, the share and the rest; the target's
// times are all t.
func Shortcut(path string, t time.Time) []byte {
	le := binary.LittleEndian
	b := make([]byte, 76)
	le.PutUint32(b[0:], 0x4C)
	copy(b[4:], []byte{0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46})
	le.PutUint32(b[20:], 0x2|0x80) // LinkInfo, unicode
	le.PutUint32(b[24:], 0x20)
	ft := filetime(t)
	le.PutUint64(b[28:], ft)
	le.PutUint64(b[36:], ft)
	le.PutUint64(b[44:], ft)

	li := make([]byte, 28)
	le.PutUint32(li[4:], 28)
	if strings.HasPrefix(path, `\\`) {
		parts := strings.SplitN(path[2:], `\`, 3)
		share, rest := `\\`+parts[0], ""
		if len(parts) > 1 {
			share += `\` + parts[1]
		}
		if len(parts) > 2 {
			rest = parts[2]
		}
		cnrl := make([]byte, 20)
		le.PutUint32(cnrl[8:], 20) // NetName offset
		cnrl = append(cnrl, share+"\x00"...)
		le.PutUint32(cnrl[0:], uint32(len(cnrl)))
		le.PutUint32(li[8:], 2)   // CommonNetworkRelativeLinkAndPathSuffix
		le.PutUint32(li[20:], 28) // its offset
		le.PutUint32(li[24:], uint32(28+len(cnrl)))
		li = append(li, cnrl...)
		li = append(li, rest+"\x00"...)
	} else {
		vol := make([]byte, 16)
		le.PutUint32(vol[0:], 17)
		le.PutUint32(vol[4:], 3)
		le.PutUint32(vol[8:], 0x1234ABCD)
		le.PutUint32(vol[12:], 16)
		vol = append(vol, 0)
		le.PutUint32(li[8:], 1)
		le.PutUint32(li[12:], 28)
		le.PutUint32(li[16:], uint32(28+len(vol)))
		li = append(li, vol...)
		li = append(li, path+"\x00"...)
		le.PutUint32(li[24:], uint32(len(li)-1)) // an empty suffix: base's terminator
	}
	le.PutUint32(li[0:], uint32(len(li)))
	b = append(b, li...)
	return le.AppendUint32(b, 0) // terminal block
}

// compoundFile makes a version 3 compound file whose streams all live in
// the mini stream, as the streams of a real jump list do.
func compoundFile(streams map[string][]byte, order []string) []byte {
	const sec = 512
	le := binary.LittleEndian
	var mini []byte
	var miniFAT []uint32
	type ent struct {
		name        string
		start, size uint32
	}
	var ents []ent
	for _, name := range order {
		data := streams[name]
		start := uint32(len(mini) / 64)
		n := (len(data) + 63) / 64
		for i := 0; i < n; i++ {
			next := start + uint32(i) + 1
			if i == n-1 {
				next = 0xFFFFFFFE
			}
			miniFAT = append(miniFAT, next)
		}
		mini = append(mini, append(append([]byte{}, data...), make([]byte, n*64-len(data))...)...)
		ents = append(ents, ent{name, start, uint32(len(data))})
	}
	miniFATSectors := (len(miniFAT)*4 + sec - 1) / sec
	if miniFATSectors == 0 {
		miniFATSectors = 1
	}
	// Sector 0: FAT. Then the directory, the mini FAT and the mini stream.
	miniSectors := (len(mini) + sec - 1) / sec
	dirSectors := (len(ents) + 1 + 3) / 4
	fat := make([]uint32, sec/4)
	for i := range fat {
		fat[i] = 0xFFFFFFFF
	}
	fat[0] = 0xFFFFFFFD
	chain := func(start, n int) {
		for i := 0; i < n; i++ {
			fat[start+i] = uint32(start + i + 1)
		}
		fat[start+n-1] = 0xFFFFFFFE
	}
	dirStart := 1
	chain(dirStart, dirSectors)
	miniFATAt := dirStart + dirSectors
	chain(miniFATAt, miniFATSectors)
	miniAt := miniFATAt + miniFATSectors
	if miniSectors > 0 {
		chain(miniAt, miniSectors)
	}

	hdr := make([]byte, sec)
	copy(hdr, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	le.PutUint16(hdr[24:], 0x3E)
	le.PutUint16(hdr[26:], 3)
	le.PutUint16(hdr[28:], 0xFFFE)
	le.PutUint16(hdr[30:], 9)
	le.PutUint16(hdr[32:], 6)
	le.PutUint32(hdr[44:], 1)
	le.PutUint32(hdr[48:], uint32(dirStart))
	le.PutUint32(hdr[56:], 4096)
	le.PutUint32(hdr[60:], uint32(miniFATAt))
	le.PutUint32(hdr[64:], uint32(miniFATSectors))
	le.PutUint32(hdr[68:], 0xFFFFFFFE)
	for i := 0; i < 109; i++ {
		le.PutUint32(hdr[76+i*4:], 0xFFFFFFFF)
	}
	le.PutUint32(hdr[76:], 0)

	dirEntry := func(name string, typ byte, start, size uint32) []byte {
		e := make([]byte, 128)
		w := wide(name + "\x00")
		copy(e, w)
		le.PutUint16(e[64:], uint16(len(w)))
		e[66] = typ
		e[67] = 1 // black
		le.PutUint32(e[68:], 0xFFFFFFFF)
		le.PutUint32(e[72:], 0xFFFFFFFF)
		le.PutUint32(e[76:], 0xFFFFFFFF)
		le.PutUint32(e[116:], start)
		le.PutUint32(e[120:], size)
		return e
	}
	// The streams hang off the root as a chain of right siblings, which
	// keeps the red-black tree valid without balancing it.
	rootStart := uint32(miniAt)
	if miniSectors == 0 {
		rootStart = 0xFFFFFFFE
	}
	dir := dirEntry("Root Entry", 5, rootStart, uint32(len(mini)))
	if len(ents) > 0 {
		le.PutUint32(dir[76:], 1)
	}
	for i, e := range ents {
		d := dirEntry(e.name, 2, e.start, e.size)
		if i+1 < len(ents) {
			le.PutUint32(d[72:], uint32(i+2))
		}
		dir = append(dir, d...)
	}
	dir = append(dir, make([]byte, dirSectors*sec-len(dir))...)

	out := append([]byte{}, hdr...)
	for _, v := range fat {
		out = le.AppendUint32(out, v)
	}
	out = append(out, dir...)
	mf := make([]byte, miniFATSectors*sec)
	for i := range mf {
		mf[i] = 0xFF
	}
	for i, v := range miniFAT {
		le.PutUint32(mf[i*4:], v)
	}
	out = append(out, mf...)
	return append(out, append(mini, make([]byte, miniSectors*sec-len(mini))...)...)
}
