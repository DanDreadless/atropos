package imagefs

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// isoBuilder lays out a small ISO 9660 image with Joliet names by hand.
type isoBuilder struct {
	img    []byte
	next   int // next free sector
	joliet bool
}

func (b *isoBuilder) alloc(data []byte) (sector int) {
	sector = b.next
	n := (len(data) + isoSector - 1) / isoSector
	if n == 0 {
		n = 1
	}
	b.next += n
	for len(b.img) < b.next*isoSector {
		b.img = append(b.img, make([]byte, isoSector)...)
	}
	copy(b.img[sector*isoSector:], data)
	return sector
}

func (b *isoBuilder) record(name string, sector, length int, dir bool) []byte {
	var id []byte
	switch {
	case name == ".":
		id = []byte{0}
	case name == "..":
		id = []byte{1}
	case b.joliet:
		for _, u := range utf16.Encode([]rune(name)) {
			id = binary.BigEndian.AppendUint16(id, u)
		}
		if !dir {
			id = append(id, 0, ';', 0, '1')
		}
	default:
		id = []byte(strings.ToUpper(name))
		if !dir {
			id = append(id, ';', '1')
		}
	}
	n := 33 + len(id)
	if n%2 == 1 {
		n++
	}
	r := make([]byte, n)
	r[0] = byte(n)
	binary.LittleEndian.PutUint32(r[2:], uint32(sector))
	binary.BigEndian.PutUint32(r[6:], uint32(sector))
	binary.LittleEndian.PutUint32(r[10:], uint32(length))
	binary.BigEndian.PutUint32(r[14:], uint32(length))
	copy(r[18:], []byte{124, 3, 9, 14, 30, 0, 4}) // 2024-03-09 14:30:00 at GMT+1
	if dir {
		r[25] = 2
	}
	r[32] = byte(len(id))
	copy(r[33:], id)
	return r
}

type node struct {
	name     string
	data     []byte
	children []*node
	sector   int
	length   int
}

func (b *isoBuilder) layout(n *node) {
	if n.children == nil {
		n.sector, n.length = b.alloc(n.data), len(n.data)
		return
	}
	for _, c := range n.children {
		b.layout(c)
	}
	// Reserve the directory's sector first so it can describe itself.
	n.sector, n.length = b.alloc(nil), isoSector
	dir := append(b.record(".", n.sector, isoSector, true), b.record("..", n.sector, isoSector, true)...)
	for _, c := range n.children {
		dir = append(dir, b.record(c.name, c.sector, c.length, c.children != nil)...)
	}
	if len(dir) > isoSector {
		panic("test directory too large for one sector")
	}
	copy(b.img[n.sector*isoSector:], dir)
}

func tree() *node {
	return &node{name: "", children: []*node{
		{name: "readme.txt", data: []byte("hello from the disc\n")},
		{name: "Événements récents.log", data: []byte("2024-03-01T10:00:00Z from the iso\n")},
		{name: "sources", children: []*node{
			{name: "install.bin", data: bytes.Repeat([]byte{0xAB}, 5000)},
			{name: "deep", children: []*node{{name: "leaf.txt", data: []byte("leaf")}}},
		}},
	}}
}

func buildISO(t *testing.T, withUDFMarker bool) []byte {
	t.Helper()
	b := &isoBuilder{next: 20}
	b.img = make([]byte, 20*isoSector)
	plain, jol := tree(), tree()
	b.layout(plain)
	b.joliet = true
	b.layout(jol)
	vd := func(sector int, typ byte, root *node, joliet bool) {
		d := b.img[sector*isoSector:]
		d[0] = typ
		copy(d[1:], "CD001")
		d[6] = 1
		if joliet {
			copy(d[88:], "%/E")
			for i, u := range utf16.Encode([]rune("TESTDISC")) {
				binary.BigEndian.PutUint16(d[40+i*2:], u)
			}
		} else {
			copy(d[40:], "TESTDISC")
		}
		bb := &isoBuilder{joliet: joliet}
		copy(d[156:], bb.record(".", root.sector, root.length, true))
	}
	vd(16, 1, plain, false)
	vd(17, 2, jol, true)
	b.img[18*isoSector] = 255
	copy(b.img[18*isoSector+1:], "CD001")
	if withUDFMarker {
		copy(b.img[19*isoSector+1:], "NSR02")
	}
	// A boot sector signature, as hybrid discs have: it must not win.
	b.img[510], b.img[511] = 0x55, 0xAA
	return b.img
}

func names(es []Entry) string {
	var s []string
	for _, e := range es {
		if e.IsDir {
			s = append(s, e.Name+"/")
		} else {
			s = append(s, e.Name)
		}
	}
	return strings.Join(s, " ")
}

func TestISO(t *testing.T) {
	img := buildISO(t, false)
	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if d := fs.Describe(); !strings.Contains(d, "Joliet") || !strings.Contains(d, "TESTDISC") || strings.Contains(d, "UDF") {
		t.Errorf("describe: %s", d)
	}
	root, err := fs.List("/")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(root); got != "sources/ readme.txt Événements récents.log" {
		t.Errorf("root listing: %s", got)
	}
	for _, e := range root {
		if e.Name == "readme.txt" {
			// 14:30 at GMT+1 is 13:30 UTC.
			if e.Size != 20 || e.Path != "/readme.txt" || e.Modified != 1709991000*1e9 {
				t.Errorf("readme entry: %+v", e)
			}
		}
	}
	sub, err := fs.List("/sources")
	if err != nil || names(sub) != "deep/ install.bin" || sub[1].Path != "/sources/install.bin" || sub[1].Size != 5000 {
		t.Errorf("sources: %s %v", names(sub), err)
	}
	// Lookups ignore case and accept either slash.
	r, size, err := fs.Open(`\SOURCES\deep\LEAF.TXT`)
	if err != nil || size != 4 {
		t.Fatalf("open: %v size %d", err, size)
	}
	if b, _ := io.ReadAll(r); string(b) != "leaf" {
		t.Errorf("content: %q", b)
	}
	r, size, _ = fs.Open("/sources/install.bin")
	if b, _ := io.ReadAll(r); len(b) != 5000 || size != 5000 || b[4999] != 0xAB {
		t.Errorf("install.bin: %d bytes", len(b))
	}
	for _, bad := range []string{"/nope", "/readme.txt/x", "/sources/../readme.txt", "/sources"} {
		if _, _, err := fs.Open(bad); err == nil {
			t.Errorf("Open(%q) succeeded", bad)
		}
	}
	if _, err := fs.List("/readme.txt"); err == nil {
		t.Error("listed a file as a directory")
	}
}

func TestISOSaysWhenUDFIsPresent(t *testing.T) {
	img := buildISO(t, true)
	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fs.Describe(), "UDF") {
		t.Errorf("describe does not warn about UDF: %s", fs.Describe())
	}
}

// Damaged and hostile images end in an error, never a panic or a hang.
func TestDamagedImages(t *testing.T) {
	img := buildISO(t, false)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:21*isoSector] },
		"root points outside": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[17*isoSector+158:], 9999999)
			binary.LittleEndian.PutUint32(b[16*isoSector+158:], 9999999)
			return b
		},
		"huge directory": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[17*isoSector+166:], 0xFFFFFFF0); return b },
		"random": func(b []byte) []byte {
			for i := range b {
				b[i] = byte(i*31 + i>>8)
			}
			return b
		},
		"empty":                func(b []byte) []byte { return nil },
		"boot sector only":     func(b []byte) []byte { c := make([]byte, 4096); c[510], c[511] = 0x55, 0xAA; return c },
		"self-referencing dir": func(b []byte) []byte { return b },
	} {
		data := mutate(append([]byte(nil), img...))
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: panic: %v", name, p)
				}
			}()
			fs, err := Open(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				return
			}
			defer fs.Close()
			var walk func(p string, depth int)
			walk = func(p string, depth int) {
				if depth > 70 {
					t.Fatalf("%s: walk did not terminate", name)
				}
				es, err := fs.List(p)
				if err != nil {
					return
				}
				for _, e := range es {
					if e.IsDir {
						walk(e.Path, depth+1)
					} else if r, _, err := fs.Open(e.Path); err == nil {
						io.Copy(io.Discard, io.LimitReader(r, 1<<20))
					}
				}
			}
			walk("/", 0)
		}()
	}
}

func sampleNTFS(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "test.ntfs.dd"))
	if err != nil {
		t.Skip("no sample NTFS volume; run scripts/fetch-testdata.sh")
	}
	return b
}

func TestNTFSVolume(t *testing.T) {
	img := sampleNTFS(t)
	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	root, err := fs.List("/")
	if err != nil || len(root) < 5 {
		t.Fatalf("root: %d entries, %v", len(root), err)
	}
	have := map[string]Entry{}
	for _, e := range root {
		if have[e.Name].Name != "" {
			t.Errorf("%s listed twice", e.Name)
		}
		have[e.Name] = e
	}
	for _, want := range []string{"$MFT", "$LogFile", "$Volume", "$Extend"} {
		if _, ok := have[want]; !ok {
			t.Errorf("%s missing from the root; have %s", want, names(root))
		}
	}
	if !have["$Extend"].IsDir || have["$MFT"].IsDir || have["$MFT"].Born == 0 || have["$MFT"].Path != "/$MFT" {
		t.Errorf("entries: %+v %+v", have["$Extend"], have["$MFT"])
	}
	r, size, err := fs.Open("/$MFT")
	if err != nil || size != 262144 {
		t.Fatalf("open $MFT: %v size %d", err, size)
	}
	b, _ := io.ReadAll(r)
	if int64(len(b)) != size || string(b[:4]) != "FILE" {
		t.Errorf("$MFT content: %d bytes starting %q", len(b), b[:4])
	}
	// Every file in the volume can be opened and read to its stated size.
	files := 0
	var walk func(p string)
	walk = func(p string) {
		es, err := fs.List(p)
		if err != nil {
			t.Errorf("list %s: %v", p, err)
			return
		}
		for _, e := range es {
			if e.IsDir {
				walk(e.Path)
				continue
			}
			r, size, err := fs.Open(e.Path)
			if err != nil {
				if e.Size == 0 {
					continue
				}
				t.Errorf("open %s: %v", e.Path, err)
				continue
			}
			n, _ := io.Copy(io.Discard, r)
			if n != size {
				t.Errorf("%s: read %d of %d bytes", e.Path, n, size)
			}
			files++
		}
	}
	walk("/")
	if files < 10 {
		t.Errorf("only %d files could be read", files)
	}
	if _, _, err := fs.Open("/no/such/file"); err == nil {
		t.Error("opened a file that does not exist")
	}
}

// A raw disk image: partition table in front, NTFS volume inside.
func TestPartitionedDisk(t *testing.T) {
	vol := sampleNTFS(t)
	const start = 2048 // sectors
	for _, scheme := range []string{"MBR", "GPT"} {
		img := make([]byte, start*512+len(vol)+34*512)
		copy(img[start*512:], vol)
		img[510], img[511] = 0x55, 0xAA
		e := img[446:]
		if scheme == "MBR" {
			e[4] = 0x07
			binary.LittleEndian.PutUint32(e[8:], start)
			binary.LittleEndian.PutUint32(e[12:], uint32(len(vol)/512))
			// A second partition whose content Atropos cannot read.
			e2 := img[462:]
			e2[4] = 0x83
			binary.LittleEndian.PutUint32(e2[8:], uint32(start+len(vol)/512))
			binary.LittleEndian.PutUint32(e2[12:], 16)
		} else {
			e[4] = 0xEE
			binary.LittleEndian.PutUint32(e[8:], 1)
			h := img[512:]
			copy(h, "EFI PART")
			binary.LittleEndian.PutUint64(h[72:], 2)
			binary.LittleEndian.PutUint32(h[80:], 4)
			binary.LittleEndian.PutUint32(h[84:], 128)
			p := img[1024:]
			p[0] = 1 // any non-zero type GUID
			binary.LittleEndian.PutUint64(p[32:], start)
			binary.LittleEndian.PutUint64(p[40:], uint64(start+len(vol)/512-1))
			for i, u := range utf16.Encode([]rune("Basic data partition")) {
				binary.LittleEndian.PutUint16(p[56+i*2:], u)
			}
		}
		fs, err := Open(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if !strings.Contains(fs.Describe(), scheme) {
			t.Errorf("%s: describe %q", scheme, fs.Describe())
		}
		root, _ := fs.List("/")
		if len(root) == 0 || root[0].Name != "p1" || !root[0].IsDir || !strings.Contains(root[0].Note, "NTFS") {
			t.Fatalf("%s: partitions %+v", scheme, root)
		}
		if scheme == "GPT" && !strings.Contains(root[0].Note, "Basic data partition") {
			t.Errorf("GPT name not shown: %s", root[0].Note)
		}
		if scheme == "MBR" {
			if len(root) != 2 || root[1].IsDir || !strings.Contains(root[1].Note, "not readable") {
				t.Errorf("unreadable partition: %+v", root)
			}
			if _, err := fs.List("/p2"); err == nil || !strings.Contains(err.Error(), "cannot read yet") {
				t.Errorf("listing an unreadable partition: %v", err)
			}
		}
		inside, err := fs.List("/p1")
		if err != nil || len(inside) < 5 || !strings.HasPrefix(inside[0].Path, "/p1/") {
			t.Fatalf("%s: inside p1: %d entries %v", scheme, len(inside), err)
		}
		r, size, err := fs.Open("/p1/$MFT")
		if err != nil || size != 262144 {
			t.Fatalf("%s: open: %v %d", scheme, err, size)
		}
		head := make([]byte, 4)
		io.ReadFull(r, head)
		if string(head) != "FILE" {
			t.Errorf("%s: $MFT starts %q", scheme, head)
		}
		fs.Close()
	}
}

func TestPathsCannotEscape(t *testing.T) {
	for _, p := range []string{"..", "/a/../b", `\..\x`, "a/./../.."} {
		if _, _, err := clean(p); err == nil {
			t.Errorf("clean(%q) accepted", p)
		}
	}
	if full, parts, _ := clean(`\Windows\\System32/./config\`); full != "/Windows/System32/config" || len(parts) != 3 {
		t.Errorf("clean: %q %v", full, parts)
	}
}

// A file's alternate data stream is listed beside it and can be read out.
func TestNTFSVolumeStream(t *testing.T) {
	img := sampleNTFS(t)
	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	list, err := fs.List("/Folder A/Folder B")
	if err != nil {
		t.Fatal(err)
	}
	var stream Entry
	for _, e := range list {
		if strings.HasSuffix(e.Name, ":goodbye.txt") {
			stream = e
		}
	}
	if stream.Name == "" || stream.Note != "alternate data stream" || stream.Size != 20 {
		t.Fatalf("stream not listed: %+v in %d entries", stream, len(list))
	}
	r, size, err := fs.Open(stream.Path)
	if err != nil || size != 20 {
		t.Fatalf("open: %d %v", size, err)
	}
	b, _ := io.ReadAll(r)
	if len(b) != 20 || !strings.Contains(strings.ToLower(string(b)), "goodbye") {
		t.Errorf("stream content: %q", b)
	}
}
