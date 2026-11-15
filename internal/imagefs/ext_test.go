package imagefs

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
)

func walkExt(t *testing.T, img []byte) map[string]ExtEntry {
	t.Helper()
	out := map[string]ExtEntry{}
	if err := WalkExt(bytes.NewReader(img), int64(len(img)), func(e ExtEntry) error {
		out[e.Path] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExt4(t *testing.T) {
	img := imagetest.Ext4()
	got := walkExt(t, img)
	if len(got) != 7 {
		t.Fatalf("%d entries: %v", len(got), got)
	}
	for path, ino := range map[string]uint32{"/docs": 12, "/docs/report.txt": 13, "/big.bin": 14, "/tree.dat": 15, "/link": 16} {
		e := got[path]
		want := imagetest.ExtTimes[ino]
		if e.Inode != ino || e.Deleted || !e.Modified.T.Equal(want[0]) || !e.Accessed.T.Equal(want[1]) || !e.Changed.T.Equal(want[2]) || !e.Born.T.Equal(want[3]) {
			t.Errorf("%s: %+v, want times %v", path, e, want)
		}
	}
	if r := got["/docs/report.txt"]; r.Size != 5000 || r.Mode != 0o100640 || r.UID != 1000 || r.GID != 100 || r.Type != "file" {
		t.Errorf("report: %+v", r)
	}
	if l := got["/link"]; l.Type != "symbolic link" || l.Target != "docs/report.txt" {
		t.Errorf("link: %+v", l)
	}
	// Deleted names, from the unused space after report.txt.
	old := got["/docs/old.txt"]
	if !old.Deleted || !old.InodeFree || old.Inode != 17 || !old.DeletedAt.T.Equal(time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)) ||
		!old.Born.T.Equal(imagetest.ExtTimes[17][3]) || old.InodeReused {
		t.Errorf("old.txt: %+v", old)
	}
	re := got["/docs/reused.txt"]
	if !re.Deleted || !re.InodeReused || re.InodeFree || re.Modified.Valid || re.Inode != 14 {
		t.Errorf("a deleted name whose inode is in use must not take that inode's times: %+v", re)
	}

	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if d := fs.Describe(); !strings.Contains(d, `ext4 volume "builder", UUID deadbeef-0102-0304-0506-0708090a0b0c, last mounted at /media/usb`) {
		t.Errorf("describe: %s", d)
	}
	read := func(p string) []byte {
		r, n, err := fs.Open(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		b, err := io.ReadAll(r)
		if err != nil || int64(len(b)) != n {
			t.Fatalf("%s: %d of %d: %v", p, len(b), n, err)
		}
		return b
	}
	want := append(append(append(bytes.Repeat([]byte("A"), 1024), bytes.Repeat([]byte("B"), 1024)...), make([]byte, 2048)...), bytes.Repeat([]byte("E"), 5000-4096)...)
	if b := read("/docs/report.txt"); !bytes.Equal(b, want) {
		t.Error("extents: written blocks, a hole and an unwritten extent read wrongly")
	}
	var bigWant []byte
	for l := 0; l < 14; l++ {
		bigWant = append(bigWant, bytes.Repeat([]byte{byte(l)}, 1024)...)
	}
	if b := read("/big.bin"); !bytes.Equal(b, bigWant) {
		t.Error("block map with an indirect block read wrongly")
	}
	if b := read("/tree.dat"); string(b) != strings.Repeat("X", 1024)+strings.Repeat("Y", 1024) {
		t.Error("extent tree read wrongly")
	}
	if _, _, err := fs.Open("/link"); err == nil || !strings.Contains(err.Error(), "symbolic link to docs/report.txt") {
		t.Errorf("link: %v", err)
	}
	if _, _, err := fs.Open("/docs/old.txt"); err == nil {
		t.Error("a deleted name opened")
	}
	if _, _, err := fs.Open("/DOCS/report.txt"); err == nil {
		t.Error("ext names are case-sensitive")
	}
	list, err := fs.List("/")
	if err != nil || len(list) != 4 || list[0].Name != "docs" || list[2].Note != "symbolic link to docs/report.txt" {
		t.Errorf("root: %+v %v", list, err)
	}
	if list[0].LocalTime || list[0].Born != imagetest.ExtTimes[12][3].UnixNano() {
		t.Errorf("ext times are UTC: %+v", list[0])
	}

	// In a partition.
	disk := imagetest.MBR(img, 0x83)
	dfs, err := Open(bytes.NewReader(disk), int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	if v := ExtVolumes(dfs); len(v) != 1 || v[0].Where != "/p1" || v[0].Kind != "ext4" {
		t.Errorf("volumes: %+v", v)
	}
	if l, err := dfs.List("/p1/docs"); err != nil || len(l) != 1 {
		t.Errorf("p1/docs: %+v %v", l, err)
	}
}

// Damaged volumes must fail or stop, never hang or panic.
func TestExtHostile(t *testing.T) {
	img := imagetest.Ext4()
	le := binary.LittleEndian
	inode := func(b []byte, n int) []byte { return b[5*1024+(n-1)*256:] }
	// An extent tree whose index points back at itself.
	loop := append([]byte(nil), img...)
	le.PutUint32(inode(loop, 15)[0x28+12+4:], 70)
	le.PutUint16(loop[70*1024+6:], 1) // the node claims depth 1 and points to itself
	le.PutUint32(loop[70*1024+12+4:], 70)
	// A directory that contains itself.
	self := append([]byte(nil), img...)
	le.PutUint32(self[22*1024+24:], 12) // report.txt's entry now names /docs
	self[22*1024+24+7] = 2
	// A file claiming an enormous size and blocks past the end.
	huge := append([]byte(nil), img...)
	le.PutUint32(inode(huge, 14)[0x6C:], 0x7FFFFFFF)
	le.PutUint32(inode(huge, 14)[0x28:], 0xFFFFFFF0)
	// Impossible geometry.
	geo := append([]byte(nil), img...)
	le.PutUint32(geo[1024+0x28:], 0)
	for i, b := range [][]byte{loop, self, huge, geo, img[:3000], img[:40*1024]} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: panic %v", i, r)
				}
			}()
			WalkExt(bytes.NewReader(b), int64(len(b)), func(ExtEntry) error { return nil })
			if fs, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				for _, p := range []string{"/tree.dat", "/big.bin", "/docs/report.txt"} {
					if r, _, err := fs.Open(p); err == nil {
						io.Copy(io.Discard, io.LimitReader(r, 1<<20))
					}
				}
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("case %d hung", i)
		}
	}
}

// dfVFS's ext2 and ext4 test images: inode numbers, modes and sizes as
// dfVFS's own tests expect them.
func TestExtSamples(t *testing.T) {
	for _, name := range []string{"ext2.raw", "ext4.raw"} {
		b, err := os.ReadFile("../../testdata/ext/" + name)
		if err != nil {
			t.Skip("testdata/ext not fetched")
		}
		got := walkExt(t, b)
		for path, ino := range map[string]uint32{"/a_directory": 12, "/a_directory/a_file": 13, "/a_directory/another_file": 15, "/a_link": 16, "/passwords.txt": 14} {
			if got[path].Inode != ino {
				t.Errorf("%s %s: inode %d, dfVFS says %d", name, path, got[path].Inode, ino)
			}
		}
		a := got["/a_directory/another_file"]
		if a.Mode != 0o100664 || a.GID != 1000 || a.UID != 1000 || a.Size != 22 || a.Links != 1 {
			t.Errorf("%s: %+v", name, a)
		}
		if got["/a_link"].Target != "a_directory/another_file" {
			t.Errorf("%s link: %+v", name, got["/a_link"])
		}
		// ext2 has no creation time; ext4's large inodes do.
		if a.Born.Valid != (name == "ext4.raw") {
			t.Errorf("%s: creation time %+v", name, a.Born)
		}
	}
}
