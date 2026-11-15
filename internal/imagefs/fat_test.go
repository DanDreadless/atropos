package imagefs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
)

func walkAll(t *testing.T, img []byte) map[string]FATEntry {
	t.Helper()
	out := map[string]FATEntry{}
	if err := WalkFAT(bytes.NewReader(img), int64(len(img)), func(e FATEntry) error {
		out[e.Path] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func readAll(t *testing.T, fs FS, path string) []byte {
	t.Helper()
	r, n, err := fs.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	b, err := io.ReadAll(r)
	if err != nil || int64(len(b)) != n {
		t.Fatalf("%s: read %d of %d bytes: %v", path, len(b), n, err)
	}
	return b
}

func wall(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05.00", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFAT16(t *testing.T) {
	img := imagetest.FAT16()
	if !IsFATVolume(bytes.NewReader(img)) {
		t.Fatal("not recognised as a FAT volume")
	}
	got := walkAll(t, img)
	var paths []string
	for p := range got {
		paths = append(paths, p)
	}
	if len(got) != 4 {
		t.Fatalf("entries: %v", paths)
	}
	r := got["/Report final.docx"]
	if r.ShortName != "REPORT~1.DOC" || r.Size != 3000 || r.Deleted || r.IsDir ||
		!r.Created.Wall.Equal(wall("2023-03-01 10:20:30.50")) || !r.Modified.Wall.Equal(wall("2023-03-02 11:22:44.00")) ||
		!r.Accessed.Wall.Equal(wall("2023-03-05 00:00:00.00")) || !r.Accessed.DateOnly || r.Modified.HasOffset {
		t.Errorf("report: %+v", r)
	}
	if j := got["/DCIM/img_0001.jpg"]; j.ShortName != "img_0001.jpg" || j.Size != 12 {
		t.Errorf("NT lower-case flags not applied: %+v", j)
	}
	// Deleting overwrote the S of SECRET~1; the long name's checksum gives it back.
	s, ok := got["/secret plan.txt"]
	if !ok || !s.Deleted || !s.NameRecovered || s.ShortName != "SECRET~1.TXT" || s.Size != 10 {
		t.Errorf("deleted entry: %+v (%v)", s, paths)
	}

	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if d := fs.Describe(); !strings.Contains(d, `FAT16 volume "TESTSTICK", serial 1234-ABCD`) {
		t.Errorf("describe: %s", d)
	}
	list, err := fs.List("/")
	if err != nil || len(list) != 2 {
		t.Fatalf("root listing (deleted entries are not listed): %+v %v", list, err)
	}
	for _, e := range list {
		if !e.LocalTime || e.Note == "" {
			t.Errorf("FAT times are local, and the listing must say so: %+v", e)
		}
	}
	want := make([]byte, 3000)
	for i := range want {
		want[i] = byte(i % 251)
	}
	// The report is in clusters 3 and 5: reading straight on would give
	// the deleted file's cluster 4.
	if b := readAll(t, fs, "/report FINAL.docx"); !bytes.Equal(b, want) {
		t.Error("the fragmented file did not follow its cluster chain")
	}
	if b := readAll(t, fs, "/dcim/IMG_0001.JPG"); string(b) != "JPEGJPEGJPEG" {
		t.Errorf("by short name: %q", b)
	}
	if _, _, err := fs.Open("/secret plan.txt"); err == nil {
		t.Error("a deleted file must not open as if it were in use")
	}
}

func TestExFAT(t *testing.T) {
	img := imagetest.ExFAT()
	got := walkAll(t, img)
	if len(got) != 4 {
		t.Fatalf("entries: %v", got)
	}
	p := got["/Holiday photo.jpg"]
	if p.Size != 5000 || !p.Created.HasOffset || p.Created.OffsetMinutes != 60 ||
		!p.Created.UTC().Equal(wall("2024-07-15 13:30:21.50")) || !p.Modified.UTC().Equal(wall("2024-07-15 13:30:20.00")) ||
		p.Accessed.DateOnly || !p.Accessed.UTC().Equal(wall("2024-07-16 08:00:00.00")) {
		t.Errorf("photo: %+v", p)
	}
	d := got["/Docs"]
	if !d.IsDir || d.Created.OffsetMinutes != -300 || !d.Created.UTC().Equal(wall("2024-01-02 08:04:06.00")) {
		t.Errorf("negative offset: %+v", d)
	}
	n := got["/Docs/notes.txt"]
	if n.Modified.HasOffset || !n.Modified.Wall.Equal(wall("2024-02-03 04:05:06.00")) {
		t.Errorf("no offset recorded: %+v", n)
	}
	if g := got["/gone.txt"]; !g.Deleted || g.Size != 10 {
		t.Errorf("deleted entry set: %+v", g)
	}
	fs, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if d := fs.Describe(); !strings.Contains(d, "exFAT volume, serial C0FF-EE11") {
		t.Errorf("describe: %s", d)
	}
	want := make([]byte, 5000)
	for i := range want {
		want[i] = byte(i % 241)
	}
	if b := readAll(t, fs, "/Holiday photo.jpg"); !bytes.Equal(b, want) {
		t.Error("contiguous file read wrongly")
	}
	if b := readAll(t, fs, "/docs/NOTES.TXT"); string(b) != "hello notes\n" {
		t.Errorf("notes: %q", b)
	}
	list, _ := fs.List("/")
	for _, e := range list {
		if e.Name == "Holiday photo.jpg" && (e.LocalTime || e.Modified != wall("2024-07-15 13:30:20.00").UnixNano()) {
			t.Errorf("an exFAT time with its offset is a true time: %+v", e)
		}
	}
}

func TestFATInPartitions(t *testing.T) {
	for _, c := range []struct {
		name string
		img  []byte
	}{{"FAT16", imagetest.MBR(imagetest.FAT16(), 0x0E)}, {"exFAT", imagetest.MBR(imagetest.ExFAT(), 0x07)}} {
		fs, err := Open(bytes.NewReader(c.img), int64(len(c.img)))
		if err != nil {
			t.Fatal(c.name, err)
		}
		vols := FATVolumes(fs)
		if len(vols) != 1 || vols[0].Where != "/p1" {
			t.Fatalf("%s: %+v", c.name, vols)
		}
		list, err := fs.List("/p1")
		if err != nil || len(list) != 2 {
			t.Errorf("%s: %+v %v", c.name, list, err)
		}
		n := 0
		WalkFAT(vols[0].R, vols[0].Size, func(FATEntry) error { n++; return nil })
		if n != 4 {
			t.Errorf("%s: walked %d entries", c.name, n)
		}
	}
}

// Damaged volumes must fail or stop, never hang or panic.
func TestFATHostile(t *testing.T) {
	img := imagetest.FAT16()
	// A cluster chain that loops: cluster 3 points back to itself.
	loop := append([]byte(nil), img...)
	loop[512+3*2], loop[512+3*2+1] = 3, 0
	// A directory that contains itself.
	self := append([]byte(nil), img...)
	rootOff := (1 + 2*32) * 512
	dataOff := rootOff + 512*32
	copy(self[dataOff+3*32:], self[rootOff+3*32:rootOff+4*32]) // DCIM inside DCIM
	ex := imagetest.ExFAT()
	exloop := append([]byte(nil), ex...)
	copy(exloop[24*512+4*4:], []byte{4, 0, 0, 0}) // the root chain points to itself
	for i, b := range [][]byte{loop, self, exloop, img[:4096], ex[:8192]} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: panic %v", i, r)
				}
			}()
			WalkFAT(bytes.NewReader(b), int64(len(b)), func(FATEntry) error { return nil })
			if fs, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				if r, _, err := fs.Open("/Report final.docx"); err == nil {
					io.Copy(io.Discard, r)
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

// dfVFS's FAT12 test image: names, sizes and the directory entry offset
// that dfVFS gives as its inode number.
func TestFAT12Sample(t *testing.T) {
	b, err := os.ReadFile("../../testdata/fat/fat12.raw")
	if err != nil {
		t.Skip("testdata/fat not fetched")
	}
	got := walkAll(t, b)
	var lines []string
	for _, p := range []string{"/a_directory", "/a_directory/a_file", "/a_directory/another_file", "/passwords.txt"} {
		e := got[p]
		lines = append(lines, fmt.Sprintf("%s %d %v", p, e.Size, e.IsDir))
	}
	want := []string{"/a_directory 0 true", "/a_directory/a_file 53 false", "/a_directory/another_file 22 false", "/passwords.txt 116 false"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") || len(got) != 4 {
		t.Errorf("got\n%s", strings.Join(lines, "\n"))
	}
	if got["/a_directory/another_file"].Offset != 0x62A0 {
		t.Errorf("entry offset %#x, dfVFS says 0x62A0", got["/a_directory/another_file"].Offset)
	}
	fs, _ := Open(bytes.NewReader(b), int64(len(b)))
	if s := readAll(t, fs, "/a_directory/another_file"); string(s) != "This is another file.\n" {
		t.Errorf("content %q", s)
	}
}
