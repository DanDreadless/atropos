package imagefs

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
)

func seg(b []byte) EWFSegment { return EWFSegment{bytes.NewReader(b), int64(len(b))} }

// media that compresses in places and not in others, and does not end on a chunk boundary.
func e01Media() []byte {
	rnd := rand.New(rand.NewSource(7))
	m := make([]byte, 9*32768+3*512)
	rnd.Read(m[:3*32768])
	copy(m[5*32768:], bytes.Repeat([]byte("atropos "), 4096))
	rnd.Read(m[len(m)-1000:])
	return m
}

func TestE01ReadsBackTheMedia(t *testing.T) {
	media := e01Media()
	sum := md5.Sum(media)
	want := hex.EncodeToString(sum[:])
	for _, o := range []imagetest.E01Options{
		{}, {Compress: true}, {Segments: 3}, {Segments: 3, Compress: true, FileBase: true}, {Segments: 2, NoSetID: true}, {Segments: 10, Compress: true},
	} {
		name := fmt.Sprintf("%+v", o)
		files := imagetest.E01(media, o)
		// The other segments are offered in the wrong order, among things that are not part of the set.
		others := []EWFSegment{seg([]byte("not an image at all")), seg(imagetest.E01(media[:32768], imagetest.E01Options{SetID: 0x55})[0])}
		for i := len(files) - 1; i >= 1; i-- {
			others = append(others, seg(files[i]))
		}
		e, err := OpenEWF(seg(files[0]), others)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if e.Size() != int64(len(media)) || e.Segments != len(files) || e.Info.MD5 != want {
			t.Fatalf("%s: size %d segments %d stored md5 %s", name, e.Size(), e.Segments, e.Info.MD5)
		}
		got, err := io.ReadAll(io.NewSectionReader(e, 0, e.Size()))
		if err != nil || !bytes.Equal(got, media) {
			t.Fatalf("%s: read back %d bytes, err %v, equal %v", name, len(got), err, bytes.Equal(got, media))
		}
		rnd := rand.New(rand.NewSource(1))
		for i := 0; i < 200; i++ {
			off, n := rnd.Intn(len(media)), rnd.Intn(70000)
			buf := make([]byte, n)
			k, err := e.ReadAt(buf, int64(off))
			end := off + n
			if end > len(media) {
				end = len(media)
			}
			if k != end-off || !bytes.Equal(buf[:k], media[off:end]) || (k < n) != (err == io.EOF) {
				t.Fatalf("%s: ReadAt(%d, %d) gave %d bytes, err %v", name, off, n, k, err)
			}
		}
		if sum, err := e.MediaMD5(); err != nil || sum != want {
			t.Errorf("%s: media md5 %s, %v", name, sum, err)
		}
		if e.Info.Header["case_number"] != "CASE-7" || e.Info.Header["examiner"] != "A. Examiner" {
			t.Errorf("%s: header %v", name, e.Info.Header)
		}
		if _, leaked := e.Info.Header["p"]; leaked || len(e.Info.Header) != 9 {
			t.Errorf("%s: header fields %v", name, e.Info.Header)
		}
		// Any segment of the set opens it.
		if len(files) > 1 {
			all := []EWFSegment{}
			for _, f := range files {
				all = append(all, seg(f))
			}
			if e2, err := OpenEWF(seg(files[len(files)-1]), all); err != nil || e2.Segments != len(files) {
				t.Errorf("%s: opening by the last segment: %v", name, err)
			}
		}
	}
}

// A set with a segment missing is refused, saying which.
func TestE01IncompleteSet(t *testing.T) {
	files := imagetest.E01(e01Media(), imagetest.E01Options{Segments: 4})
	if _, err := OpenEWF(seg(files[0]), []EWFSegment{seg(files[1]), seg(files[3])}); err == nil || !strings.Contains(err.Error(), "segment 3") {
		t.Errorf("middle segment missing: %v", err)
	}
	if _, err := OpenEWF(seg(files[0]), []EWFSegment{seg(files[1])}); err == nil || !strings.Contains(err.Error(), "continues after segment 2") {
		t.Errorf("last segments missing: %v", err)
	}
	if _, err := OpenEWF(seg(files[0]), nil); err == nil {
		t.Error("the first segment alone was accepted as a whole image")
	}
	// With no set identifier, two different second segments cannot be told apart.
	a := imagetest.E01(e01Media(), imagetest.E01Options{Segments: 2, NoSetID: true})
	other := e01Media()
	other[len(other)-1] ^= 1
	b := imagetest.E01(other, imagetest.E01Options{Segments: 2, NoSetID: true})
	if _, err := OpenEWF(seg(a[0]), []EWFSegment{seg(a[1]), seg(b[1])}); err == nil || !strings.Contains(err.Error(), "cannot be told apart") {
		t.Errorf("ambiguous segments: %v", err)
	}
}

// Damage inside a chunk is an error at that chunk, and nowhere else.
func TestE01DamagedChunk(t *testing.T) {
	media := e01Media()
	for _, compress := range []bool{false, true} {
		file := imagetest.E01(media, imagetest.E01Options{Compress: compress})[0]
		// Chunk 1 is random data, stored as it is; chunk 5 is text, compressed when asked.
		target := 1
		if compress {
			target = 5
		}
		good, err := OpenEWF(seg(file), nil)
		if err != nil {
			t.Fatal(err)
		}
		tb := good.tables[0]
		at := tb.base + int64(tb.entries[target]&0x7FFFFFFF) + 20
		bad := append([]byte(nil), file...)
		bad[at] ^= 0xFF
		e, err := OpenEWF(seg(bad), nil)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32768)
		if _, err := e.ReadAt(buf, int64(target)*32768); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("chunk %d", target)) {
			t.Errorf("compress=%v: damaged chunk read gave %v", compress, err)
		}
		if _, err := e.ReadAt(buf, 0); err != nil || !bytes.Equal(buf, media[:32768]) {
			t.Errorf("compress=%v: an undamaged chunk could not be read: %v", compress, err)
		}
		if _, err := e.MediaMD5(); err == nil {
			t.Errorf("compress=%v: verification passed over a damaged chunk", compress)
		}
	}
}

// Hostile input: never a panic, a hang or a wrong answer given as right.
func TestE01Corrupt(t *testing.T) {
	media := e01Media()[:3*32768]
	file := imagetest.E01(media, imagetest.E01Options{Compress: true})[0]
	sum := md5.Sum(media)
	want := hex.EncodeToString(sum[:])
	try := func(b []byte) {
		e, err := OpenEWF(seg(b), nil)
		if err != nil {
			return
		}
		got, err := e.MediaMD5()
		if err == nil && got != want && e.Size() == int64(len(media)) {
			t.Fatalf("a damaged image read without error and gave different content")
		}
	}
	// Every byte outside the chunk data, and a spread of bytes inside it.
	for i := 0; i < len(file); i++ {
		if i > 2500 && i < len(file)-2500 && i%97 != 0 {
			continue
		}
		for _, v := range []byte{0x00, 0xFF, file[i] ^ 0x01} {
			if v == file[i] {
				continue
			}
			bad := append([]byte(nil), file...)
			bad[i] = v
			try(bad)
		}
	}
	for n := 0; n < len(file); n += 37 {
		try(file[:n])
	}
}

// An NTFS volume inside a split E01 image browses as the volume itself does.
func TestE01HoldsAFileSystem(t *testing.T) {
	img := sampleNTFS(t)
	direct, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := direct.List("/")
	files := imagetest.E01(img, imagetest.E01Options{Segments: 3, Compress: true})
	fs, err := OpenSet(bytes.NewReader(files[0]), int64(len(files[0])), []EWFSegment{seg(files[2]), seg(files[1])})
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.List("/")
	if err != nil || names(got) != names(want) || len(got) == 0 {
		t.Fatalf("listing through E01: %v\n%s\n%s", err, names(got), names(want))
	}
	if !strings.HasPrefix(fs.Describe(), direct.Describe()) || !strings.Contains(fs.Describe(), "E01 image of 3 segments") {
		t.Errorf("describe: %q", fs.Describe())
	}
	// A file read through the image is the file.
	for _, e := range got {
		if e.IsDir || e.Size == 0 || e.Size > 1<<20 {
			continue
		}
		r1, n1, err1 := direct.Open(e.Path)
		r2, n2, err2 := fs.Open(e.Path)
		if err1 != nil || err2 != nil || n1 != n2 {
			t.Fatalf("%s: %v %v %d %d", e.Path, err1, err2, n1, n2)
		}
		b1, _ := io.ReadAll(r1)
		b2, _ := io.ReadAll(r2)
		if !bytes.Equal(b1, b2) {
			t.Errorf("%s differs when read through the E01 image", e.Path)
		}
		break
	}
	// The first segment alone says what is missing rather than "no file system".
	if _, err := Open(bytes.NewReader(files[0]), int64(len(files[0]))); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("first segment alone: %v", err)
	}
}

// Images made by another tool (ewfacquire, from the dfVFS test data): the
// hash that tool stored must be the hash of what is read here.
func TestE01PublicSamples(t *testing.T) {
	load := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ewf", name))
		if err != nil {
			t.Skip("no sample E01 images; run scripts/fetch-testdata.sh")
		}
		return b
	}
	single := load("ext2.E01")
	e, err := OpenEWF(seg(single), nil)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := e.MediaMD5()
	if err != nil || e.Info.MD5 == "" || sum != e.Info.MD5 {
		t.Errorf("single segment: computed %s, stored %s, %v", sum, e.Info.MD5, err)
	}
	if e.Size() != 4194304 {
		t.Errorf("single segment: media size %d", e.Size())
	}
	s1, s2 := load("ext2.split.E01"), load("ext2.split.E02")
	e, err = OpenEWF(seg(s2), []EWFSegment{seg(single), seg(s1)})
	if err != nil {
		t.Fatal(err)
	}
	sum, err = e.MediaMD5()
	if err != nil || e.Segments != 2 || e.Info.MD5 == "" || sum != e.Info.MD5 {
		t.Errorf("split: %d segments, computed %s, stored %s, %v", e.Segments, sum, e.Info.MD5, err)
	}
	if _, err := OpenEWF(seg(s1), nil); err == nil {
		t.Error("half of a split image opened as a whole one")
	}
}
