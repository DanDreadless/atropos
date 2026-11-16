package imagefs

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

type testThumb struct {
	id   string
	data []byte
}

// thumbcache builds a cache in the given format: the 24-byte header, then
// entries back to back, then the free space as one empty entry.
func thumbcache(version uint32, thumbs ...testThumb) []byte {
	le := binary.LittleEndian
	header := 56
	if version == 21 {
		header = 48
	}
	var b bytes.Buffer
	b.WriteString("CMMM")
	binary.Write(&b, le, version)
	binary.Write(&b, le, uint32(4))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint32(24))
	binary.Write(&b, le, uint32(len(thumbs)))
	for _, t := range thumbs {
		var id []byte
		for _, c := range utf16.Encode([]rune(t.id)) {
			id = binary.LittleEndian.AppendUint16(id, c)
		}
		pad := (8 - (header+len(id))%8) % 8
		e := make([]byte, header)
		copy(e, "CMMM")
		le.PutUint32(e[4:], uint32(header+len(id)+pad+len(t.data)))
		le.PutUint64(e[8:], 0x1234)
		at := 16
		if version == 20 {
			at = 24
		}
		le.PutUint32(e[at:], uint32(len(id)))
		le.PutUint32(e[at+4:], uint32(pad))
		le.PutUint32(e[at+8:], uint32(len(t.data)))
		b.Write(e)
		b.Write(id)
		b.Write(make([]byte, pad))
		b.Write(t.data)
	}
	free := make([]byte, 4096)
	copy(free, "CMMM")
	le.PutUint32(free[4:], 4096)
	b.Write(free)
	return b.Bytes()
}

func TestThumbnailCache(t *testing.T) {
	jpg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte("j"), 300)...)
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("p"), 200)...)
	for _, v := range []uint32{21, 32} {
		img := thumbcache(v,
			testThumb{"482d656ee647f25e", jpg},
			testThumb{"77", nil}, // an entry without a picture
			testThumb{"9a1b2c3d4e5f6071", png},
			testThumb{"482d656ee647f25e", jpg}, // the same identifier again
			testThumb{`::{645FF040-5081-101B-9F08-00AA002F954E}`, png},
		)
		fs, err := Open(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			t.Fatal(v, err)
		}
		if d := fs.Describe(); !strings.Contains(d, "4 thumbnails (2 JPEG, 2 PNG, 0 BMP, 0 other), 1 entries without a picture") {
			t.Errorf("%d: %s", v, d)
		}
		l, _ := fs.List("/")
		var names []string
		for _, e := range l {
			names = append(names, e.Name)
		}
		want := "482d656ee647f25e.jpg 9a1b2c3d4e5f6071.png 482d656ee647f25e~2.jpg __{645FF040-5081-101B-9F08-00AA002F954E}.png"
		if strings.Join(names, " ") != want {
			t.Errorf("%d: %s", v, strings.Join(names, " "))
		}
		r, n, err := fs.Open("/9a1b2c3d4e5f6071.png")
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := io.ReadAll(r); !bytes.Equal(got, png) || n != int64(len(png)) {
			t.Errorf("%d: picture read wrongly", v)
		}
	}
}

func TestThumbnailCacheDamaged(t *testing.T) {
	img := thumbcache(32, testThumb{"aa", []byte("\xFF\xD8xxxx")}, testThumb{"bb", []byte("\xFF\xD8yyyy")})
	huge := append([]byte(nil), img...)
	binary.LittleEndian.PutUint32(huge[24+24:], 0xFFFFFFF0) // a data size past the end
	zero := append([]byte(nil), img...)
	binary.LittleEndian.PutUint32(zero[24+4:], 0) // an entry size of nothing
	for i, b := range [][]byte{huge, zero, img[:40], img[:100]} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if fs, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				fs.List("/")
				_ = fs.Describe()
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("case %d hung", i)
		}
	}
	fs, _ := Open(bytes.NewReader(huge), int64(len(huge)))
	if d := fs.Describe(); !strings.Contains(d, "impossible sizes") {
		t.Errorf("damage not reported: %s", d)
	}
}
