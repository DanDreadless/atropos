package imagefs

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shadowNames(t *testing.T, fs FS, dir string) string {
	t.Helper()
	l, err := fs.List(dir)
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	var out []string
	for _, e := range l {
		if !strings.HasPrefix(e.Name, "$") {
			out = append(out, e.Name)
		}
	}
	return strings.Join(out, " ")
}

// dfVFS's volume with two shadow copies. Its files vss1 and vss2 were
// written after the first and the second copy were made, so each copy
// shows the volume without what came after it.
func TestReadThroughShadowCopies(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "vss", "vss.raw"))
	if err != nil {
		t.Skip("no sample volume with shadow copies; run scripts/fetch-testdata.sh")
	}
	defer f.Close()
	st, _ := f.Stat()
	fs, err := Open(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if got := shadowNames(t, fs, "/"); got != "<shadow copy 1> <shadow copy 2> a_directory System Volume Information a_link passwords.txt vss1 vss2" {
		t.Errorf("root: %s", got)
	}
	if got := shadowNames(t, fs, "/<shadow copy 1>"); got != "a_directory System Volume Information a_link passwords.txt" {
		t.Errorf("copy 1: %s", got)
	}
	if got := shadowNames(t, fs, "/<shadow copy 2>"); got != "a_directory System Volume Information a_link passwords.txt vss1" {
		t.Errorf("copy 2: %s", got)
	}
	l, _ := fs.List("/<shadow copy 2>/a_directory")
	if len(l) != 2 || l[0].Path != "/<shadow copy 2>/a_directory/a_file" {
		t.Errorf("paths inside a copy: %+v", l)
	}
	read := func(p string) []byte {
		r, n, err := fs.Open(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		b, _ := io.ReadAll(r)
		if int64(len(b)) != n {
			t.Fatalf("%s: %d of %d", p, len(b), n)
		}
		return b
	}
	if a, b := read("/vss1"), read("/<shadow copy 2>/vss1"); !bytes.Equal(a, b) || len(a) != 7 {
		t.Errorf("vss1 now %q, in copy 2 %q", a, b)
	}
	if a, b := read("/passwords.txt"), read("/<shadow copy 1>/passwords.txt"); !bytes.Equal(a, b) {
		t.Errorf("an unchanged file differs in the copy")
	}
	if _, _, err := fs.Open("/<shadow copy 1>/vss1"); err == nil {
		t.Error("a file written after copy 1 opened in copy 1")
	}
	if _, err := fs.List("/<shadow copy 3>"); err == nil {
		t.Error("listed a copy that does not exist")
	}
	// The bytes dfVFS's own test reads from the second copy.
	copies, _ := ShadowCopies(f, st.Size())
	v, err := OpenShadowCopy(f, st.Size(), copies, 1)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	v.ReadAt(b, 0x1C9)
	e := make([]byte, 8)
	v.ReadAt(e, v.Size()-40)
	if string(b) != "rl+Alt+Del to re" || string(e) != "estart\r\n" || v.Size() != 82771968 {
		t.Errorf("%q %q %d", b, e, v.Size())
	}
	if _, err := v.ReadAt(make([]byte, 10), v.Size()-5); err != io.EOF {
		t.Errorf("reading past the end: %v", err)
	}
	// The whole of each copy, as this reader gives it. These are not yet
	// confirmed by libvshadow (scripts/compare/vss.py prints its answer);
	// they guard against the reading changing unnoticed.
	for i, want := range []string{"f2f57c1214db9ff0ece4ca96fcb903f5", "553abf3e9ac68fb3d21c66edc37b487a"} {
		v, err := OpenShadowCopy(f, st.Size(), copies, i)
		if err != nil {
			t.Fatal(err)
		}
		h := md5.New()
		if _, err := io.Copy(h, io.NewSectionReader(v, 0, v.Size())); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			t.Errorf("copy %d: MD5 %s, want %s", i+1, got, want)
		}
	}
}

// The block descriptor rules, on stores built by hand.
func TestShadowStoreRules(t *testing.T) {
	const B = vssBlock
	s := &vssStore{fwd: map[int64]*vssDesc{}, rev: map[int64]*vssDesc{}}
	s.insert(&vssDesc{orig: 1 * B, off: 100 * B})
	s.insert(&vssDesc{orig: 2 * B, off: 101 * B, flags: vssFlagNotUsed}) // ignored
	// A forwarder: block 3 is to be read where block 4 was.
	s.insert(&vssDesc{orig: 3 * B, rel: 4 * B, flags: vssFlagForwarder})
	// A forwarder to itself is ignored.
	s.insert(&vssDesc{orig: 5 * B, rel: 5 * B, flags: vssFlagForwarder})
	// An overlay on block 1: sectors 0 and 1 come from block 200.
	s.insert(&vssDesc{orig: 1 * B, rel: 1, off: 200 * B, flags: vssFlagOverlay, bitmap: 0b11})
	// A second overlay extends the first: sector 3 too.
	s.insert(&vssDesc{orig: 1 * B, rel: 1, off: 200 * B, flags: vssFlagOverlay, bitmap: 0b1000})
	if s.fwd[2*B] != nil || s.fwd[5*B] != nil {
		t.Error("an unused or self-forwarding descriptor was kept")
	}
	if d := s.fwd[1*B]; d == nil || d.overlay == nil || d.overlay.bitmap != 0b1011 {
		t.Errorf("overlay: %+v", d)
	}
	cases := []struct {
		off          int64
		active       bool
		desc         bool
		size, at     int64
		forwarderDst bool
	}{
		{1*B + 0, true, true, 1024, 200 * B, false},        // sectors 0-1 from the overlay
		{1*B + 100, true, true, 924, 200*B + 100, false},   // mid-sector
		{1*B + 1024, true, true, 512, 100*B + 1024, false}, // sector 2 is not overlaid
		{1*B + 1536, true, true, 512, 200*B + 1536, false}, // sector 3 is
		{1*B + 0, false, true, B, 100 * B, false},          // an older copy ignores overlays
		{3*B + 10, true, true, B - 10, 4*B + 10, true},     // forwarded
		{7 * B, true, false, B, 0, false},                  // nothing here
	}
	for _, c := range cases {
		d, size, at := s.rangeAt(c.off, c.active)
		if (d != nil) != c.desc || size != c.size || (d != nil && at != c.at) {
			t.Errorf("offset %d active %v: desc %v size %d at %d; want %v %d %d", c.off, c.active, d != nil, size, at, c.desc, c.size, c.at)
		}
	}
	// A descriptor for the block a forwarder points at ends the chain: the
	// new block takes the forwarder's original offset.
	s.insert(&vssDesc{orig: 4 * B, off: 300 * B})
	if d := s.fwd[3*B]; d == nil || d.off != 300*B || d.flags&vssFlagForwarder != 0 || s.rev[4*B] != nil {
		t.Errorf("chain not resolved: %+v", d)
	}
}

// Damaged stores must fail on that copy alone, never hang or panic.
func TestShadowCopiesDamaged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vss", "vss.raw"))
	if err != nil {
		t.Skip("no sample volume with shadow copies")
	}
	copies, _ := ShadowCopies(bytes.NewReader(raw), int64(len(raw)))
	le := binary.LittleEndian
	loop := append([]byte(nil), raw...)
	bl := copies[1].BlockList
	le.PutUint64(loop[bl+40:], uint64(bl)) // the block list's next block is itself
	wrong := append([]byte(nil), raw...)
	le.PutUint32(wrong[copies[0].Bitmap+20:], 3) // a bitmap block of the wrong type
	wild := append([]byte(nil), raw...)
	le.PutUint64(wild[bl+128+16:], 1<<60) // a descriptor pointing far outside
	for i, img := range [][]byte{loop, wrong, wild} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: panic %v", i, r)
				}
			}()
			fs, err := Open(bytes.NewReader(img), int64(len(img)))
			if err != nil {
				t.Errorf("case %d: the volume itself must still open: %v", i, err)
				return
			}
			if _, err := fs.List("/"); err != nil {
				t.Errorf("case %d: root: %v", i, err)
			}
			for _, c := range []string{"/<shadow copy 1>", "/<shadow copy 2>"} {
				fs.List(c)
			}
		}()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("case %d hung", i)
		}
	}
	fs, _ := Open(bytes.NewReader(loop), int64(len(loop)))
	if _, err := fs.List("/<shadow copy 2>"); err == nil || !strings.Contains(err.Error(), "loops") {
		t.Errorf("a looping block list: %v", err)
	}
}
