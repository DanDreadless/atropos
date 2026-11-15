package imagefs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vssVolume builds the parts of a volume that describe its shadow copies:
// the header at 0x1E00 and a catalog of two blocks.
func vssVolume() []byte {
	v := make([]byte, 0x20000)
	h := v[vssHeaderOffset:]
	copy(h, vssID)
	binary.LittleEndian.PutUint32(h[16:], 1)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint64(h[48:], 0x8000)
	block := func(at, next int64) []byte {
		b := v[at : at+vssBlock]
		copy(b, vssID)
		binary.LittleEndian.PutUint32(b[16:], 1)
		binary.LittleEndian.PutUint32(b[20:], 2)
		binary.LittleEndian.PutUint64(b[32:], uint64(at))
		binary.LittleEndian.PutUint64(b[40:], uint64(next))
		return b
	}
	entry := func(b []byte, slot int, kind uint64, id byte, created uint64) {
		e := b[slot*vssEntry:]
		binary.LittleEndian.PutUint64(e, kind)
		for i := 16; i < 32; i++ {
			e[i] = id
		}
		if kind == 2 {
			binary.LittleEndian.PutUint64(e[8:], 1<<30)
			binary.LittleEndian.PutUint64(e[48:], created)
		}
	}
	b1 := block(0x8000, 0x10000)
	entry(b1, 1, 2, 0xBB, 133500000000000000) // the later copy is listed first
	entry(b1, 2, 3, 0xBB, 0)
	entry(b1, 3, 1, 0, 0) // an unused entry
	b2 := block(0x10000, 0)
	entry(b2, 1, 2, 0xAA, 133400000000000000)
	return v
}

func TestShadowCopiesListed(t *testing.T) {
	v := vssVolume()
	got, err := ShadowCopies(bytes.NewReader(v), int64(len(v)))
	if err != nil || len(got) != 2 {
		t.Fatalf("%d copies, %v", len(got), err)
	}
	if got[0].ID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" || got[0].HasStore || got[0].CreatedTime().Format("2006-01-02T15:04:05Z") != "2023-09-24T03:33:20Z" ||
		got[1].ID != "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" || !got[1].HasStore || got[1].VolumeSize != 1<<30 || got[1].Offset != 0x8000+vssEntry {
		t.Errorf("copies: %+v", got)
	}
	if s := shadowSummary(bytes.NewReader(v)); !strings.Contains(s, "holds 2 volume shadow copies") || !strings.Contains(s, "2023-09-24 03:33 UTC") {
		t.Errorf("summary: %q", s)
	}
	// No header: no shadow copies, and no error.
	if got, err := ShadowCopies(bytes.NewReader(make([]byte, 0x10000)), 0x10000); err != nil || len(got) != 0 {
		t.Errorf("volume without shadow copies: %v %v", got, err)
	}
	// A catalog that points back at itself ends with an error, not a hang.
	loop := append([]byte(nil), v...)
	binary.LittleEndian.PutUint64(loop[0x10000+40:], 0x8000)
	if _, err := ShadowCopies(bytes.NewReader(loop), int64(len(loop))); err == nil {
		t.Error("a looping catalog was read without error")
	}
	// Damage anywhere in the header or the block headers must not panic.
	for _, at := range []int{vssHeaderOffset, 0x8000, 0x10000} {
		for i := 0; i < 64; i++ {
			for _, x := range []byte{0x00, 0xFF} {
				bad := append([]byte(nil), v...)
				bad[at+i] = x
				ShadowCopies(bytes.NewReader(bad), int64(len(bad)))
			}
		}
	}
	for n := 0; n < len(v); n += 997 {
		ShadowCopies(bytes.NewReader(v[:n]), int64(n))
	}
}

// A volume made by Windows (dfVFS test data), with the answer libvshadow gives.
func TestShadowCopiesPublicSample(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "vss", "vss.raw"))
	if err != nil {
		t.Skip("no sample volume with shadow copies; run scripts/fetch-testdata.sh")
	}
	defer f.Close()
	st, _ := f.Stat()
	got, err := ShadowCopies(f, st.Size())
	if err != nil || len(got) != 2 {
		t.Fatalf("%d copies, %v", len(got), err)
	}
	const layout = "2006-01-02T15:04:05.000000Z"
	if got[0].ID != "de81cc22-aa8b-11eb-9339-8cdcd4557abc" || got[0].CreatedTime().Format(layout) != "2021-05-01T17:40:03.223030Z" ||
		got[1].ID != "de81cc2b-aa8b-11eb-9339-8cdcd4557abc" || got[1].CreatedTime().Format(layout) != "2021-05-01T17:41:28.224986Z" ||
		got[0].VolumeSize != 82771968 || !got[0].HasStore {
		t.Errorf("copies: %+v", got)
	}
	fs, err := Open(f, st.Size())
	if err != nil || !strings.Contains(fs.Describe(), "holds 2 volume shadow copies") {
		t.Errorf("describe: %v %v", fs, err)
	}
}
