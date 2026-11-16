package imagefs

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// udfFixture reads a disc that Windows' own IMAPI2 wrote
// (scripts/mkudf.ps1 makes them from made-up files): UDF 1.02, the oldest
// revision, and 2.50, which keeps its directories in a metadata partition.
func udfFixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("fixtures/" + name + ".iso.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUDF(t *testing.T) {
	notes := strings.Repeat("line of notes ", 200)
	blob := make([]byte, 0, 76800)
	for i := 0; i < 300; i++ {
		for c := 0; c < 256; c++ {
			blob = append(blob, byte(c))
		}
	}
	for _, c := range []struct{ name, describe string }{
		{"udf102", `UDF 1.02 disc "UDFTEST"`},
		{"udf250", `UDF 2.50 disc "UDFTEST"`},
	} {
		img := udfFixture(t, c.name)
		fs, err := Open(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			t.Fatal(c.name, err)
		}
		if fs.Describe() != c.describe {
			t.Errorf("%s: %s", c.name, fs.Describe())
		}
		names := func(dir string) string {
			l, err := fs.List(dir)
			if err != nil {
				t.Fatalf("%s %s: %v", c.name, dir, err)
			}
			var out []string
			for _, e := range l {
				out = append(out, e.Name)
			}
			return strings.Join(out, " | ")
		}
		if got := names("/"); got != "Docs | readme.txt" {
			t.Errorf("%s root: %s", c.name, got)
		}
		if got := names("/Docs"); got != "Deep | blob.bin | notes.txt | été résumé.txt" {
			t.Errorf("%s Docs: %s", c.name, got)
		}
		read := func(p string) string {
			r, n, err := fs.Open(p)
			if err != nil {
				t.Fatalf("%s %s: %v", c.name, p, err)
			}
			b, _ := io.ReadAll(r)
			if int64(len(b)) != n {
				t.Fatalf("%s %s: %d of %d", c.name, p, len(b), n)
			}
			return string(b)
		}
		for p, want := range map[string]string{
			"/readme.txt": "UDF test disc made by IMAPI2", "/Docs/notes.txt": notes, "/Docs/blob.bin": string(blob),
			"/Docs/Deep/Deeper/bottom.log": "2024-03-01T10:00:00Z deep", "/Docs/été résumé.txt": "\xEF\xBB\xBFunicode name", // PowerShell 5 writes UTF-8 with a byte order mark
			"/DOCS/NOTES.TXT": notes,
		} {
			if got := read(p); got != want {
				t.Errorf("%s %s: %d bytes, not what was written", c.name, p, len(got))
			}
		}
		// The test file's time was set to this before the disc was made.
		l, _ := fs.List("/")
		if r := l[1]; r.Name != "readme.txt" || r.LocalTime || time.Unix(0, r.Modified).UTC() != time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC) {
			t.Errorf("%s: readme time %v local=%v", c.name, time.Unix(0, r.Modified).UTC(), r.LocalTime)
		}
		if _, _, err := fs.Open("/Docs"); err == nil {
			t.Errorf("%s: opened a folder", c.name)
		}
	}
}

func TestUDFTimes(t *testing.T) {
	ts := func(tz uint16, y int, mo, d, h, mi, s byte) []byte {
		b := make([]byte, 12)
		binary.LittleEndian.PutUint16(b, tz)
		binary.LittleEndian.PutUint16(b[2:], uint16(y))
		b[4], b[5], b[6], b[7], b[8], b[9] = mo, d, h, mi, s, 50
		return b
	}
	// Local time with an offset of +60 minutes: 11:00 local is 10:00 UTC.
	if got, local := udfTime(ts(0x1000|60, 2024, 3, 1, 11, 0, 0)); local || got != time.Date(2024, 3, 1, 10, 0, 0, 500000000, time.UTC) {
		t.Errorf("+60: %v %v", got, local)
	}
	// -300 minutes in 12 bits.
	if got, local := udfTime(ts(0x1000|(0x1000-300), 2024, 3, 1, 5, 0, 0)); local || got != time.Date(2024, 3, 1, 10, 0, 0, 500000000, time.UTC) {
		t.Errorf("-300: %v %v", got, local)
	}
	// No zone recorded (-2047): kept as written and said to be local.
	if got, local := udfTime(ts(0x1000|(0x1000-2047), 2024, 3, 1, 10, 0, 0)); !local || got.Hour() != 10 {
		t.Errorf("unspecified: %v %v", got, local)
	}
}

// Damaged discs must fail or stop, never hang or panic.
func TestUDFDamaged(t *testing.T) {
	img := udfFixture(t, "udf250")
	// Point the anchor's descriptor sequence far away, and corrupt every
	// file identifier's length.
	far := append([]byte(nil), img...)
	binary.LittleEndian.PutUint32(far[256*2048+20:], 0x7FFFFFF0)
	lengths := append([]byte(nil), img...)
	for i := 0; i+40 < len(lengths); i += 4 {
		if lengths[i] == 0x01 && lengths[i+1] == 0x01 { // a file identifier's tag
			binary.LittleEndian.PutUint16(lengths[i+36:], 0xFFFF)
		}
	}
	for i, b := range [][]byte{far, lengths, img[:300*2048], img[:len(img)/2]} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: panic %v", i, r)
				}
			}()
			if fs, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				var walk func(string, int)
				walk = func(d string, depth int) {
					l, _ := fs.List(d)
					for _, e := range l {
						if e.IsDir && depth < 10 {
							walk(e.Path, depth+1)
						} else if r, _, err := fs.Open(e.Path); err == nil {
							io.Copy(io.Discard, io.LimitReader(r, 1<<20))
						}
					}
				}
				walk("/", 0)
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("case %d hung", i)
		}
	}
}
