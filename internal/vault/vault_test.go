package vault

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error { os.Chmod(p, 0o700); return nil })
	})
	return v, dir
}

func TestPutHashesStoresAndProtects(t *testing.T) {
	v, dir := open(t)
	data := []byte("the quick brown fox")
	hs, existed, err := v.Put(bytes.NewReader(data))
	if err != nil || existed {
		t.Fatalf("put: existed=%v err=%v", existed, err)
	}
	s256, s1, m5 := sha256.Sum256(data), sha1.Sum(data), md5.Sum(data)
	if hs.SHA256 != hex.EncodeToString(s256[:]) || hs.SHA1 != hex.EncodeToString(s1[:]) || hs.MD5 != hex.EncodeToString(m5[:]) || hs.Size != int64(len(data)) {
		t.Errorf("hashes: %+v", hs)
	}
	p := v.Path(hs.SHA256)
	if !strings.HasPrefix(p, filepath.Join(dir, "evidence", hs.SHA256[:2])) {
		t.Errorf("stored at %s", p)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, data) {
		t.Error("stored content differs")
	}
	if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Error("stored file can be opened for writing")
	}
	if err := v.Verify(hs.SHA256); err != nil {
		t.Errorf("verify: %v", err)
	}
	f, err := v.Open(hs.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("the handle given to parsers is writable")
	}
	f.Close()
}

func TestIdenticalContentIsStoredOnceAndNeverOverwritten(t *testing.T) {
	v, dir := open(t)
	hs, _, _ := v.Put(strings.NewReader("same"))
	info1, _ := os.Stat(v.Path(hs.SHA256))
	hs2, existed, err := v.Put(strings.NewReader("same"))
	if err != nil || !existed || hs2 != hs {
		t.Fatalf("second put: existed=%v err=%v", existed, err)
	}
	info2, _ := os.Stat(v.Path(hs.SHA256))
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("the stored copy was rewritten")
	}
	if left, _ := os.ReadDir(filepath.Join(dir, "work")); len(left) != 0 {
		t.Errorf("%d temporary files left behind", len(left))
	}
	if hs3, _, _ := v.Put(strings.NewReader("")); hs3.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" || hs3.Size != 0 {
		t.Errorf("empty input: %+v", hs3)
	}
}

type failing struct{ n int }

func (f *failing) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("disk fell over")
	}
	f.n--
	p[0] = 'x'
	return 1, nil
}

// A read that fails part-way must leave nothing in the vault: a truncated
// copy stored under any name would be evidence that was never submitted.
func TestFailedReadStoresNothing(t *testing.T) {
	v, dir := open(t)
	if _, _, err := v.Put(&failing{n: 100}); err == nil {
		t.Fatal("no error from a failing reader")
	}
	n := 0
	filepath.Walk(dir, func(_ string, info os.FileInfo, _ error) error {
		if info != nil && info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	if n != 0 {
		t.Errorf("%d files left after a failed intake", n)
	}
}

func TestVerifyDetectsChange(t *testing.T) {
	v, _ := open(t)
	hs, _, _ := v.Put(strings.NewReader(strings.Repeat("a", 5000)))
	p := v.Path(hs.SHA256)
	os.Chmod(p, 0o600)
	b, _ := os.ReadFile(p)
	b[4999] = 'b'
	os.WriteFile(p, b, 0o600)
	if err := v.Verify(hs.SHA256); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("verify after change: %v", err)
	}
	os.Remove(p)
	if err := v.Verify(hs.SHA256); err == nil {
		t.Error("verify passed for a missing file")
	}
	src := filepath.Join(t.TempDir(), "orig.bin")
	os.WriteFile(src, []byte("original"), 0o600)
	if _, _, err := v.PutFile(src); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(src); string(got) != "original" {
		t.Error("PutFile altered its source")
	}
}
