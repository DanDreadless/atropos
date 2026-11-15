// Package vault is the write-once evidence store. Every submitted file is
// copied in while being hashed, stored under its SHA-256 and made read-only.
// Parsers only ever receive read-only handles to vault copies; the examiner's
// original is opened read-only once and never touched again.
package vault

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Vault struct {
	root string
	work string
}

type Hashes struct {
	SHA256, SHA1, MD5 string
	Size              int64
}

func Open(caseDir string) (*Vault, error) {
	v := &Vault{root: filepath.Join(caseDir, "evidence"), work: filepath.Join(caseDir, "work")}
	for _, d := range []string{v.root, v.work} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// WorkDir is where temporary files belonging to this case are written.
func (v *Vault) WorkDir() string { return v.work }

// Path returns where content with this SHA-256 lives.
func (v *Vault) Path(sha string) string {
	return filepath.Join(v.root, sha[:2], sha)
}

// Put streams r into the vault. It reports whether the content was already
// present; existing content is never overwritten.
func (v *Vault) Put(r io.Reader) (Hashes, bool, error) {
	tmp, err := os.CreateTemp(v.work, "intake-*")
	if err != nil {
		return Hashes{}, false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h256, h1, h5 := sha256.New(), sha1.New(), md5.New()
	n, err := io.Copy(io.MultiWriter(tmp, h256, h1, h5), r)
	if err != nil {
		tmp.Close()
		return Hashes{}, false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Hashes{}, false, err
	}
	if err := tmp.Close(); err != nil {
		return Hashes{}, false, err
	}
	hs := Hashes{
		SHA256: hex.EncodeToString(h256.Sum(nil)),
		SHA1:   hex.EncodeToString(h1.Sum(nil)),
		MD5:    hex.EncodeToString(h5.Sum(nil)),
		Size:   n,
	}
	dst := v.Path(hs.SHA256)
	if _, err := os.Stat(dst); err == nil {
		return hs, true, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return hs, false, err
	}
	if err := os.Chmod(tmpName, 0o440); err != nil {
		return hs, false, err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return hs, false, err
	}
	return hs, false, nil
}

// PutFile ingests a file from disk, opening the source read-only.
func (v *Vault) PutFile(path string) (Hashes, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return Hashes{}, false, err
	}
	defer f.Close()
	return v.Put(f)
}

// Open returns a read-only handle to stored content.
func (v *Vault) Open(sha string) (*os.File, error) {
	return os.OpenFile(v.Path(sha), os.O_RDONLY, 0)
}

// Verify re-hashes stored content and compares it with its recorded SHA-256.
func (v *Vault) Verify(sha string) error {
	f, err := v.Open(sha)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		return fmt.Errorf("hash mismatch: recorded %s, now %s", sha, got)
	}
	return nil
}
