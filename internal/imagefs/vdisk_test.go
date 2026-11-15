package imagefs

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vsample(t *testing.T, name string) EWFSegment {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vdisk", name))
	if err != nil {
		t.Skip("virtual disk samples not present; run scripts/fetch-testdata.sh")
	}
	return EWFSegment{bytes.NewReader(b), int64(len(b))}
}

func mediaMD5(t *testing.T, d vdisk) string {
	t.Helper()
	h := md5.New()
	if _, err := io.Copy(h, io.NewSectionReader(d, 0, d.Size())); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Media hashes of the public dfVFS samples, as libvhdi and libvmdk read them
// (pyvhdi 20260901, pyvmdk 20260714): see docs/COMPARISON.md.
var vdiskWant = map[string]string{
	"ntfs-fixed.vhd": "25e749c0ce2285d5d784ea991a5e5e2f", "ntfs-dynamic.vhd": "4ce30a0c21dd037023a5692d85ade033",
	"ntfs-differential.vhd": "4241cbc76e0e17517fb564238edbe415", "ntfs-parent.vhd": "acb42a740c63c1f72e299463375751c8",
	"ntfs-fixed.vhdx": "1ddc38e00c5854a62956270e3126530a", "ntfs-dynamic.vhdx": "20158534070142d63ee02c9ad1a9d87e",
	"ntfs-differential.vhdx": "a25df0058eecd8aa1975a68eeaa0e178", "ntfs-parent.vhdx": "75537374a81c40e51e6a4b812b36ce89",
	"ext2.vmdk": "196066add11fb71c4c49cf1bb50d6d24", // the same disk as ext2.E01, whose stored MD5 this is
}

func TestVirtualDisks(t *testing.T) {
	parentVHD, parentVHDX := vsample(t, "ntfs-parent.vhd"), vsample(t, "ntfs-parent.vhdx")
	others := []EWFSegment{parentVHD, parentVHDX, vsample(t, "ntfs-fixed.vhd")}
	open := func(name string) vdisk {
		s := vsample(t, name)
		var d vdisk
		var err error
		switch {
		case strings.HasSuffix(name, ".vhdx"):
			d, err = openVHDX(s.R, s.Size, others, 0)
		case strings.HasSuffix(name, ".vmdk"):
			d, err = openVMDK(s.R, s.Size)
		default:
			d, err = openVHD(s.R, s.Size, others, 0)
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return d
	}
	for _, name := range []string{"ntfs-fixed.vhd", "ntfs-dynamic.vhd", "ntfs-differential.vhd", "ntfs-parent.vhd",
		"ntfs-fixed.vhdx", "ntfs-dynamic.vhdx", "ntfs-differential.vhdx", "ntfs-parent.vhdx", "ext2.vmdk"} {
		d := open(name)
		got := mediaMD5(t, d)
		if os.Getenv("VDISK_PRINT") != "" {
			fmt.Printf("%s %d %s %s\n", name, d.Size(), got, d.Describe())
		}
		if want, ok := vdiskWant[name]; ok && got != want {
			t.Errorf("%s: media MD5 %s, libyal reads %s", name, got, want)
		}
	}
	// The NTFS volumes inside open and list.
	for _, name := range []string{"ntfs-dynamic.vhd", "ntfs-differential.vhdx"} {
		s := vsample(t, name)
		fs, err := OpenSet(s.R, s.Size, others)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if l, err := fs.List("/"); err != nil || len(l) == 0 || !strings.Contains(fs.Describe(), "inside a") {
			t.Errorf("%s: %d entries, %v, %q", name, len(l), err, fs.Describe())
		}
	}
	// A differencing disk without its parent says so.
	child := vsample(t, "ntfs-differential.vhd")
	if _, err := OpenSet(child.R, child.Size, nil); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Errorf("differencing VHD alone: %v", err)
	}
	childx := vsample(t, "ntfs-differential.vhdx")
	if _, err := OpenSet(childx.R, childx.Size, nil); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Errorf("differencing VHDX alone: %v", err)
	}
}

// Damage: no panic, no hang.
func TestVirtualDisksCorrupt(t *testing.T) {
	for _, name := range []string{"ntfs-dynamic.vhd", "ntfs-dynamic.vhdx", "ext2.vmdk"} {
		s := vsample(t, name)
		raw := make([]byte, s.Size)
		s.R.ReadAt(raw, 0)
		step := len(raw) / 3000
		for i := 0; i < len(raw); i += step {
			bad := append([]byte(nil), raw...)
			bad[i] ^= 0xFF
			if fs, err := OpenSet(bytes.NewReader(bad), int64(len(bad)), nil); err == nil {
				fs.List("/")
				fs.Close()
			}
		}
		for _, n := range []int{0, 512, 4096, 70000, len(raw) / 2} {
			if n < len(raw) {
				OpenSet(bytes.NewReader(raw[:n]), int64(n), nil)
			}
		}
	}
}
