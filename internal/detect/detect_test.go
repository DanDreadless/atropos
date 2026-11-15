package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// at returns a buffer of n zero bytes with magic placed at off.
func at(n, off int, magic string) []byte {
	b := make([]byte, n)
	copy(b[off:], magic)
	return b
}

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// Identify is given bytes and a size and nothing else. There is no file name
// in its signature, so a name cannot influence the result.
func TestEverySignature(t *testing.T) {
	mft := at(4096, 0, "FILE")
	copy(mft[1024:], "FILE")
	mbr := at(1024, 510, "\x55\xAA")
	mbr[0] = 0xEB
	pe := at(256, 0, "MZ")
	indx := at(4096, 0, "INDX\x28\x00\x09\x00")
	logfile := at(8192, 0, "RSTR")
	logfile[0x11] = 0x10 // system page size 4096
	copy(logfile[4096:], "RSTR")
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"evtx", at(4096, 0, "ElfFile\x00"), EVTX},
		{"registry", at(4096, 0, "regf"), Registry},
		{"dynamic vhd", at(4096, 0, "conectix"), VHD},
		{"registry log, new format", append(at(28, 0, "regf"), at(4068, 0, "\x06")...), RegistryLog},
		{"registry log, old format", append(at(28, 0, "regf"), at(4068, 0, "\x01")...), RegistryLog},
		{"hive with an unknown file type", append(at(28, 0, "regf"), at(4068, 0, "\x09")...), Registry},
		{"prefetch compressed", at(64, 0, "MAM\x04"), Prefetch},
		{"prefetch", at(256, 4, "SCCA"), Prefetch},
		{"lnk", at(256, 0, "\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"), LNK},
		{"ntfs volume", at(512, 3, "NTFS    "), NTFSVolume},
		{"mft", mft, MFT},
		{"directory index", indx, NTFSIndex},
		{"transaction log", logfile, NTFSLog},
		{"sqlite", at(100, 0, "SQLite format 3\x00"), SQLite},
		{"ese", at(4096, 4, "\xEF\xCD\xAB\x89"), ESE},
		{"ewf", at(64, 0, "EVF\x09\x0d\x0a\xff\x00"), EWF},
		{"vhdx", at(64, 0, "vhdxfile"), VHDX},
		{"vmdk", at(64, 0, "KDMV"), VMDK},
		{"zip", at(64, 0, "PK\x03\x04"), Zip},
		{"empty zip", at(22, 0, "PK\x05\x06"), Zip},
		{"gzip", at(64, 0, "\x1f\x8b\x08"), Gzip},
		{"tar", at(512, 257, "ustar"), Tar},
		{"7z", at(64, 0, "7z\xBC\xAF\x27\x1C"), SevenZip},
		{"pdf", []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"), PDF},
		{"ole", at(512, 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"), OLE},
		{"elf", at(64, 0, "\x7FELF"), ELF},
		{"pcap le", at(64, 0, "\xD4\xC3\xB2\xA1"), PCAP},
		{"pcap be", at(64, 0, "\xA1\xB2\xC3\xD4"), PCAP},
		{"pcapng", at(64, 0, "\x0A\x0D\x0D\x0A"), PCAP},
		{"pe", pe, PE},
		{"mbr disk", mbr, MBRDisk},
		{"text", []byte("2024-01-01 12:00:00 service started\n"), Text},
		{"text with bom", append([]byte{0xEF, 0xBB, 0xBF}, "hello, world\n"...), Text},
		{"text non-ascii", []byte("naïve café — ünïcödé log line\n"), Text},
		{"utf16 with bom", append([]byte{0xFF, 0xFE}, utf16le("hello")...), TextUTF16},
		{"utf16 no bom", utf16le("Windows setup log: the quick brown fox jumps over the lazy dog\r\n"), TextUTF16},
		{"unknown", bytes.Repeat([]byte{0x00, 0x01, 0x02, 0x03, 0xFE, 0x80}, 200), Unknown},
	}
	for _, c := range cases {
		got := Identify(bytes.NewReader(c.data), int64(len(c.data)))
		if got.Kind != c.want {
			t.Errorf("%s: identified as %q (%s), want %q", c.name, got.Kind, got.Reason, c.want)
		}
		if got.Reason == "" {
			t.Errorf("%s: no reason recorded", c.name)
		}
	}
	if got := Identify(bytes.NewReader(nil), 0); got.Kind != Empty {
		t.Errorf("empty file identified as %q", got.Kind)
	}
}

// Short and truncated inputs must never panic and must never be mistaken for
// a format whose signature they do not fully contain.
func TestShortInputs(t *testing.T) {
	for _, data := range [][]byte{{0}, {'M'}, {'M', 'Z'}, []byte("reg"), []byte("PK"), []byte("SQLite format"), {0x1f}, []byte("FILE")} {
		got := Identify(bytes.NewReader(data), int64(len(data)))
		switch got.Kind {
		case Unknown, Text:
		default:
			t.Errorf("%q identified as %q", data, got.Kind)
		}
	}
}

// Text that happens to mention a signature is still text.
func TestTextIsNotMistakenForBinary(t *testing.T) {
	for _, s := range []string{
		"the regf signature marks a hive\n",
		"MZ is how a PE file starts, as everyone knows from reading about executables\n",
	} {
		got := Identify(bytes.NewReader([]byte(s)), int64(len(s)))
		// "regf" at offset 0 is a hive by content; anything else here must be text.
		if got.Kind != Text {
			t.Errorf("%q identified as %q", s, got.Kind)
		}
	}
}

// Real samples, where present, are identified whatever they are called.
func TestSamplesIdentifiedByContent(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	samples := map[string]string{
		"Security.evtx": EVTX,
		"NTUSER.DAT":    Registry,
		"test.ntfs.dd":  NTFSVolume,
		filepath.Join("prefetch", "Win10", "CALC.EXE-3FBEF7FD.pf"):   Prefetch,
		filepath.Join("prefetch", "XPPro", "MSMSGS.EXE-2B6052DE.pf"): Prefetch,
	}
	found := 0
	for rel, want := range samples {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		found++
		if got := Identify(bytes.NewReader(data), int64(len(data))); got.Kind != want {
			t.Errorf("%s: identified as %q, want %q", rel, got.Kind, want)
		}
	}
	if found == 0 {
		t.Skip("no sample artefacts; run scripts/fetch-testdata.sh")
	}
}
