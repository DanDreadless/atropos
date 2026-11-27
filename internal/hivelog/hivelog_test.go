package hivelog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sample(t *testing.T, rel ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata", "hivelog"}, rel...)...))
	if err != nil {
		t.Skipf("sample %s not present; run scripts/fetch-testdata.sh", filepath.Join(rel...))
	}
	return b
}

func lg(name string, b []byte) Log {
	return Log{Name: name, R: bytes.NewReader(b), Size: int64(len(b))}
}

func readAll(t *testing.T, o *Overlay) []byte {
	t.Helper()
	b, err := io.ReadAll(io.NewSectionReader(o, 0, o.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every entry in logs written by Windows passes its two hashes: the hash
// and its seed are right.
func TestMarvin32OnRealLogEntries(t *testing.T) {
	checked := 0
	for _, f := range [][]string{{"yarp", "NewDirtyHive1", "NewDirtyHive.LOG1"}, {"yarp", "NewDirtyHive1", "NewDirtyHive.LOG2"},
		{"regipy", "SYSTEM_B.LOG1"}, {"regipy", "SYSTEM_B.LOG2"}, {"regipy", "UsrClass.dat.LOG1"}, {"regipy", "transactions_ntuser.dat.log1"}} {
		b := sample(t, f...)
		le := binary.LittleEndian
		for off := 512; off+40 <= len(b) && string(b[off:off+4]) == "HvLE"; {
			size := int(le.Uint32(b[off+4:]))
			if size < 40 || off+size > len(b) {
				break
			}
			e := b[off : off+size]
			if marvin32(e[40:]) != le.Uint64(e[24:]) || marvin32(e[:32]) != le.Uint64(e[32:]) {
				// Old entries can be partly overwritten; the first must be whole.
				if off == 512 {
					t.Errorf("%s: the first entry fails its hashes", f[len(f)-1])
				}
				break
			}
			checked++
			off += size
		}
	}
	if checked < 10 {
		t.Errorf("only %d entries checked", checked)
	}
	// The tail of a buffer that is not a whole number of words.
	if marvin32([]byte{1, 2, 3}) == marvin32([]byte{1, 2, 4}) || marvin32(nil) == marvin32([]byte{0}) {
		t.Error("trailing bytes do not change the hash")
	}
}

// The answer Windows gives: yarp's test set holds dirty hives with their
// logs and the same hive as Windows recovered it. The recovered hive must
// match Windows' byte for byte from the first hive bin to the end of the
// hive bins, and its base block must be sound with equal sequence numbers.
func TestRecoveryMatchesWindows(t *testing.T) {
	for _, c := range []struct {
		dir, hive, recovered string
		logs                 []string
		format               string
	}{
		{"NewDirtyHive1", "NewDirtyHive", "RecoveredHive_Windows10", []string{"NewDirtyHive.LOG1", "NewDirtyHive.LOG2"}, "new"},
		{"OldDirtyHive", "OldDirtyHive", "RecoveredHive_Windows7", []string{"OldDirtyHive.LOG1"}, "old"},
	} {
		hive := sample(t, "yarp", c.dir, c.hive)
		want := sample(t, "yarp", c.dir, c.recovered)
		var logs []Log
		// Offered in reverse and under other names: order and names must not matter.
		for i := len(c.logs) - 1; i >= 0; i-- {
			logs = append(logs, lg("offered-"+string(rune('a'+i)), sample(t, "yarp", c.dir, c.logs[i])))
		}
		res, err := Recover(bytes.NewReader(hive), int64(len(hive)), logs)
		if err != nil {
			t.Fatalf("%s: %v", c.dir, err)
		}
		if res.Hive == nil || len(res.Applied) == 0 || res.Applied[0].Format != c.format {
			t.Fatalf("%s: nothing applied: %+v", c.dir, res)
		}
		got := readAll(t, res.Hive)
		wb, _ := ParseBase(want)
		end := 4096 + int(wb.HbinsSize)
		// Windows stamps the first hive bin's timestamp (a backup of the
		// base block's "last written") when it writes the recovered hive.
		want = append([]byte(nil), want...)
		copy(want[4096+20:4096+28], got[4096+20:4096+28])
		// Windows 7 saved the old-format hive twice after recovering it
		// (sequence 7 against the log's 5), and the second save rewrote
		// one key's cached "largest value name length" (offset 60 of the
		// key node at 0x6BD8C). It is housekeeping, not logged data.
		if c.format == "old" && len(got) > 0x6BDC8 {
			want[0x6BDC8] = got[0x6BDC8]
		}
		if len(got) < end || !bytes.Equal(got[4096:end], want[4096:end]) {
			first := -1
			for i := 4096; i < end && i < len(got); i++ {
				if got[i] != want[i] {
					first = i
					break
				}
			}
			t.Errorf("%s: hive bins differ from Windows' recovery, first at offset %#x (got %d bytes, want %d)", c.dir, first, len(got), end)
		}
		gb, err := ParseBase(got)
		if err != nil || !gb.ChecksumOK || gb.Seq1 != gb.Seq2 || gb.Type != TypePrimary || gb.HbinsSize != wb.HbinsSize || gb.Dirty() {
			t.Errorf("%s: recovered base block %+v", c.dir, gb)
		}
		// Writing the recovered hive is itself a write, which Windows numbers one more.
		if c.format == "new" && gb.Seq1+1 != wb.Seq1 {
			t.Errorf("%s: sequence number %d after the last entry, Windows wrote %d", c.dir, gb.Seq1, wb.Seq1)
		}
		// The original was not touched.
		if !bytes.Equal(hive, sample(t, "yarp", c.dir, c.hive)) {
			t.Errorf("%s: the hive was modified", c.dir)
		}
	}
}

// Real hives from Windows 10 (regipy's test data), with the logs Windows
// left beside them.
func TestRecoveryOfRealHives(t *testing.T) {
	for _, c := range []struct {
		hive      string
		logs      []string
		applied   int
		entriesAt least
	}{
		{"SYSTEM_B", []string{"SYSTEM_B.LOG1", "SYSTEM_B.LOG2"}, 2, 2},
		{"UsrClass.dat", []string{"UsrClass.dat.LOG1", "UsrClass.dat.LOG2"}, 2, 2},
		{"transactions_NTUSER.DAT", []string{"transactions_ntuser.dat.log1", "transactions_ntuser.dat.log2"}, 1, 1},
	} {
		hive := sample(t, "regipy", c.hive)
		var logs []Log
		for _, l := range c.logs {
			logs = append(logs, lg(l, sample(t, "regipy", l)))
		}
		res, err := Recover(bytes.NewReader(hive), int64(len(hive)), logs)
		if err != nil || res.Hive == nil {
			t.Fatalf("%s: %v %+v", c.hive, err, res)
		}
		entries := 0
		for _, a := range res.Applied {
			entries += a.Entries
		}
		if len(res.Applied) != c.applied || entries < int(c.entriesAt) {
			t.Errorf("%s: applied %+v, not used %v", c.hive, res.Applied, res.NotUsed)
		}
		gb, _ := ParseBase(readAll(t, res.Hive))
		if gb.Dirty() || res.Applied[len(res.Applied)-1].Last != gb.Seq1 {
			t.Errorf("%s: base block after recovery %+v, last applied %d", c.hive, gb, res.Applied[len(res.Applied)-1].Last)
		}
	}
}

type least int

func TestLogsThatDoNotBelong(t *testing.T) {
	hive := sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive")
	other := sample(t, "regipy", "UsrClass.dat.LOG1")
	res, err := Recover(bytes.NewReader(hive), int64(len(hive)), []Log{lg("stranger", other), lg("hive itself", hive), lg("empty", nil)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Hive != nil || len(res.NotUsed) != 3 || !strings.Contains(strings.Join(res.NotUsed, "|"), "another hive") {
		t.Errorf("%+v", res)
	}
	// A clean hive is left alone, and says why its logs were not used.
	clean := sample(t, "yarp", "NewDirtyHive1", "RecoveredHive_Windows10")
	res, _ = Recover(bytes.NewReader(clean), int64(len(clean)), []Log{lg("LOG1", sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive.LOG1"))})
	if !res.Clean || res.Hive != nil || len(res.NotUsed) != 1 || !strings.Contains(res.NotUsed[0], "fully written") {
		t.Errorf("clean hive: %+v", res)
	}
}

// More logs of one hive than Windows keeps: a case holding yarp's whole set
// offers NewDirtyHive2's hive its own two logs and BadLogHive3's two, which
// name the same hive. Before, the two starting earliest were kept and the
// rest refused, so in some orders nothing was applied (found running Plaso
// over the public samples). The pair reaching furthest is used, whatever
// order the logs come in, and the hive comes out as from its own logs.
func TestMoreLogsThanWindowsKeeps(t *testing.T) {
	hive := sample(t, "yarp", "NewDirtyHive2", "NewDirtyHive")
	logs := []Log{lg("own1", sample(t, "yarp", "NewDirtyHive2", "NewDirtyHive.LOG1")), lg("own2", sample(t, "yarp", "NewDirtyHive2", "NewDirtyHive.LOG2")),
		lg("bad1", sample(t, "yarp", "BadLogHive3", "BadLogHive.LOG1")), lg("bad2", sample(t, "yarp", "BadLogHive3", "BadLogHive.LOG2"))}
	own, err := Recover(bytes.NewReader(hive), int64(len(hive)), logs[:2])
	if err != nil || own.Hive == nil {
		t.Fatalf("own logs: %v %+v", err, own)
	}
	want := readAll(t, own.Hive)
	var used string
	var perm func(k int)
	perm = func(k int) {
		if k == len(logs) {
			res, err := Recover(bytes.NewReader(hive), int64(len(hive)), append([]Log(nil), logs...))
			if err != nil || res.Hive == nil {
				t.Fatalf("order %v: nothing applied: %v %+v", names(logs), err, res)
			}
			if got := readAll(t, res.Hive); !bytes.Equal(got, want) {
				t.Errorf("order %v: the hive differs from its recovery with its own logs", names(logs))
			}
			var u []string
			for _, a := range res.Applied {
				u = append(u, fmt.Sprintf("%d-%d", a.First, a.Last))
			}
			// Which file is which may differ (bad2 holds own2's entries); what is applied may not.
			if s := strings.Join(u, " "); used == "" {
				used = s
			} else if s != used {
				t.Errorf("order %v: applied %s, in another order %s", names(logs), s, used)
			}
			return
		}
		for i := k; i < len(logs); i++ {
			logs[k], logs[i] = logs[i], logs[k]
			perm(k + 1)
			logs[k], logs[i] = logs[i], logs[k]
		}
	}
	perm(0)
}

func names(logs []Log) []string {
	var s []string
	for _, l := range logs {
		s = append(s, l.Name)
	}
	return s
}

// A log damaged by a crash: yarp's BadLogHive3 has logs whose base blocks
// fail their checksums; Windows still applies the entries, which are
// checked by their own hashes.
func TestDamagedLogs(t *testing.T) {
	hive := sample(t, "yarp", "BadLogHive3", "BadLogHive")
	l1, l2 := sample(t, "yarp", "BadLogHive3", "BadLogHive.LOG1"), sample(t, "yarp", "BadLogHive3", "BadLogHive.LOG2")
	if _, err := Recover(bytes.NewReader(hive), int64(len(hive)), []Log{lg("1", l1), lg("2", l2)}); err != nil {
		t.Fatal(err)
	}
	// One flipped byte in an entry stops recovery at that entry, never later.
	good, _ := Recover(bytes.NewReader(hive), int64(len(hive)), []Log{lg("1", sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive.LOG1")), lg("2", sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive.LOG2"))})
	nh := sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive")
	n1, n2 := sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive.LOG1"), sample(t, "yarp", "NewDirtyHive1", "NewDirtyHive.LOG2")
	total := 0
	for _, a := range good.Applied {
		total += a.Entries
	}
	for i := 512; i < len(n2); i += 61 {
		bad := append([]byte(nil), n2...)
		bad[i] ^= 0x5A
		res, err := Recover(bytes.NewReader(nh), int64(len(nh)), []Log{lg("1", n1), lg("2", bad)})
		if err != nil {
			continue
		}
		n := 0
		for _, a := range res.Applied {
			n += a.Entries
		}
		if n > total {
			t.Fatalf("byte %d: more entries applied from a damaged log (%d) than from the sound one (%d)", i, n, total)
		}
	}
	// Truncations and garbage: no panic.
	for n := 0; n < len(n1); n += 97 {
		Recover(bytes.NewReader(nh), int64(len(nh)), []Log{lg("1", n1[:n]), lg("2", n2[:min(n, len(n2))])})
	}
	trunc := sample(t, "yarp", "TruncatedDirtyHive")
	Recover(bytes.NewReader(trunc), int64(len(trunc)), []Log{lg("1", sample(t, "yarp", "OldDirtyHive", "OldDirtyHive.LOG1"))})
}

func TestOverlayReads(t *testing.T) {
	base := bytes.Repeat([]byte{'.'}, 8192)
	o := newOverlay(bytes.NewReader(base), int64(len(base)))
	o.write(4096+512, bytes.Repeat([]byte{'x'}, 512))
	o.write(8192+512, bytes.Repeat([]byte{'y'}, 512)) // beyond the file: it grows, with zeros between
	all := readAll(t, o)
	if len(all) != 8192+1024 || all[4096+511] != '.' || all[4096+512] != 'x' || all[4096+1024] != '.' || all[8192] != 0 || all[8192+512] != 'y' {
		t.Errorf("overlay contents wrong: size %d", len(all))
	}
	// Any read, at any offset and length, agrees with reading the whole.
	for off := 0; off < len(all); off += 37 {
		for _, n := range []int{1, 7, 511, 513, 2000} {
			p := make([]byte, n)
			k, _ := o.ReadAt(p, int64(off))
			if !bytes.Equal(p[:k], all[off:off+k]) || (k < n) != (off+n > len(all)) {
				t.Fatalf("ReadAt(%d, %d) = %d bytes, disagreeing", off, n, k)
			}
		}
	}
}
