// Package imagefs reads the file systems inside disk images and optical disc
// images, so an examiner can look through one and choose what goes on the
// timeline. It only ever reads: an image is opened through an io.ReaderAt
// and nothing here can write to it.
//
// What it understands: ISO 9660 discs (with Joliet names), NTFS volumes, and
// raw disk images partitioned with MBR or GPT whose partitions hold NTFS, and
// any of those inside an Expert Witness (E01) image, split or not.
// Other file systems are recognised and listed as present but not readable.
package imagefs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// Entry is one file or directory in an image.
type Entry struct {
	Name  string `json:"name"`
	Path  string `json:"path"` // absolute within the image, forward slashes
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	// Times are unix nanoseconds in UTC; zero means the file system does not
	// record that time.
	Modified int64 `json:"modified,string"`
	Accessed int64 `json:"accessed,string"`
	Changed  int64 `json:"changed,string"`
	Born     int64 `json:"born,string"`
	// LocalTime is set when the file system stores wall-clock times with no
	// zone that could be relied on, so the times above are not known UTC.
	LocalTime bool   `json:"local_time,omitempty"`
	Note      string `json:"note,omitempty"`
}

// FS is a read-only view of what is inside an image.
type FS interface {
	// Describe says what the image is, for the examiner.
	Describe() string
	// List returns the entries of a directory. The root is "/".
	List(path string) ([]Entry, error)
	// Open returns the content of a file and its size.
	Open(path string) (io.Reader, int64, error)
	Close()
}

// ErrNoFileSystem means the image holds nothing this package can read.
var ErrNoFileSystem = errors.New("no readable file system was found in this image")

// MaxListing bounds one directory listing, so a damaged or hostile directory
// cannot produce an unbounded reply.
const MaxListing = 100000

// clean normalises a path given by a caller: forward slashes, a leading
// slash, and no "." or ".." elements, which have no business in a request.
func clean(p string) (string, []string, error) {
	p = strings.ReplaceAll(p, "\\", "/")
	var parts []string
	for _, e := range strings.Split(p, "/") {
		switch e {
		case "", ".":
		case "..":
			return "", nil, errors.New("path may not contain ..")
		default:
			parts = append(parts, e)
		}
	}
	return "/" + strings.Join(parts, "/"), parts, nil
}

func join(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// Open works out what r holds and returns a view of it.
func Open(r io.ReaderAt, size int64) (FS, error) { return OpenSet(r, size, nil) }

// OpenSet is Open for an image that may be split across files: others are
// files that might be further segments of the same E01 image. Those that are
// not are ignored.
func OpenSet(r io.ReaderAt, size int64, others []EWFSegment) (FS, error) {
	if ewfIsSignature(r) {
		return openEWF(r, size, others)
	}
	if head, err := readAt(r, 0, 8); err == nil {
		switch {
		case string(head) == "vhdxfile":
			d, err := openVHDX(r, size, others, 0)
			if err != nil {
				return nil, err
			}
			return openVDisk(d)
		case string(head) == "conectix":
			// A dynamic or differencing VHD begins with a copy of its footer.
			d, err := openVHD(r, size, others, 0)
			if err != nil {
				return nil, err
			}
			return openVDisk(d)
		case string(head[:4]) == "KDMV":
			d, err := openVMDK(r, size)
			if err != nil {
				return nil, err
			}
			return openVDisk(d)
		}
	}
	// An optical disc first: many are also given a boot sector so they can
	// start a computer from a USB stick, and would otherwise look like a disk.
	if fs, err := openISO(r, size); err == nil {
		return fs, nil
	}
	if isNTFS(r, 0) {
		return openNTFS(r, 0, "NTFS volume")
	}
	if d, err := openDisk(r, size); err == nil {
		return d, nil
	}
	return nil, ErrNoFileSystem
}

func readAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	b := make([]byte, n)
	got, err := r.ReadAt(b, off)
	if got < n {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}

// ---------------------------------------------------------- partitions ----

type partition struct {
	index   int
	offset  int64
	length  int64
	label   string // type and name, for the examiner
	fs      FS     // nil when the content is not readable
	content string // what was found inside
}

type disk struct {
	scheme string
	parts  []partition
}

func sniff(r io.ReaderAt, off int64) string {
	b, err := readAt(r, off, 2048)
	if err != nil {
		return "unreadable"
	}
	switch {
	case string(b[3:11]) == "NTFS    ":
		return "NTFS"
	case string(b[3:11]) == "EXFAT   ":
		return "exFAT"
	case string(b[82:87]) == "FAT32":
		return "FAT32"
	case string(b[54:59]) == "FAT16" || string(b[54:59]) == "FAT12":
		return "FAT"
	case string(b[3:11]) == "-FVE-FS-":
		return "BitLocker (encrypted)"
	case b[1080] == 0x53 && b[1081] == 0xEF:
		return "ext2/3/4"
	case bytes.Equal(b[:4], []byte("XFSB")):
		return "XFS"
	case bytes.Equal(b[1024:1026], []byte("H+")) || bytes.Equal(b[1024:1026], []byte("HX")):
		return "HFS+"
	case bytes.Equal(b[32:36], []byte("NXSB")):
		return "APFS"
	case bytes.Equal(b[:8], make([]byte, 8)):
		return "empty or unknown"
	}
	return "unknown"
}

func isNTFS(r io.ReaderAt, off int64) bool { return sniff(r, off) == "NTFS" }

func openDisk(r io.ReaderAt, size int64) (FS, error) {
	mbr, err := readAt(r, 0, 512)
	if err != nil || mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil, ErrNoFileSystem
	}
	le := binary.LittleEndian
	d := &disk{scheme: "MBR"}
	add := func(off, length int64, label string) {
		if off <= 0 || off >= size || len(d.parts) >= 128 {
			return
		}
		p := partition{index: len(d.parts) + 1, offset: off, length: length, label: label, content: sniff(r, off)}
		if p.content == "NTFS" {
			if fs, err := openNTFS(r, off, "NTFS"); err == nil {
				p.fs = fs
			} else {
				p.content = "NTFS (could not be opened: " + err.Error() + ")"
			}
		}
		d.parts = append(d.parts, p)
	}
	protective := false
	for i := 0; i < 4; i++ {
		e := mbr[446+i*16:]
		if e[4] == 0xEE {
			protective = true
		}
	}
	if protective {
		for _, sector := range []int64{512, 4096} {
			h, err := readAt(r, sector, 92)
			if err != nil || string(h[:8]) != "EFI PART" {
				continue
			}
			d.scheme = "GPT"
			first, n, each := int64(le.Uint64(h[72:])), int(le.Uint32(h[80:])), int(le.Uint32(h[84:]))
			if n > 256 || each < 128 || each > 4096 {
				break
			}
			for i := 0; i < n; i++ {
				e, err := readAt(r, first*sector+int64(i*each), 128)
				if err != nil {
					break
				}
				if bytes.Equal(e[:16], make([]byte, 16)) {
					continue
				}
				u := make([]uint16, 0, 36)
				for j := 56; j+1 < 128; j += 2 {
					if c := le.Uint16(e[j:]); c != 0 {
						u = append(u, c)
					} else {
						break
					}
				}
				start, end := int64(le.Uint64(e[32:])), int64(le.Uint64(e[40:]))
				add(start*sector, (end-start+1)*sector, strings.TrimSpace("GPT partition "+string(utf16.Decode(u))))
			}
			break
		}
	} else {
		for i := 0; i < 4; i++ {
			e := mbr[446+i*16:]
			if e[4] == 0 {
				continue
			}
			add(int64(le.Uint32(e[8:]))*512, int64(le.Uint32(e[12:]))*512, fmt.Sprintf("MBR partition, type 0x%02X", e[4]))
		}
	}
	if len(d.parts) == 0 {
		return nil, ErrNoFileSystem
	}
	return d, nil
}

func (d *disk) Describe() string {
	return fmt.Sprintf("Disk image with %s partition table, %d partitions", d.scheme, len(d.parts))
}

func (d *disk) Close() {
	for _, p := range d.parts {
		if p.fs != nil {
			p.fs.Close()
		}
	}
}

func (d *disk) find(parts []string) (*partition, error) {
	for i := range d.parts {
		if fmt.Sprintf("p%d", d.parts[i].index) == parts[0] {
			if d.parts[i].fs == nil {
				return nil, fmt.Errorf("partition %d holds %s, which Atropos cannot read yet", d.parts[i].index, d.parts[i].content)
			}
			return &d.parts[i], nil
		}
	}
	return nil, fmt.Errorf("no partition %q in this image", parts[0])
}

func (d *disk) List(path string) ([]Entry, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		var out []Entry
		for _, p := range d.parts {
			note := fmt.Sprintf("%s; contains %s", p.label, p.content)
			if p.fs == nil {
				note += " (not readable by Atropos yet)"
			}
			out = append(out, Entry{Name: fmt.Sprintf("p%d", p.index), Path: fmt.Sprintf("/p%d", p.index), IsDir: p.fs != nil, Size: p.length, Note: note})
		}
		return out, nil
	}
	p, err := d.find(parts)
	if err != nil {
		return nil, err
	}
	list, err := p.fs.List("/" + strings.Join(parts[1:], "/"))
	for i := range list {
		list[i].Path = "/" + parts[0] + list[i].Path
	}
	return list, err
}

func (d *disk) Open(path string) (io.Reader, int64, error) {
	_, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	if len(parts) < 2 {
		return nil, 0, errors.New("not a file")
	}
	p, err := d.find(parts)
	if err != nil {
		return nil, 0, err
	}
	return p.fs.Open("/" + strings.Join(parts[1:], "/"))
}
