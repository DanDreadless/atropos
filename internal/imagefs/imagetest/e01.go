package imagetest

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/binary"
	"hash/adler32"
)

// E01Options chooses the shape of a test image.
type E01Options struct {
	Segments int  // how many segment files to split the media across (default 1)
	Compress bool // compress each chunk that shrinks; otherwise store every chunk with its checksum
	NoSetID  bool // leave the set identifier empty, as old writers do
	FileBase bool // table offsets relative to the start of the file (EnCase 5 and earlier) rather than a base
	SetID    byte // varies the set identifier, to make two different sets
}

const (
	e01SectorsPerChunk = 64
	e01SectorSize      = 512
	e01ChunkSize       = e01SectorsPerChunk * e01SectorSize
)

func e01Section(out *bytes.Buffer, kind string, data []byte, self bool) {
	start := int64(out.Len())
	d := make([]byte, 76)
	copy(d, kind)
	next := start + 76 + int64(len(data))
	size := int64(76 + len(data))
	if self {
		next, size = start, 0
	}
	binary.LittleEndian.PutUint64(d[16:], uint64(next))
	binary.LittleEndian.PutUint64(d[24:], uint64(size))
	binary.LittleEndian.PutUint32(d[72:], adler32.Checksum(d[:72]))
	out.Write(d)
	out.Write(data)
}

func deflate(b []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(b)
	w.Close()
	return z.Bytes()
}

// E01 writes media as an Expert Witness image and returns its segment
// files in order. The media's length must be a multiple of 512.
func E01(media []byte, o E01Options) [][]byte {
	if o.Segments < 1 {
		o.Segments = 1
	}
	chunks := (len(media) + e01ChunkSize - 1) / e01ChunkSize
	vol := make([]byte, 1052)
	vol[0] = 1
	binary.LittleEndian.PutUint32(vol[4:], uint32(chunks))
	binary.LittleEndian.PutUint32(vol[8:], e01SectorsPerChunk)
	binary.LittleEndian.PutUint32(vol[12:], e01SectorSize)
	binary.LittleEndian.PutUint64(vol[16:], uint64(len(media)/e01SectorSize))
	if !o.NoSetID {
		for i := 0; i < 16; i++ {
			vol[64+i] = byte(0xA0+i) ^ o.SetID
		}
	}
	binary.LittleEndian.PutUint32(vol[1048:], adler32.Checksum(vol[:1048]))

	if o.Segments > chunks {
		o.Segments = chunks // a segment with no chunks is not a thing
	}
	var segs [][]byte
	for s := 0; s < o.Segments; s++ {
		var out bytes.Buffer
		out.WriteString("EVF\x09\x0d\x0a\xff\x00")
		out.Write([]byte{1, byte(s + 1), byte((s + 1) >> 8), 0, 0})
		if s == 0 {
			e01Section(&out, "header", deflate([]byte("1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\r\nCASE-7\tEV-1\ttest disk\tA. Examiner\tnone\t7.0\tWindows\t1700000000\t1700000000\t0\r\n\r\n")), false)
			e01Section(&out, "volume", vol, false)
		} else {
			e01Section(&out, "data", vol, false)
		}
		first, last := s*chunks/o.Segments, (s+1)*chunks/o.Segments
		// The chunk data, with each chunk's offset from the start of the data.
		var data bytes.Buffer
		var entries []uint32
		for c := first; c < last; c++ {
			end := (c + 1) * e01ChunkSize
			if end > len(media) {
				end = len(media)
			}
			raw := media[c*e01ChunkSize : end]
			entry := uint32(data.Len())
			if z := deflate(raw); o.Compress && len(z) < len(raw) {
				entry |= 0x80000000
				data.Write(z)
			} else {
				data.Write(raw)
				binary.Write(&data, binary.LittleEndian, adler32.Checksum(raw))
			}
			entries = append(entries, entry)
		}
		dataStart := int64(out.Len()) + 76
		e01Section(&out, "sectors", data.Bytes(), false)
		table := make([]byte, 24, 24+len(entries)*4+4)
		binary.LittleEndian.PutUint32(table, uint32(len(entries)))
		if !o.FileBase {
			binary.LittleEndian.PutUint64(table[8:], uint64(dataStart))
		}
		binary.LittleEndian.PutUint32(table[20:], adler32.Checksum(table[:20]))
		for _, e := range entries {
			if o.FileBase {
				e += uint32(dataStart)
			}
			table = binary.LittleEndian.AppendUint32(table, e)
		}
		table = binary.LittleEndian.AppendUint32(table, adler32.Checksum(table[24:]))
		e01Section(&out, "table", table, false)
		e01Section(&out, "table2", table, false)
		if s == o.Segments-1 {
			h := make([]byte, 36)
			sum := md5.Sum(media)
			copy(h, sum[:])
			binary.LittleEndian.PutUint32(h[32:], adler32.Checksum(h[:32]))
			e01Section(&out, "hash", h, false)
			e01Section(&out, "done", nil, true)
		} else {
			e01Section(&out, "next", nil, true)
		}
		segs = append(segs, out.Bytes())
	}
	return segs
}
