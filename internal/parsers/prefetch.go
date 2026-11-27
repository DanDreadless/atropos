package parsers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/DanDreadless/atropos/internal/timeutil"

	prefetch "www.velocidex.com/golang/go-prefetch"
)

type prefetchParser struct{}

func (prefetchParser) Name() string { return "prefetch" }
func (prefetchParser) Version() string {
	return "4 (velocidex/go-prefetch 4bae979; run times read natively; volumes: device path, serial number and creation time)"
}

// Real prefetch files are well under a megabyte, compressed or not.
const prefetchMax = 64 << 20

// prefetchLayout gives, per format version, the size of one file-metrics
// entry and where the last-run FILETIME slots sit in the file.
var prefetchLayout = map[uint32]struct {
	metricSize int
	runOffset  int
	runSlots   int
}{
	17: {20, 120, 1}, // Windows XP, 2003
	23: {32, 128, 1}, // Vista, 7
	26: {32, 128, 8}, // 8, 8.1
	30: {32, 128, 8}, // 10
	31: {32, 128, 8}, // 11
}

// prefetchImage returns the uncompressed prefetch file after checking that
// its header describes something that fits inside it. The check matters: the
// library trusts the counts in the header, and a damaged file can otherwise
// send it round a loop billions of times.
func prefetchImage(ctx *Context) ([]byte, error) {
	if ctx.Size > prefetchMax {
		return nil, fmt.Errorf("prefetch file is implausibly large (%d bytes)", ctx.Size)
	}
	raw, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if bytes.HasPrefix(raw, []byte("MAM\x04")) {
		if len(raw) < 16 {
			return nil, errors.New("truncated compressed prefetch header")
		}
		size := le.Uint32(raw[4:])
		if size < 84 || size > prefetchMax {
			return nil, fmt.Errorf("compressed prefetch states an implausible uncompressed size (%d bytes)", size)
		}
		raw, err = prefetch.LZXpressHuffmanDecompressWithFallback(raw[8:], int(size))
		if err != nil {
			return nil, fmt.Errorf("decompressing: %w", err)
		}
	}
	if len(raw) < 84+68 || string(raw[4:8]) != "SCCA" {
		return nil, errors.New("not a prefetch file: no SCCA header")
	}
	version := le.Uint32(raw)
	lay, ok := prefetchLayout[version]
	if !ok {
		return nil, fmt.Errorf("unsupported prefetch format version %d", version)
	}
	// File information block, at offset 84 in every version.
	metricsOff, metricsN := int64(le.Uint32(raw[84:])), int64(le.Uint32(raw[88:]))
	namesOff, namesSize := int64(le.Uint32(raw[100:])), int64(le.Uint32(raw[104:]))
	n := int64(len(raw))
	if metricsOff+metricsN*int64(lay.metricSize) > n {
		return nil, fmt.Errorf("header describes %d file entries at offset %d, which do not fit in %d bytes", metricsN, metricsOff, n)
	}
	if namesOff+namesSize > n {
		return nil, fmt.Errorf("header places the file name table at %d+%d, beyond the end of the file (%d bytes)", namesOff, namesSize, n)
	}
	if lay.runOffset+lay.runSlots*8 > len(raw) {
		return nil, errors.New("truncated before the last-run times")
	}
	return raw, nil
}

func (prefetchParser) Parse(ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	raw, err := prefetchImage(ctx)
	if err != nil {
		return err
	}
	info, err := prefetch.LoadPrefetch(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	files := info.FilesAccessed
	fields := map[string]any{
		"executable": clean(info.Executable), "prefetch_hash": info.Hash,
		"format": info.Version, "run_count": info.RunCount,
		"files_accessed_count": len(files),
	}
	if len(files) > 300 {
		fields["files_accessed_truncated"] = true
		files = files[:300]
	}
	cleaned := make([]string, len(files))
	for i, f := range files {
		cleaned[i] = clean(f)
	}
	fields["files_accessed"] = cleaned
	vols := prefetchVolumes(ctx, raw)
	if len(vols) > 0 {
		var list []map[string]any
		for _, v := range vols {
			m := map[string]any{"device_path": v.device, "serial": v.serial}
			if v.ok {
				m["created"] = v.created.UTC.Format("2006-01-02T15:04:05.0000000Z")
			}
			list = append(list, m)
		}
		fields["volumes"] = list
	}
	path := clean(info.Path)
	if path == "" {
		path = clean(info.Executable)
	}

	// The run times are read here rather than taken from the library, which
	// drops any that are later than the clock of the machine doing the
	// parsing. That would make the result depend on when and where it was
	// produced, and would hide a future-dated run time from the examiner.
	lay := prefetchLayout[binary.LittleEndian.Uint32(raw)]
	type slot struct {
		i     int
		stamp timeutil.Stamp
	}
	var runs []slot
	for i := 0; i < lay.runSlots; i++ {
		ft := binary.LittleEndian.Uint64(raw[lay.runOffset+i*8:])
		if ft == 0 {
			continue
		}
		stamp, ok := timeutil.FromFiletime(ft)
		if !ok {
			ctx.Warn("last run time slot %d holds an implausible value (FILETIME 0x%016X); not placed on the timeline", i, ft)
			continue
		}
		runs = append(runs, slot{i, stamp})
	}
	if len(runs) == 0 {
		ctx.Note("prefetch file records no run times")
	}
	for n, r := range runs {
		if err := ctx.Emit(Event{
			Stamp: r.stamp, Type: "program-executed (prefetch)", Category: CatExecution, Source: "prefetch",
			Host: ctx.Host, Path: path,
			Message: fmt.Sprintf("Prefetch: %s executed (run count %d, run time %d of %d recorded)",
				clean(info.Executable), info.RunCount, n+1, len(runs)),
			Fields: fields, Ref: fmt.Sprintf("last run time slot %d", r.i),
		}); err != nil {
			return err
		}
	}
	// Each volume the program used, at the time the volume was created
	// (formatted), with its serial number: a removable drive a program ran
	// from or read is named here, and the serial joins it to shortcuts.
	for i, v := range vols {
		if !v.ok {
			continue
		}
		if err := ctx.Emit(Event{
			Stamp: v.created, Type: "volume-created (prefetch)", Category: CatFileSystem, Source: "prefetch",
			Host: ctx.Host, Path: v.device,
			Message: fmt.Sprintf("Volume %s (serial %s) created, as recorded in the prefetch file of %s", v.device, v.serial, clean(info.Executable)),
			Fields: map[string]any{"device_path": v.device, "serial": v.serial, "executable": clean(info.Executable), "prefetch_hash": info.Hash,
				"time_meaning": "the volume's creation time, as the prefetch file recorded it: when the volume was formatted"},
			Ref: fmt.Sprintf("volume information entry %d", i),
		}); err != nil {
			return err
		}
	}
	return nil
}

type prefetchVolume struct {
	device, serial string
	created        timeutil.Stamp
	ok             bool
}

// prefetchVolumeEntry is the size of one volume information entry per
// format version (libscca's "Windows Prefetch File (PF) format").
var prefetchVolumeEntry = map[uint32]int{17: 40, 23: 104, 26: 104, 30: 96, 31: 96}

// prefetchVolumes reads the volume information block: at offset 108 of the
// file information its offset, at 112 the number of volumes and at 116 its
// size. Each entry holds the offset (from the block's start) and length in
// characters of the volume's device path, the volume's creation FILETIME
// and its serial number.
func prefetchVolumes(ctx *Context, raw []byte) []prefetchVolume {
	le := binary.LittleEndian
	entry := prefetchVolumeEntry[le.Uint32(raw)]
	if entry == 0 || len(raw) < 120 {
		return nil
	}
	off, count, size := int64(le.Uint32(raw[108:])), int64(le.Uint32(raw[112:])), int64(le.Uint32(raw[116:]))
	n := int64(len(raw))
	if count == 0 {
		return nil
	}
	if count > 256 || off < 120 || off+size > n || count*int64(entry) > size {
		ctx.Warn("the volume information (%d volumes at offset %d, %d bytes) does not fit in the file; not read", count, off, size)
		return nil
	}
	var out []prefetchVolume
	for i := int64(0); i < count; i++ {
		e := raw[off+i*int64(entry):]
		pathOff, pathLen := int64(le.Uint32(e)), int64(le.Uint32(e[4:]))
		v := prefetchVolume{serial: fmt.Sprintf("%08X", le.Uint32(e[16:]))}
		if pathLen > 0 && pathLen < 1024 && pathOff+2*pathLen <= size {
			v.device = clean(utf16At(raw, int(off+pathOff), int(pathLen)))
		}
		if ft := le.Uint64(e[8:]); ft != 0 {
			v.created, v.ok = timeutil.FromFiletime(ft)
			if !v.ok {
				ctx.Warn("volume %d's creation time is implausible (FILETIME 0x%016X); not placed on the timeline", i, ft)
			}
		}
		out = append(out, v)
	}
	return out
}
