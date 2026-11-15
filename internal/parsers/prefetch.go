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
	return "3 (velocidex/go-prefetch 4bae979; run times read natively)"
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
	return nil
}
