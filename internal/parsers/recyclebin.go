package parsers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// recycleParser reads the $I record Windows writes when a file is sent to
// the Recycle Bin: the file's original path and size, and when it was
// deleted. The matching $R file is the deleted content itself.
type recycleParser struct{}

func (recycleParser) Name() string    { return "recycle-bin" }
func (recycleParser) Version() string { return "1 (native)" }

// RecycleRecord reports whether b is a $I record, for detection. size is the
// whole file's length.
//
// Version 1 (Vista to 8.1) is a fixed 544 bytes. Version 2 (Windows 10 on)
// states its path length. Both begin with the version as a 64-bit number,
// then the deleted file's size, then the deletion time.
func RecycleRecord(b []byte, size int64) bool {
	if len(b) < 28 {
		return false
	}
	le := binary.LittleEndian
	switch le.Uint64(b) {
	case 1:
		if size != 544 {
			return false
		}
	case 2:
		if n := int64(le.Uint32(b[24:])); n == 0 || n > 32768 || size != 28+2*n {
			return false
		}
	default:
		return false
	}
	_, ok := timeutil.FromFiletime(le.Uint64(b[16:]))
	return ok
}

func (recycleParser) Parse(ctx *Context) error {
	if ctx.Size > 128<<10 {
		return errors.New("Recycle Bin record is implausibly large")
	}
	b, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return err
	}
	if !RecycleRecord(b, ctx.Size) {
		return errors.New("not a Recycle Bin record")
	}
	le := binary.LittleEndian
	version := le.Uint64(b)
	raw := b[24:]
	if version == 2 {
		raw = b[28:]
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := le.Uint16(raw[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	original := clean(string(utf16.Decode(u)))
	fileSize := le.Uint64(b[8:])
	stamp, _ := timeutil.FromFiletime(le.Uint64(b[16:]))
	return ctx.Emit(Event{
		Stamp: stamp, Type: "file-deleted (recycle bin)", Category: CatDeletion, Source: "recyclebin",
		Host: ctx.Host, Path: original,
		Message: fmt.Sprintf("Sent to Recycle Bin: %s (%d bytes)", original, fileSize),
		Fields:  map[string]any{"original_path": original, "size": fileSize, "record_version": version, "record_name": ctx.Name},
		Ref:     "$I record header",
	})
}
