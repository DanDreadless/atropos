package parsers

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

// genericParser is the floor under every artefact: whatever a file is, it is
// hashed, identified, measured and made searchable by its text content, so
// nothing submitted to a case is ever unfindable.
type genericParser struct{}

func (genericParser) Name() string    { return "generic" }
func (genericParser) Version() string { return "2 (native: strings, entropy, pe header)" }

const (
	maxText      = 4 << 20
	minStringLen = 6
)

func (genericParser) Parse(ctx *Context) error {
	if ctx.Size == 0 {
		ctx.Note("file is empty")
		return nil
	}
	var out strings.Builder
	truncated := false
	var counts [256]int64
	buf := make([]byte, 1<<20)
	r := io.NewSectionReader(ctx.File, 0, ctx.Size)
	isText := ctx.Kind == detect.Text
	var run []byte
	add := func(s []byte) {
		if out.Len() >= maxText {
			truncated = true
			return
		}
		out.Write(s)
		out.WriteByte('\n')
	}
	var wide []byte
	var low byte
	haveLow := false
	endWide := func() {
		if len(wide) >= minStringLen {
			add(wide)
		}
		wide = wide[:0]
	}
	for {
		n, err := r.Read(buf)
		chunk := buf[:n]
		for _, c := range chunk {
			counts[c]++
		}
		if isText {
			if out.Len() < maxText {
				room := maxText - out.Len()
				if len(chunk) > room {
					chunk = chunk[:room]
					truncated = true
				}
				out.Write(chunk)
			} else if n > 0 {
				truncated = true
			}
		} else {
			// Printable ASCII runs, carried across chunk boundaries.
			for _, c := range chunk {
				if c >= 0x20 && c < 0x7F || c == '\t' {
					run = append(run, c)
					continue
				}
				if len(run) >= minStringLen {
					add(run)
				}
				run = run[:0]
			}
			// UTF-16LE runs (ASCII character followed by a zero byte), at
			// either byte alignment and carried across chunk boundaries.
			for _, c := range chunk {
				if haveLow {
					haveLow = false
					if c == 0 {
						wide = append(wide, low)
						continue
					}
					endWide()
				}
				if c >= 0x20 && c < 0x7F {
					low, haveLow = c, true
				} else {
					endWide()
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			ctx.Warn("read stopped early: %v", err)
			break
		}
	}
	if len(run) >= minStringLen {
		add(run)
	}
	endWide()

	entropy := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / float64(ctx.Size)
			entropy -= p * math.Log2(p)
		}
	}
	ctx.Fact("file.entropy", fmt.Sprintf("%.3f", entropy), "Shannon entropy in bits per byte; values near 8 suggest compressed or encrypted content")

	method := "strings (ASCII and UTF-16LE, minimum 6 characters)"
	if isText {
		method = "full text"
	}
	body := clean(out.String())
	if ctx.Kind == detect.TextUTF16 {
		// Strings extraction already recovered the UTF-16 runs.
		method = "strings from UTF-16 text"
	}
	if strings.TrimSpace(body) != "" {
		ctx.Text(method, truncated, body)
		if truncated {
			ctx.Note("indexed text was capped at %d bytes; the stored evidence is complete", maxText)
		}
	} else {
		ctx.Note("no readable text found in the file")
	}

	if ctx.Kind == detect.PE {
		if err := peTimestamp(ctx); err != nil {
			ctx.Warn("PE header: %v", err)
		}
	}
	return nil
}

// peTimestamp places an executable's link time on the timeline. The value is
// set by the build toolchain and is trivially forged, which the type records.
func peTimestamp(ctx *Context) error {
	hdr := make([]byte, 0x40)
	if _, err := ctx.File.ReadAt(hdr, 0); err != nil {
		return err
	}
	off := int64(binary.LittleEndian.Uint32(hdr[0x3C:]))
	pe := make([]byte, 24)
	if _, err := ctx.File.ReadAt(pe, off); err != nil {
		return fmt.Errorf("no PE header at offset 0x%X", off)
	}
	if string(pe[:4]) != "PE\x00\x00" {
		return fmt.Errorf("missing PE signature at offset 0x%X", off)
	}
	ts := binary.LittleEndian.Uint32(pe[8:])
	stamp, ok := timeutil.FromTimeNative(time.Unix(int64(ts), 0), fmt.Sprintf("TimeDateStamp 0x%08X", ts))
	if !ok {
		return nil
	}
	return ctx.Emit(Event{
		Stamp: stamp, Type: "pe-link-time (unverified)", Category: CatFileSystem, Source: "file", Host: ctx.Host, Path: ctx.Name,
		Message: fmt.Sprintf("Executable %s reports this link time in its header", ctx.Name),
		Fields:  map[string]any{"machine": fmt.Sprintf("0x%04X", binary.LittleEndian.Uint16(pe[4:])), "sections": binary.LittleEndian.Uint16(pe[6:])},
		Ref:     fmt.Sprintf("COFF header at offset 0x%X", off+4),
	})
}
