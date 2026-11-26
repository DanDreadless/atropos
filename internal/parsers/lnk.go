package parsers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// lnkParser reads Windows shell links per the MS-SHLLINK specification.
type lnkParser struct{}

func (lnkParser) Name() string { return "lnk" }
func (lnkParser) Version() string {
	return "4 (native; a target from the item list without link information; an undated shortcut kept as text)"
}

const lnkMax = 8 << 20

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func utf16z(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}

func (lnkParser) Parse(ctx *Context) error {
	if ctx.Size > lnkMax {
		return fmt.Errorf("shortcut is implausibly large (%d bytes)", ctx.Size)
	}
	b, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return err
	}
	n, fields, err := parseLnkFields(ctx, b, "Shortcut "+ctx.Name, "shell link header")
	if err == nil && n == 0 {
		// No time to place it by, but what it points at and runs is kept as
		// text: searchable, and seen by the command checks over file text.
		ctx.Note("shortcut header carries no timestamps; its target and arguments are kept as searchable text")
		var lines []string
		for _, k := range []struct{ key, label string }{{"target", "Target"}, {"target_from", "Target read from"}, {"arguments", "Arguments"},
			{"working_dir", "Working directory"}, {"relative_path", "Relative path"}, {"description", "Description"}, {"icon_location", "Icon"},
			{"network_share", "Network share"}, {"tracker_machine_id", "Machine"}} {
			if v, ok := fields[k.key].(string); ok && v != "" {
				lines = append(lines, k.label+": "+v)
			}
		}
		if len(lines) > 0 {
			ctx.Text("full text", false, strings.Join(lines, "\n"))
		}
	}
	return err
}

// parseLnk reads one shell link from b and emits an event for each of the
// target's times. label names the link in messages and ref locates it in the
// evidence. It returns how many events it emitted.
func parseLnk(ctx *Context, b []byte, label, ref string) (int, error) {
	n, _, err := parseLnkFields(ctx, b, label, ref)
	return n, err
}

// parseLnkFields is parseLnk that also returns what was read of the link.
func parseLnkFields(ctx *Context, b []byte, label, ref string) (int, map[string]any, error) {
	if len(b) < 76 {
		return 0, nil, errors.New("truncated shell link header")
	}
	le := binary.LittleEndian
	flags := le.Uint32(b[20:])
	fields := map[string]any{
		"link_flags":      fmt.Sprintf("0x%08X", flags),
		"file_attributes": fmt.Sprintf("0x%08X", le.Uint32(b[24:])),
		"target_size":     le.Uint32(b[52:]),
	}
	created, accessed, written := le.Uint64(b[28:]), le.Uint64(b[36:]), le.Uint64(b[44:])
	off := 76
	unicode := flags&0x80 != 0

	var idList []byte
	if flags&0x1 != 0 { // LinkTargetIDList
		if off+2 > len(b) {
			return 0, nil, errors.New("truncated target ID list")
		}
		n := int(le.Uint16(b[off:]))
		if off+2+n <= len(b) {
			idList = b[off+2 : off+2+n]
		}
		off += 2 + n
	}
	target := ""
	if flags&0x2 != 0 && off+28 <= len(b) { // LinkInfo
		li := b[off:]
		size := int(le.Uint32(li))
		if size < 28 || size > len(li) {
			ctx.Warn("link information block has an invalid size")
		} else {
			li = li[:size]
			hdrSize := le.Uint32(li[4:])
			liFlags := le.Uint32(li[8:])
			at := func(o uint32) []byte {
				if o == 0 || int(o) >= len(li) {
					return nil
				}
				return li[o:]
			}
			suffix := cstr(at(le.Uint32(li[24:])))
			if hdrSize >= 0x24 && len(li) >= 36 {
				if s := utf16z(at(le.Uint32(li[32:]))); s != "" {
					suffix = s
				}
			}
			if liFlags&0x1 != 0 {
				target = cstr(at(le.Uint32(li[16:])))
				if hdrSize >= 0x24 && len(li) >= 36 {
					if s := utf16z(at(le.Uint32(li[28:]))); s != "" {
						target = s
					}
				}
				if vol := at(le.Uint32(li[12:])); len(vol) >= 16 {
					fields["volume_serial"] = fmt.Sprintf("%08X", le.Uint32(vol[8:]))
					fields["drive_type"] = le.Uint32(vol[4:])
					if lo := le.Uint32(vol[12:]); lo != 0 && int(lo) < len(vol) && lo != 0x14 {
						fields["volume_label"] = clean(cstr(vol[lo:]))
					}
				}
			}
			if liFlags&0x2 != 0 {
				if net := at(le.Uint32(li[20:])); len(net) >= 20 {
					if no := le.Uint32(net[8:]); no != 0 && int(no) < len(net) {
						share := cstr(net[no:])
						fields["network_share"] = clean(share)
						if target == "" {
							target = share
						}
					}
				}
			}
			if suffix != "" {
				if target != "" && !strings.HasSuffix(target, `\`) {
					target += `\`
				}
				target += suffix
			}
		}
		off += size
	}

	for _, s := range []struct {
		bit  uint32
		name string
	}{{0x4, "description"}, {0x8, "relative_path"}, {0x10, "working_dir"}, {0x20, "arguments"}, {0x40, "icon_location"}} {
		if flags&s.bit == 0 {
			continue
		}
		if off+2 > len(b) {
			ctx.Warn("string data truncated before %s", s.name)
			break
		}
		n := int(le.Uint16(b[off:]))
		off += 2
		width := 1
		if unicode {
			width = 2
		}
		if off+n*width > len(b) {
			ctx.Warn("string data truncated in %s", s.name)
			break
		}
		raw := b[off : off+n*width]
		off += n * width
		var v string
		if unicode {
			u := make([]uint16, n)
			for i := range u {
				u[i] = le.Uint16(raw[i*2:])
			}
			v = string(utf16.Decode(u))
		} else {
			v = string(raw)
		}
		fields[s.name] = trunc(clean(v), 2048)
	}

	// Extra data blocks: the tracker block names the machine the target was on.
	for off+8 <= len(b) {
		size := int(le.Uint32(b[off:]))
		if size < 8 || off+size > len(b) {
			break
		}
		if le.Uint32(b[off+4:]) == 0xA0000003 && size >= 96 {
			blk := b[off : off+size]
			fields["tracker_machine_id"] = clean(cstr(blk[16:32]))
			mac := blk[58:64]
			fields["tracker_mac"] = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		}
		off += size
	}

	target = clean(target)
	// Without link information (a target that did not exist, or a shortcut
	// made by a program), the shell item list names it, as Explorer shows it.
	if target == "" {
		if p := clean(pidlPath(idList)); p != "" {
			target, fields["target_from"] = p, "the shell item list (the shortcut has no link information)"
		}
	}
	if target == "" {
		if rp, ok := fields["relative_path"].(string); ok {
			target = rp
		}
	}
	fields["target"] = target
	n := 0
	// The header holds the target file's own times as they were when the
	// shortcut was last updated, so each is a true M, A or B time.
	for _, t := range []struct {
		ft   uint64
		kind string
		word string
		macb string
	}{{created, "link-target-created", "created", "...B"}, {written, "link-target-modified", "modified", "M..."}, {accessed, "link-target-accessed", "accessed", ".A.."}} {
		stamp, ok := timeutil.FromFiletime(t.ft)
		if !ok {
			continue
		}
		n++
		msg := fmt.Sprintf("%s: target %s %s", label, target, t.word)
		if a, ok := fields["arguments"].(string); ok && a != "" {
			msg += "  args: " + trunc(a, 200)
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: t.kind, MACB: t.macb, Category: CatFileOpening, Source: "lnk", Host: ctx.Host, Path: target,
			Message: msg, Fields: fields, Ref: ref,
		}); err != nil {
			return n, fields, err
		}
	}
	return n, fields, nil
}
