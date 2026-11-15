package parsers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/timeutil"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

type ntfsParser struct{}

func (ntfsParser) Name() string { return "ntfs-mft" }
func (ntfsParser) Version() string {
	return "4 (velocidex/go-ntfs v0.2.1; named streams and zone marks)"
}

// macb groups a record's four timestamps by value so each distinct moment is
// one event, labelled with the familiar MACB letters.
func macb(m, a, c, b time.Time) map[time.Time]string {
	out := map[time.Time][]byte{}
	set := func(t time.Time, i int, ch byte) {
		if t.IsZero() {
			return
		}
		t = t.UTC()
		if out[t] == nil {
			out[t] = []byte("....")
		}
		out[t][i] = ch
	}
	set(m, 0, 'M')
	set(a, 1, 'A')
	set(c, 2, 'C')
	set(b, 3, 'B')
	res := map[time.Time]string{}
	for t, v := range out {
		res[t] = string(v)
	}
	return res
}

func (ntfsParser) Parse(ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	var items chan *ntfs.MFTHighlight
	bg, cancel := context.WithCancel(context.Background())
	defer cancel()

	var vol *ntfs.NTFSContext  // set when the evidence is a whole volume
	dirs := map[int64]string{} // directories in use, for reading their indexes
	// File records are read a second time, directly, for the named streams
	// of files that have them.
	var records io.ReaderAt = ctx.File
	recSize := int64(1024)
	if ctx.Kind == detect.NTFSVolume {
		nctx, err := ntfs.GetNTFSContext(ctx.File, 0)
		if err != nil {
			return fmt.Errorf("volume: %w", err)
		}
		defer nctx.Close()
		vol = nctx
		mft, err := ntfs.GetDataForPath(nctx, "$MFT")
		if err != nil {
			return fmt.Errorf("locating $MFT: %w", err)
		}
		items = ntfs.ParseMFTFile(bg, mft, ntfs.RangeSize(mft), nctx.ClusterSize, nctx.RecordSize)
		records, recSize = mft, nctx.RecordSize
		ctx.Note("volume image: the file table, the unused space of every directory index and the transaction log were read. Files inside the volume are added from the Files tab")
		if err := volumeShadowCopies(ctx); err != nil {
			return err
		}
	} else {
		// The record size is stated in each record header; the cluster size
		// is not recoverable from a bare $MFT, so the NTFS default is used.
		hdr := make([]byte, 0x20)
		if _, err := ctx.File.ReadAt(hdr, 0); err == nil {
			if n := int64(binary.LittleEndian.Uint32(hdr[0x1C:])); n == 1024 || n == 4096 {
				recSize = n
			}
		}
		items = ntfs.ParseMFTFile(bg, ctx.File, ctx.Size, 4096, recSize)
	}

	// The library follows each file with one more row per named stream. A
	// stream has no times of its own, so those rows are not events: their
	// names are gathered onto the file they belong to.
	var held *ntfs.MFTHighlight
	var heldStreams []string
	streamFiles, zoneMarks, unread := 0, 0, 0
	handle := func(h *ntfs.MFTHighlight, streams []string) error {
		path := clean(h.FullPath())
		if vol != nil && h.IsDir && h.InUse {
			dirs[h.EntryNumber] = path
		}
		base := map[string]any{
			"entry": h.EntryNumber, "sequence": h.SequenceNumber, "in_use": h.InUse,
			"is_dir": h.IsDir, "size": h.FileSize, "has_ads": h.HasADS,
			"parent_entry": h.ParentEntryNumber,
		}
		var flags []string
		if len(streams) > 0 {
			streamFiles++
			var found map[string]streamInfo
			if recSize >= 512 && recSize <= 65536 {
				rec := make([]byte, recSize)
				if n, _ := records.ReadAt(rec, h.EntryNumber*recSize); int64(n) == recSize {
					found = recordStreams(rec)
				}
			}
			list := make([]map[string]any, 0, len(streams))
			names := make([]string, 0, len(streams))
			for _, name := range streams {
				name = clean(name)
				names = append(names, name)
				item := map[string]any{"name": name}
				if s, ok := found[name]; ok {
					item["size"] = s.Size
					if strings.EqualFold(name, "Zone.Identifier") {
						if z, ok := parseZone(s.Content); ok && s.Resident {
							zoneMarks++
							z.fields(base)
							flags = append(flags, z.summary())
						} else {
							unread++
							base["zone_identifier"] = "present, but its content is not held in the file record and was not read"
						}
					}
				} else if strings.EqualFold(name, "Zone.Identifier") {
					unread++
					base["zone_identifier"] = "present, but its content is not held in the file record and was not read"
				}
				list = append(list, item)
			}
			base["streams"] = list
			flags = append(flags, "streams: "+trunc(strings.Join(names, ", "), 300))
		}
		if !h.InUse {
			flags = append(flags, "deleted")
		}
		if h.IsDir {
			flags = append(flags, "directory")
		}
		if h.SI_Lt_FN {
			// $STANDARD_INFORMATION earlier than $FILE_NAME is a classic
			// sign of timestamp manipulation.
			flags = append(flags, "SI<FN")
			base["si_earlier_than_fn"] = true
		}
		if h.USecZeros {
			flags = append(flags, "zero-subseconds")
			base["subseconds_zero"] = true
		}
		if h.Copied {
			base["copied"] = true
		}
		suffix := ""
		if len(flags) > 0 {
			suffix = " [" + strings.Join(flags, ", ") + "]"
		}
		emit := func(attr string, groups map[time.Time]string) error {
			keys := make([]time.Time, 0, len(groups))
			for t := range groups {
				keys = append(keys, t)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
			for _, t := range keys {
				stamp, ok := timeutil.FromTimeNative(t, "")
				if !ok {
					continue
				}
				if err := ctx.Emit(Event{
					Stamp: stamp, Type: attr + " " + groups[t], MACB: groups[t], Category: CatFileSystem, Source: "mft",
					Host: ctx.Host, Path: path,
					Message: fmt.Sprintf("%s %s  %s (%d bytes)%s", attr, groups[t], path, h.FileSize, suffix),
					Fields:  base, Ref: fmt.Sprintf("MFT entry %d-%d", h.EntryNumber, h.SequenceNumber),
				}); err != nil {
					return err
				}
			}
			return nil
		}
		si := macb(h.LastModified0x10, h.LastAccess0x10, h.LastRecordChange0x10, h.Created0x10)
		if err := emit("$SI", si); err != nil {
			return err
		}
		// $FILE_NAME times are emitted only where they add a moment that
		// $STANDARD_INFORMATION does not already show.
		fn := macb(h.LastModified0x30, h.LastAccess0x30, h.LastRecordChange0x30, h.Created0x30)
		for t := range fn {
			if _, dup := si[t]; dup {
				delete(fn, t)
			}
		}
		return emit("$FN", fn)
	}
	for h := range items {
		if strings.Contains(h.Inode, ":") {
			if held != nil && held.EntryNumber == h.EntryNumber && len(heldStreams) < 64 {
				if _, name, ok := strings.Cut(h.Inode, ":"); ok && name != "" {
					heldStreams = append(heldStreams, name)
				}
			}
			continue
		}
		if held != nil {
			if err := handle(held, heldStreams); err != nil {
				return err
			}
		}
		held, heldStreams = h, nil
	}
	if held != nil {
		if err := handle(held, heldStreams); err != nil {
			return err
		}
	}
	if streamFiles > 0 {
		ctx.Note("%d files carry named (alternate) data streams, listed in each file's fields. A stream has no times of its own; the times shown are the file's", streamFiles)
		if zoneMarks > 0 {
			ctx.Note("%d files carry a Zone.Identifier that was read: the zone, and where it is stated the address the file came from, are in that file's events", zoneMarks)
		}
		if unread > 0 {
			ctx.Note("%d Zone.Identifier streams are stored outside their file record and were not read", unread)
		}
	}
	if vol != nil {
		if err := volumeIndexSlack(ctx, vol, dirs); err != nil {
			return err
		}
		if err := volumeLogFile(ctx, vol, dirs); err != nil {
			return err
		}
	}
	return nil
}
