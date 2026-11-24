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
	return "5 (velocidex/go-ntfs v0.2.1; named streams, zone marks, every file name's times)"
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
	recordsSize := ctx.Size
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
		records, recSize, recordsSize = mft, nctx.RecordSize, ntfs.RangeSize(mft)
		ctx.Note("volume image: the file table, the unused space of every directory index and the transaction log were read. Files inside the volume are added from the Images tab")
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
	// A second reader of the same file records, for the $FILE_NAME
	// attributes the library does not report (fileNames).
	// On a volume it is the volume's own context, which can also follow an
	// attribute list held outside the record; a bare $MFT cannot, so the
	// extension records holding names are also found by a scan of their own
	// (extensionNames) and read directly.
	fnCtx := vol
	if fnCtx == nil {
		fnCtx = ntfs.GetNTFSContextFromRawMFT(records, 4096, recSize)
		defer fnCtx.Close()
	}
	extNames := extensionNames(records, recordsSize, recSize)
	namesExtra := 0
	seen := map[int64]bool{}       // base records with extension names that the library reported
	dirPaths := map[int64]string{} // every directory's path, for files the library skipped

	var held *ntfs.MFTHighlight
	var heldStreams []string
	streamFiles, zoneMarks, unread := 0, 0, 0
	handle := func(h *ntfs.MFTHighlight, streams []string) error {
		path := clean(h.FullPath())
		if vol != nil && h.IsDir && h.InUse {
			dirs[h.EntryNumber] = path
		}
		if extNames[h.EntryNumber] != nil {
			seen[h.EntryNumber] = true
		}
		if h.IsDir {
			dirPaths[h.EntryNumber] = path
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
		emitAs := func(attr string, groups map[time.Time]string, fields map[string]any, also string) error {
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
					Message: fmt.Sprintf("%s %s  %s (%d bytes)%s%s", attr, groups[t], path, h.FileSize, also, suffix),
					Fields:  fields, Ref: fmt.Sprintf("MFT entry %d-%d", h.EntryNumber, h.SequenceNumber),
				}); err != nil {
					return err
				}
			}
			return nil
		}
		emit := func(attr string, groups map[time.Time]string) error { return emitAs(attr, groups, base, "") }
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
		if err := emit("$FN", fn); err != nil {
			return err
		}
		// The library reports the times of the record's first $FILE_NAME
		// only. A file with several names (hard links, a POSIX name beside
		// a Win32 one) has a $FILE_NAME for each, with its own times: when
		// that name was made, last renamed or moved. Each other name's
		// moments that are not already shown become events of their own.
		exts := extNames[h.EntryNumber].of(h.SequenceNumber)
		if len(h.FileNames) < 2 && len(exts) == 0 {
			return nil
		}
		shown := map[time.Time]bool{}
		for t := range si {
			shown[t] = true
		}
		for t := range fn {
			shown[t] = true
		}
		added := false
		first := [4]time.Time{h.LastModified0x30.UTC(), h.LastAccess0x30.UTC(), h.LastRecordChange0x30.UTC(), h.Created0x30.UTC()}
		for _, n := range fileNames(fnCtx, h.EntryNumber, exts) {
			if n.times == first {
				continue
			}
			groups := macb(n.times[0], n.times[1], n.times[2], n.times[3])
			for t := range groups {
				if shown[t] {
					delete(groups, t)
				}
			}
			if len(groups) == 0 {
				continue
			}
			for t := range groups {
				shown[t] = true
			}
			fields := make(map[string]any, len(base)+3)
			for k, v := range base {
				fields[k] = v
			}
			fields["file_name"] = n.name
			fields["file_name_namespace"] = n.space
			fields["file_name_parent_entry"] = n.parent
			also := fmt.Sprintf(" [times of its name %q in directory entry %d]", n.name, n.parent)
			if err := emitAs("$FN", groups, fields, also); err != nil {
				return err
			}
			added = true
		}
		if added {
			namesExtra++
		}
		return nil
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
	if err := skippedByLibrary(ctx, fnCtx, extNames, seen, dirPaths); err != nil {
		return err
	}
	if namesExtra > 0 {
		ctx.Note("%d files have more than one name whose $FILE_NAME times differ; each other name's times are events of their own, naming it in file_name", namesExtra)
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

// fileName is one $FILE_NAME attribute of a file record.
type fileName struct {
	name, space string
	parent      uint64
	times       [4]time.Time // M, A, C, B
}

// fileNames reads every $FILE_NAME attribute of a file record: those the
// library finds (in the record, or through an attribute list it can read)
// and those in the extension records given. The library panics on some
// damaged records; such a record gives nothing.
func fileNames(n *ntfs.NTFSContext, entry int64, exts []int64) []fileName {
	var out []fileName
	have := map[fileName]bool{}
	read := func(id int64) {
		defer func() { _ = recover() }()
		rec, err := n.GetMFT(id)
		if err != nil {
			return
		}
		for _, attr := range rec.EnumerateAttributes(n) {
			if attr.Type().Value != ntfs.ATTR_TYPE_FILE_NAME {
				continue
			}
			f := n.Profile.FILE_NAME(attr.Data(n), 0)
			fn := fileName{
				name: clean(f.Name()), space: f.NameType().Name, parent: f.MftReference(),
				times: [4]time.Time{f.File_modified().Time.UTC(), f.File_accessed().Time.UTC(), f.Mft_modified().Time.UTC(), f.Created().Time.UTC()},
			}
			if !have[fn] {
				have[fn] = true
				out = append(out, fn)
			}
		}
	}
	read(entry)
	for _, id := range exts {
		read(id)
	}
	return out
}

// extRecord is an extension record holding a $FILE_NAME, and the sequence
// number its base reference names.
type extRecord struct {
	id  int64
	seq uint16
}

type extList []extRecord

// of gives the extension records that belong to the base record's current
// use: one left from an earlier file in the same slot names an older
// sequence number.
func (l extList) of(seq uint16) []int64 {
	var out []int64
	for _, e := range l {
		if e.seq == seq {
			out = append(out, e.id)
		}
	}
	return out
}

// extensionNames finds, in one pass over the file records, every extension
// record in use that holds a $FILE_NAME, keyed by its base record. A file
// whose attributes overflow its record continues in extension records, and
// its attribute list says where; when that list is itself held outside the
// record, a bare $MFT does not contain it, and this is the only way to find
// the names (it is how MFTECmd finds them).
func extensionNames(r io.ReaderAt, size, recSize int64) map[int64]extList {
	out := map[int64]extList{}
	if recSize < 512 || recSize > 65536 || size <= 0 {
		return out
	}
	le := binary.LittleEndian
	chunk := make([]byte, recSize*1024)
	for off := int64(0); off < size; off += int64(len(chunk)) {
		n, _ := r.ReadAt(chunk, off)
		n -= n % int(recSize)
		if n <= 0 {
			break
		}
		for p := 0; p < n; p += int(recSize) {
			rec := chunk[p : p+int(recSize)]
			if string(rec[:4]) != "FILE" || le.Uint16(rec[0x16:])&1 == 0 {
				continue
			}
			ref := le.Uint64(rec[0x20:])
			base := int64(ref & 0xFFFFFFFFFFFF)
			if base == 0 {
				continue // a base record itself
			}
			// Walk the attribute headers for a $FILE_NAME. Only each header's
			// type and length are read, and checked against the record.
			a := int(le.Uint16(rec[0x14:]))
			for steps := 0; a >= 0x18 && a+8 <= len(rec) && steps < 64; steps++ {
				typ, length := le.Uint32(rec[a:]), int(le.Uint32(rec[a+4:]))
				if typ == 0xFFFFFFFF || length < 16 || a+length > len(rec) {
					break
				}
				if typ == 0x30 {
					id := (off + int64(p)) / recSize
					out[base] = append(out[base], extRecord{id: id, seq: uint16(ref >> 48)})
					break
				}
				a += length
			}
		}
		if n < len(chunk) {
			break
		}
	}
	return out
}

// skippedByLibrary puts on the timeline the files whose base record holds
// no $FILE_NAME of its own, every name being in extension records. The
// library leaves such a record out altogether; it is read here directly:
// its $STANDARD_INFORMATION, its names, and its path from its parent
// directory's. Its streams are not read.
func skippedByLibrary(ctx *Context, n *ntfs.NTFSContext, extNames map[int64]extList, seen map[int64]bool, dirPaths map[int64]string) error {
	bases := make([]int64, 0)
	for b := range extNames {
		if !seen[b] {
			bases = append(bases, b)
		}
	}
	sort.Slice(bases, func(i, j int) bool { return bases[i] < bases[j] })
	recovered := 0
	for _, b := range bases {
		var si [4]time.Time
		var seq uint16
		var inUse, isDir, ok bool
		var size int64
		func() {
			defer func() { _ = recover() }()
			rec, err := n.GetMFT(b)
			if err != nil {
				return
			}
			seq, inUse, isDir = rec.Sequence_value(), rec.Flags().IsSet("ALLOCATED"), rec.Flags().IsSet("DIRECTORY")
			for _, attr := range rec.EnumerateAttributes(n) {
				switch attr.Type().Value {
				case ntfs.ATTR_TYPE_STANDARD_INFORMATION:
					x := n.Profile.STANDARD_INFORMATION(attr.Data(n), 0)
					si = [4]time.Time{x.File_altered_time().Time.UTC(), x.File_accessed_time().Time.UTC(), x.Mft_altered_time().Time.UTC(), x.Create_time().Time.UTC()}
					ok = true
				case ntfs.ATTR_TYPE_DATA:
					if size == 0 && attr.Name() == "" {
						size = attr.DataSize()
					}
				}
			}
		}()
		exts := extNames[b].of(seq)
		if !ok || len(exts) == 0 {
			continue
		}
		names := fileNames(n, b, exts)
		if len(names) == 0 {
			continue
		}
		// The name a path is built from: a long name before a DOS short one.
		main := names[0]
		for _, nm := range names {
			if nm.space != "DOS" {
				main = nm
				break
			}
		}
		dir := dirPaths[int64(main.parent)]
		if main.parent == 5 || dir == "/." {
			dir = ""
		} else if dir == "" {
			dir = fmt.Sprintf("/<directory entry %d>", main.parent)
		}
		path := dir + "/" + main.name
		base := map[string]any{
			"entry": b, "sequence": seq, "in_use": inUse, "is_dir": isDir, "size": size,
			"parent_entry": main.parent, "names_only_in_extension_records": true,
		}
		ref := fmt.Sprintf("MFT entry %d-%d", b, seq)
		emit := func(attr string, groups map[time.Time]string, fields map[string]any, also string) error {
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
					Message: fmt.Sprintf("%s %s  %s (%d bytes)%s [names held only in extension records]", attr, groups[t], path, size, also),
					Fields:  fields, Ref: ref,
				}); err != nil {
					return err
				}
			}
			return nil
		}
		shown := macb(si[0], si[1], si[2], si[3])
		if err := emit("$SI", shown, base, ""); err != nil {
			return err
		}
		seenT := map[time.Time]bool{}
		for t := range shown {
			seenT[t] = true
		}
		for _, nm := range names {
			groups := macb(nm.times[0], nm.times[1], nm.times[2], nm.times[3])
			for t := range groups {
				if seenT[t] {
					delete(groups, t)
				} else {
					seenT[t] = true
				}
			}
			if len(groups) == 0 {
				continue
			}
			fields, also := base, ""
			if nm != main {
				fields = make(map[string]any, len(base)+3)
				for k, v := range base {
					fields[k] = v
				}
				fields["file_name"] = nm.name
				fields["file_name_namespace"] = nm.space
				fields["file_name_parent_entry"] = nm.parent
				also = fmt.Sprintf(" [times of its name %q in directory entry %d]", nm.name, nm.parent)
			}
			if err := emit("$FN", groups, fields, also); err != nil {
				return err
			}
		}
		recovered++
	}
	if recovered > 0 {
		ctx.Note("%d files hold all their names in extension records, which the file-table library leaves out; they were read directly (their streams were not read)", recovered)
	}
	return nil
}
