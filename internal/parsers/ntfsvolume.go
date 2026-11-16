package parsers

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/timeutil"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

// Limits on what is read from inside a volume. A directory index or a log
// larger than these is not a normal one, and evidence must not be able to
// make Atropos read without end.
const (
	maxIndexStream = 256 << 20
	maxLogFile     = 1 << 30
)

// volumeIndexSlack reads the index of every directory in use on a volume and
// emits what is left in the unused space of each. Live entries are not
// emitted: the file table already puts those files on the timeline.
func volumeIndexSlack(ctx *Context, vol *ntfs.NTFSContext, dirs map[int64]string) error {
	ids := make([]int64, 0, len(dirs))
	for id := range dirs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	recovered, dirsWith, failed := 0, 0, 0
	for _, id := range ids {
		streams, err := indexAllocations(vol, id)
		if err != nil {
			failed++
			continue
		}
		for _, st := range streams {
			if st.size > maxIndexStream {
				ctx.Warn("the index of %s is %d bytes; only the first %d were read", dirs[id], st.size, maxIndexStream)
				st.size = maxIndexStream
			}
			dir := dirs[id]
			_, slack := readIndexStream(st.r, st.size, func(format string, a ...any) {
				ctx.Warn("index of %s: "+format, append([]any{dir}, a...)...)
			})
			if len(slack) > 0 {
				dirsWith++
			}
			for _, e := range slack {
				recovered++
				path := joinDir(dir, clean(e.name))
				if err := emitIndexEntry(ctx, e, "i30", "$I30-slack",
					"recovered from unused space in the directory's index, so the file was deleted, renamed, moved, or had these times before they changed",
					path, fmt.Sprintf("index of MFT entry %d, slack entry at offset %d", id, e.offset),
					map[string]any{"directory": dir, "directory_entry": id}); err != nil {
					return err
				}
			}
		}
	}
	if failed > 0 {
		ctx.Warn("the indexes of %d directories could not be read", failed)
	}
	ctx.Note("directory indexes: %d entries recovered from unused space in %d of %d directories. A recovered entry's times are the file's own, as the directory last recorded them, not when it was removed", recovered, dirsWith, len(ids))
	return nil
}

type indexStream struct {
	r    io.ReaderAt
	size int64
}

// indexAllocations returns a directory's $INDEX_ALLOCATION streams. The
// library is isolated here: a damaged record must cost one directory.
func indexAllocations(vol *ntfs.NTFSContext, id int64) (out []indexStream, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	entry, err := vol.GetMFT(id)
	if err != nil {
		return nil, err
	}
	for _, attr := range entry.EnumerateAttributes(vol) {
		if attr.Type().Value == ntfs.ATTR_TYPE_INDEX_ALLOCATION && attr.Name() == "$I30" {
			out = append(out, indexStream{attr.Data(vol), attr.DataSize()})
		}
	}
	return out, nil
}

// volumeLogFile reads the transaction log from inside a volume.
func volumeLogFile(ctx *Context, vol *ntfs.NTFSContext, dirs map[int64]string) (err error) {
	var r io.ReaderAt
	var size int64
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("parser panic: %v", p)
			}
		}()
		rng, gerr := ntfs.GetDataForPath(vol, "$LogFile")
		if gerr != nil {
			err = gerr
			return
		}
		r, size = rng, ntfs.RangeSize(rng)
	}()
	if err != nil {
		ctx.Warn("the transaction log ($LogFile) could not be opened: %v", err)
		return nil
	}
	if size > maxLogFile {
		ctx.Warn("the transaction log is %d bytes; only the first %d were read", size, maxLogFile)
		size = maxLogFile
	}
	if _, perr := parseLogFile(ctx, r, size, "$LogFile in the volume, ", func(entry uint64) string { return dirs[int64(entry)] }); perr != nil {
		// A log that cannot be read must not cost the file table already parsed.
		if !errors.Is(perr, errLogUnreadable) {
			return perr // the store refused an event: stop
		}
		ctx.Warn("the transaction log ($LogFile) could not be read: %v", perr)
	}
	return nil
}

// volumeShadowCopies puts the making of each of the volume's shadow copies
// on the timeline. Their contents are browsed on the Images tab.
func volumeShadowCopies(ctx *Context) error {
	copies, err := imagefs.ShadowCopies(ctx.File, ctx.Size)
	if err != nil {
		ctx.Warn("%v", err)
		return nil
	}
	return emitShadowCopies(ctx, copies, "")
}

// emitShadowCopies puts a volume's shadow copies on the timeline; where is
// the partition ("p1"), or empty for a volume on its own.
func emitShadowCopies(ctx *Context, copies []imagefs.ShadowCopy, where string) error {
	if len(copies) == 0 {
		return nil
	}
	for _, c := range copies {
		stamp, ok := timeutil.FromFiletime(c.Created)
		if !ok {
			ctx.Warn("shadow copy %s has no usable creation time", c.ID)
			continue
		}
		fields := map[string]any{"store_id": c.ID, "volume_size": c.VolumeSize, "has_store": c.HasStore}
		ref := fmt.Sprintf("shadow copy catalog entry at offset %d", c.Offset)
		if where != "" {
			fields["partition"] = where
			ref = "partition " + where + ", " + ref
		}
		if err := ctx.Emit(Event{
			Stamp: stamp, Type: "shadow-copy-created", Category: CatFileSystem, Source: "vss", Host: ctx.Host,
			Message: "Volume shadow copy created: {" + c.ID + "}", Fields: fields, Ref: ref,
		}); err != nil {
			return err
		}
	}
	key, on := "vss.shadow_copies", "this volume"
	if where != "" {
		key, on = "vss."+where+".shadow_copies", "partition "+where
	}
	ctx.Fact(key, fmt.Sprint(len(copies)), "volume shadow copies listed in the volume's catalog")
	ctx.Note("%d volume shadow copies are on %s: earlier states of it, which often still hold files since deleted. Each appears on the Images tab as a folder <shadow copy N> at the volume's root, to browse and copy files out of", len(copies), on)
	return nil
}
