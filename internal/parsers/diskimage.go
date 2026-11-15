package parsers

import (
	"errors"
	"os"
	"strings"

	"github.com/DanDreadless/atropos/internal/imagefs"
)

// diskImageParser puts the FAT, exFAT and ext2/3/4 volumes of an image on
// the timeline: a volume on its own (a USB stick, a memory card, a Linux
// partition imaged by itself), or the partitions of a raw disk, VHD, VHDX
// or VMDK image. Every name is read, in use or deleted.
//
// NTFS partitions inside an image are not walked here: their file table
// says far more, and the Windows artefacts action copies it out.
type diskImageParser struct{}

func (diskImageParser) Name() string { return "disk-image" }
func (diskImageParser) Version() string {
	return "3 (native: shadow copies of NTFS partitions; FAT12/16/32 and exFAT directory entries; ext2/3/4 inodes and names, deleted names from directory slack)"
}

func (diskImageParser) Parse(ctx *Context) error {
	var others []imagefs.EWFSegment
	for _, p := range ctx.Segments {
		f, err := os.OpenFile(p, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		defer f.Close()
		if st, err := f.Stat(); err == nil {
			others = append(others, imagefs.EWFSegment{R: f, Size: st.Size()})
		}
	}
	fsys, err := imagefs.OpenSet(ctx.File, ctx.Size, others)
	if err != nil {
		if errors.Is(err, imagefs.ErrNoFileSystem) {
			ctx.Note("%v", err)
			return nil
		}
		ctx.Warn("%v", err)
		return nil
	}
	defer fsys.Close()
	return imageVolumes(ctx, fsys)
}

// imageVolumes walks the FAT, exFAT and ext volumes of an opened image, and
// says what the rest of it holds.
func imageVolumes(ctx *Context, fsys imagefs.FS) error {
	ctx.Fact("image.contents", trunc(fsys.Describe(), 500), "what the image holds, as Atropos opened it")
	for _, p := range imagefs.Partitions(fsys) {
		ctx.Note("%s", p)
	}
	for _, v := range imagefs.ShadowCopiesIn(fsys) {
		if v.Where == "/" {
			continue // a volume on its own: the NTFS parser lists them
		}
		if err := emitShadowCopies(ctx, v.Copies, strings.TrimPrefix(v.Where, "/")); err != nil {
			return err
		}
	}
	fat, ext := imagefs.FATVolumes(fsys), imagefs.ExtVolumes(fsys)
	if len(fat)+len(ext) == 0 {
		ctx.Note("no FAT, exFAT or ext volume in this image to put on the timeline. Open it under Files to browse it and choose what goes on the timeline; for an NTFS partition, the Windows artefacts action copies out its file table")
		return nil
	}
	for _, v := range fat {
		if err := fatTimeline(ctx, v); err != nil {
			return err
		}
	}
	for _, v := range ext {
		if err := extTimeline(ctx, v); err != nil {
			return err
		}
	}
	return nil
}
