package parsers

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/DanDreadless/atropos/internal/imagefs"
)

// ewfParser records what an Expert Witness (E01) image says about itself,
// and checks the image: every chunk against its checksum, and the whole of
// the media against the hash the imaging tool stored.
//
// An E01 image is one piece of evidence that usually arrives as several
// files. The check is made from the first segment, using whichever other
// E01 files in the case belong to the same set (ctx.Segments); the other
// segments record only what they are. This is the one parser whose result
// depends on files other than its own, and its notes say which were used.
type ewfParser struct{}

func (ewfParser) Name() string { return "ewf-image" }
func (ewfParser) Version() string {
	return "2 (native: EWF version 1, E01; media verified against the stored hash; FAT and exFAT volumes inside put on the timeline)"
}

func (ewfParser) Parse(ctx *Context) error {
	info, err := imagefs.InspectEWF(ctx.File, ctx.Size)
	if err != nil {
		return err
	}
	ctx.Fact("ewf.segment", fmt.Sprint(info.Segment), "this file's number in its set of segment files")
	if info.SetID != "" {
		ctx.Fact("ewf.set_identifier", info.SetID, "identifier shared by the segment files of one image")
	}
	if info.HasGeometry {
		ctx.Fact("ewf.media_size", fmt.Sprint(info.MediaSize()), "size in bytes of the disk or volume that was imaged")
		ctx.Fact("ewf.sector_size", fmt.Sprint(info.BytesPerSector), "bytes to a sector of the imaged media")
	}
	for _, n := range info.Notes {
		ctx.Warn("%s", n)
	}
	if info.Segment != 1 {
		ctx.Note("segment %d of an E01 image. The image is opened, browsed and verified from its first segment", info.Segment)
		return nil
	}
	keys := make([]string, 0, len(info.Header))
	for k := range info.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ctx.Fact("ewf.acquisition."+k, clean(trunc(info.Header[k], 2000)), "recorded in the image by the tool that made it")
	}

	primary := imagefs.EWFSegment{R: ctx.File, Size: ctx.Size}
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
	img, err := imagefs.OpenEWF(primary, others)
	if err != nil {
		ctx.Warn("%v. Parse this file again once the set is complete", err)
		return nil
	}
	ctx.Fact("ewf.segments", fmt.Sprint(img.Segments), "segment files that make up the image")
	for _, n := range img.Info.Notes[len(info.Notes):] {
		ctx.Warn("%s", n)
	}
	if img.Info.MD5 != "" {
		ctx.Fact("ewf.stored_md5", img.Info.MD5, "MD5 of the media, stored in the image by the tool that made it")
	}
	if img.Info.SHA1 != "" {
		ctx.Fact("ewf.stored_sha1", img.Info.SHA1, "SHA-1 of the media, stored in the image by the tool that made it")
	}
	md5sum, sha1sum, err := img.MediaHashes()
	if err != nil {
		ctx.Warn("the image could not be read in full, so it is not verified: %v", err)
		return nil
	}
	ctx.Fact("ewf.computed_md5", md5sum, "MD5 of the media as read from the image by Atropos")
	ctx.Fact("ewf.computed_sha1", sha1sum, "SHA-1 of the media as read from the image by Atropos")
	of := fmt.Sprintf("%d bytes of media in %d segment file(s)", img.Size(), img.Segments)
	switch {
	case img.Info.MD5 == "" && img.Info.SHA1 == "":
		ctx.Fact("ewf.verified", "no stored hash", "the image holds no hash of its media to compare with")
		ctx.Note("%s read in full, every chunk passing its checksum. The image stores no hash of the media, so there is nothing to compare the computed one with", of)
	case (img.Info.MD5 == "" || img.Info.MD5 == md5sum) && (img.Info.SHA1 == "" || img.Info.SHA1 == sha1sum):
		ctx.Fact("ewf.verified", "yes", "the media read from the image has the hash the imaging tool stored")
		ctx.Note("verified: %s read in full, and the hash computed matches the one stored in the image when it was made", of)
	default:
		ctx.Fact("ewf.verified", "NO", "the media read from the image does not have the hash the imaging tool stored")
		ctx.Warn("NOT VERIFIED: the hash of the media read from the image (MD5 %s) is not the one stored in it when it was made (MD5 %s). The image has changed since acquisition, or was written wrongly", md5sum, img.Info.MD5)
	}
	// The acquisition time is on the timeline only when the tool wrote it as
	// a count of seconds, which is UTC. EnCase writes the examiner's local
	// time with no zone; that stays a fact.
	if a := strings.TrimSpace(info.Header["acquired"]); a != "" {
		if secs, err := strconv.ParseInt(a, 10, 64); err == nil {
			if stamp, ok := unixSeconds(secs); ok {
				fields := map[string]any{"media_size": img.Size(), "segments": img.Segments}
				for _, k := range keys {
					fields[k] = clean(trunc(info.Header[k], 500))
				}
				if err := ctx.Emit(Event{Stamp: stamp, Type: "image-acquired", Category: CatLog, Source: "ewf", Host: ctx.Host,
					Message: "Disk image acquired" + titleSuffix(clean(trunc(info.Header["description"], 200))), Fields: fields, Ref: "header"}); err != nil {
					return err
				}
			}
		}
	}
	fsys, err := imagefs.Open(img, img.Size())
	if err != nil {
		ctx.Note("%v", err)
		return nil
	}
	defer fsys.Close()
	return imageVolumes(ctx, fsys)
}
