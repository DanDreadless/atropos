package parsers

import (
	"fmt"
	"strings"

	"github.com/DanDreadless/atropos/internal/imagefs"
)

// thumbcacheParser records what a thumbnail cache holds. The cache keeps no
// times, so nothing goes on the timeline; its thumbnails are viewed and
// copied out on the Images tab. The identifiers are indexed as text, so
// searching for a Windows Search item's thumbnail_cache_id finds the cache
// that holds its picture.
type thumbcacheParser struct{}

func (thumbcacheParser) Name() string    { return "thumbnail-cache" }
func (thumbcacheParser) Version() string { return "1 (native: formats 20, 21, 30, 31 and 32)" }

func (thumbcacheParser) Parse(ctx *Context) error {
	thumbs, describe, err := imagefs.Thumbnails(ctx.File, ctx.Size)
	if err != nil {
		return err
	}
	ctx.Fact("thumbcache.thumbnails", fmt.Sprint(len(thumbs)), "thumbnails with a picture in the cache")
	ctx.Note("%s. A thumbnail cache records no times; open it on the Images tab to see its thumbnails and copy out any of them. Each is named by its identifier, which the Windows Search index records against the file's path as thumbnail_cache_id", describe)
	var b strings.Builder
	for _, t := range thumbs {
		fmt.Fprintf(&b, "%s\n", t.ID)
	}
	body := b.String()
	ctx.Text("thumbnail identifiers", len(body) > maxText, trunc(body, maxText))
	return nil
}
