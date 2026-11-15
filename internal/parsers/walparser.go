package parsers

import "fmt"

// walParser records what a SQLite write-ahead log holds. Its rows are put
// on the timeline with its database: when the database is parsed, a log
// that fits it is applied first. The log's text is indexed as any file's.
type walParser struct{}

func (walParser) Name() string    { return "sqlite-wal" }
func (walParser) Version() string { return "1 (native: frames and commits; applied with its database)" }

func (walParser) Parse(ctx *Context) error {
	w, err := readWAL(ctx.File, ctx.Size)
	if err != nil {
		return err
	}
	ctx.Fact("sqlite_wal.page_size", fmt.Sprint(w.pageSize), "page size of the database the log belongs to")
	ctx.Fact("sqlite_wal.commits", fmt.Sprint(w.commits), "complete transactions in the log")
	ctx.Fact("sqlite_wal.frames", fmt.Sprint(w.frames), "valid frames (pages written), committed or not")
	ctx.Note("a SQLite write-ahead log: %d complete transactions in %d frames, touching %d pages. It is applied to the database it belongs to, found by its pages, when that database is parsed; add the database too if it is not in the case", w.commits, w.frames, len(w.pages))
	return genericParser{}.Parse(ctx)
}
