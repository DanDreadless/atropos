package parsers

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DanDreadless/atropos/internal/hivelog"
)

// A registry transaction log (.LOG, .LOG1, .LOG2) is not read on its own:
// it is applied to its hive when the hive is parsed. Parsed by itself, it
// records what it is and which hive it belongs to.
type regLogParser struct{}

func (regLogParser) Name() string { return "registry-log" }
func (regLogParser) Version() string {
	return "1 (native: old and new formats; applied to its hive by the registry parser)"
}

func (regLogParser) Parse(ctx *Context) error {
	head := make([]byte, 4096)
	n, _ := ctx.File.ReadAt(head, 0)
	b, err := hivelog.ParseBase(head[:n])
	if err != nil {
		return err
	}
	format := "new (Windows 8.1 and later)"
	if b.Type != hivelog.TypeLogNew {
		format = "old (Windows XP to 8)"
	}
	ctx.Fact("registry_log.format", format, "transaction log format, from its base block")
	ctx.Fact("registry_log.hive_name", clean(b.Name), "the end of the hive's path, as the log's copy of the hive's base block records it")
	if b.Type == hivelog.TypeLogNew {
		ctx.Fact("registry_log.first_sequence", fmt.Sprint(b.Seq1), "sequence number of the first entry in this batch of the log")
		entries := countLogEntries(ctx.File, ctx.Size)
		ctx.Fact("registry_log.entries", fmt.Sprint(entries), "log entries found one after another from the start; earlier, already applied entries may follow them")
	}
	ctx.Note("transaction log of the hive %q. It is applied when that hive is parsed, if both are in the case; add the hive and its logs together, or parse the hive again after adding the logs", clean(b.Name))
	return nil
}

// countLogEntries counts the entries that follow one another from the
// start of a new-format log.
func countLogEntries(r io.ReaderAt, size int64) int {
	n := 0
	h := make([]byte, 8)
	for off := int64(512); off+40 <= size && n < 1<<20; n++ {
		if k, _ := r.ReadAt(h, off); k < 8 || string(h[:4]) != "HvLE" {
			break
		}
		sz := int64(binary.LittleEndian.Uint32(h[4:]))
		if sz < 40 || sz%512 != 0 {
			break
		}
		off += sz
	}
	return n
}

// replayLogs returns the hive as Windows would load it: with whichever of
// the offered transaction logs belong to it applied. It returns ctx.File
// itself when the hive was fully written or no log of it is in the case,
// and says which in the run's notes. The logs are the only files other than
// its own that this parser reads.
func replayLogs(ctx *Context) (io.ReaderAt, int64, []func()) {
	head := make([]byte, 4096)
	n, _ := ctx.File.ReadAt(head, 0)
	base, err := hivelog.ParseBase(head[:n])
	if err != nil {
		return ctx.File, ctx.Size, nil
	}
	var logs []hivelog.Log
	var closers []func()
	for _, p := range ctx.Segments {
		f, err := os.OpenFile(p, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		closers = append(closers, func() { f.Close() })
		if st, err := f.Stat(); err == nil {
			// The vault names a file by its SHA-256, which ties a log to its evidence item.
			logs = append(logs, hivelog.Log{Name: filepath.Base(p), R: f, Size: st.Size()})
		}
	}
	if !base.Dirty() {
		if len(logs) > 0 {
			res, err := hivelog.Recover(ctx.File, ctx.Size, logs)
			if err == nil && len(res.NotUsed) > 0 && hasOwnLog(res.NotUsed) {
				ctx.Note("the hive was fully written when it was copied, so its transaction logs hold nothing Windows would apply")
			}
		}
		return ctx.File, ctx.Size, closers
	}
	if len(logs) == 0 {
		ctx.Warn("the hive was not fully written when it was copied (its sequence numbers are %d and %d): the most recent changes are in its transaction logs (.LOG1, .LOG2), which are not in the case. Add them, and this hive is parsed again with them applied", base.Seq1, base.Seq2)
		return ctx.File, ctx.Size, closers
	}
	res, err := hivelog.Recover(ctx.File, ctx.Size, logs)
	if err != nil {
		ctx.Warn("the transaction logs could not be applied: %v", err)
		return ctx.File, ctx.Size, closers
	}
	if res.Hive == nil {
		ctx.Warn("the hive was not fully written when it was copied, and none of the transaction logs in the case can be applied to it, so its most recent changes are missing")
		for _, why := range res.NotUsed {
			if !strings.Contains(why, "another hive") {
				ctx.Note("transaction log %s", why)
			}
		}
		return ctx.File, ctx.Size, closers
	}
	var parts, logsUsed []string
	entries := 0
	for _, a := range res.Applied {
		logsUsed = append(logsUsed, a.Log)
		entries += a.Entries
		if a.Format == "new" {
			parts = append(parts, fmt.Sprintf("%d entries (sequence %d to %d) from %s", a.Entries, a.First, a.Last, a.Log))
		} else {
			parts = append(parts, fmt.Sprintf("%d pages from %s (old format)", a.Pages, a.Log))
		}
		if a.StoppedBecause != "" && a.StoppedBecause != "no further entry" {
			ctx.Note("in %s, recovery stopped where Windows would: %s", a.Log, a.StoppedBecause)
		}
	}
	ctx.Fact("registry.transaction_logs_applied", strings.Join(logsUsed, ", "), "SHA-256 of each transaction log applied to the hive before it was read")
	ctx.Note("the hive was not fully written when it was copied; its transaction logs were applied first, as Windows would on loading it: %s. %d pages of the hive were replaced. The key times and values on the timeline are those of the recovered hive", strings.Join(parts, "; "), res.Hive.Pages())
	if res.BaseFromLog {
		ctx.Note("the hive's own base block was damaged; the copy in its transaction log was used")
	}
	for _, why := range res.NotUsed {
		if !strings.Contains(why, "another hive") {
			ctx.Note("transaction log %s", why)
		}
	}
	return res.Hive, res.Hive.Size(), closers
}

func hasOwnLog(notUsed []string) bool {
	for _, w := range notUsed {
		if !strings.Contains(w, "another hive") {
			return true
		}
	}
	return false
}
