package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/DanDreadless/atropos/internal/store"
)

// The Sleuth Kit's bodyfile (version 3), which mactime and other timeline
// tools read: one line per file,
//
//	MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
//
// with times in whole seconds since 1970, and 0 where a time is not known.
//
// Atropos keeps one event per distinct moment, with MACB letters saying
// which of a file's times that moment is. The export puts them back
// together: events from one record of one evidence item become one line.
// Only events that carry a MACB letter are written. Anything else (a log
// record, a program run, a visit) is not a file time, and a bodyfile has no
// way to say so: writing it would claim that it is.

// ExportResult says what an export wrote.
type ExportResult struct {
	Events  int64 `json:"events"`             // events written
	Lines   int64 `json:"lines,omitempty"`    // bodyfile lines they made
	LeftOut int64 `json:"left_out,omitempty"` // events with no file time, not written to a bodyfile
}

type bodyLine struct {
	name, inode, mode string
	size              int64
	times             [4]int64 // M, A, C, B in seconds
	set               [4]bool
}

func bodyName(s string) string {
	// The format has no escaping: a separator or line break inside a name
	// would shift every field after it.
	s = strings.NewReplacer("|", "%7C", "\n", " ", "\r", " ").Replace(s)
	if s == "" {
		s = "(no name)"
	}
	return s
}

func exportBodyfile(s *store.Store, q store.Query, w io.Writer) (ExportResult, error) {
	var res ExportResult
	open := map[string]*bodyLine{}
	var order []*bodyLine
	err := s.Stream(q, func(e store.EventRow) error {
		if len(e.MACB) != 4 || e.MACB == "...." {
			res.LeftOut++
			return nil
		}
		res.Events++
		attr := ""
		switch {
		case strings.HasPrefix(e.TSType, "$SI"):
			attr = "$SI"
		case strings.HasPrefix(e.TSType, "$FN"):
			attr = "$FN"
		}
		key := fmt.Sprintf("%d\x00%s\x00%s\x00%s", e.EvidenceID, e.RecordRef, attr, e.Path)
		secs := e.TSUTC / 1e9
		if secs < 0 {
			secs = 0
		}
		l := open[key]
		// A second, different time for a slot already filled is another line.
		if l != nil {
			for i := 0; i < 4; i++ {
				if e.MACB[i] != '.' && l.set[i] && l.times[i] != secs {
					l = nil
					break
				}
			}
		}
		if l == nil {
			l = &bodyLine{name: bodyName(e.Path), inode: "0", mode: "0"}
			switch {
			case attr == "$FN":
				l.name += " ($FILE_NAME)"
			case attr == "" && e.Source != "":
				l.name += " (" + e.Source + ": " + e.TSType + ")"
			}
			if ref, ok := strings.CutPrefix(e.RecordRef, "MFT entry "); ok {
				l.inode = ref
				var f struct {
					Size  int64 `json:"size"`
					IsDir bool  `json:"is_dir"`
				}
				if json.Unmarshal(e.Fields, &f) == nil {
					l.size = f.Size
					l.mode = "r/rrwxrwxrwx"
					if f.IsDir {
						l.mode = "d/drwxrwxrwx"
					}
				}
			}
			open[key] = l
			order = append(order, l)
		}
		for i := 0; i < 4; i++ {
			if e.MACB[i] != '.' {
				l.times[i], l.set[i] = secs, true
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	for _, l := range order {
		// Field order in the file is atime, mtime, ctime, crtime.
		if _, err := fmt.Fprintf(bw, "0|%s|%s|%s|0|0|%d|%d|%d|%d|%d\n", l.name, l.inode, l.mode, l.size,
			l.times[1], l.times[0], l.times[2], l.times[3]); err != nil {
			return res, err
		}
		res.Lines++
	}
	return res, bw.Flush()
}
