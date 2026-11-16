package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/parsers"
	"github.com/DanDreadless/atropos/internal/store"
)

// An item is stale when this build would read it differently from the run shown.
func TestStale(t *testing.T) {
	text := parsers.For("text")
	one := int64(1)
	for _, c := range []struct {
		name string
		e    store.Evidence
		want bool
	}{
		{"read by this version", store.Evidence{Kind: "text", Parser: text.Name(), ParserVersion: text.Version()}, false},
		{"read by an earlier version", store.Evidence{Kind: "text", Parser: text.Name(), ParserVersion: "1 (old)"}, true},
		{"crashed", store.Evidence{Kind: "text", Parser: text.Name(), ParserVersion: text.Version(), Notes: "stopped early: parser panic: index out of range"}, true},
		{"nothing found by an unknown version", store.Evidence{Kind: "text", Parser: "generic", ParserVersion: parsers.Generic().Version(), Notes: `dedicated parser "text-log" produced no events`}, true},
		{"nothing found by this version", store.Evidence{Kind: "text", Parser: "generic", ParserVersion: parsers.Generic().Version(), Notes: `dedicated parser "text-log" (version ` + text.Version() + `) produced no events`}, false},
		{"no dedicated parser, same reader", store.Evidence{Kind: "pdf", Parser: "generic", ParserVersion: parsers.Generic().Version()}, false},
		{"no dedicated parser, older reader", store.Evidence{Kind: "pdf", Parser: "generic", ParserVersion: "0"}, true},
		{"duplicate", store.Evidence{Kind: "text", Parser: text.Name(), ParserVersion: "1 (old)", DuplicateOf: &one}, false},
		{"not parsed yet", store.Evidence{Kind: "text"}, false},
		{"archive", store.Evidence{Kind: "zip-archive", Parser: "container", ParserVersion: "0"}, false},
		// A disk image read before this build had a parser for disk images.
		{"kind that has gained a parser", store.Evidence{Kind: "disk-image", Parser: "generic", ParserVersion: parsers.Generic().Version(), Notes: "this is an image: open it on the Images tab to browse its contents"}, true},
	} {
		if got := Stale(&c.e); (got != "") != c.want {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

// Whatever this build has just parsed, it does not then call stale: the
// "bring up to date" step must come to rest.
func TestFreshlyParsedItemsAreNotStale(t *testing.T) {
	c := newCase(t)
	dir := t.TempDir()
	var paths []string
	for name, body := range map[string]string{
		"app.log":   "2024-03-01T10:00:00Z started\n",
		"notes.txt": "nothing with a time in it\n",
		"blob.bin":  "\x00\x01\x02\x03 binary \xff\xfe",
		"empty.db":  "SQLite format 3\x00" + strings.Repeat("\x00", 100),
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		paths = append(paths, p)
	}
	c.ingest(t, paths...)
	list := c.evidence(t)
	if len(list) < 4 {
		t.Fatalf("%d items", len(list))
	}
	for i := range list {
		if why := Stale(&list[i]); why != "" {
			t.Errorf("%s (%s, parser %s, status %s) is stale straight after parsing: %s; notes %s", list[i].Name, list[i].Kind, list[i].Parser, list[i].Status, why, list[i].Notes)
		}
	}
}
