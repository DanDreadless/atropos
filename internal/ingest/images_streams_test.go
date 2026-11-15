package ingest

import (
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/imagefs"
)

// fakeFS is a file system of a few files, some with alternate streams.
type fakeFS struct {
	dirs  map[string][]imagefs.Entry
	files map[string]string
}

func (f *fakeFS) Describe() string { return "test volume" }
func (f *fakeFS) Close()           {}
func (f *fakeFS) List(p string) ([]imagefs.Entry, error) {
	if l, ok := f.dirs[p]; ok {
		return l, nil
	}
	return nil, errors.New("not a directory")
}
func (f *fakeFS) Open(p string) (io.Reader, int64, error) {
	if c, ok := f.files[p]; ok {
		return strings.NewReader(c), int64(len(c)), nil
	}
	return nil, 0, errors.New("not found in this volume")
}

// A file copied out of an image brings its mark of the web with it, whether
// it was chosen on its own or as part of a folder; other streams are left
// until asked for by name, and a file without a mark raises no warning.
func TestExtractionTakesTheZoneMark(t *testing.T) {
	fs := &fakeFS{
		dirs: map[string][]imagefs.Entry{
			"/Users/a/Downloads": {
				{Name: "tool.exe", Path: "/Users/a/Downloads/tool.exe"},
				{Name: "tool.exe:Zone.Identifier", Path: "/Users/a/Downloads/tool.exe:Zone.Identifier"},
				{Name: "tool.exe:other", Path: "/Users/a/Downloads/tool.exe:other"},
				{Name: "plain.txt", Path: "/Users/a/Downloads/plain.txt"},
			},
		},
		files: map[string]string{
			"/Users/a/Downloads/tool.exe":                 "MZ",
			"/Users/a/Downloads/tool.exe:Zone.Identifier": "[ZoneTransfer]\r\nZoneId=3\r\n",
			"/Users/a/Downloads/tool.exe:other":           "something else",
			"/Users/a/Downloads/plain.txt":                "hello",
		},
	}
	extract := func(items ...string) (got, warns []string) {
		s := quietSink()
		s.warn = func(w string) { warns = append(warns, w) }
		s.file = func(tmp, inner string) error {
			got = append(got, inner)
			return os.Remove(tmp)
		}
		x := &extractor{fs: fs, j: job{OutDir: t.TempDir(), MaxFiles: 100, MaxBytes: 1 << 20}, s: s}
		for _, it := range items {
			x.add(it, 0)
		}
		sort.Strings(got)
		return got, warns
	}
	got, warns := extract("/Users/a/Downloads")
	if strings.Join(got, " ") != "/Users/a/Downloads/plain.txt /Users/a/Downloads/tool.exe /Users/a/Downloads/tool.exe:Zone.Identifier" || len(warns) != 0 {
		t.Errorf("folder: %q warns %q", got, warns)
	}
	got, warns = extract("/Users/a/Downloads/tool.exe", "/Users/a/Downloads/plain.txt")
	if strings.Join(got, " ") != "/Users/a/Downloads/plain.txt /Users/a/Downloads/tool.exe /Users/a/Downloads/tool.exe:Zone.Identifier" || len(warns) != 0 {
		t.Errorf("single files: %q warns %q", got, warns)
	}
	// A stream chosen by name is copied out, and nothing is added to it.
	got, warns = extract("/Users/a/Downloads/tool.exe:other")
	if strings.Join(got, " ") != "/Users/a/Downloads/tool.exe:other" || len(warns) != 0 {
		t.Errorf("stream by name: %q warns %q", got, warns)
	}
}
