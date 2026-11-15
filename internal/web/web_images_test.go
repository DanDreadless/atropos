package web

import (
	"strings"
	"testing"

	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
	"github.com/DanDreadless/atropos/internal/store"
)

type browseResp struct {
	Describe string          `json:"describe"`
	Path     string          `json:"path"`
	Entries  []imagefs.Entry `json:"entries"`
}

// A disc image is added like any evidence, browsed over HTTP, and the files
// chosen from it end up on the timeline as its children.
func TestBrowseAndExtractOverHTTP(t *testing.T) {
	h := start(t)
	iso := imagetest.ISO(
		map[string][]byte{"APP.LOG": []byte("2024-03-01T10:00:00Z from the disc\n"), "NOTES.TXT": []byte("nothing timed\n")},
		map[string][]byte{"DEEP.LOG": []byte("2024-04-01T00:00:00Z from a folder\n")},
		[]string{"APP.LOG", "NOTES.TXT", "DEEP.LOG"})
	h.upload(map[string]string{"disc.iso": string(iso), "plain.log": "2024-01-01T00:00:00Z not an image\n"}, "disc.iso", "plain.log")

	var ev struct {
		Evidence []store.Evidence `json:"evidence"`
	}
	h.get("/api/evidence", &ev)
	if len(ev.Evidence) != 2 || ev.Evidence[0].Kind != "iso-image" {
		t.Fatalf("evidence: %+v", ev.Evidence)
	}

	var b browseResp
	h.get("/api/evidence/1/browse", &b)
	if !strings.Contains(b.Describe, "ISO 9660") || b.Path != "/" || len(b.Entries) != 3 || !b.Entries[0].IsDir || b.Entries[0].Name != "SUB" {
		t.Fatalf("root: %+v", b)
	}
	h.get("/api/evidence/1/browse?path=/SUB", &b)
	if len(b.Entries) != 1 || b.Entries[0].Path != "/SUB/DEEP.LOG" || b.Entries[0].Size != 35 {
		t.Errorf("sub: %+v", b.Entries)
	}
	for path, want := range map[string]int{
		"/api/evidence/1/browse?path=/NOPE":      400,
		"/api/evidence/1/browse?path=/SUB/../..": 400,
		"/api/evidence/2/browse":                 400, // not an image
		"/api/evidence/99/browse":                404,
	} {
		if code, _, _ := h.do("GET", path, nil, nil); code != want {
			t.Errorf("GET %s = %d, want %d", path, code, want)
		}
	}
	for name, c := range map[string]struct {
		url  string
		body map[string]any
		want int
	}{
		"nothing chosen": {"/api/evidence/1/extract", map[string]any{}, 400},
		"not an image":   {"/api/evidence/2/extract", map[string]any{"paths": []string{"/x"}}, 400},
		"no such item":   {"/api/evidence/99/extract", map[string]any{"paths": []string{"/x"}}, 404},
	} {
		if code := h.post(c.url, c.body, nil); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}

	if code := h.post("/api/evidence/1/extract", map[string]any{"paths": []string{"/SUB", "/APP.LOG"}}, nil); code != 200 {
		t.Fatalf("extract: %d", code)
	}
	h.wait()
	h.get("/api/evidence", &ev)
	if len(ev.Evidence) != 4 {
		t.Fatalf("%d evidence items after extraction, want 4", len(ev.Evidence))
	}
	for _, e := range ev.Evidence[2:] {
		if e.ParentID == nil || *e.ParentID != 1 || e.Status != "parsed" || e.EventCount != 1 || !strings.Contains(e.Origin, "disc.iso!/") {
			t.Errorf("extracted item: %+v", e)
		}
	}
	var all eventsResp
	h.get("/api/events?q=disc", &all)
	if len(all.Events) != 1 {
		t.Errorf("%d events from the disc", len(all.Events))
	}
	var st struct {
		Last string `json:"last"`
	}
	h.get("/api/status", &st)
	if !strings.Contains(st.Last, "2 file(s) copied out of disc.iso") {
		t.Errorf("status does not report the extraction: %q", st.Last)
	}
	var rep struct {
		OK bool `json:"ok"`
	}
	if h.post("/api/verify", nil, &rep); !rep.OK {
		t.Error("case does not verify after extraction")
	}
}
