package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/ingest"
	"github.com/DanDreadless/atropos/internal/store"
	"github.com/DanDreadless/atropos/internal/vault"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type harness struct {
	t   *testing.T
	srv *httptest.Server
	s   *store.Store
	in  *ingest.Ingester
}

func start(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "case.db"), "tester")
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	in := &ingest.Ingester{S: s, V: v}
	srv := httptest.NewServer(Handler(s, in, testToken))
	t.Cleanup(func() {
		srv.Close()
		// Let any background parse finish before the database closes.
		for i := 0; i < 200 && in.Status().Busy; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		s.Close()
		filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error { os.Chmod(p, 0o700); return nil })
	})
	return &harness{t, srv, s, in}
}

func (h *harness) do(method, path string, body io.Reader, hdr map[string]string) (int, http.Header, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, body)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, v := range hdr {
		switch {
		case k == "Host":
			req.Host = v
		case v == "":
			req.Header.Del(k)
		default:
			req.Header.Set(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

func (h *harness) get(path string, into any) {
	h.t.Helper()
	code, _, body := h.do("GET", path, nil, nil)
	if code != 200 {
		h.t.Fatalf("GET %s: %d %s", path, code, body)
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			h.t.Fatalf("GET %s: %v in %s", path, err, body)
		}
	}
}

func (h *harness) post(path string, payload any, into any) int {
	h.t.Helper()
	b, _ := json.Marshal(payload)
	code, _, body := h.do("POST", path, bytes.NewReader(b), map[string]string{"Content-Type": "application/json"})
	if into != nil && code == 200 {
		if err := json.Unmarshal(body, into); err != nil {
			h.t.Fatalf("POST %s: %v in %s", path, err, body)
		}
	}
	return code
}

// upload submits files as one multipart request, as the page does, and waits
// for background parsing to finish.
func (h *harness) upload(files map[string]string, order ...string) {
	h.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, name := range order {
		hdr := textproto.MIMEHeader{}
		hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, name))
		hdr.Set("Content-Type", "application/octet-stream")
		pw, _ := mw.CreatePart(hdr)
		pw.Write([]byte(files[name]))
	}
	mw.Close()
	code, _, body := h.do("POST", "/api/upload", &buf, map[string]string{"Content-Type": mw.FormDataContentType()})
	if code != 200 {
		h.t.Fatalf("upload: %d %s", code, body)
	}
	h.wait()
}

func (h *harness) wait() {
	h.t.Helper()
	for i := 0; i < 500; i++ {
		var st ingest.Status
		h.get("/api/status", &st)
		if !st.Busy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("ingest did not finish")
}

var sampleFiles = map[string]string{
	"host1/logs/app.log": "2024-03-01T10:00:00Z service started\n2024-03-01T10:00:05Z powershell.exe launched\n2024-03-02T08:00:00Z service stopped\n",
	"host1/local.log":    "2024-07-15 12:00:00 local entry with no zone\n",
	"host1/notes.txt":    "free text mentioning mimikatz\n",
	"evil.log":           "2024-03-01T11:00:00Z <script>alert(1)</script> \"quoted\", comma\n",
}

func seeded(t *testing.T) *harness {
	h := start(t)
	h.upload(sampleFiles, "host1/logs/app.log", "host1/local.log", "host1/notes.txt", "evil.log")
	return h
}

type eventsResp struct {
	Events []struct {
		ID       int64    `json:"id"`
		TS       string   `json:"ts_utc"`
		TZSource string   `json:"tz_source"`
		Message  string   `json:"message"`
		Tags     []string `json:"tags"`
	} `json:"events"`
}

func TestPageIsServedWithAStrictPolicy(t *testing.T) {
	h := start(t)
	for path, want := range map[string]string{"/": "<title>Atropos</title>", "/app.js": "'use strict'", "/app.css": "--accent"} {
		code, hdr, body := h.do("GET", path, nil, nil)
		if code != 200 || !strings.Contains(string(body), want) {
			t.Errorf("GET %s: %d, missing %q", path, code, want)
		}
		csp := hdr.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Errorf("GET %s: policy %q", path, csp)
		}
		if hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s: no nosniff header", path)
		}
	}
	// The policy forbids inline script and style, so the page must not contain any.
	page, _ := uiFS.ReadFile("ui/index.html")
	for _, banned := range []string{"<style", "style=", "onclick=", "javascript:"} {
		if bytes.Contains(page, []byte(banned)) {
			t.Errorf("index.html contains %q, which the content security policy blocks", banned)
		}
	}
	if n := bytes.Count(page, []byte("<script")); n != 1 || !bytes.Contains(page, []byte(`<script src="app.js"></script>`)) {
		t.Errorf("index.html has %d script tags; want only the external app.js", n)
	}
	// Evidence is hostile input: the script must never build markup from it.
	js, _ := uiFS.ReadFile("ui/app.js")
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("} {
		if bytes.Contains(js, []byte(banned)) {
			t.Errorf("app.js uses %s", banned)
		}
	}
}

func TestCrossSiteAndForeignHostRequestsAreRefused(t *testing.T) {
	h := start(t)
	local := strings.TrimPrefix(h.srv.URL, "http://")
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"same origin", map[string]string{"Origin": h.srv.URL}, 200},
		{"no origin (command-line client)", nil, 200},
		{"localhost name", map[string]string{"Host": "localhost:8484"}, 200},
		{"other site", map[string]string{"Origin": "https://evil.example"}, 403},
		{"other port on this machine", map[string]string{"Origin": "http://127.0.0.1:1"}, 403},
		{"cross-site fetch metadata", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"dns rebinding", map[string]string{"Host": "evil.example:8484", "Origin": "http://evil.example:8484"}, 403},
		{"dns rebinding without origin", map[string]string{"Host": "evil.example"}, 403},
	}
	for _, c := range cases {
		for _, req := range []struct{ method, path string }{{"GET", "/api/status"}, {"POST", "/api/verify"}} {
			code, _, _ := h.do(req.method, req.path, nil, c.hdr)
			if code != c.want {
				t.Errorf("%s: %s %s = %d, want %d (server at %s)", c.name, req.method, req.path, code, c.want, local)
			}
		}
	}
}

func TestServeRefusesNonLoopbackAddresses(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8484", ":8484", "192.168.1.10:8484", "example.com:80", "nonsense"} {
		if err := Serve(context.Background(), addr, testToken, nil, nil, nil); err == nil {
			t.Errorf("Serve(%q) did not refuse", addr)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LOCALHOST", "127.0.0.9"} {
		if !isLoopback(host) {
			t.Errorf("%s not accepted as loopback", host)
		}
	}
}

func TestUploadSearchAndDetail(t *testing.T) {
	h := seeded(t)

	var ev struct {
		Evidence []store.Evidence `json:"evidence"`
	}
	h.get("/api/evidence", &ev)
	if len(ev.Evidence) != 4 {
		t.Fatalf("%d evidence items", len(ev.Evidence))
	}
	// A dropped folder keeps each file's place in it; the name is the last element.
	if e := ev.Evidence[0]; e.Name != "app.log" || e.Origin != "upload:host1/logs/app.log" || e.Status != "parsed" || e.EventCount != 3 {
		t.Errorf("first item: %+v", e)
	}
	for _, e := range ev.Evidence {
		if e.BatchID != 1 {
			t.Errorf("%s in batch %d: files uploaded together must share a batch", e.Name, e.BatchID)
		}
	}

	var all eventsResp
	h.get("/api/events", &all)
	if len(all.Events) != 5 {
		t.Fatalf("%d events", len(all.Events))
	}
	// Nanosecond times exceed what a JavaScript number holds, so they travel as strings.
	if all.Events[0].TS != "1709287200000000000" {
		t.Errorf("ts_utc = %q, want the exact nanosecond value as a string", all.Events[0].TS)
	}

	for q, want := range map[string]int{
		"q=powersh": 1, "q=service": 2, "q=tz:assumed": 1, "q=-service": 3, "q=evidence:1": 3,
		"from=1709287205000000000&to=1709290800000000000": 2, "q=nomatch": 0, "limit=2": 2,
	} {
		var r eventsResp
		h.get("/api/events?"+q, &r)
		if len(r.Events) != want {
			t.Errorf("%s: %d events, want %d", q, len(r.Events), want)
		}
	}
	// Paging by cursor visits every event once, in either order.
	for _, order := range []string{"asc", "desc"} {
		seen := map[int64]bool{}
		cursor := ""
		for {
			var r eventsResp
			h.get("/api/events?limit=2&order="+order+cursor, &r)
			if len(r.Events) == 0 {
				break
			}
			for _, e := range r.Events {
				if seen[e.ID] {
					t.Fatalf("%s: event %d returned twice", order, e.ID)
				}
				seen[e.ID] = true
			}
			last := r.Events[len(r.Events)-1]
			cursor = fmt.Sprintf("&after_ts=%s&after_id=%d", last.TS, last.ID)
		}
		if len(seen) != 5 {
			t.Errorf("%s: paging reached %d of 5 events", order, len(seen))
		}
	}

	var sum struct {
		Count int64  `json:"count"`
		Min   string `json:"min_ts"`
		Max   string `json:"max_ts"`
		Bars  []struct{ I, N int64 }
	}
	h.get("/api/summary?buckets=50", &sum)
	var total int64
	for _, b := range sum.Bars {
		total += b.N
	}
	if sum.Count != 5 || total != 5 || sum.Min != "1709287200000000000" || len(sum.Bars) != 2 || sum.Bars[1].I != 49 {
		t.Errorf("summary: %+v", sum)
	}

	var detail struct {
		Event struct {
			Fields    map[string]any `json:"fields"`
			RecordRef string         `json:"record_ref"`
			TSRaw     string         `json:"ts_raw"`
		} `json:"event"`
		Evidence    store.Evidence     `json:"evidence"`
		Annotations []store.Annotation `json:"annotations"`
	}
	h.get(fmt.Sprintf("/api/event/%d", all.Events[0].ID), &detail)
	if detail.Event.RecordRef != "line 1" || detail.Event.TSRaw == "" || detail.Evidence.Name != "app.log" || len(detail.Evidence.SHA256) != 64 || detail.Annotations == nil {
		t.Errorf("detail: %+v", detail)
	}
	if code, _, _ := h.do("GET", "/api/event/99999", nil, nil); code != 404 {
		t.Errorf("unknown event: %d", code)
	}

	var hits struct {
		Hits []store.TextHit `json:"hits"`
	}
	h.get("/api/textsearch?q=mimikatz", &hits)
	if len(hits.Hits) != 1 || hits.Hits[0].Name != "notes.txt" {
		t.Errorf("text search: %+v", hits)
	}

	var info struct {
		Examiner string                      `json:"examiner"`
		Facets   map[string]map[string]int64 `json:"facets"`
	}
	h.get("/api/case", &info)
	if info.Examiner != "tester" || info.Facets["tz_source"]["assumed"] != 1 || info.Facets["source"]["log"] != 5 {
		t.Errorf("case: %+v", info)
	}
}

func TestAnnotateAndRetract(t *testing.T) {
	h := seeded(t)
	var all eventsResp
	h.get("/api/events", &all)
	id := all.Events[1].ID

	var made struct {
		ID int64 `json:"id"`
	}
	if code := h.post("/api/annotate", map[string]any{"event_id": id, "kind": "tag", "body": "suspicious"}, &made); code != 200 || made.ID == 0 {
		t.Fatalf("tag: %d", code)
	}
	if code := h.post("/api/annotate", map[string]any{"event_id": id, "kind": "comment", "body": "launched by the service account"}, nil); code != 200 {
		t.Fatalf("comment: %d", code)
	}
	for name, bad := range map[string]map[string]any{
		"unknown event":         {"event_id": 99999, "kind": "tag", "body": "x"},
		"unknown kind":          {"event_id": id, "kind": "delete", "body": "x"},
		"retraction of nothing": {"event_id": id, "kind": "retract"},
	} {
		if code := h.post("/api/annotate", bad, nil); code == 200 {
			t.Errorf("%s was accepted", name)
		}
	}
	var r eventsResp
	h.get("/api/events?q=tag:suspicious", &r)
	if len(r.Events) != 1 || r.Events[0].ID != id || len(r.Events[0].Tags) != 1 {
		t.Fatalf("tag search: %+v", r)
	}
	if code := h.post("/api/annotate", map[string]any{"event_id": id, "kind": "retract", "refers_to": made.ID}, nil); code != 200 {
		t.Fatalf("retract: %d", code)
	}
	h.get("/api/events?q=tag:suspicious", &r)
	if len(r.Events) != 0 {
		t.Error("withdrawn tag still matches")
	}
	var detail struct {
		Annotations []store.Annotation `json:"annotations"`
	}
	h.get(fmt.Sprintf("/api/event/%d", id), &detail)
	if len(detail.Annotations) != 3 || !detail.Annotations[0].Retracted || detail.Annotations[1].Retracted {
		t.Errorf("annotations after withdrawal: %+v", detail.Annotations)
	}
}

func TestExports(t *testing.T) {
	h := seeded(t)
	code, hdr, body := h.do("GET", "/api/export?format=csv", nil, nil)
	if code != 200 || !strings.Contains(hdr.Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv: %d %v", code, hdr)
	}
	recs, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || len(recs) != 6 {
		t.Fatalf("csv: %d records, %v", len(recs), err)
	}
	if recs[0][0] != "datetime_utc" || recs[0][1] != "macb" || recs[0][3] != "category" || recs[1][0] != "2024-03-01T10:00:00.000000Z" || recs[1][1] != "...." || recs[1][3] != "log" {
		t.Errorf("csv header/first row: %v / %v", recs[0], recs[1])
	}
	// Hostile text survives the round trip exactly: quoting is the encoder's job.
	found := false
	for _, r := range recs {
		if strings.Contains(r[8], `<script>alert(1)</script> "quoted", comma`) {
			found = true
		}
	}
	if !found {
		t.Error("csv lost or altered a message containing quotes and commas")
	}

	for format, key := range map[string]string{"jsonl": "datetime_utc", "timesketch": "datetime"} {
		_, _, body := h.do("GET", "/api/export?format="+format+"&q=service", nil, nil)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if len(lines) != 2 {
			t.Errorf("%s: %d lines, want 2", format, len(lines))
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &m); err != nil || m[key] != "2024-03-01T10:00:00.000000Z" || m["message"] == nil || m["timestamp_desc"] == nil {
			t.Errorf("%s: %v %v", format, m, err)
		}
	}
	if code, _, _ := h.do("GET", "/api/export?format=xml", nil, nil); code != 400 {
		t.Errorf("unknown format: %d", code)
	}

	var audit struct {
		Audit []store.AuditRow `json:"audit"`
	}
	h.get("/api/audit", &audit)
	exports := 0
	for _, a := range audit.Audit {
		if a.Action == "export" {
			exports++
		}
	}
	if exports != 3 {
		t.Errorf("%d exports audited, want 3", exports)
	}
}

func TestVerifyAndReparseOverHTTP(t *testing.T) {
	h := seeded(t)
	var rep ingest.Report
	if code := h.post("/api/verify", nil, &rep); code != 200 || !rep.OK || rep.EvidenceChecked != 4 || len(rep.AuditHead) != 64 {
		t.Fatalf("verify: %d %+v", code, rep)
	}
	if rep.EvidenceBad == nil || rep.RunsBad == nil || rep.RunsUnaudited == nil || rep.RunsMissing == nil {
		t.Error("empty lists must be [] in JSON, not null: the page reads their length")
	}
	before := rep.RunsChecked

	if code := h.post("/api/evidence/1/reparse", nil, nil); code != 200 {
		t.Fatalf("reparse: %d", code)
	}
	h.wait()
	if code := h.post("/api/evidence/999/reparse", nil, nil); code != 404 {
		t.Errorf("reparse of unknown evidence: %d", code)
	}
	if code := h.post("/api/verify", nil, &rep); code != 200 || !rep.OK || rep.RunsChecked != before+1 {
		t.Errorf("verify after re-parse: ok=%v runs=%d (was %d)", rep.OK, rep.RunsChecked, before)
	}
	var all eventsResp
	h.get("/api/events", &all)
	if len(all.Events) != 5 {
		t.Errorf("timeline has %d events after an identical re-parse, want 5", len(all.Events))
	}
}

// A second upload is a second submission, and identical content is recorded
// as a duplicate rather than parsed twice.
func TestSecondUploadIsANewBatch(t *testing.T) {
	h := seeded(t)
	h.upload(map[string]string{"again.log": sampleFiles["host1/logs/app.log"], "new.log": "2025-01-01T00:00:00Z new\n"}, "again.log", "new.log")
	var ev struct {
		Evidence []store.Evidence `json:"evidence"`
	}
	h.get("/api/evidence", &ev)
	if len(ev.Evidence) != 6 {
		t.Fatalf("%d items", len(ev.Evidence))
	}
	if e := ev.Evidence[4]; e.BatchID != 2 || e.Status != "duplicate" || e.DuplicateOf == nil || *e.DuplicateOf != 1 {
		t.Errorf("re-uploaded file: %+v", e)
	}
	var all eventsResp
	h.get("/api/events", &all)
	if len(all.Events) != 6 {
		t.Errorf("%d events, want 6", len(all.Events))
	}
}
