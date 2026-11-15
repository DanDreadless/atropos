package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

// Nothing is served without the session token: not the page, not the API.
func TestEveryRequestNeedsTheToken(t *testing.T) {
	h := seeded(t)
	for _, c := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"no credentials", map[string]string{"Authorization": ""}, 401},
		{"wrong bearer", map[string]string{"Authorization": "Bearer " + strings.Repeat("0", 64)}, 401},
		{"right token, wrong scheme", map[string]string{"Authorization": "Basic " + testToken}, 401},
		{"token prefix only", map[string]string{"Authorization": "Bearer " + testToken[:63]}, 401},
		{"bearer", nil, 200},
	} {
		for _, req := range []struct{ method, path string }{
			{"GET", "/"}, {"GET", "/app.js"}, {"GET", "/api/events"}, {"GET", "/api/evidence"}, {"GET", "/api/audit"},
			{"GET", "/api/export?format=csv"}, {"GET", "/api/report?format=json"}, {"GET", "/api/groups"}, {"POST", "/api/verify"},
		} {
			code, _, body := h.do(req.method, req.path, nil, c.hdr)
			if code != c.want {
				t.Errorf("%s: %s %s = %d, want %d", c.name, req.method, req.path, code, c.want)
			}
			if c.want == 401 && (bytes.Contains(body, []byte("service started")) || bytes.Contains(body, []byte("sha256"))) {
				t.Errorf("%s: %s %s leaked case data in a refusal", c.name, req.method, req.path)
			}
		}
	}
}

// The printed link signs a browser in: it sets a cookie that scripts cannot
// read and other sites cannot send, then redirects so the token does not
// stay in the address bar or the history.
func TestTokenLinkSignsABrowserIn(t *testing.T) {
	h := seeded(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string, cookie *http.Cookie) *http.Response {
		req, _ := http.NewRequest("GET", h.srv.URL+path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := get("/?token=wrong", nil); res.StatusCode != 401 || len(res.Cookies()) != 0 {
		t.Errorf("wrong token: %d, cookies %v", res.StatusCode, res.Cookies())
	}
	res := get("/?token="+testToken, nil)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("token link: %d -> %q", res.StatusCode, res.Header.Get("Location"))
	}
	if len(res.Cookies()) != 1 {
		t.Fatalf("cookies: %v", res.Cookies())
	}
	c := res.Cookies()[0]
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(h.srv.URL, "http://"))
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Name != "atropos_session_"+port || c.Path != "/" {
		t.Errorf("cookie: %+v", c)
	}
	if res := get("/api/events", c); res.StatusCode != 200 {
		t.Errorf("with the cookie: %d", res.StatusCode)
	}
	// A cookie for another port's session is not accepted here.
	if res := get("/api/events", &http.Cookie{Name: "atropos_session_1", Value: testToken}); res.StatusCode != 401 {
		t.Errorf("cookie under another port's name: %d", res.StatusCode)
	}
	// The token is only taken from the address on the front page, so it
	// cannot be used to make a cross-site API request carry credentials.
	if res := get("/api/events?token="+testToken, nil); res.StatusCode != 401 {
		t.Errorf("token in an API address: %d", res.StatusCode)
	}
}

func TestResponsesAreNotCacheable(t *testing.T) {
	h := seeded(t)
	for _, p := range []string{"/", "/api/events", "/api/export?format=csv"} {
		_, hdr, _ := h.do("GET", p, nil, nil)
		if hdr.Get("Cache-Control") != "no-store" || hdr.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: Cache-Control %q, Referrer-Policy %q", p, hdr.Get("Cache-Control"), hdr.Get("Referrer-Policy"))
		}
	}
}

func TestServeStartsAndStopsCleanly(t *testing.T) {
	h := start(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, addr, testToken, h.s, h.in, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve ended early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve never became ready")
	}
	res, err := http.Get("http://" + addr + "/api/status")
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("live server without token: %v %v", res, err)
	}
	res.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v after cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

type groupsResp struct {
	Groups []store.Group `json:"groups"`
}

func TestGroupsOverHTTP(t *testing.T) {
	h := seeded(t)
	var all eventsResp
	h.get("/api/events", &all)

	var g store.Group
	if code := h.post("/api/groups", map[string]any{"name": "Malware", "note": "initial access"}, &g); code != 200 || g.ID == 0 {
		t.Fatalf("create: %d %+v", code, g)
	}
	if code := h.post("/api/groups", map[string]any{"name": "malware"}, nil); code != 400 {
		t.Errorf("duplicate name: %d", code)
	}
	var changed struct {
		Changed, Requested int64
	}
	url := fmt.Sprintf("/api/groups/%d/events", g.ID)
	if code := h.post(url, map[string]any{"action": "add", "event_ids": []int64{all.Events[0].ID, all.Events[1].ID}}, &changed); code != 200 || changed.Changed != 2 {
		t.Fatalf("add by id: %d %+v", code, changed)
	}
	// Everything a search shows, in one step: here, all of one evidence item.
	if code := h.post(url, map[string]any{"action": "add", "query": map[string]string{"q": "evidence:1"}}, &changed); code != 200 || changed.Changed != 1 || changed.Requested != 3 {
		t.Fatalf("add by search: %d %+v", code, changed)
	}
	for name, bad := range map[string]map[string]any{
		"no events":      {"action": "add"},
		"unknown action": {"action": "delete", "event_ids": []int64{1}},
	} {
		if code := h.post(url, bad, nil); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code := h.post("/api/groups/999/events", map[string]any{"action": "add", "event_ids": []int64{1}}, nil); code != 404 {
		t.Errorf("unknown group: %d", code)
	}

	var gr groupsResp
	h.get("/api/groups", &gr)
	if len(gr.Groups) != 1 || gr.Groups[0].Count != 3 || gr.Groups[0].Note != "initial access" {
		t.Fatalf("groups: %+v", gr)
	}
	// The group is a timeline of its own: events, summary and export all follow it.
	var in eventsResp
	h.get("/api/events?group=Malware", &in)
	if len(in.Events) != 3 {
		t.Errorf("group timeline has %d events", len(in.Events))
	}
	var sum struct {
		Count int64 `json:"count"`
	}
	h.get("/api/summary?group=Malware&q=powersh", &sum)
	if sum.Count != 1 {
		t.Errorf("search within the group: %d", sum.Count)
	}
	_, _, body := h.do("GET", "/api/export?format=csv&group=Malware", nil, nil)
	if recs, _ := csv.NewReader(bytes.NewReader(body)).ReadAll(); len(recs) != 4 {
		t.Errorf("export of the group: %d rows", len(recs))
	}

	if code := h.post(url, map[string]any{"action": "remove", "event_ids": []int64{all.Events[0].ID}}, &changed); code != 200 || changed.Changed != 1 {
		t.Errorf("remove: %d %+v", code, changed)
	}
	h.get("/api/events?group=Malware", &in)
	if len(in.Events) != 2 {
		t.Errorf("after removal the group has %d events", len(in.Events))
	}
	if code := h.post(fmt.Sprintf("/api/groups/%d/archive", g.ID), nil, nil); code != 200 {
		t.Errorf("archive: %d", code)
	}
	h.get("/api/groups", &gr)
	if len(gr.Groups) != 0 {
		t.Errorf("archived group still listed: %+v", gr)
	}
	var rep struct {
		OK bool `json:"ok"`
	}
	if h.post("/api/verify", nil, &rep); !rep.OK {
		t.Error("case does not verify after group changes")
	}
}

// Evidence can contain text a spreadsheet would run as a formula.
func TestCSVExportDefusesFormulas(t *testing.T) {
	h := start(t)
	h.upload(map[string]string{"x.jsonl": `{"time":"2024-01-01T00:00:00Z","msg":"=HYPERLINK(\"http://evil.example\",\"click\")","user":"+cmd|' /C calc'!A0","host":"@SUM(1+1)"}` + "\n"}, "x.jsonl")
	_, _, body := h.do("GET", "/api/export?format=csv", nil, nil)
	recs, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || len(recs) != 2 {
		t.Fatalf("csv: %v %d", err, len(recs))
	}
	for i, cell := range recs[1] {
		if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
			t.Errorf("column %s starts a formula: %q", recs[0][i], cell)
		}
	}
	if recs[1][8] != `'=HYPERLINK("http://evil.example","click")` {
		t.Errorf("message cell: %q", recs[1][8])
	}
	// The JSON export is for programs, and carries the value untouched.
	_, _, body = h.do("GET", "/api/export?format=jsonl", nil, nil)
	var m map[string]any
	json.Unmarshal(bytes.TrimSpace(body), &m)
	if m["message"] != `=HYPERLINK("http://evil.example","click")` {
		t.Errorf("jsonl message: %v", m["message"])
	}
}

func TestReport(t *testing.T) {
	h := seeded(t)
	var all eventsResp
	h.get("/api/events", &all)
	var g store.Group
	h.post("/api/groups", map[string]any{"name": "Key events <b>", "note": "the story"}, &g)
	h.post(fmt.Sprintf("/api/groups/%d/events", g.ID), map[string]any{"action": "add", "event_ids": []int64{all.Events[0].ID, all.Events[2].ID}}, nil)
	h.post("/api/annotate", map[string]any{"event_id": all.Events[1].ID, "kind": "comment", "body": "examiner comment here"}, nil)

	code, hdr, body := h.do("GET", "/api/report?format=json", nil, nil)
	if code != 200 || !strings.Contains(hdr.Get("Content-Disposition"), "attachment") {
		t.Fatalf("json report: %d", code)
	}
	var r struct {
		GeneratedBy string `json:"generated_by"`
		EventCount  int64  `json:"event_count"`
		Integrity   struct {
			OK        bool   `json:"ok"`
			AuditHead string `json:"audit_head"`
		} `json:"integrity"`
		Evidence []store.Evidence `json:"evidence"`
		Runs     []store.RunRow   `json:"runs"`
		Groups   []struct {
			Name   string           `json:"name"`
			Events []store.EventRow `json:"events"`
		} `json:"groups"`
		Notes      []store.NoteRow             `json:"notes"`
		Audit      []store.AuditRow            `json:"audit"`
		AuditTotal int64                       `json:"audit_total"`
		Facets     map[string]map[string]int64 `json:"facets"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	if r.GeneratedBy != "tester" || r.EventCount != 5 || !r.Integrity.OK || len(r.Integrity.AuditHead) != 64 {
		t.Errorf("header: %+v", r)
	}
	if len(r.Evidence) != 4 || len(r.Evidence[0].SHA256) != 64 || len(r.Runs) < 4 || r.Runs[0].ParserVersion == "" || len(r.Runs[0].EventDigest) != 64 {
		t.Errorf("evidence %d, runs %d", len(r.Evidence), len(r.Runs))
	}
	if len(r.Groups) != 1 || len(r.Groups[0].Events) != 2 || r.Groups[0].Events[0].TSUTC > r.Groups[0].Events[1].TSUTC {
		t.Errorf("groups: %+v", r.Groups)
	}
	if len(r.Notes) != 3 || int64(len(r.Audit)) != r.AuditTotal || r.Audit[0].ID != 1 || r.Facets["tz_source"]["assumed"] != 1 {
		t.Errorf("notes %d, audit %d of %d", len(r.Notes), len(r.Audit), r.AuditTotal)
	}

	code, hdr, body = h.do("GET", "/api/report?format=html", nil, nil)
	html := string(body)
	if code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
		t.Fatalf("html report: %d %q", code, hdr.Get("Content-Type"))
	}
	for _, want := range []string{"Everything verified", r.Evidence[0].SHA256, "have a time zone that was <b>assumed</b>", "the story",
		"examiner comment here", "evidence.intake", r.Integrity.AuditHead[:16], "powershell.exe launched"} {
		if !strings.Contains(html, want) {
			t.Errorf("html report lacks %q", want)
		}
	}
	// Evidence and examiner text are data in the report, never markup.
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "Key events <b>") {
		t.Error("html report contains unescaped text from the case")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") || !strings.Contains(html, "Key events &lt;b&gt;") {
		t.Error("escaped text not found where expected")
	}
	// It is one self-contained file: nothing is fetched when it is opened.
	for _, banned := range []string{"<script", "src=", "href=", "url(", "@import"} {
		if strings.Contains(html, banned) {
			t.Errorf("html report contains %q", banned)
		}
	}
	if code, _, _ := h.do("GET", "/api/report?format=pdf", nil, nil); code != 400 {
		t.Errorf("unknown format: %d", code)
	}
	var audit struct {
		Audit []store.AuditRow `json:"audit"`
	}
	h.get("/api/audit", &audit)
	n := 0
	for _, a := range audit.Audit {
		if a.Action == "report.generate" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d reports audited, want 2", n)
	}
}

// An upload that breaks off part-way still gets the files that did arrive
// parsed: evidence is never left received but unexamined.
func TestBrokenUploadStillProcessesWhatArrived(t *testing.T) {
	h := start(t)
	boundary := "xxBOUNDARYxx"
	body := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"first.log\"\r\n\r\n" +
		"2024-01-01T00:00:00Z arrived whole\n\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"second.log\"\r\n\r\n" +
		"2024-01-02T00:00:00Z cut off he" // no closing boundary: the connection dropped
	code, _, resp := h.do("POST", "/api/upload", io.NopCloser(strings.NewReader(body)), map[string]string{"Content-Type": "multipart/form-data; boundary=" + boundary})
	if code == 200 {
		t.Fatalf("a truncated upload was accepted: %s", resp)
	}
	if !strings.Contains(string(resp), "received before this are being processed") {
		t.Errorf("refusal does not say what happened to the files that arrived: %s", resp)
	}
	h.wait()
	var ev struct {
		Evidence []store.Evidence `json:"evidence"`
	}
	h.get("/api/evidence", &ev)
	if len(ev.Evidence) != 1 || ev.Evidence[0].Name != "first.log" || ev.Evidence[0].Status != "parsed" {
		t.Errorf("after a broken upload: %+v", ev.Evidence)
	}
}

// The timestamp comparison is served as JSON, says what it had to compare,
// and leaves an audit entry.
func TestAnalysisOverHTTP(t *testing.T) {
	h := seeded(t)
	var rep struct {
		Findings []map[string]any `json:"findings"`
		Compared map[string]int64 `json:"compared"`
		Notes    []string         `json:"notes"`
	}
	h.get("/api/analysis/timestamps", &rep)
	if rep.Findings == nil || len(rep.Findings) != 0 {
		t.Errorf("findings should be an empty list for a case with no file table: %v", rep.Findings)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "No file table") {
		t.Errorf("notes do not say what was missing: %v", rep.Notes)
	}
	rows, err := h.s.ListAudit(5)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range rows {
		if a.Action == "analysis.timestamps" {
			found = true
		}
	}
	if !found {
		t.Error("running the analysis left no audit entry")
	}
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/analysis/timestamps", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("without the token: %d", resp.StatusCode)
	}
}

func TestAnomaliesAndDetailsOverHTTP(t *testing.T) {
	h := seeded(t)
	var rep struct {
		Findings []map[string]any `json:"findings"`
		Kinds    []map[string]any `json:"kinds"`
		Scanned  int64            `json:"scanned"`
		Notes    []string         `json:"notes"`
	}
	h.get("/api/analysis/anomalies", &rep)
	if rep.Findings == nil || len(rep.Kinds) == 0 || rep.Scanned == 0 || len(rep.Notes) == 0 {
		t.Errorf("anomaly report: %d findings, %d kinds, %d scanned", len(rep.Findings), len(rep.Kinds), rep.Scanned)
	}
	var tagged struct {
		Added int64 `json:"tags_added"`
	}
	if code := h.post("/api/analysis/anomalies/tag", nil, &tagged); code != 200 {
		t.Errorf("tagging: %d", code)
	}
	// Tagging changes the case, so it must not be reachable by a link.
	if code, _, _ := h.do("GET", "/api/analysis/anomalies/tag", nil, nil); code == 200 {
		t.Error("tagging answered a GET")
	}

	var saved struct {
		Changed int `json:"changed"`
	}
	if code := h.post("/api/details", map[string]any{"host": "WS-1", "values": map[string]string{"serial_number": "<script>alert(1)</script>", "make": "Dell"}}, &saved); code != 200 || saved.Changed != 2 {
		t.Fatalf("saving details: %d, %d changed", code, saved.Changed)
	}
	if code := h.post("/api/details", map[string]any{"host": "WS-1", "values": map[string]string{"nonsense": "x"}}, nil); code != 400 {
		t.Errorf("an unknown field: %d", code)
	}
	var d struct {
		Hosts []struct {
			Name   string `json:"name"`
			Values map[string]struct {
				Value string `json:"value"`
			} `json:"values"`
		} `json:"hosts"`
		HostFields []map[string]any `json:"host_fields"`
	}
	h.get("/api/details", &d)
	if len(d.Hosts) != 1 || d.Hosts[0].Values["make"].Value != "Dell" || len(d.HostFields) < 20 {
		t.Errorf("details read back: %+v", d.Hosts)
	}
	// The report carries them, with markup made harmless.
	code, _, body := h.do("GET", "/api/report?format=html", nil, nil)
	if code != 200 || !strings.Contains(string(body), "Hosts examined") || strings.Contains(string(body), "<script>alert(1)") || !strings.Contains(string(body), "&lt;script&gt;alert(1)") {
		t.Errorf("report (%d) does not carry the host details safely", code)
	}
	rows, _ := h.s.ListAudit(20)
	seen := map[string]bool{}
	for _, a := range rows {
		seen[a.Action] = true
	}
	for _, want := range []string{"analysis.anomalies", "analysis.anomalies.tag", "details.set"} {
		if !seen[want] {
			t.Errorf("no audit entry for %s", want)
		}
	}
	for _, p := range []string{"/api/analysis/anomalies", "/api/details"} {
		req, _ := http.NewRequest("GET", h.srv.URL+p, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s without the token: %d", p, resp.StatusCode)
		}
	}
}
