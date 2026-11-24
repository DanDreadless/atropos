// Package web serves the case over HTTP: a JSON API and the embedded interface.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/analysis"
	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/ingest"
	"github.com/DanDreadless/atropos/internal/report"
	"github.com/DanDreadless/atropos/internal/store"
)

//go:embed ui
var uiFS embed.FS

type server struct {
	s  *store.Store
	in *ingest.Ingester
	up uploads
}

// NewToken returns a fresh session token: 256 random bits, hex encoded.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Serve listens on addr, which must be a loopback address, until ctx is
// cancelled. Every request must carry token (see auth). ready, if not nil,
// is called once the listener is accepting connections.
func Serve(ctx context.Context, addr, token string, s *store.Store, in *ingest.Ingester, ready func()) error {
	if err := CheckListen(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           Handler(s, in, token),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	if ready != nil {
		ready()
	}
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		grace, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(grace)
		close(stopped)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-stopped
	return nil
}

// CheckListen reports whether addr is one Serve will accept.
func CheckListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	if !isLoopback(host) {
		return fmt.Errorf("--listen %s refused: Atropos only serves on a loopback address (127.0.0.1, ::1 or localhost). To use it from another machine, tunnel to it, for example with ssh -L", addr)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Handler is the whole interface: the embedded page and the JSON API. An
// empty token disables authentication, which is only for tests.
func Handler(s *store.Store, in *ingest.Ingester, token string) http.Handler {
	sv := &server{s: s, in: in, up: uploads{open: map[int64]*openBatch{}}}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	mux.HandleFunc("GET /api/case", sv.caseInfo)
	mux.HandleFunc("GET /api/status", sv.status)
	mux.HandleFunc("POST /api/upload", sv.upload)
	mux.HandleFunc("GET /api/upload/{batch}", sv.uploadReceived)
	mux.HandleFunc("POST /api/upload/unreadable", sv.uploadUnreadable)
	mux.HandleFunc("GET /api/hosts", sv.hosts)
	mux.HandleFunc("POST /api/hosts", sv.hostAdd)
	mux.HandleFunc("POST /api/submissions/{batch}/host", sv.assignSubmission)
	mux.HandleFunc("GET /api/events", sv.events)
	mux.HandleFunc("GET /api/summary", sv.summary)
	mux.HandleFunc("GET /api/facets", sv.facetCounts)
	mux.HandleFunc("GET /api/event/{id}", sv.event)
	mux.HandleFunc("GET /api/evidence", sv.evidence)
	mux.HandleFunc("POST /api/evidence/{id}/reparse", sv.reparse)
	mux.HandleFunc("POST /api/evidence/reparse-stale", sv.reparseStale)
	mux.HandleFunc("POST /api/evidence/{id}/exclude", sv.exclude)
	mux.HandleFunc("GET /api/evidence/{id}/browse", sv.browse)
	mux.HandleFunc("POST /api/evidence/{id}/extract", sv.extract)
	mux.HandleFunc("GET /api/evidence/{id}/picture", sv.picture)
	mux.HandleFunc("GET /api/audit", sv.audit)
	mux.HandleFunc("GET /api/facts", sv.facts)
	mux.HandleFunc("GET /api/textsearch", sv.textSearch)
	mux.HandleFunc("POST /api/verify", sv.verify)
	mux.HandleFunc("POST /api/annotate", sv.annotate)
	mux.HandleFunc("GET /api/export", sv.export)
	mux.HandleFunc("GET /api/report", sv.report)
	mux.HandleFunc("GET /api/analysis/timestamps", sv.analyseTimestamps)
	mux.HandleFunc("GET /api/analysis/anomalies", sv.analyseAnomalies)
	mux.HandleFunc("GET /api/analysis/connections", sv.analyseConnections)
	mux.HandleFunc("POST /api/analysis/anomalies/tag", sv.tagAnomalies)
	mux.HandleFunc("GET /api/details", sv.details)
	mux.HandleFunc("POST /api/details", sv.detailsSet)
	mux.HandleFunc("GET /api/groups", sv.groups)
	mux.HandleFunc("POST /api/groups", sv.groupCreate)
	mux.HandleFunc("POST /api/groups/{id}/archive", sv.groupArchive)
	mux.HandleFunc("POST /api/groups/{id}/events", sv.groupEvents)
	return guard(auth(token, mux))
}

// auth requires the session token on every request. The interface is only
// reachable from this machine, but so are other users and other programs;
// without the token, which is printed once on the terminal that started the
// server, none of them can read the case or add to it.
//
// The token arrives one of three ways: in the link printed at start-up
// (?token=...), which sets a cookie and redirects so the token does not stay
// in the address bar or the history; in that cookie afterwards; or as a
// bearer token, for scripts.
func auth(token string, h http.Handler) http.Handler {
	if token == "" {
		return h
	}
	same := func(got string) bool { return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cookies ignore ports, so the name includes ours: two cases open at
		// once on different ports must not sign each other out.
		_, port, _ := net.SplitHostPort(r.Host)
		name := "atropos_session_" + port
		if t := r.URL.Query().Get("token"); t != "" && r.Method == http.MethodGet && r.URL.Path == "/" {
			if !same(t) {
				denied(w)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: name, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie(name); err == nil && same(c.Value) {
			h.ServeHTTP(w, r)
			return
		}
		if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && same(b) {
			h.ServeHTTP(w, r)
			return
		}
		denied(w)
	})
}

func denied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, "Atropos: not signed in.\n\nOpen the full address that \"atropos serve\" printed when it started. It ends in ?token=... and signs this browser in.\nThe token changes every time the server starts.\n")
}

// guard refuses cross-site requests. The server is intended for localhost;
// this stops another page in the examiner's browser from driving it. The Host
// check closes the remaining route, DNS rebinding, where a hostile site
// resolves its own name to 127.0.0.1 and so appears same-origin.
func guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		if !isLoopback(strings.Trim(host, "[]")) {
			http.Error(w, "request for an unexpected host refused", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host && o != "https://"+r.Host {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if s := r.Header.Get("Sec-Fetch-Site"); s == "cross-site" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Case data must not be left in the browser's disk cache or sent on in a referrer.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func atoi(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func queryFrom(r *http.Request) store.Query {
	v := r.URL.Query()
	return store.Query{
		Text: v.Get("q"), From: atoi(v.Get("from")), To: atoi(v.Get("to")),
		EvidenceID: atoi(v.Get("evidence")), AfterTS: atoi(v.Get("after_ts")), AfterID: atoi(v.Get("after_id")),
		Limit: int(atoi(v.Get("limit"))), Desc: v.Get("order") == "desc", Group: v.Get("group"),
	}
}

func (sv *server) caseInfo(w http.ResponseWriter, r *http.Request) {
	meta, err := sv.s.Meta()
	if err != nil {
		fail(w, 500, err)
		return
	}
	facets, err := sv.s.Facets()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{
		"meta": meta, "examiner": sv.s.Actor, "tool_version": store.ToolVersion,
		"local_zone": sv.in.ExaminerZoneName, "facets": facets, "ingest": sv.in.Status(),
	})
}

// facetCounts gives the chip counts for the events matching q (and group):
// the interface sends the "From" filter, so the counts follow it.
func (sv *server) facetCounts(w http.ResponseWriter, r *http.Request) {
	q := store.Query{Text: r.URL.Query().Get("q"), Group: r.URL.Query().Get("group")}
	facets, err := sv.s.FacetsFor(q)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"facets": facets})
}

// status is cheap enough to poll: it touches no tables.
func (sv *server) status(w http.ResponseWriter, r *http.Request) {
	st := sv.in.Status()
	st.Last = sv.in.LastExtract()
	writeJSON(w, st)
}

// browse lists one directory inside a disk or disc image.
func (sv *server) browse(w http.ResponseWriter, r *http.Request) {
	e, err := sv.s.GetEvidence(atoi(r.PathValue("id")))
	if err != nil {
		fail(w, 404, err)
		return
	}
	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = "/"
	}
	describe, entries, err := sv.in.Browse(e, dir)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"describe": describe, "path": dir, "entries": entries})
}

// maxPicture bounds the size of a picture the browser is given.
const maxPicture = 100 << 20

// picture gives the browser an evidence item that is a raster picture, to
// show it. The type comes from the stored bytes, not the name or the
// recorded kind, and anything else is refused: no SVG, no HTML, nothing a
// browser would run. The response may not be framed, run script or be kept.
func (sv *server) picture(w http.ResponseWriter, r *http.Request) {
	e, err := sv.s.GetEvidence(atoi(r.PathValue("id")))
	if err != nil {
		fail(w, 404, err)
		return
	}
	if e.Size > maxPicture {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the item is %d bytes; pictures over %d bytes are not shown", e.Size, maxPicture))
		return
	}
	f, err := sv.in.V.Open(e.SHA256)
	if err != nil {
		fail(w, 404, err)
		return
	}
	defer f.Close()
	head := make([]byte, 32)
	n, _ := io.ReadFull(f, head)
	kind := detect.PictureType(head[:n])
	mime := map[string]string{"JPEG": "image/jpeg", "PNG": "image/png", "GIF": "image/gif", "WebP": "image/webp", "BMP": "image/bmp"}[kind]
	if mime == "" {
		fail(w, http.StatusUnsupportedMediaType, fmt.Errorf("this item is not a picture Atropos shows (JPEG, PNG, GIF, WebP or BMP)"))
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", fmt.Sprint(e.Size))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="evidence-%d.%s"`, e.ID, strings.ToLower(kind)))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	io.Copy(w, io.LimitReader(f, e.Size))
}

// extract copies chosen files out of an image and puts them on the timeline.
func (sv *server) extract(w http.ResponseWriter, r *http.Request) {
	e, err := sv.s.GetEvidence(atoi(r.PathValue("id")))
	if err != nil {
		fail(w, 404, err)
		return
	}
	var body struct {
		Paths    []string `json:"paths"`
		Standard bool     `json:"standard"` // the standard Windows artefacts
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	if !ingest.Browsable(e.Kind) {
		fail(w, 400, fmt.Errorf("evidence #%d is %s, which has no contents to extract", e.ID, e.Kind))
		return
	}
	if len(body.Paths) == 0 && !body.Standard {
		fail(w, 400, fmt.Errorf("nothing was chosen to extract"))
		return
	}
	sv.in.ExtractAsync(e, body.Paths, body.Standard)
	writeJSON(w, map[string]any{"queued": e.ID})
}

func (sv *server) events(w http.ResponseWriter, r *http.Request) {
	rows, err := sv.s.Search(queryFrom(r))
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"events": rows})
}

func (sv *server) summary(w http.ResponseWriter, r *http.Request) {
	sum, err := sv.s.Summarise(queryFrom(r), int(atoi(r.URL.Query().Get("buckets"))))
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, sum)
}

func (sv *server) event(w http.ResponseWriter, r *http.Request) {
	id := atoi(r.PathValue("id"))
	e, err := sv.s.GetEvent(id)
	if err != nil {
		fail(w, 404, err)
		return
	}
	ev, err := sv.s.GetEvidence(e.EvidenceID)
	if err != nil {
		fail(w, 500, err)
		return
	}
	notes, err := sv.s.Annotations(id)
	if err != nil {
		fail(w, 500, err)
		return
	}
	out := map[string]any{"event": e, "evidence": ev, "annotations": notes}
	// A change-journal record names its folder only by file-table entry.
	if folder, err := sv.s.JournalParent(e); err == nil && folder != nil {
		out["journal_folder"] = folder
	}
	writeJSON(w, out)
}

func (sv *server) evidence(w http.ResponseWriter, r *http.Request) {
	list, err := sv.s.ListEvidence()
	if err != nil {
		fail(w, 500, err)
		return
	}
	for i := range list {
		list[i].Stale = ingest.Stale(&list[i])
	}
	writeJSON(w, map[string]any{"evidence": list, "ingest": sv.in.Status()})
}

// reparseStale queues a new parse run for every item this build would read
// differently from the run now shown: after an upgrade, one step brings the
// whole case up to date. Earlier runs are kept, as with any re-parse.
func (sv *server) reparseStale(w http.ResponseWriter, r *http.Request) {
	list, err := sv.s.ListEvidence()
	if err != nil {
		fail(w, 500, err)
		return
	}
	var todo []*store.Evidence
	for i := range list {
		if list[i].Excluded {
			continue // out of the case's view: not worth a run until included again
		}
		if why := ingest.Stale(&list[i]); why != "" {
			sv.s.Audit("parse.requested", fmt.Sprintf("evidence:%d", list[i].ID), map[string]any{"reason": "examiner asked for items read by an earlier version to be parsed again: " + why})
			todo = append(todo, &list[i])
		}
	}
	if len(todo) > 0 {
		sv.in.ProcessAsync(todo)
	}
	writeJSON(w, map[string]any{"queued": len(todo)})
}

func (sv *server) reparse(w http.ResponseWriter, r *http.Request) {
	e, err := sv.s.GetEvidence(atoi(r.PathValue("id")))
	if err != nil {
		fail(w, 404, err)
		return
	}
	if e.DuplicateOf != nil {
		fail(w, 400, fmt.Errorf("this item duplicates evidence %d; re-parse that item", *e.DuplicateOf))
		return
	}
	sv.s.Audit("parse.requested", fmt.Sprintf("evidence:%d", e.ID), map[string]any{"reason": "examiner requested a new parse run"})
	sv.in.ProcessAsync([]*store.Evidence{e})
	writeJSON(w, map[string]any{"queued": e.ID})
}

// exclude takes an item, and everything that came out of it, out of the
// case's view, or brings it back. Nothing is deleted: the decision is
// recorded with its reason, and audited, by the store.
func (sv *server) exclude(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Exclude bool   `json:"exclude"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	id := atoi(r.PathValue("id"))
	if _, err := sv.s.GetEvidence(id); err != nil {
		fail(w, 404, fmt.Errorf("no such evidence item"))
		return
	}
	if err := sv.s.SetExcluded(id, body.Exclude, body.Reason); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "excluded": body.Exclude})
}

func (sv *server) audit(w http.ResponseWriter, r *http.Request) {
	limit := int(atoi(r.URL.Query().Get("limit")))
	if limit <= 0 {
		limit = 500
	}
	rows, err := sv.s.ListAudit(limit)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"audit": rows})
}

// analyseTimestamps compares what the file table, ShimCache, Amcache and the
// change journal say about the same files. It reads only, and is audited.
func (sv *server) analyseTimestamps(w http.ResponseWriter, r *http.Request) {
	rep, err := analysis.Timestomp(sv.s)
	if err != nil {
		fail(w, 500, err)
		return
	}
	sv.s.Audit("analysis.timestamps", "case", map[string]any{"findings": rep.Counts, "compared": rep.Compared})
	writeJSON(w, rep)
}

// analyseAnomalies lists things that do not belong where they were found:
// programs in folders intruders stage tools in, Windows program names in the
// wrong place, commands of a kind attackers use. It reads only, and is audited.
func (sv *server) analyseAnomalies(w http.ResponseWriter, r *http.Request) {
	rep, err := analysis.Anomalies(sv.s)
	if err != nil {
		fail(w, 500, err)
		return
	}
	sv.s.Audit("analysis.anomalies", "case", map[string]any{"findings": rep.Counts, "scanned": rep.Scanned})
	writeJSON(w, rep)
}

// analyseConnections pairs the two ends of connections between the case's
// hosts (Remote Desktop so far). It reads only, and is audited.
func (sv *server) analyseConnections(w http.ResponseWriter, r *http.Request) {
	rep, err := analysis.Connections(sv.s)
	if err != nil {
		fail(w, 500, err)
		return
	}
	sv.s.Audit("analysis.connections", "case", map[string]any{"connections": len(rep.Connections), "events": rep.Events})
	writeJSON(w, rep)
}

// tagAnomalies runs the checks again and tags every event they list, so the
// tags always match the case as it is now rather than a list the browser held.
func (sv *server) tagAnomalies(w http.ResponseWriter, r *http.Request) {
	rep, err := analysis.Anomalies(sv.s)
	if err != nil {
		fail(w, 500, err)
		return
	}
	n, err := analysis.TagAnomalies(sv.s, rep)
	if err != nil {
		fail(w, 500, err)
		return
	}
	sv.s.Audit("analysis.anomalies.tag", "case", map[string]any{"findings": rep.Counts, "tags_added": n})
	writeJSON(w, map[string]any{"tags_added": n, "findings": len(rep.Findings)})
}

// details returns what the examiner has stated about the case and its hosts.
func (sv *server) details(w http.ResponseWriter, r *http.Request) {
	d, err := sv.s.Details()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, d)
}

// detailsSet states details for the case (no host) or for one host.
func (sv *server) detailsSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host   string            `json:"host"`
		Values map[string]string `json:"values"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	n, err := sv.s.SetDetails(body.Host, body.Values)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"changed": n})
}

func (sv *server) facts(w http.ResponseWriter, r *http.Request) {
	f, err := sv.s.Facts("")
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"facts": f})
}

func (sv *server) textSearch(w http.ResponseWriter, r *http.Request) {
	hits, err := sv.s.SearchText(r.URL.Query().Get("q"), 50)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"hits": hits})
}

func (sv *server) verify(w http.ResponseWriter, r *http.Request) {
	rep, err := sv.in.Verify()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, rep)
}

func (sv *server) annotate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		EventID  int64  `json:"event_id"`
		Kind     string `json:"kind"`
		Body     string `json:"body"`
		RefersTo *int64 `json:"refers_to"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	if _, err := sv.s.GetEvent(body.EventID); err != nil {
		fail(w, 404, fmt.Errorf("no such event"))
		return
	}
	id, err := sv.s.Annotate(body.EventID, body.Kind, body.Body, body.RefersTo)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"id": id})
}

func (sv *server) export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	ext := map[string]string{"csv": "csv", "jsonl": "jsonl", "timesketch": "jsonl", "bodyfile": "body"}[format]
	if ext == "" {
		fail(w, 400, fmt.Errorf("format must be csv, jsonl, timesketch or bodyfile"))
		return
	}
	q := queryFrom(r)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="atropos-%s-%s.%s"`, format, time.Now().UTC().Format("20060102T150405Z"), ext))
	res, err := ExportWith(sv.s, q, format, w)
	details := map[string]any{"format": format, "query": q.Text, "from": q.From, "to": q.To, "events": res.Events}
	if format == "bodyfile" {
		details["lines"], details["left_out_no_file_time"] = res.Lines, res.LeftOut
	}
	if err != nil {
		details["error"] = err.Error()
	}
	sv.s.Audit("export", "case", details)
}

func (sv *server) report(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "html" && format != "json" {
		fail(w, 400, fmt.Errorf("format must be html or json"))
		return
	}
	rep, err := report.Build(sv.s, sv.in)
	if err != nil {
		fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="atropos-report-%s.%s"`, time.Now().UTC().Format("20060102T150405Z"), format))
	if format == "html" {
		// The report carries its own inline style sheet and nothing else.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	report.Write(sv.s, rep, format, w)
}

func (sv *server) groups(w http.ResponseWriter, r *http.Request) {
	list, err := sv.s.Groups()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"groups": list})
}

func (sv *server) groupCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	g, err := sv.s.CreateGroup(body.Name, body.Note)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, g)
}

func (sv *server) groupArchive(w http.ResponseWriter, r *http.Request) {
	if err := sv.s.ArchiveGroup(atoi(r.PathValue("id"))); err != nil {
		fail(w, 404, err)
		return
	}
	writeJSON(w, map[string]any{"archived": true})
}

// maxGroupBulk bounds "add everything this search shows".
const maxGroupBulk = 100000

// groupEvents adds events to a group or removes them. The events are either
// listed by id or described by a search, which is how a whole evidence item
// or everything in a time window is added in one step.
func (sv *server) groupEvents(w http.ResponseWriter, r *http.Request) {
	g, err := sv.s.GroupByID(atoi(r.PathValue("id")))
	if err != nil {
		fail(w, 404, err)
		return
	}
	var body struct {
		Action   string  `json:"action"` // add | remove
		EventIDs []int64 `json:"event_ids"`
		Query    *struct {
			Q     string `json:"q"`
			From  string `json:"from"`
			To    string `json:"to"`
			Group string `json:"group"`
		} `json:"query"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	ids, how := body.EventIDs, "selected events"
	if body.Query != nil {
		q := store.Query{Text: body.Query.Q, From: atoi(body.Query.From), To: atoi(body.Query.To), Group: body.Query.Group}
		if ids, err = sv.s.MatchingIDs(q, maxGroupBulk); err != nil {
			fail(w, 400, err)
			return
		}
		how = fmt.Sprintf("every event matching search %q", body.Query.Q)
		if q.From != 0 || q.To != 0 {
			how += fmt.Sprintf(" between %s and %s", isoUTC(q.From), isoUTC(q.To))
		}
	}
	if len(ids) == 0 {
		fail(w, 400, fmt.Errorf("no events were given"))
		return
	}
	if len(ids) > maxGroupBulk {
		fail(w, 400, fmt.Errorf("at most %d events can be changed at once", maxGroupBulk))
		return
	}
	var n int64
	switch body.Action {
	case "add":
		n, err = sv.s.AddToGroup(g.Name, ids, how)
	case "remove":
		n, err = sv.s.RemoveFromGroup(g.Name, ids)
	default:
		err = fmt.Errorf("action must be add or remove")
	}
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"changed": n, "requested": len(ids)})
}

func isoUTC(ns int64) string {
	return time.Unix(0, ns).UTC().Format("2006-01-02T15:04:05.000000Z")
}

// csvSafe stops a spreadsheet treating evidence as a formula. A cell that
// begins with =, +, - or @ is run by Excel and others when the file is
// opened, and event text comes from evidence an attacker may have written.
// A leading apostrophe makes the cell plain text; the JSON exports carry the
// value untouched.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ExportWith writes matching events in time order and says what it wrote.
func ExportWith(s *store.Store, q store.Query, format string, w io.Writer) (ExportResult, error) {
	if format == "bodyfile" {
		return exportBodyfile(s, q, w)
	}
	n, err := Export(s, q, format, w)
	return ExportResult{Events: n}, err
}

// Export writes matching events in time order and returns how many.
func Export(s *store.Store, q store.Query, format string, w io.Writer) (int64, error) {
	var n int64
	switch format {
	case "csv":
		cw := csv.NewWriter(w)
		cw.Write([]string{"datetime_utc", "macb", "timestamp_desc", "category", "source", "host", "user", "path", "message", "tz_source", "tz_name", "timestamp_raw", "record_ref", "evidence_id", "event_id"})
		err := s.Stream(q, func(e store.EventRow) error {
			n++
			row := []string{isoUTC(e.TSUTC), e.MACB, e.TSType, e.Category, e.Source, e.Host, e.User, e.Path, e.Message, e.TZSource, e.TZName, e.TSRaw, e.RecordRef, strconv.FormatInt(e.EvidenceID, 10), strconv.FormatInt(e.ID, 10)}
			for i := range row {
				row[i] = csvSafe(row[i])
			}
			return cw.Write(row)
		})
		cw.Flush()
		if err == nil {
			err = cw.Error()
		}
		return n, err
	case "jsonl":
		enc := json.NewEncoder(w)
		return n, s.Stream(q, func(e store.EventRow) error {
			n++
			return enc.Encode(map[string]any{
				"datetime_utc": isoUTC(e.TSUTC), "ts_utc_ns": e.TSUTC, "timestamp_desc": e.TSType, "source": e.Source,
				"macb": e.MACB, "category": e.Category,
				"host": e.Host, "user": e.User, "path": e.Path, "message": e.Message, "tz_source": e.TZSource,
				"tz_name": e.TZName, "timestamp_raw": e.TSRaw, "record_ref": e.RecordRef,
				"evidence_id": e.EvidenceID, "event_id": e.ID, "fields": e.Fields,
			})
		})
	case "timesketch":
		// Timesketch's JSONL import requires message, datetime and timestamp_desc.
		enc := json.NewEncoder(w)
		return n, s.Stream(q, func(e store.EventRow) error {
			n++
			return enc.Encode(map[string]any{
				"message": e.Message, "datetime": isoUTC(e.TSUTC), "timestamp_desc": e.TSType,
				"data_type": "atropos:" + e.Source, "hostname": e.Host, "username": e.User, "path": e.Path,
				"macb": e.MACB, "category": e.Category,
				"tz_source": e.TZSource, "timestamp_raw": e.TSRaw, "record_ref": e.RecordRef,
				"atropos_evidence_id": e.EvidenceID, "atropos_event_id": e.ID,
			})
		})
	}
	return 0, fmt.Errorf("unknown format %q", format)
}
