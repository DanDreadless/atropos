package web

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

// A large folder (a browser profile, a user's AppData) is sent by the page
// in chunks, all into one submission, so that one file the browser cannot
// read, or that changes while it is being sent, costs that file and not the
// whole upload. The submission stays open between chunks; nothing in it is
// parsed until the page sends the last chunk (final=1), so that files that
// belong together (a database and its write-ahead log, a hive and its
// transaction logs) are parsed together. If the page goes away before
// that, what arrived is parsed once no chunk has come for openBatchIdle, so
// evidence is never left received but unexamined.

var openBatchIdle = 2 * time.Minute // a variable so a test can shorten it

type openBatch struct {
	top      []*store.Evidence
	received map[string]bool // the paths stored so far, for the page to resume from
	timer    *time.Timer
}

type uploads struct {
	mu   sync.Mutex
	open map[int64]*openBatch
}

// begin returns the submission a chunk goes into: a new one, or the open one
// the page names.
func (sv *server) beginChunk(r *http.Request) (int64, *openBatch, error) {
	sv.up.mu.Lock()
	defer sv.up.mu.Unlock()
	if v := r.URL.Query().Get("batch"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("bad submission number")
		}
		ob := sv.up.open[id]
		if ob == nil {
			return 0, nil, fmt.Errorf("submission %d is not open for more files: it was finished, or waited too long and was parsed", id)
		}
		ob.timer.Stop()
		return id, ob, nil
	}
	hostID, source, assign, err := uploadAssignment(r)
	if err != nil {
		return 0, nil, err
	}
	id, err := sv.s.NextBatch()
	if err != nil {
		return 0, nil, err
	}
	// A submission still open has no evidence rows yet if its first chunk
	// held none; do not hand its number out twice.
	for open := range sv.up.open {
		if open >= id {
			id = open + 1
		}
	}
	// Where the files come from is recorded before any of them, so that
	// parsing them already knows their host.
	if assign {
		if err := sv.s.AssignBatch(id, hostID, source); err != nil {
			return 0, nil, err
		}
	}
	ob := &openBatch{received: map[string]bool{}}
	sv.up.open[id] = ob
	return id, ob, nil
}

// endChunk either keeps the submission open, with a fresh idle timer, or
// closes it and parses what it holds.
func (sv *server) endChunk(id int64, ob *openBatch, final bool) {
	sv.up.mu.Lock()
	defer sv.up.mu.Unlock()
	if !final {
		ob.timer = time.AfterFunc(openBatchIdle, func() { sv.closeBatch(id, "no more files arrived") })
		return
	}
	delete(sv.up.open, id)
	if len(ob.top) > 0 {
		sv.in.ProcessAsync(ob.top)
	}
}

func (sv *server) closeBatch(id int64, why string) {
	sv.up.mu.Lock()
	ob := sv.up.open[id]
	delete(sv.up.open, id)
	sv.up.mu.Unlock()
	if ob == nil {
		return
	}
	sv.s.Audit("upload.closed", fmt.Sprintf("batch:%d", id), map[string]any{"reason": why, "files": len(ob.top)})
	if len(ob.top) > 0 {
		sv.in.ProcessAsync(ob.top)
	}
}

func (sv *server) upload(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil && r.URL.Query().Get("batch") == "" {
		fail(w, 400, err)
		return
	}
	final := r.URL.Query().Get("final") != "0"
	batch, ob, err := sv.beginChunk(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	var got []*store.Evidence
	// broke ends a chunk that broke off. What was stored stays in the
	// submission. A chunk of a larger upload keeps it open for the page to
	// send the rest; a final one (and an upload in one piece) closes it and
	// parses what arrived at once.
	broke := func(code int, err error) {
		sv.up.mu.Lock()
		n := len(ob.top)
		sv.up.mu.Unlock()
		if final {
			sv.endChunk(batch, ob, true)
			if n > 0 {
				err = fmt.Errorf("%w (the %d files received before this are being processed)", err, n)
			}
		} else {
			sv.endChunk(batch, ob, false)
			err = fmt.Errorf("%w (the %d files received so far are kept in submission %d, which stays open for the rest)", err, n, batch)
		}
		fail(w, code, err)
	}
	for mr != nil {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			broke(400, err)
			return
		}
		// part.FileName() keeps only the last path element. The full value is
		// read here so a dropped folder keeps each file's place in it.
		_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		rel := strings.TrimLeft(strings.ReplaceAll(params["filename"], "\\", "/"), "/")
		if rel == "" {
			continue
		}
		// Files are streamed straight into the vault while being hashed.
		e, err := sv.in.Intake(batch, path.Base(rel), "upload:"+rel, part, nil, 0)
		if err != nil {
			broke(500, err)
			return
		}
		got = append(got, e)
		sv.up.mu.Lock()
		ob.top = append(ob.top, e)
		ob.received[rel] = true
		sv.up.mu.Unlock()
	}
	sv.endChunk(batch, ob, final)
	writeJSON(w, map[string]any{"batch": batch, "received": got, "final": final})
}

// uploadReceived lists the paths an open submission holds, so the page can
// send the rest after a chunk broke off.
func (sv *server) uploadReceived(w http.ResponseWriter, r *http.Request) {
	id := atoi(r.PathValue("batch"))
	sv.up.mu.Lock()
	defer sv.up.mu.Unlock()
	ob := sv.up.open[id]
	if ob == nil {
		fail(w, 404, fmt.Errorf("submission %d is not open", id))
		return
	}
	paths := make([]string, 0, len(ob.received))
	for p := range ob.received {
		paths = append(paths, p)
	}
	writeJSON(w, map[string]any{"batch": id, "paths": paths})
}

// uploadUnreadable records, in the audit log, the files the page could not
// send: they are not evidence in the case, but the examiner chose them and
// the record of what was asked for must say they are missing.
func (sv *server) uploadUnreadable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Batch int64    `json:"batch"`
		Paths []string `json:"paths"`
		Error string   `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	if len(body.Paths) == 0 {
		writeJSON(w, map[string]any{"recorded": 0})
		return
	}
	if err := sv.s.Audit("upload.unreadable", fmt.Sprintf("batch:%d", body.Batch), map[string]any{
		"paths": body.Paths, "count": len(body.Paths), "browser_error": body.Error,
	}); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"recorded": len(body.Paths)})
}
