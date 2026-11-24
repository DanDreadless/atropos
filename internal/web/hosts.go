package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/DanDreadless/atropos/internal/store"
)

// hosts lists the hosts described in the case, for the add-evidence choice.
func (sv *server) hosts(w http.ResponseWriter, r *http.Request) {
	hs, err := sv.s.Hosts()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"hosts": hs})
}

// hostAdd adds a host by name (the Details tab, before anything about it is
// stated).
func (sv *server) hostAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	h, err := sv.s.AddHost(body.Name)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, h)
}

// uploadAssignment reads where an upload's files come from: ?host=ID, or
// ?not_from_host=DESCRIPTION. ok is false when the request says neither (a
// script, or a test): the submission is then left unassigned, as before
// hosts existed. The page always says one or the other.
func uploadAssignment(r *http.Request) (hostID *int64, source string, ok bool, err error) {
	q := r.URL.Query()
	if v := q.Get("host"); v != "" {
		id, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil {
			return nil, "", false, fmt.Errorf("bad host number")
		}
		return &id, "", true, nil
	}
	if _, given := q["not_from_host"]; given {
		return nil, q.Get("not_from_host"), true, nil
	}
	return nil, "", false, nil
}

// assignSubmission states, or changes, which host a submission came from.
// A change parses the submission's items again, as new runs: the host and
// its time zone are part of how they are read.
func (sv *server) assignSubmission(w http.ResponseWriter, r *http.Request) {
	batch := atoi(r.PathValue("batch"))
	var body struct {
		HostID *int64 `json:"host_id"`
		Source string `json:"not_from_host"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	list, err := sv.s.ListEvidence()
	if err != nil {
		fail(w, 500, err)
		return
	}
	var items []*store.Evidence
	for i := range list {
		e := &list[i]
		if e.BatchID != batch {
			continue
		}
		// Archives are not parsed again (that would unpack them twice), nor
		// are duplicates; everything that came out of them is.
		if e.DuplicateOf != nil || e.Status == "unpacked" {
			continue
		}
		items = append(items, e)
	}
	if len(items) == 0 && !batchExists(list, batch) {
		fail(w, 404, fmt.Errorf("no submission %d", batch))
		return
	}
	if err := sv.s.AssignBatch(batch, body.HostID, body.Source); err != nil {
		fail(w, 400, err)
		return
	}
	for _, e := range items {
		sv.s.Audit("parse.requested", fmt.Sprintf("evidence:%d", e.ID), map[string]any{"reason": "its submission was assigned to another host"})
	}
	if len(items) > 0 {
		sv.in.ProcessAsync(items)
	}
	writeJSON(w, map[string]any{"batch": batch, "reparsing": len(items)})
}

func batchExists(list []store.Evidence, batch int64) bool {
	for _, e := range list {
		if e.BatchID == batch {
			return true
		}
	}
	return false
}
