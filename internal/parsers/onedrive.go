package parsers

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// OneDrive's own databases, in %LOCALAPPDATA%\Microsoft\OneDrive\settings\
// <Personal|Business1>:
//
//   - SyncEngineDatabase.db: every file and folder in the synced tree, with
//     the times OneDrive recorded for it, when an online-only file was
//     downloaded because something opened it (hydration), and a history of
//     the client's operations.
//   - SafeDelete.db: deletions OneDrive noticed, among them the path of a
//     deleted file and the program that deleted it.
//
// The layout was read from a real Windows 11 OneDrive client's databases
// (table and column names, value ranges; their contents were not used),
// so it is that version's: columns are looked up by name, and a missing
// one is left out rather than guessed. Every time is Unix seconds.

func sqlColumns(db *sql.DB, table string) map[string]bool {
	out := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out[strings.ToLower(n)] = true
		}
	}
	return out
}

// sqlSelect selects the named columns that exist, NULL for those that do not.
func sqlSelect(db *sql.DB, table string, cols ...string) (*sql.Rows, error) {
	have := sqlColumns(db, table)
	parts := make([]string, len(cols))
	for i, c := range cols {
		if have[strings.ToLower(c)] {
			parts[i] = `"` + c + `"`
		} else {
			parts[i] = "NULL"
		}
	}
	return db.Query(`SELECT ` + strings.Join(parts, ", ") + ` FROM "` + table + `"`)
}

type odFolder struct{ parent, name string }

// oneDrivePaths turns resource identifiers into local paths: up the
// folders to a sync root, whose local folder the scope table records.
func oneDrivePaths(db *sql.DB) func(parent, name string) string {
	roots := map[string]string{}
	if rows, err := sqlSelect(db, "od_ScopeInfo_Records", "scopeID", "lastKnownFolderPath"); err == nil {
		for rows.Next() {
			var id, path sql.NullString
			if rows.Scan(&id, &path) == nil && id.String != "" {
				roots[id.String] = path.String
			}
		}
		rows.Close()
	}
	folders := map[string]odFolder{}
	if rows, err := sqlSelect(db, "od_ClientFolder_Records", "resourceID", "parentResourceID", "folderName"); err == nil {
		for rows.Next() {
			var id, parent, name sql.NullString
			if rows.Scan(&id, &parent, &name) == nil {
				folders[id.String] = odFolder{parent.String, name.String}
			}
		}
		rows.Close()
	}
	cache := map[string]string{}
	var dir func(id string, seen map[string]bool) string
	dir = func(id string, seen map[string]bool) string {
		if p, ok := cache[id]; ok {
			return p
		}
		var p string
		if root, ok := roots[id]; ok {
			p = root
			if p == "" {
				p = "(OneDrive)"
			}
		} else if f, ok := folders[id]; ok {
			if seen[id] || len(seen) > 256 {
				// Not cached: the same folder reached another way may resolve.
				return "(OneDrive, folders that contain each other)"
			}
			seen[id] = true
			p = dir(f.parent, seen) + `\` + f.name
		} else {
			p = "(OneDrive, folder not recorded)"
		}
		cache[id] = p
		return p
	}
	return func(parent, name string) string { return dir(parent, map[string]bool{}) + `\` + name }
}

// oneDriveSync reads SyncEngineDatabase.db. It returns the events emitted.
func oneDriveSync(ctx *Context, db *sql.DB) (int, error) {
	path := oneDrivePaths(db)
	n := 0
	emit := func(secs int64, typ, macb, cat, p, msg, ref string, fields map[string]any) error {
		s, ok := unixSeconds(secs)
		if !ok {
			return nil
		}
		n++
		return ctx.Emit(Event{Stamp: s, Type: typ, MACB: macb, Category: cat, Source: "onedrive", Host: ctx.Host,
			Path: p, Message: msg, Fields: fields, Ref: ref})
	}
	if rows, err := sqlSelect(db, "od_ScopeInfo_Records", "lastKnownFolderPath", "webURL"); err == nil {
		var roots, webs []string
		for rows.Next() {
			var p, w sql.NullString
			if rows.Scan(&p, &w) == nil {
				if p.String != "" {
					roots = append(roots, clean(trunc(p.String, 500)))
				}
				if w.String != "" {
					webs = append(webs, clean(trunc(w.String, 500)))
				}
			}
		}
		rows.Close()
		sort.Strings(roots)
		sort.Strings(webs)
		if len(roots) > 0 {
			ctx.Fact("onedrive.local_folders", strings.Join(roots, "; "), "the local folders OneDrive syncs")
		}
		if len(webs) > 0 {
			ctx.Fact("onedrive.web_urls", strings.Join(webs, "; "), "the online libraries they sync with")
		}
	}

	files := map[string]string{}
	rows, err := sqlSelect(db, "od_ClientFile_Records", "resourceID", "parentResourceID", "fileName", "size", "lastChange", "serverLastChange",
		"diskLastAccessTime", "diskCreationTime", "mediaDateTaken", "locallyDeleted", "serverDeleted", "localHashDigest", "localHashAlgorithm", "sharedItem")
	if err != nil {
		return n, err
	}
	var count int
	for rows.Next() {
		var id, parent, name sql.NullString
		var size, last, server, access, create, taken, ldel, sdel, alg, shared sql.NullInt64
		var hash []byte
		if rows.Scan(&id, &parent, &name, &size, &last, &server, &access, &create, &taken, &ldel, &sdel, &hash, &alg, &shared) != nil {
			continue
		}
		count++
		p := clean(trunc(path(parent.String, name.String), 2000))
		files[id.String] = p
		fields := map[string]any{"resource_id": clean(trunc(id.String, 100)), "size": size.Int64}
		if ldel.Int64 != 0 {
			fields["locally_deleted"] = true
		}
		if sdel.Int64 != 0 {
			fields["server_deleted"] = true
		}
		if shared.Int64 != 0 {
			fields["shared_item"] = true
		}
		if len(hash) > 0 && len(hash) <= 64 {
			fields["hash"], fields["hash_algorithm"] = hex.EncodeToString(hash), alg.Int64
		}
		ref := "od_ClientFile_Records resourceID " + clean(trunc(id.String, 100))
		// The file's own times as OneDrive recorded them, grouped as for NTFS.
		groups := map[int64][]byte{}
		for i, t := range []int64{last.Int64, access.Int64, 0, create.Int64} {
			if t <= 0 {
				continue
			}
			if groups[t] == nil {
				groups[t] = []byte("....")
			}
			groups[t][i] = "MACB"[i]
		}
		times := make([]int64, 0, len(groups))
		for t := range groups {
			times = append(times, t)
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		for _, t := range times {
			mb := string(groups[t])
			if err := emit(t, "onedrive "+mb, mb, CatFileSystem, p, fmt.Sprintf("OneDrive %s  %s, as the sync client recorded it", mb, p), ref, fields); err != nil {
				return n, err
			}
		}
		if err := emit(server.Int64, "onedrive-server-changed", "", CatFileSystem, p, "Changed in the cloud copy: "+p, ref, fields); err != nil {
			return n, err
		}
		if err := emit(taken.Int64, "media-date-taken", "", CatFileSystem, p, "Picture or video taken (the date OneDrive records for it): "+p, ref, fields); err != nil {
			return n, err
		}
	}
	rows.Close()

	hydrated := 0
	if rows, err := sqlSelect(db, "od_HydrationData", "resourceID", "firstHydrationTime", "lastHydrationTime", "hydrationCount", "lastHydrationType"); err == nil {
		for rows.Next() {
			var id, typ sql.NullString
			var first, last, cnt sql.NullInt64
			if rows.Scan(&id, &first, &last, &cnt, &typ) != nil {
				continue
			}
			hydrated++
			p := files[id.String]
			if p == "" {
				p = "(OneDrive item " + clean(trunc(id.String, 100)) + ")"
			}
			fields := map[string]any{"resource_id": clean(trunc(id.String, 100)), "hydration_count": cnt.Int64, "last_hydration_type": clean(trunc(typ.String, 100))}
			ref := "od_HydrationData resourceID " + clean(trunc(id.String, 100))
			what := "an online-only file was downloaded because something opened it"
			if err := emit(first.Int64, "onedrive-file-downloaded (first)", "", CatFileOpening, p, "OneDrive: "+what+" (first time): "+p, ref, fields); err != nil {
				return n, err
			}
			if last.Int64 != first.Int64 {
				if err := emit(last.Int64, "onedrive-file-downloaded (last)", "", CatFileOpening, p, "OneDrive: "+what+" (last time): "+p, ref, fields); err != nil {
					return n, err
				}
			}
		}
		rows.Close()
	}

	ops := 0
	if rows, err := sqlSelect(db, "od_ServiceOperationHistory", "id", "timestamp", "operationName", "resultCode", "sizeInBytes", "scenarioName"); err == nil {
		for rows.Next() {
			var id, ts, code sql.NullInt64
			var op, scen sql.NullString
			var size sql.NullFloat64
			if rows.Scan(&id, &ts, &op, &code, &size, &scen) != nil {
				continue
			}
			ops++
			fields := map[string]any{"operation": clean(trunc(op.String, 200)), "result_code": code.Int64, "size": int64(size.Float64), "scenario": clean(trunc(scen.String, 200))}
			if err := emit(ts.Int64, "onedrive-operation", "", CatLog, "", fmt.Sprintf("OneDrive operation %s (%s), result %d", op.String, scen.String, code.Int64),
				fmt.Sprintf("od_ServiceOperationHistory id %d", id.Int64), fields); err != nil {
				return n, err
			}
		}
		rows.Close()
	}
	ctx.Note("OneDrive sync database: %d files, %d downloads of online-only files, %d client operations. Paths are built from the folder records up to the synced folder; times are those OneDrive recorded", count, hydrated, ops)
	return n, nil
}

// oneDriveSafeDelete reads SafeDelete.db.
func oneDriveSafeDelete(ctx *Context, db *sql.DB) (int, error) {
	n := 0
	emit := func(secs int64, typ, p, msg, ref string, fields map[string]any) error {
		s, ok := unixSeconds(secs)
		if !ok {
			return nil
		}
		n++
		return ctx.Emit(Event{Stamp: s, Type: typ, Category: CatDeletion, Source: "onedrive", Host: ctx.Host, Path: p, Message: msg, Fields: fields, Ref: ref})
	}
	tables := []struct {
		table, typ string
		cols       []string
		describe   func(v []sql.NullString) (string, string, map[string]any)
	}{
		{"filter_delete_info", "file-deleted (noticed by OneDrive)", []string{"notificationTime", "path", "process", "fileId", "volumeId"},
			func(v []sql.NullString) (string, string, map[string]any) {
				return v[1].String, fmt.Sprintf("Deleted in the OneDrive folder by %s: %s", v[2].String, v[1].String),
					map[string]any{"process": clean(trunc(v[2].String, 300)), "file_id": v[3].String, "volume_id": v[4].String}
			}},
		{"items_moved_to_recycle_bin", "moved to the Recycle Bin (noticed by OneDrive)", []string{"notificationTime", "itemName", "resourceId", "fileId", "volumeId"},
			func(v []sql.NullString) (string, string, map[string]any) {
				return v[1].String, "Moved to the Recycle Bin from the OneDrive folder: " + v[1].String,
					map[string]any{"resource_id": clean(trunc(v[2].String, 100)), "file_id": v[3].String, "volume_id": v[4].String}
			}},
		{"placeholder_deletes_info", "online-only file deleted (noticed by OneDrive)", []string{"notificationTime", "originalFileName", "resourceId"},
			func(v []sql.NullString) (string, string, map[string]any) {
				return v[1].String, "Online-only file deleted: " + v[1].String, map[string]any{"resource_id": clean(trunc(v[2].String, 100))}
			}},
		{"unvalidated_deletes_displayed_in_ux", "deletion shown to the user by OneDrive", []string{"notificationTime", "path", "resourceId"},
			func(v []sql.NullString) (string, string, map[string]any) {
				return v[1].String, "OneDrive showed a deletion to the user: " + v[1].String, map[string]any{"resource_id": clean(trunc(v[2].String, 100))}
			}},
		{"deletes_last_touched_by_sync_engine", "deletion handled by OneDrive", []string{"notificationTime", "resourceId"},
			func(v []sql.NullString) (string, string, map[string]any) {
				id := clean(trunc(v[1].String, 100))
				return "(OneDrive item " + id + ")", "OneDrive handled the deletion of item " + id, map[string]any{"resource_id": id}
			}},
	}
	counts := []string{}
	for _, tb := range tables {
		if len(sqlColumns(db, tb.table)) == 0 {
			continue
		}
		rows, err := sqlSelect(db, tb.table, tb.cols...)
		if err != nil {
			ctx.Warn("%s: %v", tb.table, err)
			continue
		}
		k := 0
		for rows.Next() {
			v := make([]sql.NullString, len(tb.cols))
			ptrs := make([]any, len(v))
			for i := range v {
				ptrs[i] = &v[i]
			}
			if rows.Scan(ptrs...) != nil {
				continue
			}
			var secs int64
			fmt.Sscan(v[0].String, &secs)
			p, msg, fields := tb.describe(v)
			k++
			if err := emit(secs, tb.typ, clean(trunc(p, 2000)), clean(trunc(msg, 2000)), tb.table, fields); err != nil {
				rows.Close()
				return n, err
			}
		}
		rows.Close()
		counts = append(counts, fmt.Sprintf("%s %d", tb.table, k))
	}
	ctx.Note("OneDrive SafeDelete database: %s. Each is a deletion OneDrive noticed in its folder, at the time it noticed", strings.Join(counts, ", "))
	return n, nil
}
