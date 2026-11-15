package parsers

import (
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/Velocidex/ordereddict"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"
	ese "www.velocidex.com/golang/go-ese/parser"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Windows Search: the index Windows 11 keeps in SQLite (Windows.db, under
// ProgramData\Microsoft\Search\Data\Applications\Windows). Each indexed
// item has a WorkId and a set of properties, one row each, named by the
// metadata table: files and folders with the times the indexer recorded,
// browser history and shortcuts, and Windows 10 activity history. The index
// can still describe files that have since been deleted.
//
// The layout (SystemIndex_1_PropertyStore and its _Metadata table) was read
// from a public Windows.db and from SIDR (Stroz Friedberg's Windows Search
// reader, Apache-2.0), whose reports on the same file are the comparison.
// Values are decoded by their variant type (64 FILETIME, 31 text, 72 GUID,
// 21 an unsigned 64-bit integer), not guessed from the property's name.

type wsValue struct {
	name string
	vt   int64
	v    any // string, int64, uint64, float64, or a FILETIME as wsTime
}

type wsTime uint64

// wsLocalTime is a FILETIME of the device's local clock, not UTC.
type wsLocalTime uint64

// wsDates are properties Microsoft's property schema documents as dates
// that the index stores as unsigned 64-bit integers (variant type 21):
// FILETIMEs, the Local ones on the device's own clock.
var wsDates = map[string]bool{"System.ActivityHistory.StartTime": true, "System.ActivityHistory.EndTime": true}
var wsLocalDates = map[string]bool{"System.ActivityHistory.LocalStartTime": true, "System.ActivityHistory.LocalEndTime": true}

func wsDecode(vt int64, raw any) any {
	switch x := raw.(type) {
	case int64, float64:
		return x
	case string:
		return x
	case []byte:
		switch {
		case vt == 64 && len(x) == 8:
			return wsTime(binary.LittleEndian.Uint64(x))
		case (vt == 21 || vt == 20) && len(x) == 8:
			return binary.LittleEndian.Uint64(x)
		case vt == 72 && len(x) == 16:
			return "{" + guidString(x) + "}"
		case vt == 31:
			return string(x)
		}
		// UTF-16 text, as System.Kind holds, else hexadecimal.
		if len(x)%2 == 0 && len(x) >= 2 {
			u := make([]uint16, len(x)/2)
			text := true
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(x[2*i:])
				if u[i] != 0 && u[i] < 0x20 {
					text = false
				}
			}
			if text {
				var parts []string
				for _, s := range strings.Split(string(utf16.Decode(u)), "\x00") {
					if s != "" {
						parts = append(parts, s)
					}
				}
				return strings.Join(parts, "; ")
			}
		}
		if len(x) > 64 {
			x = x[:64]
		}
		return fmt.Sprintf("%X", x)
	}
	return nil
}

// windowsSearch reads the index. It returns the number of events.
func windowsSearch(ctx *Context, db *sql.DB) (int, error) {
	meta := map[int64]wsValue{}
	rows, err := db.Query(`SELECT Id, Name, VariantType FROM SystemIndex_1_PropertyStore_Metadata`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id, vt int64
		var name string
		if rows.Scan(&id, &name, &vt) == nil {
			meta[id] = wsValue{name: name, vt: vt}
		}
	}
	rows.Close()
	rows, err = db.Query(`SELECT WorkId, ColumnId, Value FROM SystemIndex_1_PropertyStore ORDER BY WorkId, ColumnId`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n, items := 0, 0
	kinds := map[string]int{}
	cur := int64(-1)
	rec := map[string]any{}
	flush := func() error {
		if len(rec) == 0 {
			return nil
		}
		items++
		k, err := wsItem(ctx, cur, rec, &n)
		kinds[k]++
		rec = map[string]any{}
		return err
	}
	for rows.Next() {
		var work, col int64
		var raw any
		if err := rows.Scan(&work, &col, &raw); err != nil {
			continue
		}
		if work != cur {
			if err := flush(); err != nil {
				return n, err
			}
			cur = work
		}
		m, ok := meta[col]
		if !ok {
			continue
		}
		v := wsDecode(m.vt, raw)
		if u, ok := v.(uint64); ok {
			switch {
			case wsDates[m.name]:
				v = wsTime(u)
			case wsLocalDates[m.name]:
				v = wsLocalTime(u)
			}
		}
		if v != nil {
			rec[m.name] = v
		}
	}
	if err := flush(); err != nil {
		return n, err
	}
	if h := wsComputer(db); h != "" {
		ctx.Fact("windows_search.computer_name", clean(trunc(h, 100)), "the computer name the index records for its items")
	}
	ctx.Note("Windows Search index: %d items (%d files and folders, %d web addresses, %d activity history entries). Its times are those the indexer recorded when it last read each item; an item can outlive the file it describes", items, kinds["file"], kinds["internet"], kinds["activity"])
	return n, nil
}

func wsComputer(db *sql.DB) string {
	var h string
	db.QueryRow(`SELECT CAST(p.Value AS TEXT) FROM SystemIndex_1_PropertyStore p JOIN SystemIndex_1_PropertyStore_Metadata m ON m.Id = p.ColumnId WHERE m.Name = 'System.ComputerName' LIMIT 1`).Scan(&h)
	return h
}

func wsStr(rec map[string]any, name string) string {
	if s, ok := rec[name].(string); ok {
		return clean(trunc(s, 2000))
	}
	return ""
}

// wsItem puts one indexed item on the timeline, and says what it was.
func wsItem(ctx *Context, work int64, rec map[string]any, n *int) (string, error) {
	kind := "file"
	switch {
	case wsStr(rec, "System.ItemType") == "ActivityHistoryItem":
		kind = "activity"
	case strings.HasPrefix(wsStr(rec, "System.Link.TargetUrl"), "http"),
		strings.HasPrefix(wsStr(rec, "System.ItemUrl"), "iehistory://"),
		strings.HasPrefix(wsStr(rec, "System.ItemUrl"), "winrt://") && strings.Contains(wsStr(rec, "System.ItemUrl"), "/Microsoft Edge/"):
		// A web address: a link to one, or the browser's own history.
		kind = "internet"
	}
	fields := map[string]any{"work_id": work, "index_kind": kind}
	keys := make([]string, 0, len(rec))
	for k := range rec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	props := map[string]any{}
	for _, k := range keys {
		switch v := rec[k].(type) {
		case wsTime:
			if s, ok := timeutil.FromFiletime(uint64(v)); ok {
				props[k] = s.UTC.Format("2006-01-02T15:04:05.0000000Z")
			}
		case wsLocalTime:
			if s, ok := timeutil.FromFiletime(uint64(v)); ok {
				props[k] = s.UTC.Format("2006-01-02T15:04:05.0000000") + " (the device's local clock)"
			}
		case string:
			props[k] = clean(trunc(v, 2000))
		default:
			props[k] = v
		}
	}
	fields["properties"] = props
	ref := fmt.Sprintf("WorkId %d", work)
	emit := func(t wsTime, typ, macb, cat, path, msg string) error {
		s, ok := timeutil.FromFiletime(uint64(t))
		if !ok {
			return nil
		}
		*n++
		return ctx.Emit(Event{Stamp: s, Type: typ, MACB: macb, Category: cat, Source: "windows-search", Host: ctx.Host,
			Path: path, Message: msg, Fields: fields, Ref: ref})
	}
	at := func(name string) wsTime {
		t, _ := rec[name].(wsTime)
		return t
	}
	path := wsStr(rec, "System.ItemPathDisplay")
	if path == "" {
		path = wsStr(rec, "System.ItemUrl")
	}
	if kind == "activity" {
		app := wsStr(rec, "System.Activity.AppDisplayName")
		if app == "" {
			app = wsStr(rec, "System.ActivityHistory.AppId")
		}
		content := wsStr(rec, "System.Activity.ContentUri")
		what := wsStr(rec, "System.Activity.DisplayText")
		target := content
		if target == "" {
			target = what
		}
		cat := CatExecution
		if content != "" {
			cat = CatFileOpening
			// The file's volume and object identifiers, as NTFS link tracking
			// records them, are in the address's query.
			if u, err := url.Parse(content); err == nil {
				q := u.Query()
				for _, k := range []string{"VolumeId", "ObjectId"} {
					if v := q.Get(k); v != "" {
						fields[map[string]string{"VolumeId": "volume_id", "ObjectId": "object_id"}[k]] = clean(trunc(v, 64))
					}
				}
			}
		}
		if err := emit(at("System.ActivityHistory.StartTime"), "activity-started", "", cat, target, fmt.Sprintf("Activity started: %s — %s", app, trunc(what, 300))); err != nil {
			return kind, err
		}
		return kind, emit(at("System.ActivityHistory.EndTime"), "activity-ended", "", cat, target, fmt.Sprintf("Activity ended: %s — %s", app, trunc(what, 300)))
	}
	// The file's own times as the indexer read them, grouped as for NTFS.
	m, a, b := at("System.DateModified"), at("System.DateAccessed"), at("System.DateCreated")
	groups := map[wsTime][]byte{}
	for i, t := range []wsTime{m, a, 0, b} {
		if t == 0 {
			continue
		}
		if groups[t] == nil {
			groups[t] = []byte("....")
		}
		groups[t][i] = "MACB"[i]
	}
	times := make([]wsTime, 0, len(groups))
	for t := range groups {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	what := "file"
	if wsStr(rec, "System.ItemType") == "Directory" {
		what = "folder"
	}
	for _, t := range times {
		mb := string(groups[t])
		if err := emit(t, "search-index "+mb, mb, CatFileSystem, path, fmt.Sprintf("Windows Search %s  %s %s, as the indexer recorded it", mb, what, path)); err != nil {
			return kind, err
		}
	}
	gathered := at("System.Search.GatherTime")
	if kind == "internet" {
		u := wsStr(rec, "System.Link.TargetUrl")
		if u == "" {
			u = wsStr(rec, "System.ItemUrl")
		}
		title := wsStr(rec, "System.Title")
		return kind, emit(gathered, "search-indexed-url", "", CatBrowser, u, fmt.Sprintf("Web address in the Windows Search index: %s %s", u, title))
	}
	return kind, emit(gathered, "search-indexed", "", CatFileSystem, path, fmt.Sprintf("Indexed by Windows Search: %s %s", what, path))
}

// windowsSearchESE reads the index as Windows 10 and earlier keep it, in
// an ESE database (Windows.edb): one row an item, one column a property,
// named "<id>-System_ItemPathDisplay". ESE records no variant type, so an
// 8-byte value is taken as a FILETIME when its property is a date or time,
// as SIDR does; the Local ones are the device's clock.
func windowsSearchESE(ctx *Context, cat *ese.Catalog) (int, error) {
	n, items := 0, 0
	kinds := map[string]int{}
	computer := ""
	err := dumpTable(cat, "SystemIndex_PropertyStore", func(row *ordereddict.Dict) error {
		rec := map[string]any{}
		var work int64
		for _, col := range row.Keys() {
			v, _ := row.Get(col)
			if col == "WorkID" {
				switch x := v.(type) {
				case uint32:
					work = int64(x)
				case int32:
					work = int64(x)
				case int64:
					work = x
				}
				continue
			}
			i := strings.IndexByte(col, '-')
			if i < 0 || !strings.HasPrefix(col[i+1:], "System_") {
				continue
			}
			name := strings.ReplaceAll(col[i+1:], "_", ".")
			switch x := v.(type) {
			case nil:
			case string:
				// The library gives some binary columns as hexadecimal text.
				dated := (strings.Contains(name, "Date") || strings.Contains(name, "Time")) && !strings.Contains(name, "Duration")
				if b, err := hex.DecodeString(x); err == nil && len(x) == 16 && dated {
					if wsLocalDates[name] {
						rec[name] = wsLocalTime(binary.LittleEndian.Uint64(b))
					} else {
						rec[name] = wsTime(binary.LittleEndian.Uint64(b))
					}
				} else if x != "" {
					rec[name] = x
				}
			case []byte:
				if len(x) == 0 {
					continue
				}
				dated := (strings.Contains(name, "Date") || strings.Contains(name, "Time")) && !strings.Contains(name, "Duration")
				switch {
				case len(x) == 8 && wsLocalDates[name]:
					rec[name] = wsLocalTime(binary.LittleEndian.Uint64(x))
				case len(x) == 8 && dated:
					rec[name] = wsTime(binary.LittleEndian.Uint64(x))
				case len(x) == 8:
					rec[name] = binary.LittleEndian.Uint64(x)
				case len(x) == 16 && (strings.HasSuffix(name, "Id") || strings.HasSuffix(name, "ID")):
					rec[name] = "{" + guidString(x) + "}"
				default:
					rec[name] = wsDecode(65, x)
				}
			case int8, int16, int32, int64, uint8, uint16, uint32, uint64:
				rec[name] = fmt.Sprint(x)
			case bool, float32, float64:
				rec[name] = fmt.Sprint(x)
			}
		}
		if len(rec) == 0 {
			return nil
		}
		if computer == "" {
			computer = wsStr(rec, "System.ComputerName")
		}
		items++
		k, err := wsItem(ctx, work, rec, &n)
		kinds[k]++
		return err
	})
	if computer != "" {
		ctx.Fact("windows_search.computer_name", clean(trunc(computer, 100)), "the computer name the index records for its items")
	}
	ctx.Note("Windows Search index (ESE): %d items (%d files and folders, %d web addresses, %d activity history entries). Its times are those the indexer recorded when it last read each item; an item can outlive the file it describes", items, kinds["file"], kinds["internet"], kinds["activity"])
	return n, err
}
