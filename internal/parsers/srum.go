package parsers

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/timeutil"

	"github.com/Velocidex/ordereddict"
	ese "www.velocidex.com/golang/go-ese/parser"
)

// srumParser reads the System Resource Usage Monitor database
// (Windows\System32\sru\SRUDB.dat). Windows records, roughly once an hour
// and at shutdown, which programs ran, under which account, and how much
// they read, wrote, sent and received. It keeps about a month of history and
// includes programs that have since been deleted, which makes it evidence of
// both execution and data transfer.
//
// The time on a usage record is when Windows wrote the record, not when the
// program started: the activity happened in the hour or so before it. Each
// event's type says "recorded" for that reason.
type srumParser struct{}

func (srumParser) Name() string { return "srum" }
func (srumParser) Version() string {
	return "7 (velocidex/go-ese 458e8ab; Windows Search Windows.edb; record times rounded, not cut; program named in activity records; push notification, energy and vfuprov tables)"
}

const (
	srumAppUsage   = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
	srumNetUsage   = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
	srumNetConnect = "{DD6636C4-8929-4683-974E-22C046A43763}"
	srumTimeline   = "{5C8CF1C7-7257-4F13-B223-970EF5939312}"
	srumVfu        = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}"
	srumPush       = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
	srumEnergy     = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"
	srumEnergyLT   = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT"
)

func num(row *ordereddict.Dict, key string) uint64 {
	v, _ := row.Get(key)
	switch x := v.(type) {
	case uint64:
		return x
	case int64:
		return uint64(x)
	case int32:
		return uint64(uint32(x))
	case uint32:
		return uint64(x)
	case int16:
		return uint64(uint16(x))
	case uint16:
		return uint64(x)
	case uint8:
		return uint64(x)
	case int:
		return uint64(x)
	}
	return 0
}

// sidString renders a binary security identifier as S-1-5-21-...
func sidString(b []byte) string {
	if len(b) < 8 || b[0] != 1 || int(b[1]) > 15 || len(b) < 8+4*int(b[1]) {
		return ""
	}
	auth := uint64(0)
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s
}

// dumpTable reads every row of a table. The library panics on a row it
// cannot decode, which a database copied from a running system can contain;
// that ends the table with an error, keeping the rows already read.
func dumpTable(cat *ese.Catalog, name string, cb func(row *ordereddict.Dict) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("a row could not be decoded (%v)", r)
		}
	}()
	return cat.DumpTable(name, cb)
}

// srumIDs reads the table that maps the numbers used in every other table
// to application paths, service names and account identifiers.
func srumIDs(cat *ese.Catalog) (map[uint64]string, error) {
	ids := map[uint64]string{}
	err := dumpTable(cat, "SruDbIdMapTable", func(row *ordereddict.Dict) error {
		blob, _ := row.GetString("IdBlob")
		raw, err := hex.DecodeString(blob)
		if err != nil || len(raw) == 0 {
			return nil
		}
		var name string
		if num(row, "IdType") == 3 {
			name = sidString(raw)
		} else {
			u := make([]uint16, 0, len(raw)/2)
			for i := 0; i+1 < len(raw); i += 2 {
				if c := binary.LittleEndian.Uint16(raw[i:]); c != 0 {
					u = append(u, c)
				}
			}
			name = clean(string(utf16.Decode(u)))
		}
		if name != "" {
			ids[num(row, "IdIndex")] = name
		}
		return nil
	})
	return ids, err
}

func (srumParser) Parse(ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	// The library reads a few bytes at a time, thousands of times per page.
	// Straight from the file that is one system call each, which made a real
	// 49 MB database take many minutes; from memory it takes seconds. SRUM
	// databases are tens of megabytes, so anything huge is read from the file.
	var src io.ReaderAt = ctx.File
	if ctx.Size <= 1<<30 {
		whole, rerr := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
		if rerr != nil {
			return rerr
		}
		src = bytes.NewReader(whole)
	}
	ectx, err := ese.NewESEContext(src, ctx.Size)
	if err != nil {
		return err
	}
	cat, err := ese.ReadCatalog(ectx)
	if err != nil {
		return err
	}
	if _, ok := cat.Tables.Get("SystemIndex_PropertyStore"); ok {
		n, err := windowsSearchESE(ctx, cat)
		if err != nil {
			ctx.Warn("windows search index: %v", err)
		}
		if n == 0 {
			return ErrNothingExtracted
		}
		return nil
	}
	if _, ok := cat.Tables.Get("SruDbIdMapTable"); !ok {
		// An ESE database that is not SRUM: a search index, a browser cache,
		// a directory database. Generic handling takes it.
		ctx.Note("ESE database with tables Atropos has no parser for: %s", trunc(strings.Join(cat.Tables.Keys(), ", "), 400))
		return ErrNothingExtracted
	}
	ids, err := srumIDs(cat)
	if err != nil {
		ctx.Warn("the table of application and user names could not be read in full: %v", err)
	}
	name := func(row *ordereddict.Dict, key string) string {
		id := num(row, key)
		if n, ok := ids[id]; ok {
			return n
		}
		return fmt.Sprintf("(SRUM id %d)", id)
	}
	emitted := 0
	table := func(guid string, each func(row *ordereddict.Dict, ref string) (Event, bool)) error {
		if _, ok := cat.Tables.Get(guid); !ok {
			return nil
		}
		rawTimeStamp(cat, guid)
		rows := 0
		var emitErr error
		derr := dumpTable(cat, guid, func(row *ordereddict.Dict) error {
			rows++
			ev, ok := each(row, fmt.Sprintf("table %s, AutoIncId %d", guid, num(row, "AutoIncId")))
			if !ok {
				return nil
			}
			emitted++
			emitErr = ctx.Emit(ev)
			return emitErr
		})
		if emitErr != nil {
			return emitErr
		}
		if derr != nil {
			ctx.Warn("table %s: reading stopped after %d rows: %v", guid, rows, derr)
		}
		return nil
	}
	recorded := func(row *ordereddict.Dict) (timeutil.Stamp, bool) {
		v, _ := row.Get("TimeStamp")
		switch t := v.(type) {
		case float64:
			return oleStamp(t)
		case time.Time:
			return timeutil.FromTimeNative(t, "")
		}
		return timeutil.Stamp{}, false
	}

	if err := table(srumAppUsage, func(row *ordereddict.Dict, ref string) (Event, bool) {
		stamp, ok := recorded(row)
		if !ok {
			return Event{}, false
		}
		app, user := name(row, "AppId"), name(row, "UserId")
		fg, bg := num(row, "ForegroundCycleTime"), num(row, "BackgroundCycleTime")
		return Event{
			Stamp: stamp, Type: "srum-application-usage-recorded", Category: CatExecution, Source: "srum",
			Host: ctx.Host, User: user, Path: app,
			Message: fmt.Sprintf("SRUM: %s ran as %s in the period before this record (read %d bytes, wrote %d bytes)", app, user,
				num(row, "ForegroundBytesRead")+num(row, "BackgroundBytesRead"), num(row, "ForegroundBytesWritten")+num(row, "BackgroundBytesWritten")),
			Fields: map[string]any{
				"application": app, "user": user, "foreground_cycle_time": fg, "background_cycle_time": bg,
				"foreground_bytes_read": num(row, "ForegroundBytesRead"), "foreground_bytes_written": num(row, "ForegroundBytesWritten"),
				"background_bytes_read": num(row, "BackgroundBytesRead"), "background_bytes_written": num(row, "BackgroundBytesWritten"),
				"face_time": num(row, "FaceTime"),
			},
			Ref: ref,
		}, true
	}); err != nil {
		return err
	}
	if err := table(srumNetUsage, func(row *ordereddict.Dict, ref string) (Event, bool) {
		stamp, ok := recorded(row)
		if !ok {
			return Event{}, false
		}
		app, user := name(row, "AppId"), name(row, "UserId")
		sent, recv := num(row, "BytesSent"), num(row, "BytesRecvd")
		return Event{
			Stamp: stamp, Type: "srum-network-usage-recorded", Category: CatNetwork, Source: "srum",
			Host: ctx.Host, User: user, Path: app,
			Message: fmt.Sprintf("SRUM: %s as %s sent %d bytes and received %d bytes in the period before this record", app, user, sent, recv),
			Fields: map[string]any{"application": app, "user": user, "bytes_sent": sent, "bytes_received": recv,
				"interface_luid": num(row, "InterfaceLuid"), "l2_profile_id": num(row, "L2ProfileId")},
			Ref: ref,
		}, true
	}); err != nil {
		return err
	}
	if err := table(srumNetConnect, func(row *ordereddict.Dict, ref string) (Event, bool) {
		// Unlike the usage tables this one records a true start time.
		stamp, ok := timeutil.FromFiletime(num(row, "ConnectStartTime"))
		if !ok {
			return Event{}, false
		}
		secs := num(row, "ConnectedTime")
		return Event{
			Stamp: stamp, Type: "srum-network-connected", Category: CatNetwork, Source: "srum", Host: ctx.Host,
			Message: fmt.Sprintf("SRUM: network connection started, lasting %d seconds (profile %d)", secs, num(row, "L2ProfileId")),
			Fields:  map[string]any{"connected_seconds": secs, "interface_luid": num(row, "InterfaceLuid"), "l2_profile_id": num(row, "L2ProfileId")},
			Ref:     ref,
		}, true
	}); err != nil {
		return err
	}
	if err := table(srumTimeline, func(row *ordereddict.Dict, ref string) (Event, bool) {
		stamp, ok := timeutil.FromFiletime(num(row, "EndTime"))
		if !ok {
			return Event{}, false
		}
		stored, user := name(row, "AppId"), name(row, "UserId")
		ms := num(row, "DurationMS")
		fields := map[string]any{"user": user, "duration_ms": ms}
		app := srumProgram(stored, fields)
		return Event{
			Stamp: stamp, Type: "srum-application-activity-ended", Category: CatExecution, Source: "srum",
			Host: ctx.Host, User: user, Path: app,
			Message: fmt.Sprintf("SRUM: a period of activity by %s as %s ended, after %.1f seconds", app, user, float64(ms)/1000),
			Fields:  fields,
			Ref:     ref,
		}, true
	}); err != nil {
		return err
	}
	// What the "vfuprov" provider measures is not documented; SrumECmd
	// reads it the same way. Each row is a period for one application.
	if err := table(srumVfu, func(row *ordereddict.Dict, ref string) (Event, bool) {
		stamp, ok := timeutil.FromFiletime(num(row, "EndTime"))
		if !ok {
			return Event{}, false
		}
		stored, user := name(row, "AppId"), name(row, "UserId")
		fields := map[string]any{"user": user, "flags": num(row, "Flags"),
			"table_note": "the vfuprov table: Windows does not document what it measures"}
		if st, ok := timeutil.FromFiletime(num(row, "StartTime")); ok {
			fields["period_start"] = st.UTC.Format("2006-01-02T15:04:05.0000000Z")
			fields["period_seconds"] = float64(num(row, "EndTime")-num(row, "StartTime")) / 1e7
		}
		app := srumProgram(stored, fields)
		return Event{
			Stamp: stamp, Type: "srum-usage-period-ended (vfuprov)", Category: CatExecution, Source: "srum",
			Host: ctx.Host, User: user, Path: app,
			Message: fmt.Sprintf("SRUM (vfuprov): a period recorded for %s as %s ended", app, user),
			Fields:  fields, Ref: ref,
		}, true
	}); err != nil {
		return err
	}
	if err := table(srumPush, func(row *ordereddict.Dict, ref string) (Event, bool) {
		stamp, ok := recorded(row)
		if !ok {
			return Event{}, false
		}
		stored, user := name(row, "AppId"), name(row, "UserId")
		fields := map[string]any{"user": user, "notification_type": num(row, "NotificationType"),
			"payload_bytes": num(row, "PayloadSize"), "network_type": num(row, "NetworkType")}
		app := srumProgram(stored, fields)
		return Event{
			Stamp: stamp, Type: "srum-push-notification-recorded", Category: CatNetwork, Source: "srum",
			Host: ctx.Host, User: user, Path: app,
			Message: fmt.Sprintf("SRUM: a push notification of %d bytes for %s as %s, in the period before this record", num(row, "PayloadSize"), app, user),
			Fields:  fields, Ref: ref,
		}, true
	}); err != nil {
		return err
	}
	for _, g := range []string{srumEnergy, srumEnergyLT} {
		longTerm := g == srumEnergyLT
		if err := table(g, func(row *ordereddict.Dict, ref string) (Event, bool) {
			stamp, ok := recorded(row)
			if !ok {
				return Event{}, false
			}
			fields := map[string]any{"long_term": longTerm}
			for _, c := range []string{"ChargeLevel", "DesignedCapacity", "FullChargedCapacity", "CycleCount", "StateTransition",
				"ActiveAcTime", "ActiveDcTime", "ActiveDischargeTime", "ActiveEnergy", "CsAcTime", "CsDcTime", "CsDischargeTime", "CsEnergy"} {
				if v, ok := row.Get(c); ok && v != nil {
					fields[strings.ToLower(c[:1])+c[1:]] = num(row, c)
				}
			}
			if et, ok := timeutil.FromFiletime(num(row, "EventTimestamp")); ok {
				fields["state_changed"] = et.UTC.Format("2006-01-02T15:04:05.0000000Z")
			}
			what := "battery and power state"
			if longTerm {
				what = "long-term battery and power totals"
			}
			return Event{
				Stamp: stamp, Type: "srum-energy-recorded", Category: CatLog, Source: "srum", Host: ctx.Host,
				Message: "SRUM: " + what + " recorded", Fields: fields, Ref: ref,
			}, true
		}); err != nil {
			return err
		}
	}
	if emitted == 0 {
		return ErrNothingExtracted
	}
	ctx.Note("SRUM usage records are written about once an hour: each is timed when Windows recorded it, and the activity it describes happened in the period before")
	return nil
}

// rawTimeStamp asks the library for a table's TimeStamp column as the number
// it is stored as. SRUM stores it as an OLE date, a count of days held in a
// double, and the library cuts that to whole seconds: a time written as
// 19:55:00 and stored a fraction of a microsecond short comes back as
// 19:54:59. Reading the number and rounding it here avoids that.
func rawTimeStamp(cat *ese.Catalog, guid string) {
	v, _ := cat.Tables.Get(guid)
	t, ok := v.(*ese.Table)
	if !ok || t == nil {
		return
	}
	for _, c := range t.Columns {
		if c != nil && c.Name == "TimeStamp" && c.Type == "DateTime" && c.Flags == 0 && c.SpaceUsage == 8 {
			c.Type = "Double precision FP"
		}
	}
}

// oleStamp converts an OLE date. A double of days is good to under a
// microsecond at present-day dates, so the result is rounded to the nearest
// millisecond. Some writers put a FILETIME in the same column; read as a
// double that is a vanishingly small number, and it is taken as a FILETIME.
func oleStamp(days float64) (timeutil.Stamp, bool) {
	if !(days > 1.0) {
		return timeutil.FromFiletime(math.Float64bits(days))
	}
	if days > 110000 { // past the year 2200
		return timeutil.Stamp{}, false
	}
	const unixEpochDays = 25569 // 30 December 1899 to 1 January 1970
	ms := math.Round((days - unixEpochDays) * 86400 * 1000)
	return timeutil.FromTimeNative(time.UnixMilli(int64(ms)).UTC(), "")
}

// srumProgram names the program in an application identifier and sets the
// application fields. The activity table identifies a program as
// "!!name!link time!checksum!services": the name is what an examiner looks
// for, and the rest is kept beside it. Any other identifier is the name.
func srumProgram(stored string, fields map[string]any) string {
	fields["application"] = stored
	parts := strings.Split(stored, "!")
	if !strings.HasPrefix(stored, "!!") || len(parts) < 5 || parts[2] == "" {
		return stored
	}
	fields["application"], fields["application_stored"] = parts[2], stored
	if parts[3] != "" {
		// Written as the image's link time, with no zone; it is not a time anything happened.
		fields["program_link_time"] = parts[3]
	}
	if len(parts) > 5 && parts[5] != "" {
		fields["services"] = strings.Join(parts[5:], "!")
	}
	return parts[2]
}
