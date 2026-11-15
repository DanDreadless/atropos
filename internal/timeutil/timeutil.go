// Package timeutil normalises every timestamp the tool touches to UTC and
// records how the zone was established, so an examiner can tell a timestamp
// that is UTC by definition from one that relied on an assumption.
package timeutil

import (
	"fmt"
	"time"
	_ "time/tzdata" // embed the IANA database so the binary is self-contained
)

// Zone provenance values stored with every event.
const (
	// ZoneNative: the format defines the value as UTC (FILETIME, EVTX, WebKit time).
	ZoneNative = "native-utc"
	// ZoneExplicit: the source value carried its own UTC offset.
	ZoneExplicit = "explicit-offset"
	// ZoneHost: local time converted using the zone read from the host's own
	// registry hive present in the case.
	ZoneHost = "host-registry"
	// ZoneExaminer: local time converted using a zone the examiner stated for
	// the case. The statement is recorded in the audit log.
	ZoneExaminer = "examiner-set"
	// ZoneAssumed: the source had no zone and none could be established; the
	// case default was applied. These events need examiner attention.
	ZoneAssumed = "assumed"
)

// Stamp is a timestamp normalised to UTC with its provenance.
type Stamp struct {
	UTC      time.Time // always in UTC
	Raw      string    // the value as it appeared in the source
	ZoneFrom string    // one of the Zone* constants
	ZoneName string    // zone applied, e.g. "UTC", "+01:00", "Europe/London"
	// Caveat is set when the conversion to UTC was not unique (a local time
	// falling in a daylight-saving change). It is stored with the event.
	Caveat string
}

const filetimeEpochDelta = 116444736000000000 // 100ns ticks between 1601 and 1970

// FromFiletime converts a Windows FILETIME (100ns ticks since 1601-01-01 UTC).
// ok is false for zero or out-of-range values, which carry no information.
func FromFiletime(ft uint64) (Stamp, bool) {
	if ft == 0 || ft > 0x7FFFFFFFFFFFFFFF {
		return Stamp{}, false
	}
	ticks := int64(ft) - filetimeEpochDelta
	t := time.Unix(ticks/10000000, (ticks%10000000)*100).UTC()
	if !Plausible(t) {
		return Stamp{}, false
	}
	return Stamp{UTC: t, Raw: fmt.Sprintf("FILETIME 0x%016X", ft), ZoneFrom: ZoneNative, ZoneName: "UTC"}, true
}

// FromTimeNative wraps a time.Time that a parser decoded from a format which
// is UTC by definition.
func FromTimeNative(t time.Time, raw string) (Stamp, bool) {
	if t.IsZero() || !Plausible(t) {
		return Stamp{}, false
	}
	if raw == "" {
		raw = t.UTC().Format(time.RFC3339Nano)
	}
	return Stamp{UTC: t.UTC(), Raw: raw, ZoneFrom: ZoneNative, ZoneName: "UTC"}, true
}

// FromUnixMicro converts microseconds since the Unix epoch (UTC by definition).
func FromUnixMicro(us int64, label string) (Stamp, bool) {
	if us <= 0 {
		return Stamp{}, false
	}
	t := time.UnixMicro(us).UTC()
	if !Plausible(t) {
		return Stamp{}, false
	}
	return Stamp{UTC: t, Raw: fmt.Sprintf("%s %d", label, us), ZoneFrom: ZoneNative, ZoneName: "UTC"}, true
}

// FromWebkitMicro converts microseconds since 1601-01-01 UTC (Chromium).
func FromWebkitMicro(us int64) (Stamp, bool) {
	if us <= 0 {
		return Stamp{}, false
	}
	const delta = 11644473600000000
	t := time.UnixMicro(us - delta).UTC()
	if !Plausible(t) {
		return Stamp{}, false
	}
	return Stamp{UTC: t, Raw: fmt.Sprintf("webkit-us %d", us), ZoneFrom: ZoneNative, ZoneName: "UTC"}, true
}

// FromExplicit wraps a time parsed from a value that carried its own offset.
func FromExplicit(t time.Time, raw string) Stamp {
	_, off := t.Zone()
	return Stamp{UTC: t.UTC(), Raw: raw, ZoneFrom: ZoneExplicit, ZoneName: offsetName(off)}
}

// LocalContext describes what is known about the zone of zoneless local
// timestamps for the evidence being parsed.
type LocalContext struct {
	Loc      *time.Location // zone to apply
	ZoneFrom string         // ZoneHost or ZoneAssumed
	ZoneName string
}

// AssumedUTC is the fallback context when nothing better is known.
func AssumedUTC() LocalContext {
	return LocalContext{Loc: time.UTC, ZoneFrom: ZoneAssumed, ZoneName: "UTC"}
}

// FromLocal interprets a zoneless wall-clock time in the given context.
// The wall-clock fields of t are used; its location is ignored.
//
// A wall-clock time does not always name exactly one instant. When clocks go
// back it occurs twice, and when they go forward it does not occur at all.
// Neither case is resolved silently: the earlier instant is used for a
// repeated time, the pre-change offset for a skipped one, and Caveat says so.
func FromLocal(t time.Time, raw string, lc LocalContext) Stamp {
	loc := lc.Loc
	if loc == nil {
		loc = time.UTC
	}
	// The wall clock read as if it were UTC; subtracting a zone offset gives
	// the instant that offset would place it at.
	naive := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	_, before := naive.Add(-36 * time.Hour).In(loc).Zone()
	_, after := naive.Add(36 * time.Hour).In(loc).Zone()
	var valid []time.Time
	for _, off := range []int{before, after} {
		c := naive.Add(-time.Duration(off) * time.Second)
		if _, got := c.In(loc).Zone(); got == off && (len(valid) == 0 || !valid[0].Equal(c)) {
			valid = append(valid, c)
		}
	}
	s := Stamp{Raw: raw, ZoneFrom: lc.ZoneFrom, ZoneName: lc.ZoneName}
	switch len(valid) {
	case 1:
		s.UTC = valid[0]
	case 2:
		if valid[1].Before(valid[0]) {
			valid[0], valid[1] = valid[1], valid[0]
		}
		s.UTC = valid[0]
		s.Caveat = fmt.Sprintf("local time occurs twice in %s (clocks went back); the earlier instant was used, the later is %s",
			lc.ZoneName, valid[1].Format(time.RFC3339Nano))
	default:
		s.UTC = naive.Add(-time.Duration(before) * time.Second)
		s.Caveat = fmt.Sprintf("local time does not exist in %s (clocks went forward); the offset in force before the change was applied", lc.ZoneName)
	}
	return s
}

// WindowsZone resolves a Windows time zone key name (as stored in the SYSTEM
// hive) to an IANA location.
func WindowsZone(name string) (*time.Location, string, bool) {
	iana, ok := windowsZones[name]
	if !ok {
		return nil, "", false
	}
	loc, err := time.LoadLocation(iana)
	if err != nil {
		return nil, "", false
	}
	return loc, iana, true
}

// Plausible rejects timestamps that are almost certainly decoding noise.
func Plausible(t time.Time) bool {
	y := t.UTC().Year()
	return y >= 1980 && y <= 2100
}

func offsetName(off int) string {
	if off == 0 {
		return "UTC"
	}
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	return fmt.Sprintf("%s%02d:%02d", sign, off/3600, (off%3600)/60)
}
