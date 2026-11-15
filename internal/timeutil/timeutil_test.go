package timeutil

import (
	"strings"
	"testing"
	"time"
)

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestFromFiletimeKnownValues(t *testing.T) {
	cases := []struct {
		ft   uint64
		want string
	}{
		{116444736000000000, "1970-01-01T00:00:00Z"},           // the Unix epoch
		{0x01D4BE26BF9A2775, "2019-02-06T14:17:53.3172597Z"},   // Security.evtx record 31878
		{0x01CA1515D3F64B54, "2009-08-04T15:11:22.811067600Z"}, // XP UserAssist sample
		{132223104000000000, "2020-01-01T00:00:00Z"},
	}
	for _, c := range cases {
		s, ok := FromFiletime(c.ft)
		if !ok {
			// 1970 is outside the plausible window by design; check that separately.
			if c.want == "1970-01-01T00:00:00Z" {
				continue
			}
			t.Errorf("FromFiletime(%d) rejected", c.ft)
			continue
		}
		want, _ := time.Parse(time.RFC3339Nano, c.want)
		if !s.UTC.Equal(want) {
			t.Errorf("FromFiletime(%#x) = %s, want %s", c.ft, s.UTC.Format(time.RFC3339Nano), c.want)
		}
		if s.ZoneFrom != ZoneNative || s.ZoneName != "UTC" || s.UTC.Location() != time.UTC {
			t.Errorf("FromFiletime(%#x) provenance = %s/%s", c.ft, s.ZoneFrom, s.ZoneName)
		}
		if !strings.Contains(s.Raw, "FILETIME 0x") {
			t.Errorf("raw value not preserved: %q", s.Raw)
		}
	}
}

func TestImplausibleValuesAreRejected(t *testing.T) {
	if _, ok := FromFiletime(0); ok {
		t.Error("zero FILETIME accepted")
	}
	if _, ok := FromFiletime(0xFFFFFFFFFFFFFFFF); ok {
		t.Error("out-of-range FILETIME accepted")
	}
	if _, ok := FromFiletime(116444736000000000); ok { // 1970: decoding noise, not evidence
		t.Error("1970 FILETIME accepted")
	}
	if _, ok := FromWebkitMicro(0); ok {
		t.Error("zero WebKit time accepted")
	}
	if _, ok := FromUnixMicro(-5, "x"); ok {
		t.Error("negative Unix time accepted")
	}
	if _, ok := FromTimeNative(time.Time{}, ""); ok {
		t.Error("zero time accepted")
	}
}

func TestFromWebkitAndUnix(t *testing.T) {
	// 13350000000000000 µs after 1601 = 1705526400 s after 1970.
	s, ok := FromWebkitMicro(13350000000000000)
	if !ok || s.UTC.Unix() != 1705526400 {
		t.Errorf("webkit: got %v ok=%v", s.UTC, ok)
	}
	if s.UTC.Format(time.RFC3339) != "2024-01-17T21:20:00Z" {
		t.Errorf("webkit: got %s", s.UTC.Format(time.RFC3339))
	}
	u, ok := FromUnixMicro(1700000000123456, "prtime")
	if !ok || u.UTC.Format(time.RFC3339Nano) != "2023-11-14T22:13:20.123456Z" {
		t.Errorf("unix micro: got %s", u.UTC.Format(time.RFC3339Nano))
	}
	if u.Raw != "prtime 1700000000123456" || u.ZoneFrom != ZoneNative {
		t.Errorf("unix micro provenance: %+v", u)
	}
}

func TestFromExplicitKeepsOffset(t *testing.T) {
	tm, _ := time.Parse(time.RFC3339, "2024-03-01T10:00:05+01:00")
	s := FromExplicit(tm, "2024-03-01T10:00:05+01:00")
	if s.UTC.Format(time.RFC3339) != "2024-03-01T09:00:05Z" || s.ZoneFrom != ZoneExplicit || s.ZoneName != "+01:00" {
		t.Errorf("got %+v", s)
	}
	tm, _ = time.Parse(time.RFC3339, "2024-03-01T10:00:05-05:30")
	if s := FromExplicit(tm, ""); s.ZoneName != "-05:30" {
		t.Errorf("negative offset name = %q", s.ZoneName)
	}
}

func wall(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFromLocalAcrossDaylightSaving(t *testing.T) {
	london := LocalContext{Loc: mustLoad(t, "Europe/London"), ZoneFrom: ZoneHost, ZoneName: "Europe/London"}
	ny := LocalContext{Loc: mustLoad(t, "America/New_York"), ZoneFrom: ZoneExaminer, ZoneName: "America/New_York"}
	cases := []struct {
		lc      LocalContext
		local   string
		wantUTC string
		caveat  string // substring, "" for none
	}{
		{london, "2024-01-15 12:00:00", "2024-01-15T12:00:00Z", ""}, // GMT
		{london, "2024-07-15 12:00:00", "2024-07-15T11:00:00Z", ""}, // BST
		{london, "2024-03-31 00:59:59", "2024-03-31T00:59:59Z", ""}, // last second of GMT
		{london, "2024-03-31 02:00:00", "2024-03-31T01:00:00Z", ""}, // first second of BST
		{london, "2024-03-31 01:30:00", "2024-03-31T01:30:00Z", "does not exist"},
		{london, "2024-10-27 00:59:59", "2024-10-26T23:59:59Z", ""}, // still BST
		{london, "2024-10-27 01:30:00", "2024-10-27T00:30:00Z", "occurs twice"},
		{london, "2024-10-27 02:00:00", "2024-10-27T02:00:00Z", ""}, // back on GMT
		{ny, "2024-11-03 01:30:00", "2024-11-03T05:30:00Z", "occurs twice"},
		{ny, "2024-03-10 02:30:00", "2024-03-10T07:30:00Z", "does not exist"},
		{ny, "2024-03-10 03:00:00", "2024-03-10T07:00:00Z", ""},
	}
	for _, c := range cases {
		s := FromLocal(wall(c.local), c.local, c.lc)
		if got := s.UTC.Format(time.RFC3339); got != c.wantUTC {
			t.Errorf("%s in %s = %s, want %s", c.local, c.lc.ZoneName, got, c.wantUTC)
		}
		if c.caveat == "" && s.Caveat != "" {
			t.Errorf("%s in %s: unexpected caveat %q", c.local, c.lc.ZoneName, s.Caveat)
		}
		if c.caveat != "" && !strings.Contains(s.Caveat, c.caveat) {
			t.Errorf("%s in %s: caveat %q, want it to mention %q", c.local, c.lc.ZoneName, s.Caveat, c.caveat)
		}
		if s.ZoneFrom != c.lc.ZoneFrom || s.ZoneName != c.lc.ZoneName || s.Raw != c.local {
			t.Errorf("%s: provenance lost: %+v", c.local, s)
		}
	}
	// The repeated hour names the other candidate so the examiner can see both.
	s := FromLocal(wall("2024-10-27 01:30:00"), "", london)
	if !strings.Contains(s.Caveat, "2024-10-27T01:30:00Z") {
		t.Errorf("caveat does not give the later instant: %q", s.Caveat)
	}
}

func TestFromLocalAssumedIsFlagged(t *testing.T) {
	s := FromLocal(wall("2024-07-15 12:00:00"), "x", AssumedUTC())
	if s.ZoneFrom != ZoneAssumed || s.UTC.Format(time.RFC3339) != "2024-07-15T12:00:00Z" {
		t.Errorf("got %+v", s)
	}
	// A context with no location must not panic and must not invent a zone.
	s = FromLocal(wall("2024-07-15 12:00:00"), "x", LocalContext{ZoneFrom: ZoneAssumed, ZoneName: "UTC"})
	if s.UTC.Format(time.RFC3339) != "2024-07-15T12:00:00Z" {
		t.Errorf("nil location: got %s", s.UTC)
	}
}

func TestWindowsZone(t *testing.T) {
	cases := map[string]string{
		"GMT Standard Time":         "Europe/London",
		"Pacific Standard Time":     "America/Los_Angeles",
		"UTC":                       "Etc/UTC",
		"AUS Eastern Standard Time": "Australia/Sydney",
		"India Standard Time":       "Asia/Calcutta", // CLDR keeps the older alias,
	}
	for win, want := range cases {
		_, iana, ok := WindowsZone(win)
		if !ok || iana != want {
			t.Errorf("WindowsZone(%q) = %q ok=%v, want %q", win, iana, ok, want)
		}
	}
	if _, _, ok := WindowsZone("Not A Zone"); ok {
		t.Error("unknown zone resolved")
	}
}

// Every entry in the generated table must name a zone the embedded IANA
// database can load, or a host's time zone would silently fail to resolve.
func TestEveryWindowsZoneLoads(t *testing.T) {
	if len(windowsZones) < 100 {
		t.Fatalf("zone table has only %d entries", len(windowsZones))
	}
	for win, iana := range windowsZones {
		if _, err := time.LoadLocation(iana); err != nil {
			t.Errorf("%q -> %q: %v", win, iana, err)
		}
	}
}
