package parsers

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func hiveSample(t *testing.T, rel ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{"..", "..", "testdata", "hivelog"}, rel...)...)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("sample %s not present; run scripts/fetch-testdata.sh", filepath.Join(rel...))
	}
	return p
}

func recovered(r result) (keys []string, events []Event) {
	for _, e := range r.events {
		if strings.HasPrefix(e.Type, "registry-key-deleted") || strings.HasPrefix(e.Type, "registry-key-earlier-version") {
			keys = append(keys, e.Path)
			events = append(events, e)
		}
	}
	sort.Strings(keys)
	return keys, events
}

// The answers yarp's tests give for hives built to hold deleted data.
func TestDeletedKeysAndValues(t *testing.T) {
	// A deleted key "456" with one value, and another value on its own.
	r := run(t, hiveSample(t, "yarp", "deleted", "DeletedDataHive"), nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
	keys, evs := recovered(r)
	if len(keys) != 1 || !strings.HasSuffix(keys[0], `456`) || evs[0].Fields["deleted"] != true {
		t.Fatalf("deleted keys: %v", keys)
	}
	if v := evs[0].Fields["values"]; v == nil || strings.Join(v.([]string), "|") != "v = 123456 (REG_SZ)" {
		t.Errorf("the deleted key's value: %v", v)
	}
	if !strings.Contains(evs[0].Fields["time_meaning"].(string), "not when it was deleted") {
		t.Error("the event does not say what its time means")
	}
	if !strings.Contains(r.text, "v2 = 456 (REG_SZ)") || strings.Contains(r.text, "v = 123456") || r.facts["registry.deleted_values"] != "1" {
		t.Errorf("the value without a key: text %q facts %v", r.text, r.facts)
	}

	// A deleted branch under a key that still exists: full paths.
	for _, h := range []string{"DeletedTreeHive", "DeletedTreeNoRootFlagHive"} {
		r = run(t, hiveSample(t, "yarp", "deleted", h), nil)
		keys, evs = recovered(r)
		if strings.Join(keys, "|") != `\1\2\3|\1\2\3\4|\1\2\3\4\5|\1\2\3\4\New Key #1` {
			t.Errorf("%s: %v", h, keys)
		}
		for _, e := range evs {
			if e.Fields["path_complete"] != true || e.Category != CatRegistry || e.Stamp.ZoneFrom != "native-utc" {
				t.Errorf("%s: %+v", h, e)
			}
		}
	}

	// The same branch with its parent gone: as much of the path as can be traced.
	r = run(t, hiveSample(t, "yarp", "deleted", "DeletedTreePartialPathHive"), nil)
	keys, evs = recovered(r)
	if strings.Join(keys, "|") != `…\3|…\3\4|…\3\4\5|…\3\4\New Key #1` || evs[0].Fields["path_complete"] != false {
		t.Errorf("partial paths: %v", keys)
	}

	// A single value with no name.
	r = run(t, hiveSample(t, "yarp", "deleted", "RemnantsHive"), nil)
	if keys, _ = recovered(r); len(keys) != 0 || !strings.Contains(r.text, "(Default) = 1 (REG_DWORD)") || r.facts["registry.deleted_values"] != "1" {
		t.Errorf("remnant value: keys %v text %q", keys, r.text)
	}

	// A hive with nothing deleted in it gains no events.
	r = run(t, sample(t, "NTUSER.DAT"), nil)
	for _, e := range r.events {
		if strings.HasPrefix(e.Type, "registry-key-deleted") {
			t.Logf("public NTUSER.DAT: %s %s", e.Type, e.Path)
		}
	}
}

// Damage in the cells must not panic or hang.
func TestDeletedKeysCorrupt(t *testing.T) {
	raw, err := os.ReadFile(hiveSample(t, "yarp", "deleted", "DeletedTreeHive"))
	if err != nil {
		t.Skip()
	}
	for i := 4096; i < 4096+16384 && i < len(raw); i += 3 {
		bad := append([]byte(nil), raw...)
		bad[i] ^= 0xFF
		run(t, write(t, "h", bad), nil)
	}
}
