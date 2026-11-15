package parsers

import "testing"

// A registry name is Latin-1 or UTF-16 by a flag. Found by comparison with
// dissect.regf on a real UsrClass.dat, where keys named in other scripts
// came out as noise.
func TestStoredRegistryName(t *testing.T) {
	for _, c := range []struct {
		raw        string
		compressed bool
		want       string
	}{
		{"Software", true, "Software"},
		{"caf\xe9", true, "café"}, // Latin-1, one byte a character
		{string(wide("Software")), false, "Software"},
		{string(wide("日本語.txt")), false, "日本語.txt"},
		{string(wide("Ω")) + "\x41", false, "Ω"}, // an odd byte at the end is not a character
		{"", true, ""},
		{"", false, ""},
	} {
		if got := storedName(c.raw, c.compressed); got != c.want {
			t.Errorf("%q (compressed %v): got %q, want %q", c.raw, c.compressed, got, c.want)
		}
	}
}
