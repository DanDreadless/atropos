package parsers

import "testing"

func TestKnownFolderPath(t *testing.T) {
	for in, want := range map[string]string{
		`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe`:     `%SystemRoot%\System32\cmd.exe`,
		`{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}\cmd.exe`:     `%SystemRoot%\System32\cmd.exe`,
		`{374DE290-123F-4565-9164-39C4925E467B}\tool.exe`:    `%USERPROFILE%\Downloads\tool.exe`,
		`{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\App\app.exe`: `%ProgramFiles(x86)%\App\app.exe`,
		// Not one that is known, not an identifier, and one cut short.
		`{00000000-0000-0000-0000-000000000000}\other.exe`: `{00000000-0000-0000-0000-000000000000}\other.exe`,
		`C:\Windows\notepad.exe`:                           `C:\Windows\notepad.exe`,
		`Microsoft.Windows.Explorer`:                       `Microsoft.Windows.Explorer`,
		`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7`:            `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7`,
	} {
		got, ok := knownFolderPath(in)
		if got != want || ok != (got != in) {
			t.Errorf("%s: got %s (%v), want %s", in, got, ok, want)
		}
	}
}
