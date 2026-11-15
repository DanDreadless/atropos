package parsers

import "strings"

// knownFolderPaths are the Windows known-folder identifiers that Explorer puts
// at the front of a path instead of the folder itself (in UserAssist, among
// other places), with where each points on a default installation. They are
// Microsoft's KNOWNFOLDERID values. The folder is given in the form of the
// environment variable an examiner would expect, since the real location
// can be redirected and is not recorded with the entry.
var knownFolderPaths = map[string]string{
	"{F38BF404-1D43-42F2-9305-67DE0B28FC23}": `%SystemRoot%`,
	"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": `%SystemRoot%\System32`,
	"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": `%SystemRoot%\SysWOW64`,
	"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": `%ProgramFiles%`,
	"{6D809377-6AF0-444B-8957-A3773F02200E}": `%ProgramFiles%`,
	"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": `%ProgramFiles(x86)%`,
	"{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": `%ProgramData%`,
	"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": `%LOCALAPPDATA%`,
	"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": `%APPDATA%`,
	"{5E6C858F-0E22-4760-9AFE-EA3317B67173}": `%USERPROFILE%`,
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": `%USERPROFILE%\Desktop`,
	"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": `%USERPROFILE%\Documents`,
	"{374DE290-123F-4565-9164-39C4925E467B}": `%USERPROFILE%\Downloads`,
	"{DFDF76A2-C82A-4D63-906A-5644AC457385}": `%PUBLIC%`,
	"{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": `%PUBLIC%\Desktop`,
	"{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": `%APPDATA%\Microsoft\Windows\Start Menu`,
	"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": `%APPDATA%\Microsoft\Windows\Start Menu\Programs`,
	"{A4115719-D62E-491D-AA7C-E74B8BE3B067}": `%ProgramData%\Microsoft\Windows\Start Menu`,
	"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": `%ProgramData%\Microsoft\Windows\Start Menu\Programs`,
	"{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": `%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned`,
}

// knownFolderPath replaces a known-folder identifier at the front of a path
// with the folder it stands for. ok is false when the path does not begin
// with one that is known, and the path is then returned as it came.
func knownFolderPath(p string) (string, bool) {
	if len(p) < 38 || p[0] != '{' || p[37] != '}' {
		return p, false
	}
	folder, ok := knownFolderPaths[strings.ToUpper(p[:38])]
	if !ok {
		return p, false
	}
	return folder + p[38:], true
}
