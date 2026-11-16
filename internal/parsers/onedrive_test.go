package parsers

import (
	"strings"
	"testing"
)

// The tables of a Windows 11 OneDrive client's databases, cut down to the
// columns read (and one table with a column missing, as older clients have).
func TestOneDriveSyncDatabase(t *testing.T) {
	p := makeDB(t, "SyncEngineDatabase.db",
		`CREATE TABLE od_ScopeInfo_Records(scopeID TEXT, scopeType INTEGER, lastKnownFolderPath TEXT, webURL TEXT)`,
		`CREATE TABLE od_ClientFolder_Records(resourceID TEXT, parentResourceID TEXT, folderName TEXT)`,
		`CREATE TABLE od_ClientFile_Records(resourceID TEXT, parentResourceID TEXT, fileName TEXT, size INTEGER, lastChange INTEGER, serverLastChange INTEGER,
			diskLastAccessTime INTEGER, diskCreationTime INTEGER, mediaDateTaken INTEGER, locallyDeleted INTEGER, serverDeleted INTEGER,
			localHashDigest BLOB, localHashAlgorithm INTEGER)`,
		`CREATE TABLE od_HydrationData(resourceID TEXT, firstHydrationTime INTEGER, lastHydrationTime INTEGER, hydrationCount INTEGER, lastHydrationType TEXT)`,
		`CREATE TABLE od_ServiceOperationHistory(id INTEGER, timestamp INTEGER, scopeId TEXT, operationName TEXT, resultCode INTEGER, sizeInBytes REAL, scenarioName TEXT)`,
		`INSERT INTO od_ScopeInfo_Records VALUES ('ROOT',3,'C:\Users\someone\OneDrive','https://onedrive.live.com/?cid=x')`,
		`INSERT INTO od_ClientFolder_Records VALUES ('F1','ROOT','Documents'),('F2','F1','Plans'),('LOOP','LOOP','Odd')`,
		// 1714564800 = 2024-05-01T12:00:00Z
		`INSERT INTO od_ClientFile_Records VALUES ('A','F2','budget.xlsx',1234,1714564800,1714564900,1714651200,1714478400,0,0,1,x'ABCD',5)`,
		`INSERT INTO od_ClientFile_Records VALUES ('B','GONE','orphan.txt',1,1714564800,0,1714564800,1714564800,1714000000,1,0,NULL,0)`,
		`INSERT INTO od_ClientFile_Records VALUES ('C','LOOP','odd.txt',1,1714564800,0,0,0,0,0,0,NULL,0)`,
		`INSERT INTO od_HydrationData VALUES ('A',1714600000,1714700000,3,'UserInitiated')`,
		`INSERT INTO od_ServiceOperationHistory VALUES (1,1714564801,'ROOT','Upload',0,1234.0,'Sync')`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.warns) > 0 {
		t.Fatalf("%v %v", r.err, r.warns)
	}
	if r.facts["onedrive.local_folders"] != `C:\Users\someone\OneDrive` {
		t.Errorf("facts: %v", r.facts)
	}
	got := map[string]string{}
	for _, e := range r.events {
		got[e.Type+" "+utc(e)+" "+e.Path] = e.Path
		if e.Source != "onedrive" {
			t.Errorf("source: %+v", e)
		}
	}
	want := map[string]string{
		"onedrive M... 2024-05-01T12:00:00Z":                    `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx`,
		"onedrive .A.. 2024-05-02T12:00:00Z":                    `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx`,
		"onedrive ...B 2024-04-30T12:00:00Z":                    `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx`,
		"onedrive-server-changed 2024-05-01T12:01:40Z":          `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx`,
		"onedrive-file-downloaded (first) 2024-05-01T21:46:40Z": `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx`,
		"onedrive-file-downloaded (last) 2024-05-03T01:33:20Z":  `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx`,
		"onedrive MA.B 2024-05-01T12:00:00Z":                    `(OneDrive, folder not recorded)\orphan.txt`,
		"media-date-taken 2024-04-24T23:06:40Z":                 `(OneDrive, folder not recorded)\orphan.txt`,
		"onedrive-operation 2024-05-01T12:00:01Z":               "",
	}
	for k, v := range want {
		if _, ok := got[k+" "+v]; !ok {
			t.Errorf("missing %s %q", k, v)
		}
	}
	for _, e := range r.events {
		if strings.HasPrefix(e.Type, "onedrive ") && e.Path == `C:\Users\someone\OneDrive\Documents\Plans\budget.xlsx` && (e.Fields["server_deleted"] != true || e.Fields["hash"] != "abcd") {
			t.Errorf("fields: %+v", e.Fields)
		}
		if strings.HasSuffix(e.Path, "odd.txt") && e.Path != `(OneDrive, folders that contain each other)\Odd\odd.txt` {
			t.Errorf("a folder that is its own parent must not loop: %q", e.Path)
		}
	}
}

func TestOneDriveSafeDelete(t *testing.T) {
	p := makeDB(t, "SafeDelete.db",
		`CREATE TABLE filter_delete_info(fileId INTEGER, volumeId INTEGER, notificationTime INTEGER, path TEXT, process TEXT)`,
		`CREATE TABLE deletes_last_touched_by_sync_engine(resourceId TEXT, notificationTime INTEGER, isKFMOptOut BOOLEAN)`,
		`INSERT INTO filter_delete_info VALUES (12345,7,1714564800,'C:\Users\someone\OneDrive\secret.docx','C:\Windows\explorer.exe')`,
		`INSERT INTO deletes_last_touched_by_sync_engine VALUES ('R1',1714564900,0)`,
	)
	r := run(t, p, nil)
	if r.err != nil || len(r.events) != 2 {
		t.Fatalf("%v %d", r.err, len(r.events))
	}
	e := r.events[0]
	if e.Category != CatDeletion || utc(e) != "2024-05-01T12:00:00Z" || e.Path != `C:\Users\someone\OneDrive\secret.docx` ||
		e.Fields["process"] != `C:\Windows\explorer.exe` || !strings.Contains(e.Message, "by C:\\Windows\\explorer.exe") {
		t.Errorf("deletion: %+v", e)
	}
	if r.events[1].Fields["resource_id"] != "R1" {
		t.Errorf("sync engine deletion: %+v", r.events[1])
	}
}
