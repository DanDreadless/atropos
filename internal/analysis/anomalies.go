package analysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DanDreadless/atropos/internal/store"
)

// Kinds of anomaly, most telling first. Each is something that does not
// belong where it was found. None is proof of anything: they are places to
// look first.
const (
	AnomSystemNameElsewhere = "system-name-wrong-folder"
	AnomLookAlikeName       = "look-alike-name"
	AnomDeceptiveName       = "deceptive-name"
	AnomLogCleared          = "log-cleared"
	AnomProtection          = "protection-event"
	AnomCommand             = "suspicious-command"
	AnomPersistence         = "persistence-from-unusual-folder"
	AnomRunStaging          = "run-from-staging-folder"
	AnomRunTemp             = "run-from-temp"
	AnomTool                = "dual-use-tool"
	AnomFileStaging         = "executable-in-staging-folder"
	AnomRunDownloads        = "run-from-downloads"
	AnomCommandText         = "suspicious-command-in-text"
	AnomRunFromInternet     = "run-and-from-the-internet"
	AnomDangerousDownload   = "download-judged-dangerous"
	AnomSideloadedExtension = "browser-extension-not-from-store"
	AnomWMISubscription     = "wmi-subscription-runs-code"
)

// AnomalyKind describes one kind for the examiner.
type AnomalyKind struct {
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Why    string `json:"why"`
	Caveat string `json:"caveat"`
}

// AnomalyKinds lists the kinds in the order they are reported.
var AnomalyKinds = []AnomalyKind{
	{AnomSystemNameElsewhere, "Windows program name in the wrong folder",
		"A file with the name of a core Windows program (svchost.exe, lsass.exe and the like) outside the folders Windows keeps it in. Malware takes these names to pass unnoticed in a process list.",
		"Backups, mounted images, containers, old Windows folders and some installers hold genuine copies elsewhere. Only the name and folder are compared, not the file's content or signature."},
	{AnomLookAlikeName, "Name one character away from a Windows program",
		"A program whose name differs by one character from a core Windows program (scvhost.exe, lsasss.exe). The usual reason is to be misread.",
		"Some legitimate programs have names this close by chance. Only the name is compared."},
	{AnomDeceptiveName, "Name made to look like another type of file",
		"A document extension followed by a program extension (invoice.pdf.exe), a right-to-left override character, or a long run of spaces before the extension. Each hides what will run when the file is opened.",
		"Build tools and web projects produce some double extensions innocently."},
	{AnomLogCleared, "Event log cleared",
		"Windows recorded that an event log was cleared.",
		"Administrators clear logs too. What matters is when it happened relative to everything else."},
	{AnomProtection, "Antivirus detection or protection switched off",
		"Microsoft Defender recorded a detection, or its protection being turned off or its settings changed.",
		"A detection may have been blocked successfully, and installing another antivirus product turns Defender off."},
	{AnomCommand, "Command of a kind attackers use",
		"A recorded command line or script contains something seen far more often in attacks than in ordinary use: an encoded or hidden PowerShell command, a download run in memory, shadow copies deleted, logs cleared, a credential store copied.",
		"Administration scripts, software deployment and security products use the same commands. The match is on text alone."},
	{AnomPersistence, "Starts automatically from an unusual folder",
		"A service, scheduled task or start-up entry runs a program from a temporary, public or download folder. Software that is meant to stay installs itself somewhere permanent.",
		"Some updaters and badly behaved installers do this."},
	{AnomRunStaging, "Program run from a folder programs do not belong in",
		"A program ran from a place such as Users\\Public, the top of ProgramData, the Recycle Bin, PerfLogs, Windows\\Fonts or Windows\\Tasks. These are writable by anyone or rarely looked at, which is why intruders stage tools there.",
		"A few products do install to the top of ProgramData or a profile folder."},
	{AnomRunTemp, "Program run from a temporary folder",
		"A program ran from a Temp folder. Droppers unpack and run from there.",
		"So do most installers and updaters. Expect many innocent ones; look at the names and the times."},
	{AnomTool, "Tool often used by intruders",
		"A program with the name of a tool commonly used for remote execution, credential theft, tunnelling, scanning or copying data out (PsExec, Mimikatz, ProcDump, rclone, ngrok and others).",
		"Administrators and security staff use many of these legitimately. Only the name is compared, and a renamed tool is not found."},
	{AnomFileStaging, "Program file in a folder programs do not belong in",
		"The file system shows a program or script in a place such as Users\\Public, the top of ProgramData, PerfLogs, Windows\\Fonts or Windows\\Tasks.",
		"Presence is not execution. Check whether anything shows it running."},
	{AnomCommandText, "Command of a kind attackers use, in a file's text",
		"The same command patterns, found in the text of a file that has no times of its own: a PowerShell command history, a transcript, a script, a batch file or a log.",
		"The file shows the command was written or typed, not when, and not that it ran. Security documentation and administrators' scripts contain these too."},
	{AnomRunFromInternet, "Program that came from the internet, and ran",
		"The file system marks this program as having arrived from the internet (its Zone.Identifier), and another artefact shows it running.",
		"True of every installer someone downloaded and ran. The mark says where a file came from, not whether it is harmful."},
	{AnomDangerousDownload, "Download the browser judged dangerous",
		"The browser's own safety check flagged this download, whether it was then blocked or kept by the user.",
		"Browsers flag uncommon files as well as harmful ones."},
	{AnomWMISubscription, "WMI event subscription that runs a command or a script",
		"The WMI repository holds an event consumer that runs a command line or a script when its filter's query matches: persistence that survives reboots and leaves no file in the usual places.",
		"Some management and hardware vendors' software registers these. Windows itself ships none. The record may also be an old or deleted one: the repository is searched, not parsed."},
	{AnomSideloadedExtension, "Browser extension loaded from a folder or the command line",
		"The browser's own settings record this extension as unpacked (loaded from a folder in developer mode) or given on the command line, not installed from the store or by policy.",
		"Developers load their own extensions this way. It is also how an intruder adds one that reads every page."},
	{AnomRunDownloads, "Program run from Downloads or a browser cache",
		"A program ran straight from a Downloads folder or the browser's cache: something fetched from the internet and run.",
		"This is how most software is installed. It is listed because it is also how most malware first runs."},
}

// Anomaly is one thing out of place: usually one file or one kind of command,
// with every event that shows it.
type Anomaly struct {
	Kind    string   `json:"kind"`
	Subject string   `json:"subject"` // the path, or what was matched
	Detail  string   `json:"detail,omitempty"`
	Host    string   `json:"host,omitempty"`
	Sources []string `json:"sources"`
	// EvidenceID is set where the finding is in a file's text and not in
	// any event: there is then nothing on the timeline to show or tag.
	EvidenceID int64   `json:"evidence_id,omitempty"`
	Evidence   string  `json:"evidence,omitempty"`
	Events     int     `json:"events"`    // how many events show it
	EventIDs   []int64 `json:"event_ids"` // the first of them, in id order
	First      string  `json:"first"`     // earliest and latest event times, UTC
	Last       string  `json:"last"`

	first, last int64
	sources     map[string]bool
}

// AnomalyReport is the result of the checks.
type AnomalyReport struct {
	Findings  []Anomaly       `json:"findings"`
	Kinds     []AnomalyKind   `json:"kinds"`
	Counts    map[string]int  `json:"counts"`
	Truncated map[string]bool `json:"truncated,omitempty"`
	Scanned   int64           `json:"scanned"`
	Texts     int64           `json:"texts"` // files whose text was looked at
	Notes     []string        `json:"notes"`
}

// MaxAnomalyEvents bounds the events remembered for one finding. A program
// run ten thousand times is still one finding.
const MaxAnomalyEvents = 200

const exts = `\.(?:exe|dll|scr|com|pif|bat|cmd|ps1|vbs|vbe|jse|hta|wsf|msi|cpl)`

// Paths are compared lower-cased with forward slashes. A colon is never
// allowed between a folder and the file name, so a match in free text cannot
// run on from one path into the next.
func folderRE(folders ...string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|/)(?:` + strings.Join(folders, "|") + `)` + exts + `(?:$|[\s"',;)<&|])`)
}

const under = `/[^:"<>|*?
]{1,400}` // anywhere below
const direct = `/[^/:"<>|*?\n]{1,160}` // directly inside

var (
	reTemp = folderRE(
		`appdata/local/temp`+under, `windows/temp`+under)
	reTempRoot = regexp.MustCompile(`^(?:[a-z]:|/device/harddiskvolume\d+|/volume\{[^}]+\})?/(?:temp|tmp)/[^:]*` + exts + `$`)
	reStaging  = folderRE(
		`users/public`+under, `programdata`+direct, `perflogs`+under, `\$recycle\.bin`+under,
		`windows/tasks`+under, `windows/fonts`+under, `windows/debug`+under, `windows/tracing`+under,
		`windows/system32/spool/drivers/color`+under, `windows/system32/tasks`+under,
		`system volume information`+under, `users/default`+under,
		`appdata/roaming`+direct, `appdata/local`+direct, `appdata/locallow`+direct,
		`users/[^/:"]{1,64}`+direct,
		`users/[^/:"]{1,64}/(?:music|pictures|videos|contacts|favorites|links|saved games)`+under)
	// For files merely present, the folders installers and Windows itself
	// fill with programs are left out.
	reFileStaging = folderRE(
		`users/public`+under, `programdata`+direct, `perflogs`+under,
		`windows/tasks`+under, `windows/fonts`+under, `windows/debug`+under, `windows/tracing`+under,
		`windows/system32/spool/drivers/color`+under,
		`users/[^/:"]{1,64}/(?:music|pictures|videos|contacts|favorites|links|saved games)`+under)
	reDownloads = folderRE(
		`users/[^/:"]{1,64}/downloads`+under, `appdata/local/microsoft/windows/inetcache`+under,
		`temporary internet files`+under, `appdata/local/[^/:"]{1,64}/[^/:"]{1,64}/user data/[^/:"]{1,64}/cache`+under)

	reExeName   = regexp.MustCompile(`([^/]+)` + exts + `$`)
	reDoubleExt = regexp.MustCompile(`\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|zip|rar|7z|csv|html?|mp3|mp4|avi)\.(?:exe|scr|com|pif|bat|cmd|jse|vbs|vbe|hta|wsf|ps1|cpl)$`)
	reSpaces    = regexp.MustCompile(` {5,}\.[a-z0-9]{2,4}$`)
)

// Core Windows programs and where each is allowed to be. Every one may also
// be in the side-by-side store and the other places Windows keeps spares.
var systemNames = map[string]string{
	"svchost": "", "lsass": "", "csrss": "", "services": "", "smss": "", "winlogon": "", "wininit": "",
	"spoolsv": "", "taskhost": "", "taskhostw": "", "dllhost": "", "conhost": "", "rundll32": "",
	"lsm": "", "runtimebroker": "", "sihost": "", "ctfmon": "", "dwm": "", "fontdrvhost": "",
	"userinit": "", "logonui": "", "wmiprvse": "windows/system32/wbem/", "searchindexer": "",
	"cmd": "", "regsvr32": "", "mshta": "", "wscript": "", "cscript": "", "certutil": "", "bitsadmin": "",
	"msiexec": "", "schtasks": "", "net": "", "net1": "", "wmic": "windows/system32/wbem/", "sc": "", "reg": "",
	"powershell": "windowspowershell/v1.0/",
	"explorer":   "windows/explorer.exe", "notepad": "windows/notepad.exe", "regedit": "windows/regedit.exe",
}

var reSystemHome = regexp.MustCompile(`(?:^|/)(?:windows/(?:system32|syswow64|sysnative|winsxs|servicing|softwaredistribution|installer|prefetch|systemapps)/|windows\.old/|\$windows\.~(?:bt|ws)/|\$winreagent/|program files/windowsapps/)`)

// Names whose near-misses are worth reporting. Short names are left out:
// one character away from "lsm" or "cmd" is half the alphabet.
var lookAlikeOf = []string{"svchost", "lsass", "csrss", "services", "winlogon", "wininit", "spoolsv",
	"taskhost", "taskhostw", "dllhost", "conhost", "rundll32", "explorer", "runtimebroker", "powershell", "iexplore", "chrome", "firefox", "msedge"}

// Genuine names that sit one character from another genuine name.
var notLookAlike = map[string]bool{"taskhost": true, "taskhostw": true, "taskhostex": true, "service": true, "iexplorer": true}

var reTools = regexp.MustCompile(`^(?:psexec(?:64)?|psexesvc|paexec|mimikatz|mimilib|mimidrv|procdump(?:64)?|rclone|ngrok|plink|pscp|nc(?:64)?|ncat|netcat|lazagne|rubeus|seatbelt|sharphound|bloodhound|adfind|wce|pwdump\d*|fgdump|gsecdump|secretsdump|winpeas[\w.-]*|chisel|ligolo[\w.-]*|frpc|megasync|megacmd[\w.-]*|advanced_ip_scanner[\w.-]*|netscan|nmap|masscan|sdelete(?:64)?|kerbrute|certify|sharpup|nanodump|dumpert|safetykatz|sharpdpapi|wmiexec|smbexec|atexec|dcsync|ntdsaudit|powerview|invoke-mimikatz|cobaltstrike[\w.-]*)$`)

type cmdRule struct {
	re    *regexp.Regexp
	label string
}

// Text is lower-cased and backslashes are forward slashes by the time these run.
var cmdRules = []cmdRule{
	{regexp.MustCompile(`powershell[^\n]{0,200}\s-(?:e|ec|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[a-z0-9+/=]{16,}`), "PowerShell run with an encoded command"},
	{regexp.MustCompile(`powershell[^\n]{0,200}\s-w(?:in|indowstyle)?\s+(?:hidden|1)\b`), "PowerShell run with a hidden window"},
	{regexp.MustCompile(`(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|net\.webclient|start-bitstransfer)[^\n]{0,300}(?:iex|invoke-expression)|(?:iex|invoke-expression)[^\n]{0,300}(?:downloadstring|downloaddata|net\.webclient|invoke-webrequest)`), "PowerShell downloading and running code in memory"},
	{regexp.MustCompile(`frombase64string[^\n]{0,300}(?:iex|invoke-expression|reflection\.assembly|::load\()`), "PowerShell decoding and loading code"},
	{regexp.MustCompile(`certutil(?:\.exe)?[^\n]{0,120}[-/](?:urlcache|decode|decodehex)\b`), "certutil used to download or decode a file"},
	{regexp.MustCompile(`bitsadmin(?:\.exe)?[^\n]{0,120}/transfer\b`), "bitsadmin used to download a file"},
	{regexp.MustCompile(`mshta(?:\.exe)?["\s]+[^\n]{0,40}(?:https?:|javascript:|vbscript:)`), "mshta running a remote or inline script"},
	{regexp.MustCompile(`regsvr32(?:\.exe)?[^\n]{0,120}/i:https?:[^\n]{0,200}scrobj`), "regsvr32 running a remote script"},
	{regexp.MustCompile(`rundll32(?:\.exe)?["\s]+[^\n]{0,40}javascript:`), "rundll32 running inline script"},
	{regexp.MustCompile(`rundll32(?:\.exe)?[^\n]{0,120}comsvcs(?:\.dll)?[^\n]{0,40}minidump|procdump[^\n]{0,120}lsass|sekurlsa::|lsadump::`), "Memory of the logon process (LSASS) dumped"},
	{regexp.MustCompile(`vssadmin(?:\.exe)?[^\n]{0,60}delete\s+shadows|wmic[^\n]{0,60}shadowcopy[^\n]{0,40}delete|wbadmin[^\n]{0,60}delete\s+(?:catalog|systemstatebackup)`), "Shadow copies or backups deleted"},
	{regexp.MustCompile(`bcdedit[^\n]{0,120}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)`), "Windows recovery switched off"},
	{regexp.MustCompile(`wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog\b|remove-eventlog\b`), "Event log cleared from the command line"},
	{regexp.MustCompile(`reg(?:\.exe)?\s+save\s+hklm/(?:sam|security|system)\b|ntdsutil[^\n]{0,200}(?:ifm|create\s+full)|esentutl[^\n]{0,120}ntds\.dit`), "Account database copied (SAM, SECURITY or NTDS)"},
	{regexp.MustCompile(`set-mppreference[^\n]{0,200}-disable\w+\s+(?:\$true|1)|add-mppreference[^\n]{0,120}-exclusion`), "Defender protection changed from PowerShell"},
	{regexp.MustCompile(`netsh[^\n]{0,60}(?:advfirewall|firewall)[^\n]{0,60}(?:state\s+off|opmode[^\n]{0,20}disable)`), "Firewall switched off"},
	{regexp.MustCompile(`net1?(?:\.exe)?\s+(?:user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add)`), "Account created or made administrator from the command line"},
}

var reVolume = regexp.MustCompile(`^(?:volume\{[^}]*\}|device/harddiskvolume\d+)/`)

// normText prepares free text (a message, or an event's fields as JSON) for
// matching: lower case, and every backslash a forward slash, which also turns
// the doubled backslash of a JSON string into one separator.
func normText(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, `\\`, "/")
	return strings.ReplaceAll(s, `\`, "/")
}

// wholePath widens a match inside free text back to the drive letter the
// path began with, when one is close by on the same line.
func wholePath(text string, from, to int) string {
	for i := from - 1; i >= 1 && from-i < 260; i-- {
		c := text[i]
		if c == '"' || c == '\n' || c == '<' || c == '>' || c == '|' {
			break
		}
		if c == ':' && text[i-1] >= 'a' && text[i-1] <= 'z' {
			return text[i-1 : to]
		}
	}
	return text[from:to]
}

// normFull keeps the drive or device prefix, so a finding still shows where
// the file was.
func normFull(p string) string {
	return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
}

// oneEditApart reports whether a and b differ by one insertion, deletion,
// substitution or swap of neighbours.
func oneEditApart(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	if la > lb {
		a, b, la, lb = b, a, lb, la
	}
	if lb-la > 1 {
		return false
	}
	i := 0
	for i < la && a[i] == b[i] {
		i++
	}
	if la == lb {
		if a[i+1:] == b[i+1:] {
			return true // substitution
		}
		return i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:] // swap
	}
	return a[i:] == b[i+1:] // insertion
}

// Characters swapped for look-alikes: svch0st, expl0rer, Isass.
var homoglyphs = strings.NewReplacer("0", "o", "1", "l", "3", "e", "5", "s", "vv", "w", "rn", "m")

func lookAlike(name string) string {
	if notLookAlike[name] || len(name) < 5 {
		return ""
	}
	if _, ok := systemNames[name]; ok {
		return ""
	}
	for _, real := range lookAlikeOf {
		if name == real {
			return ""
		}
	}
	for _, real := range lookAlikeOf {
		if oneEditApart(name, real) || homoglyphs.Replace(name) == real {
			return real
		}
	}
	return ""
}

// Anomalies looks through the events on the timeline for things that do not
// belong where they are. It reads only.
func Anomalies(s *store.Store) (*AnomalyReport, error) {
	rep := &AnomalyReport{Kinds: AnomalyKinds, Counts: map[string]int{}, Truncated: map[string]bool{}}
	found := map[string]*Anomaly{}

	hit := func(e store.EventRow, kind, subject, detail string) {
		// One file is one finding however each artefact writes its path.
		key := kind + "\x00" + reVolume.ReplaceAllString(normPath(subject), "")
		a := found[key]
		if a == nil {
			if rep.Counts[kind] >= MaxPerKind {
				rep.Truncated[kind] = true
				return
			}
			rep.Counts[kind]++
			a = &Anomaly{Kind: kind, Subject: subject, Detail: detail, Host: e.Host, first: e.TSUTC, last: e.TSUTC, sources: map[string]bool{}}
			found[key] = a
		}
		a.Events++
		a.sources[e.Source] = true
		if len(a.EventIDs) < MaxAnomalyEvents {
			a.EventIDs = append(a.EventIDs, e.ID)
		}
		if e.TSUTC < a.first {
			a.first = e.TSUTC
		}
		if e.TSUTC > a.last {
			a.last = e.TSUTC
		}
	}

	// For joining a file the file system marks as from the internet to the
	// artefacts that show it running. Only what a finding needs is kept.
	marked := map[string]*store.EventRow{}
	zoneDetail := map[string]string{}
	ran := map[string][]store.EventRow{}
	fileKey := func(p string) string {
		k := reVolume.ReplaceAllString(normPath(p), "")
		if len(k) >= 2 && k[1] == ':' {
			k = k[2:]
		}
		return strings.TrimLeft(k, "/")
	}
	slim := func(e store.EventRow) store.EventRow {
		return store.EventRow{ID: e.ID, TSUTC: e.TSUTC, Source: e.Source, Host: e.Host, Path: e.Path}
	}

	err := s.Stream(store.Query{}, func(e store.EventRow) error {
		rep.Scanned++
		p := normFull(e.Path)
		if p != "" && reExeName.MatchString(p) {
			switch {
			case e.Source == "mft" && bytes.Contains(e.Fields, []byte(`"zone_id":3`)):
				if k := fileKey(e.Path); marked[k] == nil && len(marked) < 200000 {
					c := slim(e)
					marked[k] = &c
					var f struct {
						Host string `json:"zone_host_url"`
						Ref  string `json:"zone_referrer_url"`
					}
					if json.Unmarshal(e.Fields, &f) == nil {
						switch {
						case f.Host != "":
							zoneDetail[k] = "fetched from " + f.Host
						case f.Ref != "":
							zoneDetail[k] = "referred by " + f.Ref
						}
					}
				}
			case e.Category == "execution":
				if k := fileKey(e.Path); len(ran[k]) < 20 && (len(ran) < 200000 || ran[k] != nil) {
					ran[k] = append(ran[k], slim(e))
				}
			}
		}
		if e.Source == "browser" && strings.HasPrefix(e.TSType, "download-") && bytes.Contains(e.Fields, []byte(`"danger_code"`)) {
			var f struct {
				Code   int    `json:"danger_code"`
				Danger string `json:"danger"`
				URL    string `json:"url"`
			}
			// 0 is not dangerous; 9 is allowed by policy and 15 scanned and safe.
			if json.Unmarshal(e.Fields, &f) == nil && f.Code > 0 && f.Code != 9 && f.Code != 15 {
				d := f.Danger
				if d == "" {
					d = fmt.Sprintf("danger type %d", f.Code)
				}
				if f.URL != "" {
					d += "; from " + f.URL
				}
				hit(e, AnomDangerousDownload, e.Path, "the browser's verdict: "+d)
			}
		}
		if e.Source == "wmi" {
			var f struct {
				Class    string `json:"class"`
				Consumer string `json:"consumer_class"`
				Name     string `json:"name"`
				Bound    string `json:"consumer"`
			}
			if json.Unmarshal(e.Fields, &f) == nil {
				runs := func(c string) bool { return c == "CommandLineEventConsumer" || c == "ActiveScriptEventConsumer" }
				switch {
				case runs(f.Class):
					hit(e, AnomWMISubscription, f.Class+" "+f.Name, "")
				case runs(f.Consumer):
					hit(e, AnomWMISubscription, f.Consumer+" "+f.Bound, "bound to a filter")
				}
			}
		}
		if e.Source == "browser" && e.TSType == "browser-extension-installed" {
			var f struct {
				Location int    `json:"location"`
				Name     string `json:"name"`
				ID       string `json:"extension_id"`
				How      string `json:"location_name"`
			}
			// 4 is unpacked and 8 the command line (Chromium's manifest locations).
			if json.Unmarshal(e.Fields, &f) == nil && (f.Location == 4 || f.Location == 8) {
				subject := f.Name
				if subject == "" {
					subject = f.ID
				}
				hit(e, AnomSideloadedExtension, subject, f.How+"; "+e.Path)
			}
		}
		fileEvent := e.Category == "file-system" || e.Category == "deletion"
		execution := e.Category == "execution"
		persistence := e.Category == "persistence"
		isProgram := p != "" && reExeName.MatchString(p)

		// Names. These apply wherever a program's path appears.
		if isProgram {
			base := p[strings.LastIndex(p, "/")+1:]
			stem := base[:strings.LastIndex(base, ".")]
			hasFolder := strings.Contains(p, "/") && !strings.HasPrefix(p, "{")
			if home, ok := systemNames[stem]; ok && strings.HasSuffix(base, ".exe") && hasFolder && (execution || fileEvent || persistence) {
				if !reSystemHome.MatchString(p) && (home == "" || !strings.Contains(p, home)) {
					hit(e, AnomSystemNameElsewhere, e.Path, "")
				}
			}
			if strings.HasSuffix(base, ".exe") && (execution || fileEvent || persistence) {
				if real := lookAlike(stem); real != "" {
					hit(e, AnomLookAlikeName, e.Path, "close to "+real+".exe")
				}
				if reTools.MatchString(stem) {
					hit(e, AnomTool, e.Path, "")
				}
			}
		}
		if p != "" {
			switch {
			case reDoubleExt.MatchString(p):
				hit(e, AnomDeceptiveName, e.Path, "a document extension followed by a program extension")
			case strings.ContainsRune(e.Path, '‮'):
				hit(e, AnomDeceptiveName, e.Path, "contains a right-to-left override character, which reverses how part of the name is shown")
			case reSpaces.MatchString(p):
				hit(e, AnomDeceptiveName, e.Path, "a run of spaces pushes the real extension out of sight")
			}
		}

		// Folders.
		switch {
		case fileEvent:
			if isProgram && reFileStaging.MatchString(p) {
				hit(e, AnomFileStaging, e.Path, "")
			}
		case execution && isProgram:
			switch {
			case reStaging.MatchString(p):
				hit(e, AnomRunStaging, e.Path, "")
			case reTemp.MatchString(p) || reTempRoot.MatchString(p):
				hit(e, AnomRunTemp, e.Path, "")
			case reDownloads.MatchString(p):
				hit(e, AnomRunDownloads, e.Path, "")
			}
		}

		// Free text: command lines, scripts, what a task or service runs.
		if fileEvent || e.Category == "browser" || e.Category == "file-opening" {
			return nil
		}
		text := ""
		if e.Source == "evtx" || persistence || execution || e.Category == "security" || e.Category == "registry" || e.Category == "log" {
			text = normText(e.Message) + "\n" + normText(string(e.Fields))
		}
		if text == "" {
			return nil
		}
		if persistence {
			for _, re := range []*regexp.Regexp{reTemp, reStaging, reDownloads} {
				if loc := re.FindStringIndex(text); loc != nil {
					m := strings.Trim(wholePath(text, loc[0], loc[1]), ` "',;)<&|`)
					subject := e.Path
					if subject == "" {
						subject = m
					}
					hit(e, AnomPersistence, subject, "runs "+m)
					break
				}
			}
		}
		for _, r := range cmdRules {
			if r.re.MatchString(text) {
				hit(e, AnomCommand, r.label, "")
			}
		}
		// Defender's own records, outside the event log.
		if e.Source == "defender" && (e.TSType == "defender-detection" || e.TSType == "defender-detection (mplog)") {
			var f struct {
				Name string `json:"threat_name"`
			}
			json.Unmarshal(e.Fields, &f)
			if f.Name == "" {
				f.Name = "unnamed threat"
			}
			hit(e, AnomProtection, "Defender detection: "+f.Name, "")
		}
		if e.Source == "evtx" {
			var f struct {
				EventID int    `json:"event_id"`
				Channel string `json:"channel"`
			}
			if json.Unmarshal(e.Fields, &f) == nil {
				ch := strings.ToLower(f.Channel)
				switch {
				case ch == "security" && f.EventID == 1102, ch == "system" && f.EventID == 104:
					hit(e, AnomLogCleared, f.Channel+" event "+fmt.Sprint(f.EventID), "")
				case strings.Contains(ch, "windows defender"):
					switch f.EventID {
					case 1006, 1007, 1015, 1116, 1117, 1118, 1119:
						hit(e, AnomProtection, "Defender detection (event "+fmt.Sprint(f.EventID)+")", "")
					case 5001, 5010, 5012, 5007, 5013:
						hit(e, AnomProtection, "Defender protection switched off or settings changed (event "+fmt.Sprint(f.EventID)+")", "")
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Programs marked as from the internet that something shows running.
	keys := make([]string, 0, len(marked))
	for key := range marked {
		if ran[key] != nil {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		m := marked[key]
		hit(*m, AnomRunFromInternet, m.Path, zoneDetail[key])
		for _, e := range ran[key] {
			hit(e, AnomRunFromInternet, m.Path, "")
		}
	}

	// Files that are text and have no events: histories, scripts, transcripts.
	err = s.StreamFullText(func(id int64, name, origin, body string) error {
		rep.Texts++
		text := normText(body)
		for _, r := range cmdRules {
			locs := r.re.FindAllStringIndex(text, 50)
			if len(locs) == 0 {
				continue
			}
			if rep.Counts[AnomCommandText] >= MaxPerKind {
				rep.Truncated[AnomCommandText] = true
				return nil
			}
			rep.Counts[AnomCommandText]++
			var lines []string
			line, at := 1, 0
			for i, loc := range locs {
				line += strings.Count(text[at:loc[0]], "\n")
				at = loc[0]
				if i < 5 {
					lines = append(lines, fmt.Sprint(line))
				}
			}
			// The first matching line, as written. Line numbers are the same in
			// the text as stored and as prepared for matching; offsets are not.
			quote := ""
			if first, err := strconv.Atoi(lines[0]); err == nil {
				if all := strings.Split(body, "\n"); first-1 < len(all) {
					quote = strings.TrimSpace(all[first-1])
				}
			}
			if len(quote) > 300 {
				quote = quote[:300] + "…"
			}
			detail := fmt.Sprintf("%d place(s) in %s, at line %s", len(locs), name, strings.Join(lines, ", "))
			if len(locs) > 5 {
				detail += " and further on"
			}
			found[fmt.Sprintf("%s\x00%s\x00%d", AnomCommandText, r.label, id)] = &Anomaly{
				Kind: AnomCommandText, Subject: r.label, Detail: detail + ": " + quote, EvidenceID: id, Evidence: name,
				sources: map[string]bool{"text of a file": true},
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	order := map[string]int{}
	for i, k := range AnomalyKinds {
		order[k.Kind] = i
	}
	rep.Findings = make([]Anomaly, 0, len(found))
	for _, a := range found {
		for src := range a.sources {
			a.Sources = append(a.Sources, src)
		}
		sort.Strings(a.Sources)
		if a.EvidenceID == 0 {
			a.First, a.Last = utc(a.first), utc(a.last)
		}
		if a.EventIDs == nil {
			a.EventIDs = []int64{}
		}
		rep.Findings = append(rep.Findings, *a)
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		if len(a.Sources) != len(b.Sources) {
			return len(a.Sources) > len(b.Sources) // seen by more artefacts first
		}
		if a.first != b.first {
			return a.first < b.first
		}
		return a.Subject < b.Subject
	})

	if rep.Scanned == 0 {
		rep.Notes = append(rep.Notes, "There are no events in the case yet, so nothing was looked at.")
	}
	rep.Notes = append(rep.Notes,
		"These are things that do not belong where they were found, chosen by fixed rules on names, folders and command text. They are places to look first, not conclusions, and a quiet result does not mean a clean machine.",
		"ShimCache and Amcache show that Windows saw a program, which is not always the same as the program having run. Where a finding says \"run\", check which artefacts it came from.",
		"Nothing is judged by content: a renamed tool, or malware in an ordinary folder under an ordinary name, is not found here.",
		"A finding in a file's text has no event behind it, so it cannot be tagged or shown on the timeline: open the file from the finding.",
		"Tagging adds the tag \"anomaly\" and a second tag naming the kind to each event listed, so they can be found on the timeline with tag:anomaly. Tags can be withdrawn like any other.")
	var cut []string
	for k, v := range rep.Truncated {
		if v {
			cut = append(cut, fmt.Sprintf("%s: more than %d found, the first %d listed.", k, MaxPerKind, MaxPerKind))
		}
	}
	sort.Strings(cut)
	rep.Notes = append(rep.Notes, cut...)
	return rep, nil
}

// AnomalyTag is the tag every listed event is given; a second tag names the kind.
const AnomalyTag = "anomaly"

// TagAnomalies tags the events of every finding. Events that already carry a
// tag are left as they are. It returns how many tags were added.
func TagAnomalies(s *store.Store, rep *AnomalyReport) (int64, error) {
	byTag := map[string][]int64{}
	for _, a := range rep.Findings {
		byTag[AnomalyTag] = append(byTag[AnomalyTag], a.EventIDs...)
		byTag[AnomalyTag+"-"+a.Kind] = append(byTag[AnomalyTag+"-"+a.Kind], a.EventIDs...)
	}
	tags := make([]string, 0, len(byTag))
	for t := range byTag {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	var total int64
	for _, t := range tags {
		n, err := s.TagEvents(t, byTag[t], "anomaly checks")
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// WriteAnomaliesText prints the report for the terminal.
func WriteAnomaliesText(w interface{ Write([]byte) (int, error) }, r *AnomalyReport) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("Things out of place: %d finding(s) from %d events and the text of %d file(s)\n", len(r.Findings), r.Scanned, r.Texts)
	last := ""
	for _, f := range r.Findings {
		if f.Kind != last {
			last = f.Kind
			for _, k := range r.Kinds {
				if k.Kind == f.Kind {
					p("\n%s (%d)\n  %s\n  Caution: %s\n", k.Title, r.Counts[f.Kind], k.Why, k.Caveat)
				}
			}
		}
		detail := ""
		if f.Detail != "" {
			detail = "  (" + f.Detail + ")"
		}
		ids := f.EventIDs
		more := ""
		if len(ids) > 10 {
			ids, more = ids[:10], " …"
		}
		if f.EvidenceID != 0 {
			p("\n  %s%s\n    in the text of evidence %d (%s); no event, so nothing to tag\n", f.Subject, detail, f.EvidenceID, f.Evidence)
			continue
		}
		p("\n  %s%s\n    %d event(s) from %s   first %s   last %s\n    events: %v%s\n", f.Subject, detail, f.Events, strings.Join(f.Sources, ", "), f.First, f.Last, ids, more)
	}
	p("\nNotes:\n")
	for _, n := range r.Notes {
		p("  - %s\n", n)
	}
	return nil
}
