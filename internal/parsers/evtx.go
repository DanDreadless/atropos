package parsers

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/DanDreadless/atropos/internal/timeutil"

	"www.velocidex.com/golang/evtx"
)

type evtxParser struct{}

func (evtxParser) Name() string { return "evtx" }
func (evtxParser) Version() string {
	return "8 (velocidex/evtx v0.2.0, patched in third_party/evtx to bound damaged records; older records recovered from chunks' unused space; event time and record number from the event itself; more event descriptions; the host the log came from, the record's own computer kept)"
}

// Short descriptions for events analysts reach for most. The description is
// added to the message; the raw record is always kept in the fields.
var eventNames = map[string]string{
	"Security/1102": "Audit log cleared",
	"Security/4624": "Successful logon",
	"Security/4625": "Failed logon",
	"Security/4634": "Logoff",
	"Security/4647": "User-initiated logoff",
	"Security/4648": "Logon with explicit credentials",
	"Security/4672": "Special privileges assigned to new logon",
	"Security/4688": "Process created",
	"Security/4689": "Process exited",
	"Security/4697": "Service installed",
	"Security/4698": "Scheduled task created",
	"Security/4699": "Scheduled task deleted",
	"Security/4702": "Scheduled task updated",
	"Security/4720": "User account created",
	"Security/4722": "User account enabled",
	"Security/4723": "Password change attempted",
	"Security/4724": "Password reset attempted",
	"Security/4725": "User account disabled",
	"Security/4726": "User account deleted",
	"Security/4728": "Member added to security-enabled global group",
	"Security/4732": "Member added to security-enabled local group",
	"Security/4738": "User account changed",
	"Security/4740": "User account locked out",
	"Security/4768": "Kerberos TGT requested",
	"Security/4769": "Kerberos service ticket requested",
	"Security/4771": "Kerberos pre-authentication failed",
	"Security/4776": "NTLM credential validation",
	"Security/4778": "Session reconnected",
	"Security/4779": "Session disconnected",
	"Security/5140": "Network share accessed",
	"Security/5145": "Network share object checked",
	"System/104":    "Event log cleared",
	"System/6005":   "Event log service started",
	"System/6006":   "Event log service stopped",
	"System/7034":   "Service terminated unexpectedly",
	"System/7036":   "Service state changed",
	"System/7040":   "Service start type changed",
	"System/7045":   "Service installed",
	"Microsoft-Windows-PowerShell/Operational/4103":                               "PowerShell module logging",
	"Microsoft-Windows-PowerShell/Operational/4104":                               "PowerShell script block",
	"Microsoft-Windows-Sysmon/Operational/1":                                      "Process created (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/3":                                      "Network connection (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/7":                                      "Image loaded (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/8":                                      "Remote thread created (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/10":                                     "Process accessed (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/11":                                     "File created (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/12":                                     "Registry object added or deleted (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/13":                                     "Registry value set (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/22":                                     "DNS query (Sysmon)",
	"Microsoft-Windows-TaskScheduler/Operational/106":                             "Scheduled task registered",
	"Microsoft-Windows-TaskScheduler/Operational/200":                             "Scheduled task action started",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/21":       "Remote Desktop session logon",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/24":       "Remote Desktop session disconnected",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/25":       "Remote Desktop session reconnected",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational/1149": "Remote Desktop authentication succeeded",
	"Microsoft-Windows-Windows Defender/Operational/1116":                         "Defender detected malware",
	"Microsoft-Windows-Windows Defender/Operational/1117":                         "Defender acted on malware",
	"Microsoft-Windows-Windows Defender/Operational/5001":                         "Defender real-time protection disabled",

	// Account use, reconnaissance and tampering.
	"Security/1100": "Event logging service shut down",
	"Security/4616": "System time changed",
	"Security/4657": "Registry value modified",
	"Security/4700": "Scheduled task enabled",
	"Security/4701": "Scheduled task disabled",
	"Security/4719": "Audit policy changed",
	"Security/4735": "Security-enabled local group changed",
	"Security/4756": "Member added to security-enabled universal group",
	"Security/4798": "User's local group membership enumerated",
	"Security/4799": "Security-enabled local group membership enumerated",
	"Security/4800": "Workstation locked",
	"Security/4801": "Workstation unlocked",
	"Security/5142": "Network share added",
	"Security/5143": "Network share modified",
	"Security/5144": "Network share deleted",
	"System/1074":   "Shutdown or restart initiated",
	"System/6008":   "Previous shutdown was unexpected",
	"System/7031":   "Service terminated unexpectedly, recovery action taken",
	"System/7035":   "Service sent a start or stop control",

	// Remote Desktop, on the machine connected to and the machine connected from.
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/22": "Remote Desktop shell started",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/23": "Remote Desktop session logoff",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/39": "Session disconnected by another session",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/40": "Session disconnected, with reason code",
	"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/131":     "Remote Desktop connection accepted",
	"Microsoft-Windows-TerminalServices-RDPClient/Operational/1024":         "Outbound Remote Desktop connection attempted",
	"Microsoft-Windows-TerminalServices-RDPClient/Operational/1102":         "Outbound Remote Desktop connection made",

	// Scheduled tasks.
	"Microsoft-Windows-TaskScheduler/Operational/100": "Scheduled task started",
	"Microsoft-Windows-TaskScheduler/Operational/102": "Scheduled task finished",
	"Microsoft-Windows-TaskScheduler/Operational/129": "Scheduled task launched a process",
	"Microsoft-Windows-TaskScheduler/Operational/140": "Scheduled task updated",
	"Microsoft-Windows-TaskScheduler/Operational/141": "Scheduled task deleted",
	"Microsoft-Windows-TaskScheduler/Operational/201": "Scheduled task action completed",

	// WMI, PowerShell and remote management.
	"Microsoft-Windows-WMI-Activity/Operational/5857": "WMI provider loaded",
	"Microsoft-Windows-WMI-Activity/Operational/5858": "WMI query failed",
	"Microsoft-Windows-WMI-Activity/Operational/5859": "WMI event filter registered",
	"Microsoft-Windows-WMI-Activity/Operational/5860": "WMI temporary event consumer registered",
	"Microsoft-Windows-WMI-Activity/Operational/5861": "WMI permanent event consumer bound to a filter",
	"Microsoft-Windows-PowerShell/Operational/4105":   "PowerShell script block started",
	"Microsoft-Windows-PowerShell/Operational/4106":   "PowerShell script block stopped",
	"PowerShellCore/Operational/4103":                 "PowerShell module logging",
	"PowerShellCore/Operational/4104":                 "PowerShell script block",
	"Windows PowerShell/400":                          "PowerShell engine started",
	"Windows PowerShell/403":                          "PowerShell engine stopped",
	"Windows PowerShell/600":                          "PowerShell provider started",
	"Windows PowerShell/800":                          "PowerShell pipeline executed",
	"Microsoft-Windows-WinRM/Operational/6":           "Remote management session being created (outbound)",
	"Microsoft-Windows-WinRM/Operational/91":          "Remote management session created (inbound)",
	"Microsoft-Windows-WinRM/Operational/168":         "Remote management authentication",

	// Antivirus.
	"Microsoft-Windows-Windows Defender/Operational/1006": "Defender found malware",
	"Microsoft-Windows-Windows Defender/Operational/1007": "Defender acted on malware",
	"Microsoft-Windows-Windows Defender/Operational/1015": "Defender detected suspicious behaviour",
	"Microsoft-Windows-Windows Defender/Operational/1118": "Defender action on malware failed",
	"Microsoft-Windows-Windows Defender/Operational/1119": "Defender action on malware failed critically",
	"Microsoft-Windows-Windows Defender/Operational/5000": "Defender real-time protection enabled",
	"Microsoft-Windows-Windows Defender/Operational/5004": "Defender real-time protection configuration changed",
	"Microsoft-Windows-Windows Defender/Operational/5007": "Defender configuration changed",
	"Microsoft-Windows-Windows Defender/Operational/5010": "Defender spyware scanning disabled",
	"Microsoft-Windows-Windows Defender/Operational/5012": "Defender virus scanning disabled",
	"Microsoft-Windows-Windows Defender/Operational/5013": "Defender tamper protection blocked a change",

	// Sysmon and background transfers.
	"Microsoft-Windows-Sysmon/Operational/2":       "File creation time changed (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/5":       "Process terminated (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/6":       "Driver loaded (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/9":       "Raw disk read (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/15":      "Alternate data stream created (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/17":      "Named pipe created (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/18":      "Named pipe connected (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/19":      "WMI event filter registered (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/20":      "WMI event consumer registered (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/21":      "WMI consumer bound to filter (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/23":      "File deleted and archived (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/25":      "Process image tampered with (Sysmon)",
	"Microsoft-Windows-Sysmon/Operational/26":      "File deleted (Sysmon)",
	"Microsoft-Windows-Bits-Client/Operational/3":  "Background transfer job created",
	"Microsoft-Windows-Bits-Client/Operational/59": "Background transfer started",
	"Microsoft-Windows-Bits-Client/Operational/60": "Background transfer stopped",
	// Seen often in the public EVTX-ATTACK-SAMPLES set; meanings as EvtxECmd's maps give them.
	"Microsoft-Windows-Bits-Client/Operational/4":  "Background transfer job completed",
	"Microsoft-Windows-Bits-Client/Operational/5":  "Background transfer job cancelled",
	"Microsoft-Windows-Bits-Client/Operational/61": "Background transfer stopped with an error",
	"Security/4661": "Handle to an object requested (SAM or directory)",
	"Security/4662": "Operation performed on a directory object",
	"Security/5136": "Directory service object modified",
	"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/72":           "Remote Desktop interface method called",
	"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/104":          "Remote Desktop client's time zone offset",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational/261": "Remote Desktop listener received a connection",
}

func init() {
	// Devices, file access auditing and the firewall.
	for k, v := range map[string]string{
		"Security/4656": "Handle to an object requested",
		"Security/4660": "Object deleted",
		"Security/4663": "Object accessed",
		"Security/5156": "Network connection permitted by the firewall",
		"Security/6416": "New external device recognised",
		"System/20001":  "Device driver installed",
		"System/20003":  "Device service added",
		"Microsoft-Windows-Kernel-PnP/Configuration/400":                          "Device configured",
		"Microsoft-Windows-Kernel-PnP/Configuration/410":                          "Device started",
		"Microsoft-Windows-Partition/Diagnostic/1006":                             "Disk or partition connected",
		"Microsoft-Windows-Storsvc/Diagnostic/1001":                               "Storage device connected",
		"Microsoft-Windows-DriverFrameworks-UserMode/Operational/2003":            "USB device connected (driver host loading)",
		"Microsoft-Windows-DriverFrameworks-UserMode/Operational/2100":            "USB device power or plug-and-play operation",
		"Microsoft-Windows-DriverFrameworks-UserMode/Operational/2102":            "USB device disconnected",
		"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall/2004": "Firewall rule added",
		"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall/2005": "Firewall rule changed",
		"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall/2006": "Firewall rule deleted",
	} {
		eventNames[k] = v
	}
}

// providerEventNames covers logs where an event ID means something only
// together with the program that wrote it: the Application log is shared by
// everything installed, and many programs use the same low numbers.
var providerEventNames = map[string]string{
	"Application/Application Error/1000":        "Application crashed",
	"Application/Windows Error Reporting/1001":  "Windows Error Reporting recorded a fault",
	"Application/Application Hang/1002":         "Application stopped responding",
	"Application/MsiInstaller/1033":             "Product installed (Windows Installer)",
	"Application/MsiInstaller/1034":             "Product removed (Windows Installer)",
	"Application/MsiInstaller/1040":             "Windows Installer started a transaction",
	"Application/MsiInstaller/1042":             "Windows Installer ended a transaction",
	"Application/MsiInstaller/11707":            "Product installation completed (Windows Installer)",
	"System/Microsoft-Windows-Kernel-General/1": "System time changed",
}

// providerEventCategories is the same idea for categories.
var providerEventCategories = map[string]string{
	"Application/Application Error/1000":        CatExecution,
	"Application/Application Hang/1002":         CatExecution,
	"Application/Windows Error Reporting/1001":  CatExecution,
	"System/Microsoft-Windows-Kernel-General/1": CatSecurity,
}

// eventCategories says what the common events are evidence of. Anything not
// listed is an ordinary log entry.
var eventCategories = map[string]string{}

func init() {
	for cat, keys := range map[string][]string{
		CatAccount: {"Security/4624", "Security/4625", "Security/4634", "Security/4647", "Security/4648", "Security/4672",
			"Security/4720", "Security/4722", "Security/4723", "Security/4724", "Security/4725", "Security/4726", "Security/4728",
			"Security/4732", "Security/4738", "Security/4740", "Security/4768", "Security/4769", "Security/4771", "Security/4776",
			"Security/4778", "Security/4779", "Security/4735", "Security/4756", "Security/4798", "Security/4799", "Security/4800", "Security/4801",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/22",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/23",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/39",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/40",
			"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/131",
			"Microsoft-Windows-WinRM/Operational/91", "Microsoft-Windows-WinRM/Operational/168",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/21",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/24",
			"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational/25",
			"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational/1149",
			"Security/4661", "Security/4662", "Security/5136"},
		CatExecution: {"Security/4688", "Security/4689", "Microsoft-Windows-Sysmon/Operational/1", "Microsoft-Windows-Sysmon/Operational/7",
			"Microsoft-Windows-Sysmon/Operational/8", "Microsoft-Windows-Sysmon/Operational/10",
			"Microsoft-Windows-PowerShell/Operational/4103", "Microsoft-Windows-PowerShell/Operational/4104",
			"Microsoft-Windows-TaskScheduler/Operational/200", "Microsoft-Windows-TaskScheduler/Operational/100", "Microsoft-Windows-TaskScheduler/Operational/102",
			"Microsoft-Windows-TaskScheduler/Operational/129", "Microsoft-Windows-TaskScheduler/Operational/201",
			"Microsoft-Windows-PowerShell/Operational/4105", "Microsoft-Windows-PowerShell/Operational/4106", "PowerShellCore/Operational/4103", "PowerShellCore/Operational/4104",
			"Windows PowerShell/400", "Windows PowerShell/403", "Windows PowerShell/600", "Windows PowerShell/800",
			"Microsoft-Windows-WMI-Activity/Operational/5857", "Microsoft-Windows-WMI-Activity/Operational/5858",
			"Microsoft-Windows-Sysmon/Operational/5", "Microsoft-Windows-Sysmon/Operational/6", "Microsoft-Windows-Sysmon/Operational/25",
			"System/7035", "System/7036", "System/7034", "System/7031"},
		CatPersistence: {"Security/4697", "Security/4698", "Security/4699", "Security/4700", "Security/4701", "Security/4702", "System/7045", "System/7040",
			"Microsoft-Windows-TaskScheduler/Operational/106", "Microsoft-Windows-TaskScheduler/Operational/140", "Microsoft-Windows-TaskScheduler/Operational/141",
			"Microsoft-Windows-WMI-Activity/Operational/5861", "Microsoft-Windows-WMI-Activity/Operational/5859", "Microsoft-Windows-WMI-Activity/Operational/5860", "Microsoft-Windows-Sysmon/Operational/19", "Microsoft-Windows-Sysmon/Operational/20",
			"Microsoft-Windows-Sysmon/Operational/21"},
		CatNetwork: {"Security/5140", "Security/5145", "Security/5156", "Security/5142", "Security/5143", "Security/5144",
			"Microsoft-Windows-TerminalServices-RDPClient/Operational/1024", "Microsoft-Windows-TerminalServices-RDPClient/Operational/1102",
			"Microsoft-Windows-WinRM/Operational/6", "Microsoft-Windows-Bits-Client/Operational/3",
			"Microsoft-Windows-Sysmon/Operational/17", "Microsoft-Windows-Sysmon/Operational/18", "Microsoft-Windows-Sysmon/Operational/3", "Microsoft-Windows-Sysmon/Operational/22",
			"Microsoft-Windows-Bits-Client/Operational/59", "Microsoft-Windows-Bits-Client/Operational/60",
			"Microsoft-Windows-Bits-Client/Operational/4", "Microsoft-Windows-Bits-Client/Operational/5", "Microsoft-Windows-Bits-Client/Operational/61",
			"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/72", "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational/104",
			"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational/261",
			"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall/2004", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall/2005",
			"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall/2006"},
		CatSecurity: {"Security/1102", "System/104", "Security/1100", "Security/4616", "Security/4719", "System/6008", "System/1074",
			"Microsoft-Windows-Windows Defender/Operational/1006", "Microsoft-Windows-Windows Defender/Operational/1007", "Microsoft-Windows-Windows Defender/Operational/1015",
			"Microsoft-Windows-Windows Defender/Operational/1118", "Microsoft-Windows-Windows Defender/Operational/1119", "Microsoft-Windows-Windows Defender/Operational/5000",
			"Microsoft-Windows-Windows Defender/Operational/5004", "Microsoft-Windows-Windows Defender/Operational/5007", "Microsoft-Windows-Windows Defender/Operational/5010",
			"Microsoft-Windows-Windows Defender/Operational/5012", "Microsoft-Windows-Windows Defender/Operational/5013", "Microsoft-Windows-Sysmon/Operational/9", "Microsoft-Windows-Windows Defender/Operational/1116",
			"Microsoft-Windows-Windows Defender/Operational/1117", "Microsoft-Windows-Windows Defender/Operational/5001"},
		CatFileSystem: {"Microsoft-Windows-Sysmon/Operational/11", "Microsoft-Windows-Sysmon/Operational/2", "Microsoft-Windows-Sysmon/Operational/15", "Security/4663", "Security/4656"},
		CatDeletion:   {"Security/4660", "Microsoft-Windows-Sysmon/Operational/23", "Microsoft-Windows-Sysmon/Operational/26"},
		CatDevice: {"Microsoft-Windows-Partition/Diagnostic/1006", "Microsoft-Windows-DriverFrameworks-UserMode/Operational/2003",
			"Microsoft-Windows-DriverFrameworks-UserMode/Operational/2100", "Microsoft-Windows-DriverFrameworks-UserMode/Operational/2102",
			"Microsoft-Windows-Kernel-PnP/Configuration/400", "Microsoft-Windows-Kernel-PnP/Configuration/410", "System/20001", "System/20003",
			"Security/6416", "Microsoft-Windows-Storsvc/Diagnostic/1001"},
		CatRegistry: {"Microsoft-Windows-Sysmon/Operational/12", "Microsoft-Windows-Sysmon/Operational/13", "Security/4657"},
	} {
		for _, k := range keys {
			eventCategories[k] = cat
		}
	}
}

func eventCategory(channel, provider, eid string) string {
	if c, ok := providerEventCategories[channel+"/"+provider+"/"+eid]; ok {
		return c
	}
	if c, ok := eventCategories[channel+"/"+eid]; ok {
		return c
	}
	return CatLog
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case json.Number:
		return x.String()
	case bool:
		return fmt.Sprintf("%v", x)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := str(m[k]); s != "" && s != "-" {
			return s
		}
	}
	return ""
}

func (evtxParser) Parse(ctx *Context) error {
	chunks, err := evtx.GetChunks(ctx.File)
	if err != nil {
		return err
	}
	if len(chunks) == 0 {
		ctx.Warn("no valid chunks found")
	}
	fromSystem, renumbered, otherComputer := 0, 0, 0
	// The events placed, by channel, the event's own record number and its
	// exact time: a recovered record matching one is a copy (of a live
	// record, renumbered when the log was saved, or of another recovered
	// one) and is left out.
	placed := map[string]bool{}
	recovered, copies, undecoded := 0, 0, 0
	// emitRecord puts one record on the timeline; recoveredAt is its offset in
	// the chunk when it was recovered from unused space, else 0. chunkData is
	// read only when a record's own time is needed.
	emitRecord := func(chunk *evtx.Chunk, chunkData *[]byte, rec *evtx.EventRecord, recoveredAt int) error {
		raw, err := json.Marshal(rec.Event)
		if err != nil {
			ctx.Warn("record %d could not be rendered: %v", rec.Header.RecordID, err)
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			ctx.Warn("record %d could not be decoded: %v", rec.Header.RecordID, err)
			return nil
		}
		ev, _ := m["Event"].(map[string]any)
		if ev == nil {
			ev = m
		}
		// An event's time is its own TimeCreated, as Event Viewer shows
		// it. The record header holds the same time in an ordinary log;
		// in a log saved from another ("Save filtered log file as",
		// wevtutil epl) the header is rewritten, its time sometimes zero,
		// and the record numbers start again from 1.
		stamp, ok := timeutil.FromFiletime(rec.Header.FileTime)
		headerTime := ok
		if secs, isNum := dig(ev, "System", "TimeCreated", "SystemTime").(float64); isNum && secs > 0 {
			// The library gives TimeCreated as floating-point seconds,
			// which at present-day values is good to about a
			// microsecond; the exact value is taken from the record.
			if *chunkData == nil {
				*chunkData = readChunk(ctx, chunk.Offset)
			}
			if ft, found := exactFiletime(*chunkData, rec.Header, secs); found && ft != rec.Header.FileTime {
				if s2, ok2 := timeutil.FromFiletime(ft); ok2 {
					stamp, ok = s2, true
					fromSystem++
				}
			}
		}
		if !ok {
			ctx.Warn("record %d has no usable timestamp", rec.Header.RecordID)
			return nil
		}
		channel := str(dig(ev, "System", "Channel"))
		eid := str(dig(ev, "System", "EventID", "Value"))
		if eid == "" {
			eid = str(dig(ev, "System", "EventID"))
		}
		provider := str(dig(ev, "System", "Provider", "Name"))
		data, _ := ev["EventData"].(map[string]any)
		if data == nil {
			data, _ = ev["UserData"].(map[string]any)
		}
		user := firstNonEmpty(data, "TargetUserName", "SubjectUserName", "User", "AccountName")
		if user == "" {
			user = str(dig(ev, "System", "Security", "UserID"))
		}
		path := firstNonEmpty(data, "NewProcessName", "Image", "ImagePath", "ServiceFileName", "TargetFilename", "ProcessName", "Path")

		desc := eventNames[channel+"/"+eid]
		if d, ok := providerEventNames[channel+"/"+provider+"/"+eid]; ok {
			desc = d
		}
		var b strings.Builder
		if desc != "" {
			b.WriteString(desc)
		} else {
			b.WriteString("Event")
		}
		fmt.Fprintf(&b, " [%s %s]", channel, eid)
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		shown := 0
		for _, k := range keys {
			v := str(data[k])
			if v == "" || v == "-" || shown >= 10 {
				continue
			}
			fmt.Fprintf(&b, " %s=%s", k, trunc(v, 160))
			shown++
		}
		recordID := rec.Header.RecordID
		if n, isNum := dig(ev, "System", "EventRecordID").(float64); isNum && n >= 0 && uint64(n) != recordID {
			recordID = uint64(n)
			renumbered++
		}
		fields := map[string]any{
			"event_id": eid, "channel": channel, "provider": provider,
			"record_id": recordID, "event": ev,
		}
		if recordID != rec.Header.RecordID {
			fields["record_number_in_file"] = rec.Header.RecordID
		}
		if headerTime && stamp.Raw != fmt.Sprintf("FILETIME 0x%016X", rec.Header.FileTime) {
			if ht, okh := timeutil.FromFiletime(rec.Header.FileTime); okh {
				fields["record_written"] = ht.UTC.Format("2006-01-02T15:04:05.0000000Z")
			}
		}
		// The host is the computer the log came from, when that is known
		// (the submission's host, or the SYSTEM hive beside it); a record
		// that names another computer (a forwarded event) keeps that name
		// in "computer". Otherwise the record's own computer is the host.
		host := str(dig(ev, "System", "Computer"))
		if ctx.Host != "" {
			if host != "" && !SameHost(host, ctx.Host) {
				fields["computer"] = host
				otherComputer++
			}
			host = ctx.Host
		}
		same := fmt.Sprintf("%s/%d/%s", channel, recordID, stamp.Raw)
		if recoveredAt > 0 && placed[same] {
			copies++
			return nil
		}
		placed[same] = true
		typ, msg, ref := "event-logged", b.String(), fmt.Sprintf("record %d, chunk at offset %d", recordID, chunk.Offset)
		if rec.Truncated {
			// The patched library stops a record that would take unbounded
			// work to decode (third_party/evtx, maxWork).
			ctx.Warn("record %d could not be decoded in full (its binary XML is damaged or refers to itself without end); the part read is kept", recordID)
			fields["truncated"] = "decoding stopped: the record's binary XML would take unbounded work; what was read is kept"
		}
		if recoveredAt > 0 {
			// An older record left in the chunk's unused space: the log no
			// longer lists it, but nothing has yet written over it.
			recovered++
			typ, msg = "event-logged (recovered)", "Recovered record: "+msg
			ref = fmt.Sprintf("recovered record %d at offset %d of the chunk at offset %d", recordID, recoveredAt, chunk.Offset)
			fields["recovered"] = "from the chunk's unused space: an older record the log no longer lists, decoded with the templates of the records before it"
		}
		return ctx.Emit(Event{
			Stamp: stamp, Type: typ, Category: eventCategory(channel, provider, eid), Source: "evtx",
			Host: host, User: user, Path: path,
			Message: msg, Fields: fields, Ref: ref,
		})
	}
	type key struct{ id, ft uint64 }
	live := map[key]bool{}
	liveCount := make([]int, len(chunks))
	for ci, chunk := range chunks {
		records, perr := parseChunk(chunk)
		if perr != nil {
			ctx.Warn("chunk %d at offset %d: %v", ci, chunk.Offset, perr)
		}
		liveCount[ci] = len(records)
		var chunkData []byte
		for _, rec := range records {
			live[key{rec.Header.RecordID, rec.Header.FileTime}] = true
			if err := emitRecord(chunk, &chunkData, rec, 0); err != nil {
				return err
			}
		}
	}
	// Older records in the chunks' unused space, after the live ones.
	for ci, chunk := range chunks {
		data := readChunk(ctx, chunk.Offset)
		recs, bad := recoverRecords(chunk, data, liveCount[ci])
		undecoded += bad
		for _, r := range recs {
			if live[key{r.rec.Header.RecordID, r.rec.Header.FileTime}] {
				copies++
				continue
			}
			if err := emitRecord(chunk, &data, r.rec, r.off); err != nil {
				return err
			}
		}
	}
	if recovered > 0 || undecoded > 0 {
		ctx.Note("%d older records were recovered from unused space in the log's chunks (event type \"event-logged (recovered)\"); %d found there were copies of live records and left out, and %d could not be decoded, the templates they use having been overwritten", recovered, copies, undecoded)
	}
	if otherComputer > 0 {
		ctx.Note("%d records name a computer other than %s, the host this log came from: forwarded events, or a log copied from another machine. Each keeps the name it gives in its \"computer\" field", otherComputer, ctx.Host)
	}
	if fromSystem > 0 || renumbered > 0 {
		ctx.Note("this log was saved from another one: %d records were renumbered when it was written and %d have a record time that differs from the event's own. The original record numbers and each event's own time (TimeCreated) are used; the rewritten ones are kept in the fields", renumbered, fromSystem)
	}
	return nil
}

type recoveredRecord struct {
	rec *evtx.EventRecord
	off int
}

// maxRecoveredPerChunk bounds the candidates tried in one chunk: a 64 KiB
// chunk holds a few hundred real records at most.
const maxRecoveredPerChunk = 1024

// recoverRecords finds older records in a chunk's unused space (from the
// header's free-space offset to its end) and decodes them. A candidate has
// the record signature at an 8-byte boundary and its size repeated in its
// last four bytes. The library walks a chunk from its first record by each
// record's size, learning templates as it goes, and cannot be pointed at an
// offset; so it is given a copy of the chunk in which the last live record's
// size (and each earlier recovered one's) leads to the candidate, and the
// header counts one record more. A candidate whose template was defined by a
// record since overwritten does not decode, and is counted, not guessed at.
func recoverRecords(chunk *evtx.Chunk, data []byte, live int) (out []recoveredRecord, undecoded int) {
	const size = 0x10000
	if len(data) < size {
		return nil, 0
	}
	le := binary.LittleEndian
	free := int(le.Uint32(data[0x30:]))
	if free < 0x200 || free > size {
		return nil, 0
	}
	last, at := -1, 0x200
	for i := 0; i < live; i++ {
		if at+24 > size || !bytes.Equal(data[at:at+4], []byte("**\x00\x00")) {
			return nil, 0
		}
		n := int(le.Uint32(data[at+4:]))
		if n < 24 || at+n > size {
			return nil, 0
		}
		last, at = at, at+n
	}
	var cands []int
	for off := (max(free, at) + 7) &^ 7; off+28 <= size && len(cands) < maxRecoveredPerChunk; off += 8 {
		if !bytes.Equal(data[off:off+4], []byte("**\x00\x00")) {
			continue
		}
		n := int(le.Uint32(data[off+4:]))
		if n < 28 || off+n > size || int(le.Uint32(data[off+n-4:])) != n {
			continue
		}
		cands = append(cands, off)
		off += n&^7 - 8
	}
	// The templates the walk will know: those of the live records.
	known := map[uint32]bool{}
	for i, off := 0, 0x200; i < live; i++ {
		if id, _, ok := topInstance(data, off); ok {
			known[id] = true
		}
		off += int(le.Uint32(data[off+4:]))
	}
	var chain []int
	// walk decodes the accepted records and then seq, in one pass of the
	// library over a copy of the chunk; it returns seq's records.
	walk := func(seq []int) ([]*evtx.EventRecord, bool) {
		steps := append(append([]int{}, chain...), seq...)
		prev := last
		if prev < 0 {
			// No live records: the walk must start at the first record's place.
			if steps[0] != 0x200 {
				return nil, false
			}
			prev, steps = steps[0], steps[1:]
		}
		buf := make([]byte, size)
		copy(buf, data)
		for _, w := range steps {
			le.PutUint32(buf[prev+4:], uint32(w-prev))
			prev = w
		}
		h := chunk.Header
		count := live + len(chain) + len(seq)
		h.LastEventRecNumber = h.FirstEventRecNumber + uint64(count) - 1
		recs, err := parseChunk(&evtx.Chunk{Header: h, Offset: 0, Fd: bytes.NewReader(buf)})
		if err != nil || len(recs) != count {
			return nil, false
		}
		return recs[count-len(seq):], true
	}
	// try decodes a batch of candidates in one walk; when any of them fails,
	// the batch is halved and each half tried, so that a candidate fails
	// alone. Only a record whose template is defined in it, or by a record
	// read before it, is given to the library: otherwise it would read
	// whatever is at the template's old place as a definition, and it trusts
	// the counts it finds there.
	var try func(batch []int)
	try = func(batch []int) {
		if len(batch) == 0 {
			return
		}
		ids, prov, ok := make([]uint32, len(batch)), map[uint32]bool{}, true
		for i, c := range batch {
			id, inline, good := topInstance(data, c)
			if !good || (!inline && !known[id] && !prov[id]) {
				ok = false
				break
			}
			ids[i], prov[id] = id, true
		}
		var recs []*evtx.EventRecord
		if ok {
			recs, ok = walk(batch)
		}
		for i := 0; ok && i < len(recs); i++ {
			ok = !recs[i].Truncated && decodedEvent(recs[i])
		}
		if ok {
			for i, c := range batch {
				chain = append(chain, c)
				known[ids[i]] = true
				out = append(out, recoveredRecord{recs[i], c})
			}
			return
		}
		if len(batch) == 1 {
			undecoded++
			return
		}
		try(batch[:len(batch)/2])
		try(batch[len(batch)/2:])
	}
	try(cands)
	return out, undecoded
}

// topInstance reads the template instance a record's binary XML opens with:
// the fragment header (0x0F 01 01 00), then token 0x0C, 0x01, the template's
// identifier and the offset of its definition, which follows at once when
// the definition is inline (next-definition offset, GUID, size, body). Every
// count the library would read as the number of arguments must fit in the
// record, so a damaged one cannot make it allocate without bound.
func topInstance(data []byte, off int) (id uint32, inline, ok bool) {
	le := binary.LittleEndian
	if off < 0 || off+28 > len(data) {
		return 0, false, false
	}
	size := int(le.Uint32(data[off+4:]))
	end := off + size
	t := off + 28
	if size < 28 || end > len(data) || !bytes.Equal(data[off+24:t], []byte{0x0F, 0x01, 0x01, 0x00}) || t+14 > end || data[t] != 0x0C || data[t+1] != 0x01 {
		return 0, false, false
	}
	id = le.Uint32(data[t+2:])
	inline = int(le.Uint32(data[t+6:])) == t+10
	limit := uint32(size / 4)
	if le.Uint32(data[t+10:]) > limit && !inline {
		return 0, false, false
	}
	if inline {
		if t+34 > end {
			return 0, false, false
		}
		body := int(le.Uint32(data[t+30:]))
		if body < 0 || t+34+body+4 > end || le.Uint32(data[t+34+body:]) > limit || le.Uint32(data[t+10:]) > 0x10000 {
			return 0, false, false
		}
	}
	return id, inline, id != 0
}

// decodedEvent says whether a record decoded to an event with a System
// block naming its event: a record decoded with the wrong template does not.
func decodedEvent(rec *evtx.EventRecord) bool {
	raw, err := json.Marshal(rec.Event)
	if err != nil {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	ev, _ := m["Event"].(map[string]any)
	if ev == nil {
		ev = m
	}
	return dig(ev, "System", "EventID") != nil && dig(ev, "System", "Provider") != nil
}

// readChunk reads one 64 KiB chunk of the log.
func readChunk(ctx *Context, off int64) []byte {
	b := make([]byte, 0x10000)
	n, _ := ctx.File.ReadAt(b, off)
	return b[:n]
}

// exactFiletime finds, in a record's stored bytes, the FILETIME the library
// turned into secs (a floating-point count of seconds, which cannot hold all
// 100-nanosecond digits). The record is found in its chunk by its header,
// and the value accepted is the closest to secs within 3.3 microseconds
// (a float64 holds a present-day FILETIME only to the nearest 16 ticks).
func exactFiletime(chunk []byte, h evtx.EventRecordHeader, secs float64) (uint64, bool) {
	var hdr [24]byte
	copy(hdr[:4], h.Magic[:])
	binary.LittleEndian.PutUint32(hdr[4:], h.Size)
	binary.LittleEndian.PutUint64(hdr[8:], h.RecordID)
	binary.LittleEndian.PutUint64(hdr[16:], h.FileTime)
	at := bytes.Index(chunk, hdr[:])
	if at < 0 || h.Size < 24 || at+int(h.Size) > len(chunk) {
		return 0, false
	}
	rec := chunk[at+24 : at+int(h.Size)]
	want := secs*1e7 + 116444736000000000
	best, bestD := uint64(0), 33.0
	for i := 0; i+8 <= len(rec); i++ {
		v := binary.LittleEndian.Uint64(rec[i:])
		if d := math.Abs(float64(v) - want); d < bestD {
			best, bestD = v, d
		}
	}
	return best, bestD < 33
}

// parseChunk isolates the library so one corrupt chunk cannot stop the file.
func parseChunk(c *evtx.Chunk) (recs []*evtx.EventRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	return c.Parse(0)
}
