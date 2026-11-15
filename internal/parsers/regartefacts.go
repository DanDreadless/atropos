package parsers

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/DanDreadless/atropos/internal/timeutil"

	"www.velocidex.com/golang/regparser"
)

// Registry keys that are evidence of something more specific than "a key was
// written". classifyKey gives such a key's event its own type, category and
// message; regExtras emits the further events some keys hold in their values.
//
// All matching is on the lower-cased key path. Control sets are matched as
// controlsetNNN so that every set in the hive is covered, not only the
// current one: an attacker's service in an older control set is still
// evidence.

var (
	reService = regexp.MustCompile(`^\\controlset\d{3}\\services\\([^\\]+)$`)
	reUSBStor = regexp.MustCompile(`^\\controlset\d{3}\\enum\\usbstor\\([^\\]+)\\([^\\]+)$`)
	reUSBTime = regexp.MustCompile(`^\\controlset\d{3}\\enum\\(usbstor|usb|scsi)\\([^\\]+)\\([^\\]+)\\properties\\\{83da6326-97a6-4088-9453-a1923f573b29\}\\(0064|0065|0066|0067)$`)
	reBAM     = regexp.MustCompile(`^\\controlset\d{3}\\services\\(bam|dam)\\(?:state\\)?usersettings\\(s-[0-9-]+)$`)
	reRunKey  = regexp.MustCompile(`\\microsoft\\windows\\currentversion\\(run|runonce|runonceex|runservices|runservicesonce|policies\\explorer\\run)$`)
	reAmcache = regexp.MustCompile(`^\\root\\inventoryapplicationfile\\[^\\]+$`)
	reAmcDrv  = regexp.MustCompile(`^\\root\\inventorydriverbinary\\[^\\]+$`)
	reMounted = regexp.MustCompile(`^\\mounteddevices$`)

	reMountPoint   = regexp.MustCompile(`\\explorer\\mountpoints2\\[^\\]+$`)
	reRDPServer    = regexp.MustCompile(`\\software\\microsoft\\terminal server client\\servers\\[^\\]+$`)
	reSysinternals = regexp.MustCompile(`^\\software\\sysinternals\\[^\\]+$`)
	reShutdown     = regexp.MustCompile(`^\\controlset\d{3}\\control\\windows$`)
	reTasksReg     = regexp.MustCompile(`\\microsoft\\windows nt\\currentversion\\schedule\\taskcache\\tree\\.+$`)
)

// usbTimes names the device property values that hold connection times.
var usbTimes = map[string][2]string{
	"0064": {"device-first-installed", "first installed"},
	"0065": {"device-first-arrival", "first connected"},
	"0066": {"device-last-connected", "last connected"},
	"0067": {"device-last-removed", "last removed"},
}

func val(vals map[string]any, name string) string {
	for k, v := range vals {
		if strings.EqualFold(k, name) {
			if m, ok := v.(map[string]any); ok {
				s, _ := m["data"].(string)
				return s
			}
		}
	}
	return ""
}

// classifyKey returns the type, category and message for a key's last-write
// event. ok is false for an ordinary key.
func classifyKey(hive, lower, path string, vals map[string]any) (typ, cat, msg, target string, ok bool) {
	switch {
	case hive == "SYSTEM" && reService.MatchString(lower):
		image := val(vals, "ImagePath")
		if image == "" {
			image = val(vals, "ServiceDll")
		}
		if image == "" {
			return "", "", "", "", false // a key under Services that is not a service
		}
		name := reService.FindStringSubmatch(lower)[1]
		msg = fmt.Sprintf("Service key written: %s runs %s", path[strings.LastIndexByte(path, '\\')+1:], trunc(image, 300))
		if s := val(vals, "Start"); s != "" {
			msg += "  (start type " + map[string]string{"0": "boot", "1": "system", "2": "automatic", "3": "manual", "4": "disabled"}[s] + ")"
		}
		_ = name
		return "service-key-last-write", CatPersistence, msg, image, true
	case reRunKey.MatchString(lower):
		var entries []string
		for k, v := range vals {
			if m, ok := v.(map[string]any); ok {
				entries = append(entries, k+"="+trunc(fmt.Sprint(m["data"]), 200))
			}
		}
		sortStrings(entries)
		msg = "Autostart key written: " + path
		if len(entries) > 0 {
			msg += "  " + strings.Join(entries, "; ")
		}
		return "autostart-key-last-write", CatPersistence, trunc(msg, maxMessage), "", true
	case hive == "SYSTEM" && reUSBStor.MatchString(lower):
		g := reUSBStor.FindStringSubmatch(lower)
		parts := strings.Split(path, `\`)
		name := val(vals, "FriendlyName")
		if name == "" {
			name = parts[len(parts)-2]
		}
		_ = g
		msg = fmt.Sprintf("USB storage device key written: %s, serial %s", name, parts[len(parts)-1])
		return "usb-device-key-last-write", CatDevice, msg, name, true
	case hive == "AMCACHE" && reAmcache.MatchString(lower):
		p := val(vals, "LowerCaseLongPath")
		if p == "" {
			// Windows also keeps entries that hold nothing but the program's
			// and the file's identifiers: the file's name is then only in
			// the key's own name, in front of a bar. The name and the hash
			// are still evidence that the file was on the machine.
			if len(val(vals, "FileId")) != 44 {
				return "", "", "", "", false
			}
			name := path[strings.LastIndex(path, `\`)+1:]
			if i := strings.LastIndex(name, "|"); i > 0 {
				name = name[:i]
			}
			return "amcache-file-hash-recorded", CatExecution, "Amcache: file recorded by name and hash only: " + name, name, true
		}
		msg = "Amcache: file recorded: " + p
		if pub := val(vals, "Publisher"); pub != "" {
			msg += "  (" + pub + ")"
		}
		return "amcache-file-recorded", CatExecution, msg, p, true
	case hive == "AMCACHE" && reAmcDrv.MatchString(lower):
		p := val(vals, "DriverName")
		if p == "" {
			return "", "", "", "", false
		}
		return "amcache-driver-recorded", CatExecution, "Amcache: driver recorded: " + p, p, true
	case hive == "NTUSER" && reMountPoint.MatchString(lower):
		name := path[strings.LastIndexByte(path, '\\')+1:]
		if strings.HasPrefix(name, "##") {
			// Explorer writes \\server\share as ##server#share.
			share := `\\` + strings.ReplaceAll(name[2:], "#", `\`)
			return "network-share-key-last-write", CatNetwork, "Network share used by this account: " + share, share, true
		}
		return "mount-point-key-last-write", CatDevice, "Volume or drive used by this account: " + name, name, true
	case hive == "NTUSER" && reRDPServer.MatchString(lower):
		server := path[strings.LastIndexByte(path, '\\')+1:]
		msg = "Remote Desktop connection from this account to " + server
		if hint := val(vals, "UsernameHint"); hint != "" {
			msg += " (signing in as " + hint + ")"
		}
		return "rdp-client-server-key-last-write", CatNetwork, msg, server, true
	case hive == "NTUSER" && strings.HasSuffix(lower, `\software\microsoft\terminal server client\default`):
		return "rdp-client-recent-key-last-write", CatNetwork, "Remote Desktop recent connections list written: " + listValues(vals, "MRU"), "", true
	case hive == "NTUSER" && reSysinternals.MatchString(lower):
		if val(vals, "EulaAccepted") == "" {
			return "", "", "", "", false
		}
		tool := path[strings.LastIndexByte(path, '\\')+1:]
		return "sysinternals-eula-key-last-write", CatExecution,
			"Sysinternals " + tool + " licence accepted by this account, which happens when the tool is first run", tool, true
	case hive == "NTUSER" && strings.HasSuffix(lower, `\explorer\typedpaths`):
		return "typed-paths-key-last-write", CatFileOpening,
			"Paths typed into the Explorer address bar (the time is of the latest): " + listValues(vals, "url"), "", true
	case hive == "NTUSER" && strings.HasSuffix(lower, `\explorer\runmru`):
		return "run-dialog-key-last-write", CatExecution,
			"Commands typed into the Run dialog (the time is of the latest): " + mruValues(vals), "", true
	case hive == "SOFTWARE" && strings.HasSuffix(lower, `\microsoft\windows nt\currentversion\winlogon`):
		return "winlogon-key-last-write", CatPersistence,
			fmt.Sprintf("Winlogon key written: Userinit=%s; Shell=%s", trunc(val(vals, "Userinit"), 300), trunc(val(vals, "Shell"), 300)), "", true
	case hive == "SAM" && reSAMName.MatchString(lower):
		name := path[strings.LastIndexByte(path, '\\')+1:]
		return "account-name-key-last-write", CatAccount,
			"Local account name key written, which normally happens when the account is created: " + name, name, true
	case hive == "SOFTWARE" && reTasksReg.MatchString(lower):
		if val(vals, "Id") == "" {
			return "", "", "", "", false
		}
		name := path[strings.Index(strings.ToLower(path), `\tree\`)+5:]
		return "scheduled-task-key-last-write", CatPersistence, "Scheduled task registered or changed: " + name, name, true
	}
	return "", "", "", "", false
}

// listValues joins the values whose names start with prefix (url1, url2, or
// MRU0, MRU1), in name order.
func listValues(vals map[string]any, prefix string) string {
	var names []string
	for k := range vals {
		if len(k) > len(prefix) && strings.EqualFold(k[:len(prefix)], prefix) {
			names = append(names, k)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, trunc(val(vals, n), 200))
	}
	return trunc(strings.Join(out, "; "), maxMessage-200)
}

// mruValues lists a key's lettered values in the order its MRUList value
// gives, most recent first. Run dialog entries end in "\1", which is dropped.
func mruValues(vals map[string]any) string {
	var out []string
	for _, letter := range val(vals, "MRUList") {
		if v := val(vals, string(letter)); v != "" {
			out = append(out, trunc(strings.TrimSuffix(v, `\1`), 200))
		}
	}
	return trunc(strings.Join(out, "; "), maxMessage-200)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// amcacheFields adds what an Amcache file entry records about the file.
func amcacheFields(fields map[string]any, vals map[string]any) {
	// FileId is the file's SHA-1 with four zeros in front. It covers at most
	// the first 31.4 MB of the file, which is why it can differ from a hash
	// of the whole file.
	if id := val(vals, "FileId"); len(id) == 44 {
		fields["sha1_first_31mb"] = id[4:]
	}
	for field, name := range map[string]string{"publisher": "Publisher", "product": "ProductName", "version": "Version", "link_date": "LinkDate", "size": "Size", "name": "Name"} {
		if v := val(vals, name); v != "" {
			fields[field] = v
		}
	}
}

// regExtras emits events held in a key's values rather than its timestamp.
func regExtras(ctx *Context, hive, host, lower, path string, values []*regparser.CM_KEY_VALUE) error {
	if hive != "SYSTEM" {
		return nil
	}
	if g := reUSBTime.FindStringSubmatch(lower); g != nil {
		for _, v := range values {
			d := safeData(v)
			if d == nil || len(d.Data) < 8 {
				continue
			}
			stamp, ok := timeutil.FromFiletime(binary.LittleEndian.Uint64(d.Data))
			if !ok {
				continue
			}
			parts := strings.Split(path, `\`)
			// ...\Enum\<bus>\<device>\<serial>\Properties\{guid}\00NN
			device, serial := parts[len(parts)-5], parts[len(parts)-4]
			kind := usbTimes[g[4]]
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: kind[0], Category: CatDevice, Source: "registry", Host: host, Path: device,
				Message: fmt.Sprintf("Device %s: %s (serial %s, bus %s)", kind[1], device, serial, strings.ToUpper(g[1])),
				Fields:  map[string]any{"device": device, "serial": serial, "bus": strings.ToUpper(g[1]), "key": path},
				Ref:     "device property " + g[4] + " under " + device + `\` + serial,
			}); err != nil {
				return err
			}
		}
	}
	if reShutdown.MatchString(lower) {
		for _, v := range values {
			if !strings.EqualFold(valueName(v), "ShutdownTime") {
				continue
			}
			d := safeData(v)
			if d == nil || len(d.Data) < 8 {
				continue
			}
			stamp, ok := timeutil.FromFiletime(binary.LittleEndian.Uint64(d.Data))
			if !ok {
				continue
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: "system-last-shutdown", Category: CatSecurity, Source: "registry", Host: host,
				Message: "Windows last shut down cleanly (recorded in " + path + ")",
				Fields:  map[string]any{"key": path},
				Ref:     "value ShutdownTime under " + path,
			}); err != nil {
				return err
			}
		}
	}
	if g := reBAM.FindStringSubmatch(lower); g != nil {
		sid := strings.ToUpper(g[2])
		for _, v := range values {
			name := clean(valueName(v))
			d := safeData(v)
			if d == nil {
				continue
			}
			ft, isProgram := bamProgram(name, d.Data)
			if !isProgram {
				continue
			}
			stamp, ok := timeutil.FromFiletime(ft)
			if !ok {
				continue
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: "program-last-run (" + g[1] + ")", Category: CatExecution, Source: "registry",
				Host: host, User: sid, Path: name,
				Message: fmt.Sprintf("%s: %s last run by %s", strings.ToUpper(g[1]), name, sid),
				Fields:  map[string]any{"key": path, "sid": sid, "program": name},
				Ref:     strings.ToUpper(g[1]) + " value " + name,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// bamProgram reports whether a value under a BAM or DAM account key records
// a program, and when it last ran. A program is named by its path, or, for
// a Store app, by its package name, which has no backslash in it; the key's
// own Version and SequenceNumber values are four bytes and are not programs.
// Found by comparison with RECmd, which listed Store apps Atropos had left out.
func bamProgram(name string, data []byte) (uint64, bool) {
	if len(data) < 8 || name == "" || strings.EqualFold(name, "Version") || strings.EqualFold(name, "SequenceNumber") {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data), true
}
