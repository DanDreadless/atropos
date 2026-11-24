package store

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Details are what the examiner states about the case and about each host
// examined: the things a report must carry that no artefact can supply, such
// as the exhibit reference, the serial number read off the case, who
// collected it and how far its clock was from true time.
//
// The fields follow what the published reporting standards ask for:
//
//   - SWGDE Requirements for Report Writing in Digital and Multimedia
//     Forensics (18-Q-002): examining organisation, case identifier, the
//     request (who, when, purpose and scope, authority), the items submitted
//     (when, how, by whom, and what uniquely identifies each: make, model,
//     serial number, markings, hash), and disposition.
//   - ISO/IEC 17025 clause 7.8, which accredited laboratories report to:
//     unambiguous identification of the item, its condition, the dates of
//     receipt and of the work, the method used, who authorised the report.
//   - ISO/IEC 27037 and the ACPO guide: who handled the item, where and when,
//     the state it was found in, and the system clock compared with a
//     reliable source.
//   - NIST SP 800-86: acquisition method and tool, and integrity hashes.
//
// Like everything else in a case, a detail is never changed in place: a new
// value is appended and the old one stays, with who stated it and when.

// DetailField describes one thing to fill in.
type DetailField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Group string `json:"group"`
	Hint  string `json:"hint,omitempty"`
	Long  bool   `json:"long,omitempty"` // more than a line
}

// CaseFields are stated once for the case.
var CaseFields = []DetailField{
	{"case_reference", "Case reference", "Report", "The identifier this case is known by, as it will appear on every page of a report", false},
	{"organisation", "Examining organisation", "Report", "Name and address of the organisation or laboratory doing the examination", true},
	{"examiner", "Examiner", "Report", "Name, role and relevant qualifications of the person responsible for the examination", false},
	{"authorised_by", "Report authorised by", "Report", "Who reviews and authorises the report, if not the examiner", false},
	{"requested_by", "Requested by", "Request", "Name and organisation of whoever asked for the examination", false},
	{"request_date", "Date of request", "Request", "", false},
	{"authority", "Authority", "Request", "What permits the examination: consent, warrant, contract, policy, instruction", false},
	{"purpose_scope", "Purpose and scope", "Request", "What was asked, and what is and is not being examined", true},
	{"examination_dates", "Dates of examination", "Examination", "When the work was started and finished", false},
	{"limitations", "Limitations", "Examination", "Anything that limits what the findings can show: missing artefacts, encryption, time available, items not examined", true},
	{"disposition", "Disposition of items", "Examination", "What happened to the items and copies afterwards: returned, retained, destroyed, and to whom", true},
}

// HostFields are stated for each host examined.
var HostFields = []DetailField{
	{"exhibit_reference", "Exhibit reference", "Identification", "The item's unique reference in the case", false},
	{"description", "Description", "Identification", "What the item is and whose: for example, laptop issued to a named member of staff", false},
	{"make", "Make", "Identification", "", false},
	{"model", "Model", "Identification", "", false},
	{"serial_number", "Serial number", "Identification", "As read from the device itself", false},
	{"asset_tag", "Asset tag", "Identification", "", false},
	{"markings_condition", "Markings and condition", "Identification", "Labels, damage, seals, anything that distinguishes the item or shows the state it arrived in", true},
	{"owner_custodian", "Owner or custodian", "Identification", "Who the item belongs to, and who had it", false},

	{"operating_system", "Operating system", "System", "Name, edition, version and build", false},
	{"os_installed", "Operating system installed", "System", "Install date, with its time zone", false},
	{"domain", "Domain or workgroup", "System", "", false},
	{"time_zone", "Time zone", "System", "The zone the host was set to, as a zone name such as Europe/London: Atropos then uses it for times this host's evidence records in local time (a zone read from its SYSTEM hive takes precedence)", false},
	{"ip_addresses", "IP addresses", "System", "", false},
	{"mac_addresses", "MAC addresses", "System", "", false},
	{"accounts", "User accounts of interest", "System", "", true},

	{"clock_read", "System clock read", "Clock", "The date and time the device's clock showed (BIOS or firmware clock for a machine that was off)", false},
	{"clock_reference", "True time at that moment", "Clock", "From a reliable source, with its time zone", false},
	{"clock_offset", "Clock difference", "Clock", "How far the device was ahead of or behind true time. Every time on this host's timeline is out by this much", false},

	{"storage", "Storage devices", "Storage", "For each drive: make, model, serial number, capacity, interface", true},
	{"encryption", "Encryption", "Storage", "Whether the storage was encrypted, with what, and how it was unlocked", false},

	{"collected_when", "Collected or received", "Collection", "Date and time, with its time zone", false},
	{"collected_by", "Collected by", "Collection", "", false},
	{"collected_where", "Collected from", "Collection", "The place, and who handed it over if anyone", false},
	{"state_found", "State when found", "Collection", "Powered on or off, logged in or locked, connected to a network, what was on screen", true},
	{"acquisition_method", "Acquisition method", "Collection", "Physical or logical image, live triage collection, files copied; write blocker used", false},
	{"acquisition_tool", "Acquisition tool", "Collection", "Name and version of the tool and of any write blocker", false},
	{"acquisition_when", "Acquired", "Collection", "Date and time of acquisition, and by whom", false},
	{"acquisition_hashes", "Image and hashes", "Collection", "File name and format of each image, and the hashes recorded when it was made and when it was verified", true},
	{"custody", "Chain of custody", "Collection", "Each handover of the item: date, from, to, reason, and where it is stored", true},
	{"notes", "Notes", "Collection", "", true},
}

const maxDetailValue = 8000

// Detail is the current value of one field.
type Detail struct {
	Value   string `json:"value"`
	Actor   string `json:"actor"`
	MadeUTC int64  `json:"made_utc,string"`
}

// HostDetails are the stated details of one host.
type HostDetails struct {
	Name   string            `json:"name"`
	Values map[string]Detail `json:"values"`
	// Found holds what the evidence itself says, for comparison. It is never
	// copied into Values: what the examiner states and what Atropos read stay apart.
	Found map[string]string `json:"found,omitempty"`
}

// AllDetails is everything stated, plus what is needed to fill it in.
type AllDetails struct {
	CaseFields []DetailField     `json:"case_fields"`
	HostFields []DetailField     `json:"host_fields"`
	Case       map[string]Detail `json:"case"`
	Hosts      []HostDetails     `json:"hosts"`
	// KnownHosts are host names the evidence gives that have no details yet.
	KnownHosts []string `json:"known_hosts"`
}

func fieldKnown(fields []DetailField, key string) bool {
	for _, f := range fields {
		if f.Key == key {
			return true
		}
	}
	return false
}

// SetDetails states values for the case (host "") or for one host. Only
// values that differ from the current ones are written. An empty value
// withdraws a detail. It returns how many were written.
func (s *Store) SetDetails(host string, values map[string]string) (int, error) {
	host = strings.TrimSpace(host)
	if len(host) > 255 || strings.ContainsAny(host, "\x00\r\n") {
		return 0, errors.New("a host name is at most 255 characters on one line")
	}
	fields, target := CaseFields, "case"
	if host != "" {
		// Describing a host makes it one of the case's hosts, under the
		// spelling it was first given.
		h, err := s.AddHost(host)
		if err != nil {
			return 0, err
		}
		host = h.Name
		fields, target = HostFields, "host:"+host
	}
	current, err := s.currentDetails()
	if err != nil {
		return 0, err
	}
	// A host is the same host however its name is capitalised; the first
	// spelling stated is kept.
	for name := range current {
		if name != "" && strings.EqualFold(name, host) {
			host, target = name, "host:"+name
		}
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	changed := map[string]string{}
	for _, k := range keys {
		v := strings.TrimSpace(strings.ReplaceAll(values[k], "\x00", ""))
		if !fieldKnown(fields, k) {
			return 0, fmt.Errorf("%q is not a detail that can be stated here", k)
		}
		if len(v) > maxDetailValue {
			return 0, fmt.Errorf("%s is longer than %d characters", k, maxDetailValue)
		}
		if current[host][k].Value != v {
			changed[k] = v
		}
	}
	if len(changed) == 0 {
		return 0, nil
	}
	tx, err := s.w.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().UnixNano()
	for _, k := range keys {
		v, ok := changed[k]
		if !ok {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO details(host,field,value,actor,made_utc) VALUES (?,?,?,?,?)`, host, k, v, s.Actor, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(changed), s.Audit("details.set", target, map[string]any{"stated": changed})
}

// currentDetails returns the latest value of every field, by host ("" is the case).
func (s *Store) currentDetails() (map[string]map[string]Detail, error) {
	rows, err := s.w.Query(`SELECT host,field,value,actor,made_utc FROM details ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]Detail{}
	for rows.Next() {
		var host, field string
		var d Detail
		if err := rows.Scan(&host, &field, &d.Value, &d.Actor, &d.MadeUTC); err != nil {
			return nil, err
		}
		if out[host] == nil {
			out[host] = map[string]Detail{}
		}
		out[host][field] = d
	}
	return out, rows.Err()
}

// Details returns what has been stated. Withdrawn values are left out, and a
// host with nothing left stated is not listed.
func (s *Store) Details() (*AllDetails, error) {
	current, err := s.currentDetails()
	if err != nil {
		return nil, err
	}
	out := &AllDetails{CaseFields: CaseFields, HostFields: HostFields, Case: map[string]Detail{}, Hosts: []HostDetails{}, KnownHosts: []string{}}
	// What the evidence says: a host's name, and the zone read from the same
	// submission as that name.
	found := map[string]map[string]string{}
	rows, err := s.w.Query(`SELECT DISTINCT n.value, COALESCE(z.value,'') FROM facts n JOIN evidence e ON e.id = n.evidence_id
		LEFT JOIN (SELECT f.value, x.batch_id FROM facts f JOIN evidence x ON x.id = f.evidence_id WHERE f.key='host.timezone') z ON z.batch_id = e.batch_id
		WHERE n.key='host.name' ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name, zone string
		if err := rows.Scan(&name, &zone); err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if found[key] == nil {
			found[key] = map[string]string{}
			names = append(names, name)
		}
		if zone != "" {
			if have := found[key]["time_zone"]; have == "" {
				found[key]["time_zone"] = zone
			} else if !strings.Contains(have, zone) {
				found[key]["time_zone"] = have + ", " + zone
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	stated := map[string]bool{}
	hosts := make([]string, 0, len(current))
	for h := range current {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		live := map[string]Detail{}
		for k, d := range current[h] {
			if d.Value != "" {
				live[k] = d
			}
		}
		if h == "" {
			out.Case = live
			continue
		}
		if len(live) == 0 {
			continue
		}
		stated[strings.ToLower(h)] = true
		out.Hosts = append(out.Hosts, HostDetails{Name: h, Values: live, Found: found[strings.ToLower(h)]})
	}
	// Hosts the examiner has added but not yet described still have a form.
	added, err := s.Hosts()
	if err != nil {
		return nil, err
	}
	for _, h := range added {
		if !stated[strings.ToLower(h.Name)] {
			stated[strings.ToLower(h.Name)] = true
			out.Hosts = append(out.Hosts, HostDetails{Name: h.Name, Values: map[string]Detail{}, Found: found[strings.ToLower(h.Name)]})
		}
	}
	for _, n := range names {
		if !stated[strings.ToLower(n)] {
			out.KnownHosts = append(out.KnownHosts, n)
		}
	}
	return out, nil
}

// DetailChange is one statement of a value.
type DetailChange struct {
	Host    string `json:"host"`
	Field   string `json:"field"`
	Value   string `json:"value"`
	Actor   string `json:"actor"`
	MadeUTC int64  `json:"made_utc,string"`
}

// DetailHistory returns every value ever stated, oldest first, withdrawn
// and replaced ones included.
func (s *Store) DetailHistory() ([]DetailChange, error) {
	rows, err := s.w.Query(`SELECT host,field,value,actor,made_utc FROM details ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DetailChange{}
	for rows.Next() {
		var c DetailChange
		if err := rows.Scan(&c.Host, &c.Field, &c.Value, &c.Actor, &c.MadeUTC); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
