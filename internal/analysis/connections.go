package analysis

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/store"
)

// Connections pairs the two ends of the same connection recorded on two
// hosts of the case: one host's Remote Desktop client connecting, and the
// other's logon from it; a command on one naming a share on the other, and
// that share's access; PsExec run on one, and its service installed on the
// other. Each end is found in that host's own evidence; a
// pair is made when each names the other (by a stated name or address, or an
// address learned from a logon record that gives both) and the times agree
// once each host's stated clock difference is taken off. A connection seen
// at one end only is kept too: the other host may not be in the case, or its
// logs may be missing.
//
// It is a reading of the evidence, never evidence itself, and it is worked
// out afresh each time from the observables and the hosts' details. A pair
// is consistent with one connection; it does not prove it.

const (
	// Events on one host belong to one connection when they are within
	// this of its first event.
	connCluster = 2 * time.Minute
	// Ends further apart than this (after clock correction) are not paired.
	connWindow = 10 * time.Minute
	// Ends closer than this, naming each other and the same account, pair
	// strongly.
	connStrong = 60 * time.Second
)

// ConnNode is a computer or address in the connections graph.
type ConnNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"` // host (in the case), address, computer (a name not in the case), loopback
	InCase bool   `json:"in_case"`
	Detail string `json:"detail,omitempty"`
}

// ConnEvent is one event of a connection's end.
type ConnEvent struct {
	ID   int64  `json:"id"`
	TS   int64  `json:"ts_utc,string"`
	What string `json:"what"`
}

// ConnEnd is what one host recorded of a connection.
type ConnEnd struct {
	Node      string      `json:"node"`
	Start     int64       `json:"start_utc,string"`     // as the host's clock had it
	Corrected int64       `json:"corrected_utc,string"` // with its stated clock difference taken off
	Account   string      `json:"account,omitempty"`
	Events    []ConnEvent `json:"events"`
}

// Connection is one connection from one computer to another.
type Connection struct {
	Kind       string   `json:"kind"` // rdp, smb (a file share), exec (a program started remotely)
	From       string   `json:"from"`
	To         string   `json:"to"`
	Start      int64    `json:"start_utc,string"` // corrected
	Account    string   `json:"account,omitempty"`
	SeenOn     string   `json:"seen_on"`    // both, source, target
	Confidence string   `json:"confidence"` // strong, possible, one-end
	Apart      *int64   `json:"apart_ns,string,omitempty"`
	Source     *ConnEnd `json:"source,omitempty"`
	Target     *ConnEnd `json:"target,omitempty"`
	Reasons    []string `json:"reasons"`
	EventIDs   []int64  `json:"event_ids"`
}

// ConnEdge sums the connections between two nodes.
type ConnEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Count    int    `json:"count"`
	Strong   int    `json:"strong"`
	Possible int    `json:"possible"`
	OneEnd   int    `json:"one_end"`
	First    int64  `json:"first_utc,string"`
	Last     int64  `json:"last_utc,string"`
}

// ConnectionsReport is the whole reading.
type ConnectionsReport struct {
	Ready       bool                 `json:"ready"` // every run has been read
	Nodes       []ConnNode           `json:"nodes"`
	Edges       []ConnEdge           `json:"edges"`
	Connections []Connection         `json:"connections"`
	Hosts       []store.HostIdentity `json:"hosts"`
	Notes       []string             `json:"notes"`
	Events      int                  `json:"events"` // observed events read
}

type connCtx struct {
	hosts   map[string]*store.HostIdentity // by name, upper case
	byName  map[string]string              // any stated name or short name -> host
	byIP    map[string]string              // stated address -> host
	learned map[string]learnedIP
	notes   []string
}

type learnedIP struct {
	host  string
	event int64
}

func shortName(n string) string {
	if i := strings.IndexByte(n, '.'); i > 0 {
		return n[:i]
	}
	return n
}

// hostByName is the case host a computer name means, or "".
func (c *connCtx) hostByName(n string) string {
	n = strings.ToUpper(strings.TrimSpace(n))
	if n == "" {
		return ""
	}
	if h, ok := c.byName[n]; ok {
		return h
	}
	return c.byName[shortName(n)]
}

func hostNode(h string) string { return "host:" + h }

// Connections reads the links between hosts.
func Connections(s *store.Store) (*ConnectionsReport, error) {
	ids, err := s.HostIdentities()
	if err != nil {
		return nil, err
	}
	evs, ready, err := s.ObservedEvents("rdp-in", "rdp-out", "smb-in", "smb-out", "exec-in", "exec-out", "logon-in")
	if err != nil {
		return nil, err
	}
	rep := &ConnectionsReport{Ready: ready, Hosts: ids, Events: len(evs), Nodes: []ConnNode{}, Edges: []ConnEdge{}, Connections: []Connection{}}
	c := &connCtx{hosts: map[string]*store.HostIdentity{}, byName: map[string]string{}, byIP: map[string]string{}, learned: map[string]learnedIP{}}
	shortSeen := map[string]string{}
	for i := range ids {
		h := &ids[i]
		c.hosts[strings.ToUpper(h.Name)] = h
		for _, n := range h.Names {
			c.byName[n] = h.Name
			sn := shortName(n)
			if other, dup := shortSeen[sn]; dup && other != h.Name {
				shortSeen[sn] = "" // ambiguous: two hosts share the short name
			} else if !dup {
				shortSeen[sn] = h.Name
			}
		}
		for _, ip := range h.IPs {
			if other, dup := c.byIP[ip]; dup && other != h.Name {
				c.notes = append(c.notes, fmt.Sprintf("%s is stated as an address of both %s and %s, so it is not used to match either", ip, other, h.Name))
				c.byIP[ip] = ""
				continue
			}
			c.byIP[ip] = h.Name
		}
		for _, u := range h.Unread {
			c.notes = append(c.notes, h.Name+": "+u)
		}
	}
	for sn, h := range shortSeen {
		if _, full := c.byName[sn]; !full && h != "" {
			c.byName[sn] = h
		}
	}
	for ip, h := range c.byIP {
		if h == "" {
			delete(c.byIP, ip)
		}
	}

	// An address is learned for a host from a logon record that names both
	// the workstation and the address it came from.
	conflict := map[string]bool{}
	for _, e := range evs {
		if !strings.HasSuffix(e.Act, "-in") {
			continue
		}
		ip, name := item(e, "ip", "source"), item(e, "host", "source")
		if ip == "" || name == "" || isLoopback(ip) {
			continue
		}
		h := c.hostByName(name)
		if h == "" {
			continue
		}
		if stated, ok := c.byIP[ip]; ok {
			if stated != h && !conflict["s"+ip] {
				conflict["s"+ip] = true
				c.notes = append(c.notes, fmt.Sprintf("Event %d gives workstation %s at %s, but %s is stated as an address of %s; the stated address is used", e.EventID, name, ip, ip, stated))
			}
			continue
		}
		if l, ok := c.learned[ip]; ok && l.host != h {
			if !conflict[ip] {
				conflict[ip] = true
				c.notes = append(c.notes, fmt.Sprintf("%s was used by both %s (event %d) and %s (event %d), so it is not used to match either: addresses change hands", ip, l.host, l.event, h, e.EventID))
			}
			continue
		}
		if _, ok := c.learned[ip]; !ok {
			c.learned[ip] = learnedIP{h, e.EventID}
		}
	}
	for ip := range conflict {
		delete(c.learned, ip)
	}
	var learnedNotes []string
	for ip, l := range c.learned {
		learnedNotes = append(learnedNotes, fmt.Sprintf("%s is taken to be %s's address: event %d records a logon from workstation %s at that address. State the host's addresses on the Details tab to rely on them instead", ip, l.host, l.event, l.host))
	}
	sort.Strings(learnedNotes)
	c.notes = append(c.notes, learnedNotes...)

	nodes := map[string]ConnNode{}
	for _, h := range ids {
		nodes[hostNode(h.Name)] = ConnNode{ID: hostNode(h.Name), Label: h.Name, Kind: "host", InCase: true}
	}
	label := func(id string) string {
		if n, ok := nodes[id]; ok {
			return n.Label
		}
		return id
	}
	// where gives the node of the host an event was recorded on.
	where := func(e store.ObservedEvent) (string, *store.HostIdentity) {
		if h := c.hostByName(e.Host); h != "" {
			return hostNode(h), c.hosts[strings.ToUpper(h)]
		}
		n := strings.ToUpper(e.Host)
		if n == "" {
			n = "(unknown)"
		}
		id := "computer:" + n
		if _, ok := nodes[id]; !ok {
			nodes[id] = ConnNode{ID: id, Label: n, Kind: "computer", Detail: "events from this computer were added, but it is not a host of the case"}
		}
		return id, nil
	}
	corrected := func(ts int64, h *store.HostIdentity) int64 {
		if h == nil {
			return ts
		}
		return ts - int64(h.Clock)
	}
	external := func(kind, v, recorder string) string {
		switch {
		case kind == "ip" && isLoopback(v):
			id := "loopback:" + recorder
			label := nodes[recorder].Label
			nodes[id] = ConnNode{ID: id, Label: v + " on " + label, Kind: "loopback",
				Detail: "a connection from the host itself: often a tunnel (a port forwarded over SSH, a proxy) that hides where it really came from"}
			return id
		case kind == "ip":
			id := "ip:" + v
			if _, ok := nodes[id]; !ok {
				nodes[id] = ConnNode{ID: id, Label: v, Kind: "address", Detail: "an address not stated or learned for any host of the case"}
			}
			return id
		default:
			id := "computer:" + v
			if _, ok := nodes[id]; !ok {
				nodes[id] = ConnNode{ID: id, Label: v, Kind: "computer", Detail: "a computer name that is not a host of the case"}
			}
			return id
		}
	}
	// resolve finds the computer an event names in role, with the reason.
	resolve := func(e store.ObservedEvent, role, recorder string) (string, string) {
		ip, name := item(e, "ip", role), item(e, "host", role)
		if ip != "" && !isLoopback(ip) {
			if h, ok := c.byIP[ip]; ok {
				return hostNode(h), fmt.Sprintf("%s, an address stated for %s", ip, h)
			}
			if l, ok := c.learned[ip]; ok {
				return hostNode(l.host), fmt.Sprintf("%s, the address %s had in event %d", ip, l.host, l.event)
			}
		}
		if name != "" {
			if h := c.hostByName(name); h != "" {
				if strings.EqualFold(name, h) {
					return hostNode(h), name
				}
				return hostNode(h), fmt.Sprintf("%s, a name of %s", name, h)
			}
		}
		if ip != "" {
			return external("ip", ip, recorder), ip
		}
		if name != "" {
			return external("host", name, recorder), name
		}
		return "", ""
	}

	type cluster struct {
		node    string // the host that recorded it
		id      *store.HostIdentity
		family  string // rdp, or smb for shares, remote execution and network logons
		kinds   map[string]bool
		other   string // the computer at the other end
		why     string // how the other end was named
		start   int64
		last    int64
		corr    int64
		account string
		events  []store.ObservedEvent
		byTime  []string // events tied to it by time alone
		paired  bool
	}
	// kind is what the connection was, from the most telling of its events.
	kindOf := func(cl *cluster) string {
		switch {
		case cl.family == "rdp":
			return "rdp"
		case cl.kinds["exec"]:
			return "exec"
		case cl.kinds["smb"]:
			return "smb"
		}
		return "" // network logons alone: not shown
	}
	var ins, outs []*cluster
	type sourceless struct {
		e   store.ObservedEvent
		rec string
		id  *store.HostIdentity
	}
	var loose []sourceless
	open := map[string]*cluster{}
	for _, e := range evs {
		rec, hid := where(e)
		kind, dir, _ := strings.Cut(e.Act, "-")
		family := "smb"
		if kind == "rdp" {
			family = "rdp"
		}
		role := "target"
		if dir == "in" {
			role = "source"
		}
		other, why := resolve(e, role, rec)
		if other == "" {
			if dir == "in" && family == "smb" {
				loose = append(loose, sourceless{e, rec, hid})
			}
			continue
		}
		if other == rec {
			continue // the host naming itself
		}
		key := dir + "\x00" + family + "\x00" + rec
		if dir == "in" || family == "smb" {
			key += "\x00" + other // one connection per computer at the other end
		}
		cl := open[key]
		if cl == nil || e.TSUTC-cl.last > int64(connCluster) {
			cl = &cluster{node: rec, id: hid, family: family, kinds: map[string]bool{}, start: e.TSUTC, corr: corrected(e.TSUTC, hid)}
			open[key] = cl
			if dir == "in" {
				ins = append(ins, cl)
			} else {
				outs = append(outs, cl)
			}
		}
		cl.events = append(cl.events, e)
		cl.kinds[kind] = true
		cl.last = e.TSUTC
		// The other end: a host of the case is preferred to a bare address
		// or name (a client's 1024 has the name typed, its 1102 the address).
		if cl.other == "" || (!strings.HasPrefix(cl.other, "host:") && strings.HasPrefix(other, "host:")) {
			cl.other, cl.why = other, why
		}
		a := item(e, "account", "target")
		if a == "" && dir == "out" {
			a = item(e, "account", "subject")
		}
		if a != "" && (cl.account == "" || (!strings.Contains(cl.account, `\`) && strings.Contains(a, `\`))) {
			cl.account = a
		}
	}
	// A service installed, a task created, a program WMI or WinRM started:
	// each records no source. It is tied to the nearest share access or
	// network logon on the same host, within the clustering time, and when
	// it names a person's account, only to one by that account.
	var untied, local []string
	for _, l := range loose {
		acct := item(l.e, "account", "target")
		var best *cluster
		var bestD int64
		for _, cl := range ins {
			if cl.family != "smb" || cl.node != l.rec {
				continue
			}
			if acct != "" {
				same := false
				for _, e := range cl.events {
					if a := item(e, "account", "target"); a != "" && sameAccount(a, acct) {
						same = true
						break
					}
				}
				if !same {
					continue
				}
			}
			var d int64
			switch {
			case l.e.TSUTC < cl.start:
				d = cl.start - l.e.TSUTC
			case l.e.TSUTC > cl.last:
				d = l.e.TSUTC - cl.last
			}
			if d <= int64(connCluster) && (best == nil || d < bestD) {
				best, bestD = cl, d
			}
		}
		if best == nil {
			w := fmt.Sprintf("%s on %s (event %d)", l.e.What, label(l.rec), l.e.EventID)
			// Tasks and programs WMI starts are made on the host itself
			// all the time: one with no logon to tie it to is taken as
			// local. Services and remote shells are named.
			if v := item(l.e, "via", "object"); v == "task" || v == "wmi" {
				local = append(local, w)
			} else {
				untied = append(untied, w)
			}
			continue
		}
		best.events = append(best.events, l.e)
		best.kinds["exec"] = true
		if acct != "" {
			best.byTime = append(best.byTime, fmt.Sprintf("%s (event %d) records no source; it is tied to this connection by time and by its account, %s", l.e.What, l.e.EventID, acct))
		} else {
			best.byTime = append(best.byTime, fmt.Sprintf("%s (event %d) records no source; it is tied to this connection by time alone", l.e.What, l.e.EventID))
		}
		sort.SliceStable(best.events, func(a, b int) bool { return best.events[a].TSUTC < best.events[b].TSUTC })
	}
	if len(untied) > 0 {
		sort.Strings(untied)
		c.notes = append(c.notes, fmt.Sprintf("%d remote-execution record%s had no network logon or share access within %s to say where %s came from, so %s not shown as %s: %s",
			len(untied), plural(len(untied), "", "s"), fmtDur(connCluster), plural(len(untied), "it", "they"), plural(len(untied), "it is", "they are"), plural(len(untied), "a connection", "connections"), strings.Join(untied, "; ")))
	}
	if len(local) > 0 {
		sort.Strings(local)
		shown := local
		more := ""
		if len(shown) > 10 {
			shown, more = shown[:10], fmt.Sprintf("; and %d more", len(local)-10)
		}
		c.notes = append(c.notes, fmt.Sprintf("%d scheduled task%s or program%s started by WMI under a person's account had no network logon by that account within %s, so %s taken as made on the host itself: %s%s",
			len(local), plural(len(local), "", "s"), plural(len(local), "", "s"), fmtDur(connCluster), plural(len(local), "it is", "they are"), strings.Join(shown, "; "), more))
	}
	keep := ins[:0]
	for _, cl := range ins {
		if kindOf(cl) != "" {
			keep = append(keep, cl)
		}
	}
	ins = keep

	end := func(cl *cluster) *ConnEnd {
		ce := &ConnEnd{Node: cl.node, Start: cl.start, Corrected: cl.corr, Account: cl.account}
		for _, e := range cl.events {
			ce.Events = append(ce.Events, ConnEvent{ID: e.EventID, TS: e.TSUTC, What: e.What})
		}
		return ce
	}
	clockWords := func(h *store.HostIdentity) string {
		if h == nil || !h.ClockStated || h.Clock == 0 {
			return ""
		}
		dir := "ahead"
		d := h.Clock
		if d < 0 {
			dir, d = "behind", -d
		}
		return fmt.Sprintf("%s's clock (stated as %s %s)", h.Name, fmtDur(d), dir)
	}
	outWords := func(cl *cluster) string {
		switch kindOf(cl) {
		case "rdp":
			return fmt.Sprintf("%s's Remote Desktop client connected to %s", label(cl.node), cl.why)
		case "exec":
			return fmt.Sprintf("%s ran a program against %s", label(cl.node), cl.why)
		}
		return fmt.Sprintf("%s ran a command naming a share on %s", label(cl.node), cl.why)
	}
	inWords := func(cl *cluster) string {
		switch kindOf(cl) {
		case "rdp":
			return fmt.Sprintf("%s recorded a Remote Desktop logon from %s", label(cl.node), cl.why)
		case "exec":
			// How, from the records with no source tied to it: one way
			// named, or the general words.
			vias := map[string]bool{}
			for _, e := range cl.events {
				if v := item(e, "via", "object"); v != "" {
					vias[v] = true
				}
			}
			words := "a service or task started remotely"
			if len(vias) == 1 {
				switch {
				case vias["task"]:
					words = "a scheduled task made remotely"
				case vias["wmi"]:
					words = "a program started remotely by WMI"
				case vias["winrm"]:
					words = "a remote management (WinRM) session"
				}
			} else if len(vias) > 1 {
				words = "programs started remotely"
			}
			return fmt.Sprintf("%s recorded %s from %s", label(cl.node), words, cl.why)
		}
		return fmt.Sprintf("%s recorded share access from %s", label(cl.node), cl.why)
	}
	// details names the shares, services and programs an end involved.
	details := func(cl *cluster) []string {
		var out []string
		for _, k := range []struct{ kind, words string }{{"share", "shares"}, {"service", "services installed"}, {"task", "scheduled tasks"}, {"program", "programs"}} {
			seen := map[string]bool{}
			var vs []string
			for _, e := range cl.events {
				for _, it := range e.Items {
					if it.Kind == k.kind && it.Role == "object" && !seen[it.Value] {
						seen[it.Value] = true
						vs = append(vs, it.Value)
					}
				}
			}
			if len(vs) > 0 {
				out = append(out, fmt.Sprintf("%s on %s: %s", k.words, label(cl.node), strings.Join(vs, ", ")))
			}
		}
		return append(out, cl.byTime...)
	}
	stronger := func(a, b string) string {
		rank := map[string]int{"smb": 1, "exec": 2, "rdp": 3}
		if rank[b] > rank[a] {
			return b
		}
		return a
	}

	// Pair the nearest ends first.
	type cand struct {
		o, i *cluster
		dt   int64
	}
	var cands []cand
	for _, o := range outs {
		if !strings.HasPrefix(o.other, "host:") {
			continue
		}
		for _, i := range ins {
			if i.family != o.family || i.node != o.other || i.other != o.node {
				continue
			}
			dt := i.corr - o.corr
			if abs64(dt) <= int64(connWindow) {
				cands = append(cands, cand{o, i, dt})
			}
		}
	}
	sort.SliceStable(cands, func(a, b int) bool { return abs64(cands[a].dt) < abs64(cands[b].dt) })
	for _, cd := range cands {
		if cd.o.paired || cd.i.paired {
			continue
		}
		cd.o.paired, cd.i.paired = true, true
		conn := Connection{Kind: stronger(kindOf(cd.o), kindOf(cd.i)), From: cd.o.node, To: cd.i.node, Start: cd.o.corr, SeenOn: "both", Confidence: "strong",
			Source: end(cd.o), Target: end(cd.i)}
		dt := cd.dt
		conn.Apart = &dt
		conn.Reasons = append(conn.Reasons, outWords(cd.o), inWords(cd.i))
		var corr []string
		for _, w := range []string{clockWords(cd.o.id), clockWords(cd.i.id)} {
			if w != "" {
				corr = append(corr, w)
			}
		}
		gap := fmtDur(time.Duration(abs64(dt)))
		apart := gap + " apart"
		if len(corr) > 0 {
			apart += " after correcting " + strings.Join(corr, " and ")
		}
		if abs64(dt) > int64(connStrong) {
			conn.Confidence = "possible"
			apart += fmt.Sprintf("; more than %s, so possibly a different connection, or a clock difference not stated", fmtDur(connStrong))
		}
		conn.Reasons = append(conn.Reasons, apart)
		switch {
		case cd.o.account != "" && cd.i.account != "" && sameAccount(cd.o.account, cd.i.account):
			conn.Account = cd.i.account
			conn.Reasons = append(conn.Reasons, "the same account at both ends: "+cd.i.account)
		case cd.o.account != "" && cd.i.account != "":
			conn.Account = cd.i.account
			conn.Confidence = "possible"
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("different accounts at each end: %s on %s, %s on %s (other credentials can be given when connecting)",
				cd.o.account, label(cd.o.node), cd.i.account, label(cd.i.node)))
		default:
			conn.Account = cd.i.account + cd.o.account
		}
		conn.Reasons = append(conn.Reasons, details(cd.o)...)
		conn.Reasons = append(conn.Reasons, details(cd.i)...)
		rep.Connections = append(rep.Connections, conn)
	}
	for _, o := range outs {
		if o.paired || o.other == "" {
			continue
		}
		k := kindOf(o)
		conn := Connection{Kind: k, From: o.node, To: o.other, Start: o.corr, Account: o.account, SeenOn: "source", Confidence: "one-end", Source: end(o)}
		conn.Reasons = append(conn.Reasons, outWords(o))
		switch {
		case !nodes[o.other].InCase:
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("%s is not a host of this case", label(o.other)))
		case k == "rdp":
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("%s has no matching logon within %s: the connection may have failed, or that host's logs for the time are missing or were not added", label(o.other), fmtDur(connWindow)))
		default:
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("%s has no matching record within %s: share access is logged only when file share auditing is on, and service installs are in its System log, which may not have been added", label(o.other), fmtDur(connWindow)))
		}
		conn.Reasons = append(conn.Reasons, details(o)...)
		rep.Connections = append(rep.Connections, conn)
	}
	for _, i := range ins {
		if i.paired || i.other == "" {
			continue
		}
		k := kindOf(i)
		conn := Connection{Kind: k, From: i.other, To: i.node, Start: i.corr, Account: i.account, SeenOn: "target", Confidence: "one-end", Target: end(i)}
		conn.Reasons = append(conn.Reasons, inWords(i))
		switch n := nodes[i.other]; {
		case n.InCase && k == "rdp":
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("%s has no record of connecting within %s: its client log may have been cleared or not added, or another program was used", n.Label, fmtDur(connWindow)))
		case n.InCase:
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("%s has no record of it within %s: the commands a computer runs are logged only with process auditing and command lines (Security 4688) or Sysmon, and a share opened in Explorer leaves no such record", n.Label, fmtDur(connWindow)))
		case n.Kind == "loopback":
			conn.Reasons = append(conn.Reasons, "it came from the host itself: "+n.Detail)
		default:
			conn.Reasons = append(conn.Reasons, fmt.Sprintf("%s is not a host of this case", n.Label))
		}
		conn.Reasons = append(conn.Reasons, details(i)...)
		rep.Connections = append(rep.Connections, conn)
	}
	sort.SliceStable(rep.Connections, func(a, b int) bool {
		x, y := rep.Connections[a], rep.Connections[b]
		if x.Start != y.Start {
			return x.Start < y.Start
		}
		return x.From+x.To < y.From+y.To
	})

	edges := map[string]*ConnEdge{}
	var order []string
	used := map[string]bool{}
	for i := range rep.Connections {
		cn := &rep.Connections[i]
		for _, e := range []*ConnEnd{cn.Source, cn.Target} {
			if e != nil {
				for _, ev := range e.Events {
					cn.EventIDs = append(cn.EventIDs, ev.ID)
				}
			}
		}
		sort.Slice(cn.EventIDs, func(a, b int) bool { return cn.EventIDs[a] < cn.EventIDs[b] })
		used[cn.From], used[cn.To] = true, true
		k := cn.Kind + "\x00" + cn.From + "\x00" + cn.To
		ed := edges[k]
		if ed == nil {
			ed = &ConnEdge{From: cn.From, To: cn.To, Kind: cn.Kind, First: cn.Start, Last: cn.Start}
			edges[k] = ed
			order = append(order, k)
		}
		ed.Count++
		switch cn.Confidence {
		case "strong":
			ed.Strong++
		case "possible":
			ed.Possible++
		default:
			ed.OneEnd++
		}
		if cn.Start < ed.First {
			ed.First = cn.Start
		}
		if cn.Start > ed.Last {
			ed.Last = cn.Start
		}
	}
	for _, k := range order {
		rep.Edges = append(rep.Edges, *edges[k])
	}
	var nodeIDs []string
	for id, n := range nodes {
		if n.InCase || used[id] {
			nodeIDs = append(nodeIDs, id)
		}
	}
	sort.Slice(nodeIDs, func(a, b int) bool {
		x, y := nodes[nodeIDs[a]], nodes[nodeIDs[b]]
		if x.InCase != y.InCase {
			return x.InCase
		}
		return x.Label < y.Label
	})
	for _, id := range nodeIDs {
		rep.Nodes = append(rep.Nodes, nodes[id])
	}

	for _, h := range ids {
		if w := clockWords(&h); w != "" {
			rep.Notes = append(rep.Notes, "Times of "+h.Name+" are corrected for "+w+".")
		}
	}
	rep.Notes = append(rep.Notes, c.notes...)
	if len(ids) == 0 {
		rep.Notes = append(rep.Notes, "No hosts are described in this case. Describe them on the Details tab, with their addresses and other names, so connections between them can be matched.")
	}
	if !ready {
		rep.Notes = append(rep.Notes, "Some evidence is still being read for connections; open this again shortly for the full picture.")
	}
	rep.Notes = append(rep.Notes,
		`Read so far: Remote Desktop (the client's log, RDPClient 1024 and 1102, and Security 4648 to TERMSRV on the computer connecting; Security 4624 type 10 or 12 and 4778, RemoteConnectionManager 1149, LocalSessionManager 21, 22 and 25, and RdpCoreTS 131 on the computer connected to); file shares (commands naming \\computer, from Security 4688 with command lines or Sysmon 1, and Security 4648 to cifs on the computer connecting; Security 5140 and 5145 on the computer connected to); and programs started remotely (on the computer connecting: PsExec, PAExec, RemCom, sc, at and schtasks against \\computer, wmic /node:, winrs -r:, schtasks /s, PowerShell remoting with -ComputerName, WinRM 6, and Security 4648 to RPCSS, WSMAN, or HTTP from PowerShell; on the computer connected to: the service and task managers' pipes, PsExec's pipes, programs written to ADMIN$, services installed (System 7045, Security 4697), scheduled tasks made or changed under a person's account (Security 4698, 4702), WinRM 91, the PowerShell remoting and winrs hosts and what they start, and programs WMI starts under a person's account). Network logons (Security 4624 type 3) support these but are not shown alone: a domain controller or file server has thousands. Records on the computer connected to that name no source are tied to a network logon or share access within two minutes, by the same account where they name one. Sysmon network connections (Sysmon 3) and DCOM are not read yet.`,
		fmt.Sprintf("Ends are paired when each names the other and they are within %s once stated clock differences are taken off; strongly when within %s and with the same account. A pair is consistent with one connection, not proof of it.", fmtDur(connWindow), fmtDur(connStrong)))
	return rep, nil
}

func item(e store.ObservedEvent, kind, role string) string {
	for _, it := range e.Items {
		if it.Kind == kind && it.Role == role {
			return it.Value
		}
	}
	return ""
}

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1"
}

func sameAccount(a, b string) bool {
	user := func(s string) string {
		if i := strings.LastIndexByte(s, '\\'); i >= 0 {
			s = s[i+1:]
		}
		if i := strings.IndexByte(s, '@'); i > 0 {
			s = s[:i]
		}
		return strings.ToLower(s)
	}
	return user(a) == user(b)
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// fmtDur writes a duration as people say it: "2 seconds", "3 minutes 10 seconds".
func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Second {
		return "under a second"
	}
	h, m, s := int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second)
	var parts []string
	unit := func(n int, w string) {
		if n == 1 {
			parts = append(parts, "1 "+w)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %ss", n, w))
		}
	}
	unit(h, "hour")
	unit(m, "minute")
	unit(s, "second")
	return strings.Join(parts, " ")
}

// WriteConnectionsText writes the connections as plain text, one per
// paragraph, in time order.
func WriteConnectionsText(w io.Writer, r *ConnectionsReport) error {
	label := map[string]string{}
	for _, n := range r.Nodes {
		label[n.ID] = n.Label
	}
	ts := func(ns int64) string { return time.Unix(0, ns).UTC().Format("2006-01-02 15:04:05") }
	fmt.Fprintf(w, "Connections between hosts: %d (from %d events)\n", len(r.Connections), r.Events)
	for _, c := range r.Connections {
		seen := map[string]string{"both": "both ends", "source": "the connecting end only", "target": "the end connected to only"}[c.SeenOn]
		fmt.Fprintf(w, "\n%s UTC  %s -> %s  %s", ts(c.Start), label[c.From], label[c.To], ConnKindWords[c.Kind])
		if c.Account != "" {
			fmt.Fprintf(w, "  %s", c.Account)
		}
		fmt.Fprintf(w, "\n  %s, seen at %s; events %s\n", c.Confidence, seen, joinIDs(c.EventIDs))
		for _, why := range c.Reasons {
			fmt.Fprintf(w, "  - %s\n", why)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range r.Notes {
			if _, err := fmt.Fprintf(w, "  - %s\n", n); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinIDs(ids []int64) string {
	var b strings.Builder
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprint(&b, id)
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ConnKindWords names each kind of connection.
var ConnKindWords = map[string]string{"rdp": "Remote Desktop", "smb": "File share", "exec": "Program started remotely"}
