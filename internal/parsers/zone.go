package parsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Windows marks a file that arrived from another security zone by attaching
// an alternate data stream named Zone.Identifier (the "mark of the web").
// The stream is a few lines of text: the zone, and since Windows 10 often the
// address the file came from and the page that led to it.

var zoneNames = map[int]string{0: "local machine", 1: "local intranet", 2: "trusted sites", 3: "internet", 4: "restricted sites"}

type zoneInfo struct {
	ID       int
	HasID    bool
	HostURL  string
	Referrer string
	Writer   string            // the packaged app that wrote the mark
	Other    map[string]string // anything else the stream states
}

func looksLikeZone(head []byte) bool {
	head = bytes.TrimLeft(head, " \t\r\n")
	return len(head) >= 14 && strings.EqualFold(string(head[:14]), "[ZoneTransfer]")
}

// parseZone reads the stream's text. It reports false when the text is not
// a zone mark at all.
func parseZone(b []byte) (zoneInfo, bool) {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, binary.LittleEndian.Uint16(b[i:]))
		}
		b = []byte(string(utf16.Decode(u)))
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if !looksLikeZone(b) {
		return zoneInfo{}, false
	}
	z := zoneInfo{Other: map[string]string{}}
	for i, line := range strings.Split(clean(string(b)), "\n") {
		if i > 64 {
			break
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = trunc(strings.TrimSpace(v), 2000)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "zoneid":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < 100000 {
				z.ID, z.HasID = n, true
			}
		case "hosturl":
			z.HostURL = v
		case "referrerurl":
			z.Referrer = v
		case "lastwriterpackagefamilyname":
			z.Writer = v
		default:
			if k = strings.TrimSpace(k); k != "" && len(k) <= 64 && len(z.Other) < 16 {
				z.Other[k] = v
			}
		}
	}
	return z, true
}

func (z zoneInfo) zone() string {
	if !z.HasID {
		return "not stated"
	}
	if name, ok := zoneNames[z.ID]; ok {
		return fmt.Sprintf("%d (%s)", z.ID, name)
	}
	return strconv.Itoa(z.ID)
}

// fields adds what the mark says to an event's fields.
func (z zoneInfo) fields(into map[string]any) {
	if z.HasID {
		into["zone_id"] = z.ID
		if name, ok := zoneNames[z.ID]; ok {
			into["zone"] = name
		}
	}
	if z.HostURL != "" {
		into["zone_host_url"] = z.HostURL
	}
	if z.Referrer != "" {
		into["zone_referrer_url"] = z.Referrer
	}
	if z.Writer != "" {
		into["zone_written_by"] = z.Writer
	}
	if len(z.Other) > 0 {
		into["zone_other"] = z.Other
	}
}

// summary is the short form shown in a message.
func (z zoneInfo) summary() string {
	s := "marked as from zone " + z.zone()
	switch {
	case z.HostURL != "":
		s += ": " + trunc(z.HostURL, 300)
	case z.Referrer != "":
		s += ", referred by " + trunc(z.Referrer, 300)
	}
	return s
}

// parseZoneFile handles a Zone.Identifier stream submitted as an item of its
// own: extracted from an image, or collected beside the file it marks. The
// stream holds no time, so it yields facts and searchable text, never an event.
func parseZoneFile(ctx *Context, doc []byte) error {
	z, ok := parseZone(doc)
	if !ok {
		return ErrNothingExtracted
	}
	ctx.Fact("zone.id", z.zone(), "the security zone Windows recorded for the file this stream was attached to")
	if z.HostURL != "" {
		ctx.Fact("zone.host_url", z.HostURL, "the address the file was fetched from")
	}
	if z.Referrer != "" {
		ctx.Fact("zone.referrer_url", z.Referrer, "the page that led to the download")
	}
	if z.Writer != "" {
		ctx.Fact("zone.written_by", z.Writer, "the packaged app that wrote the mark")
	}
	keys := make([]string, 0, len(z.Other))
	for k := range z.Other {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ctx.Fact("zone.other."+strings.ToLower(k), z.Other[k], "also stated in the stream")
	}
	body := clean(string(doc))
	ctx.Text("full text", len(body) > 64<<10, trunc(body, 64<<10))
	ctx.Note("a Zone.Identifier stream (the \"mark of the web\"): %s. The stream records no time, so nothing is on the timeline; this item's name and origin say which file it was attached to", z.summary())
	return nil
}

// ---- named streams in a file record -------------------------------------

type streamInfo struct {
	Size     int64
	Resident bool
	Content  []byte // resident content, at most maxStreamRead bytes
}

const maxStreamRead = 8 << 10

// recordStreams reads one file record and returns its named $DATA
// attributes. Only the base record is read: a stream whose attribute lives
// in an extension record is not found here, and the caller says so. Every
// offset is checked against the record; a damaged record yields nothing.
func recordStreams(rec []byte) map[string]streamInfo {
	le := binary.LittleEndian
	if len(rec) < 0x30 || string(rec[:4]) != "FILE" {
		return nil
	}
	// Undo the update sequence: the last two bytes of each 512-byte sector
	// were swapped for a check value when the record was written.
	usaOff, usaCount := int(le.Uint16(rec[4:])), int(le.Uint16(rec[6:]))
	if usaCount < 1 || usaOff+usaCount*2 > len(rec) || (usaCount-1)*512 > len(rec) {
		return nil
	}
	rec = append([]byte(nil), rec...)
	for i := 1; i < usaCount; i++ {
		end := i * 512
		if rec[end-2] != rec[usaOff] || rec[end-1] != rec[usaOff+1] {
			return nil // a torn write: the record cannot be trusted
		}
		copy(rec[end-2:end], rec[usaOff+i*2:usaOff+i*2+2])
	}
	out := map[string]streamInfo{}
	off := int(le.Uint16(rec[0x14:]))
	for n := 0; n < 256 && off+16 <= len(rec); n++ {
		typ := le.Uint32(rec[off:])
		if typ == 0xFFFFFFFF {
			break
		}
		size := int(le.Uint32(rec[off+4:]))
		if size < 16 || off+size > len(rec) {
			break
		}
		a := rec[off : off+size]
		off += size
		nameLen, nameOff := int(a[9]), int(le.Uint16(a[10:]))
		if typ != 0x80 || nameLen == 0 || nameOff+nameLen*2 > len(a) {
			continue
		}
		u := make([]uint16, nameLen)
		for i := range u {
			u[i] = le.Uint16(a[nameOff+i*2:])
		}
		name := clean(string(utf16.Decode(u)))
		var s streamInfo
		if a[8] == 0 {
			if len(a) < 24 {
				continue
			}
			cs, co := int(le.Uint32(a[16:])), int(le.Uint16(a[20:]))
			if co+cs > len(a) || cs < 0 {
				continue
			}
			s = streamInfo{Size: int64(cs), Resident: true}
			if cs > maxStreamRead {
				cs = maxStreamRead
			}
			s.Content = a[co : co+cs]
		} else {
			if len(a) < 56 {
				continue
			}
			s = streamInfo{Size: int64(le.Uint64(a[48:]))}
			if s.Size < 0 {
				s.Size = 0
			}
		}
		if _, dup := out[name]; !dup {
			out[name] = s
		}
	}
	return out
}
