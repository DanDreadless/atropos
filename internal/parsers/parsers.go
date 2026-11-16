// Package parsers turns identified artefacts into normalised timeline events.
package parsers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

// Event is what a parser emits. The pipeline adds provenance and stores it.
type Event struct {
	Stamp timeutil.Stamp
	Type  string // what the timestamp means
	// MACB says which file-system style time this is: Modified, Accessed,
	// Changed (metadata) or Born, in the layout mactime and log2timeline use
	// ("M...", ".A..", "MACB"). Empty means the timestamp is none of those.
	MACB string
	// Category is what the event is evidence of (see the Cat* constants).
	Category string
	Source   string // artefact family
	Host     string
	User     string
	Path     string
	Message  string
	Fields   map[string]any
	Ref      string // location within the source file
}

// Context is everything a parser is given. File is a read-only handle to the
// vault copy of the evidence.
type Context struct {
	File  *os.File
	Size  int64
	Name  string // submitted name, for display only
	Kind  string
	Host  string                // host established for this batch, if any
	Local timeutil.LocalContext // how to interpret zoneless local times

	// Segments are other files in the case that may be further segments of
	// the same split image. Set only for an image kind that is split across
	// files (E01): such an image is one piece of evidence in several files.
	Segments []string
	// WorkDir is the case's directory for temporary working copies (a
	// database with its write-ahead log applied). Never evidence.
	WorkDir string

	// ReceivedYear anchors formats that omit the year entirely.
	ReceivedYear  int
	ReceivedMonth int

	Emit func(Event) error
	Fact func(key, value, detail string)
	// Warn records a degradation (the run is marked partial); Note records
	// information the examiner should see that does not reduce completeness.
	Warn func(format string, args ...any)
	Note func(format string, args ...any)
	Text func(method string, truncated bool, body string)
}

type Parser interface {
	Name() string
	Version() string
	Parse(ctx *Context) error
}

// Categories: what an event is evidence of. They follow the "Evidence of..."
// grouping used in SANS Windows forensics material, so an examiner can ask
// "show me program execution" across every artefact at once.
const (
	CatExecution   = "execution"    // a program ran
	CatFileOpening = "file-opening" // a file or folder was opened
	CatFileSystem  = "file-system"  // a file or directory time from the volume
	CatBrowser     = "browser"      // web browsing and downloads
	CatAccount     = "account"      // logons, logoffs and account changes
	CatNetwork     = "network"      // connections, shares, name lookups
	CatPersistence = "persistence"  // services and scheduled tasks
	CatDevice      = "device"       // external devices
	CatRegistry    = "registry"     // a registry key was written
	CatSecurity    = "security"     // detections, and tampering with logs or protection
	CatDeletion    = "deletion"     // a file was deleted
	CatLog         = "log"          // any other logged entry
)

// For returns the dedicated parser for a detected kind, or nil.
func For(kind string) Parser {
	switch kind {
	case detect.EVTX:
		return evtxParser{}
	case detect.Registry:
		return registryParser{}
	case detect.RegistryLog:
		return regLogParser{}
	case detect.MFT, detect.NTFSVolume:
		return ntfsParser{}
	case detect.Prefetch:
		return prefetchParser{}
	case detect.LNK:
		return lnkParser{}
	case detect.SQLite:
		return sqliteParser{}
	case detect.SQLiteWAL:
		return walParser{}
	case detect.Text, detect.TextUTF16:
		return textParser{}
	case detect.NTFSIndex:
		return i30Parser{}
	case detect.NTFSLog:
		return logFileParser{}
	case detect.RecycleI:
		return recycleParser{}
	case detect.WMIRepo:
		return wmiParser{}
	case detect.EWF:
		return ewfParser{}
	case detect.FATVolume, detect.ExtVolume, detect.MBRDisk, detect.VHD, detect.VHDX, detect.VMDK:
		return diskImageParser{}
	case detect.SNSS:
		return snssParser{}
	case detect.Thumbcache:
		return thumbcacheParser{}
	case detect.ODL:
		return odlParser{}
	case detect.ODLKeystore:
		return keystoreParser{}
	case detect.MozLz4:
		return mozLz4Parser{}
	case detect.DefenderDH:
		return defenderParser{}
	case detect.WinNotepad:
		return winNotepadParser{}
	case detect.USN:
		return usnParser{}
	case detect.OLE, detect.JumpList:
		return jumpListParser{}
	case detect.ESE:
		return srumParser{}
	}
	return nil
}

// Generic is the fallback applied to anything without a dedicated parser, and
// to anything whose dedicated parser produced nothing.
func Generic() Parser { return genericParser{} }

// Priority orders a batch so artefacts that establish context (the registry,
// which names the host and its time zone) are parsed before those that use it.
func Priority(kind string) int {
	if kind == detect.Registry {
		return 0
	}
	return 1
}

// clean makes a string safe to store and index.
func clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.ReplaceAll(s, "\x00", "")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// FieldsJSON renders event fields deterministically (map keys are sorted).
func FieldsJSON(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf(`{"_error":%q}`, err.Error())
	}
	return clean(string(b))
}

// Clean is exported for the pipeline.
func Clean(s string) string { return clean(s) }
