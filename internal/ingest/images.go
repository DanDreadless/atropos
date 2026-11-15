package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/DanDreadless/atropos/internal/detect"
	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/store"
)

// Disk and disc images are not unpacked on arrival: one can hold a million
// files, nearly all of them irrelevant. Instead the examiner browses the
// image and chooses what goes on the timeline, or asks for the standard set
// of Windows artefacts. Whatever is chosen is copied out, hashed and
// registered as child evidence of the image, exactly like a member of a zip,
// and then parsed in the ordinary way.
//
// Reading a file system out of an image is parsing hostile input, so it is
// done by the same isolated worker as every other parser.

// Browsable reports whether evidence of this kind can be looked inside.
func Browsable(kind string) bool {
	return kind == detect.ISO || kind == detect.MBRDisk || kind == detect.NTFSVolume || kind == detect.EWF ||
		kind == detect.VHD || kind == detect.VHDX || kind == detect.VMDK
}

// segments returns the vault copies of the other files in the case that may
// be segments of the same split image as e. An E01 image usually arrives as
// several files; they are matched by the identifier inside them, by the
// reader, so every E01 file in the case is offered.
//
// A registry hive is offered every transaction log in the case in the same
// way: the logs say by their contents which hive they belong to.
func (in *Ingester) segments(e *store.Evidence) []string {
	// A differencing virtual disk is offered every disk image in the case:
	// its parent may be a fixed VHD, which looks like a raw disk or volume.
	var want []string
	switch e.Kind {
	case detect.EWF:
		want = []string{detect.EWF}
	case detect.Registry:
		want = []string{detect.RegistryLog}
	case detect.VHD, detect.VHDX:
		want = []string{detect.VHD, detect.VHDX, detect.MBRDisk, detect.NTFSVolume}
	default:
		return nil
	}
	all, err := in.S.ListEvidence()
	if err != nil {
		return nil
	}
	var out []string
	for _, o := range all {
		if slices.Contains(want, o.Kind) && o.ID != e.ID && o.SHA256 != e.SHA256 && o.DuplicateOf == nil {
			out = append(out, in.V.Path(o.SHA256))
		}
	}
	return out
}

// DefaultMaxExtract bounds how many files one extraction may copy out.
const DefaultMaxExtract = 50000

// triagePatterns are the Windows artefacts worth having from any system
// volume, as paths from the root of the volume. A single star matches within
// one name; a double star matches any depth of directories.
var triagePatterns = []string{
	"$MFT",
	"$LogFile",
	"$Extend/$UsnJrnl:$J",
	"Windows/System32/config/SYSTEM",
	"Windows/System32/config/SOFTWARE",
	"Windows/System32/config/SAM",
	"Windows/System32/config/SECURITY",
	"Windows/System32/config/SYSTEM.LOG*",
	"Windows/System32/config/SOFTWARE.LOG*",
	"Windows/System32/config/SAM.LOG*",
	"Windows/System32/config/SECURITY.LOG*",
	"Windows/System32/winevt/Logs/*.evtx",
	"Windows/Prefetch/*.pf",
	"Windows/AppCompat/Programs/Amcache.hve",
	"Windows/AppCompat/Programs/Amcache.hve.LOG*",
	"Windows/System32/Tasks/**",
	"Windows/System32/sru/SRUDB.dat",
	"Windows/System32/wbem/Repository/OBJECTS.DATA",
	"Windows/System32/LogFiles/Firewall/*.log",
	"Users/*/NTUSER.DAT",
	"Users/*/NTUSER.DAT.LOG*",
	"Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
	"Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG*",
	"Users/*/AppData/Roaming/Microsoft/Windows/Recent/**",
	"Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
	"Users/*/Documents/PowerShell_transcript.*.txt",
	"ProgramData/Microsoft/Windows Defender/Support/MPLog-*.log",
	"ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/*/*",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/History",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/History",
	"Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Network/Cookies",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Web Data",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Login Data",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Shortcuts",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Favicons",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Top Sites",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Network Action Predictor",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Bookmarks",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Preferences",
	"Users/*/AppData/Local/Google/Chrome/User Data/*/Secure Preferences",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Network/Cookies",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Web Data",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Login Data",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Shortcuts",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Favicons",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Top Sites",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Network Action Predictor",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Bookmarks",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Preferences",
	"Users/*/AppData/Local/Microsoft/Edge/User Data/*/Secure Preferences",
	"Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/cookies.sqlite",
	"Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/formhistory.sqlite",
	"Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/extensions.json",
	"Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/sessionstore.jsonlz4",
	"Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/sessionstore-backups/*.jsonlz4",
	"Users/*/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/*.bin",
	"Users/*/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/WindowState/*.bin",
	"Users/*/AppData/Roaming/Notepad++/session.xml",
	"Users/*/AppData/Roaming/Notepad++/config.xml",
	"Users/*/AppData/Roaming/Notepad++/backup/*",
	"Documents and Settings/*/NTUSER.DAT",
	"$Recycle.Bin/*/$I*",
}

// matchTriage reports whether segs (lower case) is a complete match for a
// pattern, and whether it could become one by going deeper.
func matchTriage(pat, segs []string) (full, partial bool) {
	if len(pat) == 0 {
		return len(segs) == 0, false
	}
	if pat[0] == "**" {
		if len(segs) == 0 {
			return false, true
		}
		// The double star covers this name and may cover more.
		f1, _ := matchTriage(pat[1:], segs[1:])
		f2, _ := matchTriage(pat, segs[1:])
		return f1 || f2 || len(segs) == 1 && len(pat) == 1, true
	}
	if len(segs) == 0 {
		return false, true
	}
	if ok, _ := path.Match(pat[0], segs[0]); !ok {
		return false, false
	}
	return matchTriage(pat[1:], segs[1:])
}

type extractor struct {
	fs    imagefs.FS
	j     job
	s     sink
	files int
	bytes int64
	full  bool
	pats  [][]string
}

func (x *extractor) copyOut(inner string) {
	if x.full {
		return
	}
	if x.files >= x.j.MaxFiles {
		x.full = true
		x.s.warn(fmt.Sprintf("limit of %d files per extraction reached; the rest were not copied out", x.j.MaxFiles))
		return
	}
	r, size, err := x.fs.Open(inner)
	if err != nil {
		x.s.warn(fmt.Sprintf("%s: %v", inner, err))
		return
	}
	if x.bytes+size > x.j.MaxBytes {
		x.s.warn(fmt.Sprintf("%s (%d bytes) would exceed the extraction size limit and was not copied out", inner, size))
		return
	}
	tmp, err := os.CreateTemp(x.j.OutDir, "extract-*")
	if err != nil {
		x.s.warn(fmt.Sprintf("%s: %v", inner, err))
		return
	}
	n, cerr := io.Copy(tmp, io.LimitReader(r, size))
	if err := tmp.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil || n != size {
		os.Remove(tmp.Name())
		x.s.warn(fmt.Sprintf("%s: only %d of %d bytes could be read (%v); not copied out", inner, n, size, cerr))
		return
	}
	x.files++
	x.bytes += n
	if err := x.s.file(tmp.Name(), inner); err != nil {
		x.s.warn(fmt.Sprintf("%s: %v", inner, err))
	}
}

// add copies out a file, or everything under a directory.
func (x *extractor) add(inner string, depth int) {
	if x.full || depth > 64 {
		return
	}
	list, err := x.fs.List(inner)
	if err != nil {
		x.copyOut(inner)
		// A file chosen on its own brings its mark of the web, if it has one.
		if !strings.Contains(path.Base(inner), ":") {
			if _, _, err := x.fs.Open(inner + ":" + zoneStream); err == nil {
				x.copyOut(inner + ":" + zoneStream)
			}
		}
		return
	}
	for _, e := range list {
		switch {
		case e.IsDir:
			x.add(e.Path, depth+1)
		case !strings.Contains(e.Name, ":"):
			x.copyOut(e.Path)
		case strings.HasSuffix(strings.ToLower(e.Name), ":"+strings.ToLower(zoneStream)):
			// Of a file's alternate streams, only the mark of the web is
			// taken along unasked: it says where the file came from. Any
			// other stream is copied out when chosen by name.
			x.copyOut(e.Path)
		}
	}
}

// zoneStream is the alternate data stream Windows attaches to a file that
// arrived from another security zone.
const zoneStream = "Zone.Identifier"

// triage walks only the directories that can lead to a wanted artefact.
func (x *extractor) triage(dir string, segs []string, depth int) {
	if x.full || depth > 32 {
		return
	}
	list, err := x.fs.List(dir)
	if err != nil {
		return
	}
	for _, e := range list {
		here := append(append([]string{}, segs...), strings.ToLower(e.Name))
		want, deeper := false, false
		for _, p := range x.pats {
			full, partial := matchTriage(p, here)
			want, deeper = want || full, deeper || partial
		}
		switch {
		case e.IsDir && deeper:
			x.triage(e.Path, here, depth+1)
		case !e.IsDir && want:
			x.copyOut(e.Path)
		}
	}
}

// runImage is the image half of the worker: list a directory, or copy files out.
func runImage(j job, s sink) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("image reader panic: %v", r)
		}
	}()
	f, err := os.OpenFile(j.Path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	var others []imagefs.EWFSegment
	for _, p := range j.Segments {
		sf, err := os.OpenFile(p, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		defer sf.Close()
		if st, err := sf.Stat(); err == nil {
			others = append(others, imagefs.EWFSegment{R: sf, Size: st.Size()})
		}
	}
	fs, err := imagefs.OpenSet(f, j.Size, others)
	if err != nil {
		return err
	}
	defer fs.Close()
	if j.Op == "browse" {
		list, err := fs.List(j.Inner)
		if err != nil {
			return err
		}
		s.listing(fs.Describe(), list)
		return nil
	}
	x := &extractor{fs: fs, j: j, s: s}
	if j.Triage {
		for _, p := range triagePatterns {
			x.pats = append(x.pats, strings.Split(strings.ToLower(p), "/"))
		}
		// A partitioned disk has its volumes one level down.
		roots := []string{"/"}
		if strings.HasPrefix(fs.Describe(), "Disk image") {
			roots = nil
			if top, err := fs.List("/"); err == nil {
				for _, p := range top {
					if p.IsDir {
						roots = append(roots, p.Path)
					}
				}
			}
		}
		for _, r := range roots {
			x.triage(r, nil, 0)
		}
		if x.files == 0 {
			s.warn("none of the standard Windows artefacts were found in this image")
		}
	}
	for _, p := range j.Items {
		x.add(p, 0)
	}
	return nil
}

// run executes a job here or in a worker, as the ingester is configured.
func (in *Ingester) run(j job, s sink) error {
	if in.WorkerExe != "" {
		return in.runIsolated(j, s)
	}
	if j.Op != "" {
		return runImage(j, s)
	}
	return runJob(j, s)
}

func quietSink() sink {
	return sink{
		event: func(store.Event) error { return nil }, fact: func(string, string, string) {},
		warn: func(string) {}, note: func(string) {}, text: func(string, bool, string) {},
		listing: func(string, []imagefs.Entry) {}, file: func(string, string) error { return nil },
	}
}

// Browse lists one directory inside an image.
func (in *Ingester) Browse(e *store.Evidence, dir string) (describe string, entries []imagefs.Entry, err error) {
	if !Browsable(e.Kind) {
		return "", nil, fmt.Errorf("evidence #%d is %s, which has no contents to browse", e.ID, e.Kind)
	}
	s := quietSink()
	s.listing = func(d string, l []imagefs.Entry) { describe, entries = d, l }
	err = in.run(job{Op: "browse", Path: in.V.Path(e.SHA256), Size: e.Size, Inner: dir, Segments: in.segments(e)}, s)
	if entries == nil {
		entries = []imagefs.Entry{}
	}
	return describe, entries, err
}

// Extract copies files out of an image, registers each as child evidence of
// the image and parses them. paths may name files or directories; triage
// adds the standard Windows artefacts. It returns the children registered.
func (in *Ingester) Extract(e *store.Evidence, paths []string, triage bool) ([]*store.Evidence, error) {
	in.begin()
	defer in.end()
	children, err := in.extract(e, paths, triage)
	in.process(children)
	return children, err
}

// ExtractAsync is Extract in the background.
func (in *Ingester) ExtractAsync(e *store.Evidence, paths []string, triage bool) {
	in.begin()
	go func() {
		defer in.end()
		children, _ := in.extract(e, paths, triage)
		in.process(children)
	}()
}

func (in *Ingester) extract(e *store.Evidence, paths []string, triage bool) ([]*store.Evidence, error) {
	if !Browsable(e.Kind) {
		return nil, fmt.Errorf("evidence #%d is %s, which has no contents to extract", e.ID, e.Kind)
	}
	if len(paths) == 0 && !triage {
		return nil, errors.New("nothing was chosen to extract")
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	in.setStatus(func(s *Status) { s.Current = "copying files out of " + e.Name })
	room := in.MaxUnpack
	if room <= 0 {
		room = DefaultMaxUnpack
	}
	var children []*store.Evidence
	var notes []string
	s := quietSink()
	s.warn = func(n string) { notes = append(notes, n) }
	s.file = func(tmp, inner string) error {
		defer os.Remove(tmp)
		f, err := os.Open(tmp)
		if err != nil {
			return err
		}
		defer f.Close()
		c, err := in.Intake(e.BatchID, path.Base(inner), e.Origin+"!"+inner, f, &e.ID, e.Depth+1)
		if err != nil {
			return err
		}
		children = append(children, c)
		in.setStatus(func(s *Status) { s.Current = fmt.Sprintf("copying files out of %s (%d so far)", e.Name, len(children)) })
		return nil
	}
	err := in.run(job{Op: "extract", Path: in.V.Path(e.SHA256), Size: e.Size, Items: paths, Triage: triage, Segments: in.segments(e),
		OutDir: in.V.WorkDir(), MaxFiles: DefaultMaxExtract, MaxBytes: room}, s)
	if err != nil {
		notes = append(notes, err.Error())
	}
	var total int64
	for _, c := range children {
		total += c.Size
	}
	in.S.Audit("image.extract", fmt.Sprintf("evidence:%d", e.ID), map[string]any{
		"requested": paths, "standard_artefacts": triage, "files": len(children), "bytes": total, "notes": capNotes(notes),
	})
	summary := fmt.Sprintf("%d file(s) copied out of %s and added as evidence", len(children), e.Name)
	if len(notes) > 0 {
		summary += fmt.Sprintf("; %d could not be: %s", len(notes), strings.Join(capNotes(notes), "; "))
	}
	in.lastMu.Lock()
	in.last = summary
	in.lastMu.Unlock()
	return children, err
}

// LastExtract says how the most recent extraction went.
func (in *Ingester) LastExtract() string {
	in.lastMu.Lock()
	defer in.lastMu.Unlock()
	return in.last
}
