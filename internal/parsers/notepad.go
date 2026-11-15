package parsers

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"
	"github.com/DanDreadless/atropos/internal/winnotepad"
)

// Two editors keep a record of what was open in them, and both keep text
// that was typed and never saved: the Notepad that ships with Windows 11
// (one binary state file per tab) and Notepad++ (session.xml and config.xml).
//
// Most of what they hold has no time attached. A tab's text, a recent file,
// a search term: the editor never wrote down when. Those become facts and
// indexed text, which can be read and searched, and only what carries a time
// goes on the timeline. Nothing here invents one.

const maxNotepadState = 64 << 20

// winNotepadParser reads a Windows 11 Notepad state file.
type winNotepadParser struct{}

func (winNotepadParser) Name() string    { return "windows-notepad" }
func (winNotepadParser) Version() string { return "1 (native)" }

func (winNotepadParser) Parse(ctx *Context) error {
	if ctx.Size > maxNotepadState {
		return fmt.Errorf("Notepad state file larger than %d bytes is not decoded", maxNotepadState)
	}
	b, err := io.ReadAll(io.NewSectionReader(ctx.File, 0, ctx.Size))
	if err != nil {
		return err
	}
	f, err := winnotepad.Decode(b)
	if err != nil {
		return err
	}
	ctx.Fact("notepad.state_file", f.Kind, "kind of Windows Notepad state file, established by its checksum")

	switch f.Kind {
	case winnotepad.KindWindow:
		ctx.Fact("notepad.window_tabs", strings.Join(f.Tabs, ", "),
			fmt.Sprintf("identifiers of the tabs in the order shown (each names a tab's state file); tab %d was in front; the file's sequence number is %d", f.ActiveTab+1, f.Sequence))
		ctx.Note("Notepad window state: %d tabs listed. It records no times, so nothing was placed on the timeline", len(f.Tabs))
		return nil
	case winnotepad.KindTabState:
		ctx.Note("Notepad tab view state (where the cursor was). It holds no text and no times, so nothing was placed on the timeline")
		return nil
	}

	text, applied := f.Text()
	text = clean(text)
	if f.EditsUnread {
		ctx.Warn("typing recorded after the tab's text could not all be read: a checksum did not agree part way through")
	} else if !applied {
		ctx.Warn("some recorded typing refers to positions outside the tab's text and was not applied")
	}
	if strings.TrimSpace(text) != "" {
		truncated := len(text) > maxText
		ctx.Text("text of a Windows Notepad tab, with typing not yet saved applied", truncated, trunc(text, maxText))
	}
	unsaved := f.HasUnsaved || len(f.Edits) > 0

	if f.Kind == winnotepad.KindUnsavedTab {
		ctx.Fact("notepad.unsaved_tab", fmt.Sprintf("%d characters", len([]rune(text))),
			"a tab that was never saved to a file; its text is indexed and can be searched")
		ctx.Note("Notepad tab never saved to a file, holding %d characters. Notepad records no time for it, so it is not on the timeline; its text is indexed", len([]rune(text)))
		return nil
	}

	path := clean(f.Path)
	fields := map[string]any{
		"path": path, "encoding": f.Encoding, "line_ending": f.LineEnding, "unsaved_changes": unsaved,
		"unsaved_edits": len(f.Edits), "record_name": ctx.Name,
	}
	if f.FileSHA256 != nil {
		fields["file_sha256"] = hex.EncodeToString(f.FileSHA256)
		fields["file_sha256_meaning"] = "hash of the file on disk when Notepad read it, as Notepad recorded it"
	}
	stamp, ok := timeutil.FromFiletime(f.FileTime)
	if f.FileTime == 0 || !ok {
		detail := "a file open in a Notepad tab with nothing unsaved; Notepad records no time in that state"
		if unsaved {
			detail = "a file open in a Notepad tab with unsaved changes; no time was recorded"
		}
		ctx.Fact("notepad.open_file", path, detail)
		ctx.Note("Notepad tab open on %s. No time is recorded for it, so it is not on the timeline", path)
		return nil
	}
	// The meaning of this time comes from published research, and no file
	// carrying one was available to check it against.
	fields["time_meaning"] = "the file's last-written time on disk when Notepad read it, according to published research on the format; not independently confirmed"
	msg := "Open in Notepad: " + path
	if unsaved {
		msg += " (with changes not saved)"
	}
	return ctx.Emit(Event{
		Stamp: stamp, Type: "file-modified (notepad tab)", MACB: "M...", Category: CatFileOpening, Source: "notepad",
		Host: ctx.Host, Path: path, Message: msg, Fields: fields, Ref: "tab state header",
	})
}

// ---- Notepad++ ----

type nppFile struct {
	Filename string `xml:"filename,attr"`
	Backup   string `xml:"backupFilePath,attr"`
	Low      uint32 `xml:"originalFileLastModifTimestamp,attr"`
	High     uint32 `xml:"originalFileLastModifTimestampHigh,attr"`
	Lang     string `xml:"lang,attr"`
}

type nppName struct {
	Name string `xml:"name,attr"`
}

type nppXML struct {
	XMLName xml.Name `xml:"NotepadPlus"`
	Session *struct {
		Main struct {
			File []nppFile `xml:"File"`
		} `xml:"mainView"`
		Sub struct {
			File []nppFile `xml:"File"`
		} `xml:"subView"`
	} `xml:"Session"`
	History *struct {
		File []struct {
			Filename string `xml:"filename,attr"`
		} `xml:"File"`
	} `xml:"History"`
	Find *struct {
		Path    []nppName `xml:"Path"`
		Filter  []nppName `xml:"Filter"`
		Find    []nppName `xml:"Find"`
		Replace []nppName `xml:"Replace"`
	} `xml:"FindHistory"`
}

const maxNotepadPP = 64 << 20

// looksLikeNotepadPP reports whether a text document is one of Notepad++'s
// own files: its session, or its settings with their history.
func looksLikeNotepadPP(head []byte) bool {
	i := bytes.Index(head, []byte("<NotepadPlus>"))
	return i >= 0 && i < 512 && (bytes.Contains(head, []byte("<Session")) || bytes.Contains(head, []byte("<GUIConfigs")) ||
		bytes.Contains(head, []byte("<FindHistory")) || bytes.Contains(head, []byte("<History")))
}

// The copy Notepad++ keeps of unsaved text is named for the tab and the
// moment the copy was first made: "new 3@2024-05-01_142233".
var reNppBackup = regexp.MustCompile(`@(\d{4}-\d{2}-\d{2}_\d{6})$`)

func parseNotepadPP(ctx *Context, doc []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var d nppXML
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("Notepad++ XML: %w", err)
	}
	if d.Session == nil && d.History == nil && d.Find == nil {
		return errors.New("Notepad++ XML with no session or history in it")
	}
	// The whole document stays searchable, whatever reaches the timeline.
	body := clean(string(doc))
	ctx.Text("full text", len(body) > maxText, trunc(body, maxText))

	if d.Session != nil {
		ctx.Fact("notepad++.file", "session", "the tabs Notepad++ had open when it last wrote its session")
		undated := 0
		for vi, view := range [][]nppFile{d.Session.Main.File, d.Session.Sub.File} {
			for i, f := range view {
				name, backup := clean(f.Filename), clean(f.Backup)
				ref := fmt.Sprintf("%s File %d", []string{"mainView", "subView"}[vi], i+1)
				fields := map[string]any{"filename": name, "language": clean(f.Lang)}
				if backup != "" {
					fields["backup_path"] = backup
				}
				dated := false
				if ft := uint64(f.High)<<32 | uint64(f.Low); ft != 0 {
					if stamp, ok := timeutil.FromFiletime(ft); ok {
						dated = true
						if err := ctx.Emit(Event{
							Stamp: stamp, Type: "file-modified (notepad++ session)", MACB: "M...", Category: CatFileOpening, Source: "notepad++",
							Host: ctx.Host, Path: name,
							Message: "Open in Notepad++: " + name + " (the file's last-modified time as Notepad++ recorded it)",
							Fields:  fields, Ref: ref,
						}); err != nil {
							return err
						}
					}
				}
				if m := reNppBackup.FindStringSubmatch(backup); m != nil {
					if t, err := time.Parse("2006-01-02_150405", m[1]); err == nil && timeutil.Plausible(t) {
						dated = true
						bf := map[string]any{"filename": name, "backup_path": backup,
							"time_meaning": "taken from the name of the backup file: the local time at which Notepad++ first kept a copy of this tab's unsaved text"}
						if err := ctx.Emit(Event{
							Stamp: timeutil.FromLocal(t, m[1], ctx.Local), Type: "notepad++-unsaved-copy-kept", Category: CatFileOpening, Source: "notepad++",
							Host: ctx.Host, Path: name,
							Message: "Notepad++ began keeping a copy of unsaved text for " + name + " in " + backup,
							Fields:  bf, Ref: ref,
						}); err != nil {
							return err
						}
					}
				}
				if !dated {
					undated++
					ctx.Fact("notepad++.open_file", name, "open in the session; Notepad++ recorded no time for it")
				}
			}
		}
		if undated > 0 {
			ctx.Note("%d open files in the Notepad++ session carry no time and are recorded as facts, not on the timeline", undated)
		}
	}
	n := 0
	if d.History != nil {
		for i, f := range d.History.File {
			ctx.Fact("notepad++.recent_file", clean(f.Filename), fmt.Sprintf("recent files list, position %d (most recent first)", i+1))
			n++
		}
	}
	if d.Find != nil {
		for _, g := range []struct {
			key, what string
			list      []nppName
		}{
			{"search_term", "text searched for", d.Find.Find}, {"replace_term", "replacement text", d.Find.Replace},
			{"search_folder", "folder searched with Find in Files", d.Find.Path}, {"search_filter", "file filter used with Find in Files", d.Find.Filter},
		} {
			for i, v := range g.list {
				ctx.Fact("notepad++."+g.key, trunc(clean(v.Name), 2000), fmt.Sprintf("%s, position %d (most recent first)", g.what, i+1))
				n++
			}
		}
	}
	if n > 0 {
		ctx.Note("%d recent files and search terms from Notepad++ are recorded as facts. Notepad++ keeps no times for them, so they are not on the timeline", n)
	}
	return nil
}
