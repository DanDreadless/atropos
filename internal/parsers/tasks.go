package parsers

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Scheduled task definitions (Windows\System32\Tasks\...) are XML documents.
// A task is a way to make a program run again later, so each one is evidence
// of persistence, with the command it runs and who registered it.

type taskXML struct {
	XMLName xml.Name `xml:"Task"`
	Reg     struct {
		Date        string `xml:"Date"`
		Author      string `xml:"Author"`
		URI         string `xml:"URI"`
		Description string `xml:"Description"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal []struct {
			UserID   string `xml:"UserId"`
			GroupID  string `xml:"GroupId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Hidden  string `xml:"Hidden"`
		Enabled string `xml:"Enabled"`
	} `xml:"Settings"`
	Triggers struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"Triggers"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
			WorkDir   string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
		Com []struct {
			ClassID string `xml:"ClassId"`
			Data    string `xml:"Data"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
}

// looksLikeTask reports whether a text document is a task definition.
func looksLikeTask(head []byte) bool {
	return bytes.Contains(head, []byte("<Task ")) && bytes.Contains(head, []byte("schemas.microsoft.com/windows/2004/02/mit/task"))
}

// parseTask handles one task definition already decoded to UTF-8.
func parseTask(ctx *Context, doc []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	// The document says UTF-16; by now it has been decoded.
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var t taskXML
	if err := dec.Decode(&t); err != nil {
		return fmt.Errorf("scheduled task XML: %w", err)
	}
	var actions []string
	for _, e := range t.Actions.Exec {
		actions = append(actions, strings.TrimSpace(e.Command+" "+e.Arguments))
	}
	for _, c := range t.Actions.Com {
		actions = append(actions, "COM handler "+c.ClassID+" "+strings.TrimSpace(c.Data))
	}
	var triggers []string
	inner := xml.NewDecoder(bytes.NewReader(t.Triggers.Inner))
	depth := 0
	for {
		tok, err := inner.Token()
		if err != nil {
			break
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				triggers = append(triggers, x.Name.Local)
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
	name := clean(t.Reg.URI)
	if name == "" {
		name = ctx.Name
	}
	user := ""
	fields := map[string]any{"task": name, "actions": actions, "triggers": triggers, "author": clean(t.Reg.Author)}
	if len(t.Principals.Principal) > 0 {
		p := t.Principals.Principal[0]
		user = clean(p.UserID)
		if user == "" {
			user = clean(p.GroupID)
		}
		fields["run_as"], fields["run_level"] = user, p.RunLevel
	}
	if strings.EqualFold(strings.TrimSpace(t.Settings.Hidden), "true") {
		fields["hidden"] = true
	}
	if strings.EqualFold(strings.TrimSpace(t.Settings.Enabled), "false") {
		fields["enabled"] = false
	}
	if d := clean(t.Reg.Description); d != "" {
		fields["description"] = trunc(d, 500)
	}
	date := strings.TrimSpace(t.Reg.Date)
	if date == "" {
		// Many built-in tasks record no registration date. The task is still
		// indexed as text; it just has no place on the timeline of its own.
		ctx.Note("scheduled task %s records no registration date", name)
		return ErrNothingExtracted
	}
	stamp, ok := stampFromISO(ctx, date)
	if !ok {
		ctx.Warn("scheduled task %s has a registration date that could not be read: %q", name, date)
		return ErrNothingExtracted
	}
	path := ""
	if len(t.Actions.Exec) > 0 {
		path = clean(t.Actions.Exec[0].Command)
	}
	msg := fmt.Sprintf("Scheduled task registered: %s", name)
	if len(actions) > 0 {
		msg += "  runs " + trunc(clean(strings.Join(actions, " ; ")), 600)
	}
	if len(triggers) > 0 {
		msg += "  on " + strings.Join(triggers, ", ")
	}
	return ctx.Emit(Event{
		Stamp: stamp, Type: "scheduled-task-registered", Category: CatPersistence, Source: "task",
		Host: ctx.Host, User: user, Path: path, Message: msg, Fields: fields, Ref: "RegistrationInfo/Date",
	})
}
