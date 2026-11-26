package parsers

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/timeutil"
)

// A PowerShell transcript is the text of a session, written by
// Start-Transcript or by policy. It opens with a header between two lines of
// asterisks:
//
//	**********************
//	Windows PowerShell transcript start
//	Start time: 20240117212000
//	Username: HOST\user
//	RunAs User: HOST\user
//	Machine: HOST (Microsoft Windows NT 10.0.19045.0)
//	Host Application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
//	Process ID: 1234
//	**********************
//
// and closes with "Windows PowerShell transcript end" and "End time:". Where
// invocation headers are switched on, each command is preceded by its own
// block holding "Command start time:". All of these times are local, with no
// zone. A command without such a block has no time of its own.

const maxTranscript = 64 << 20

func looksLikeTranscript(head []byte) bool {
	i := bytes.Index(head, []byte("transcript start"))
	return i >= 0 && i < 400 && bytes.Contains(head, []byte("Start time:")) && bytes.Contains(head[:i], []byte("**********"))
}

func transcriptTime(s string) (time.Time, bool) {
	t, err := time.Parse("20060102150405", strings.TrimSpace(s))
	return t, err == nil
}

// promptLine strips a "PS C:\path> " prompt and reports whether there was one.
func promptLine(l string) (string, bool) {
	if !strings.HasPrefix(l, "PS") {
		return "", false
	}
	i := strings.Index(l, ">")
	if i < 0 || i > 300 {
		return "", false
	}
	return strings.TrimSpace(l[i+1:]), true
}

func parseTranscript(ctx *Context, doc []byte) error {
	body := clean(string(doc))
	ctx.Text("full text", len(body) > maxText, trunc(body, maxText))
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")

	local := func(t time.Time) timeutil.Stamp {
		return timeutil.FromLocal(t, "local time "+t.Format("20060102150405"), ctx.Local)
	}
	header := map[string]string{}
	user := ""
	sessions, timed, untimed, events := 0, 0, 0, 0
	emit := func(e Event) error {
		e.Category, e.Source, e.User = CatExecution, "powershell", user
		if e.Host == "" {
			e.Host = ctx.Host
		}
		events++
		return ctx.Emit(e)
	}
	// pendingAt is set by a "Command start time" line and used by the next
	// prompt line, which is the command it refers to.
	var pendingAt *time.Time
	pendingLine := 0
	// headers is set once a session shows invocation headers. Every command
	// then has its block, so a prompt-like line without one is output (a
	// log or another transcript printed), not a command.
	headers := false
	inHeader := false
	for i, l := range lines {
		l = strings.TrimRight(l, " \t")
		switch {
		case strings.HasSuffix(l, "transcript start") && !strings.Contains(l, ">"):
			inHeader, header, user, headers = true, map[string]string{}, "", false
			sessions++
			continue
		case strings.HasSuffix(l, "transcript end") && !strings.Contains(l, ">"):
			inHeader = false
			continue
		case strings.HasPrefix(l, "End time:"):
			if t, ok := transcriptTime(l[len("End time:"):]); ok {
				if err := emit(Event{Stamp: local(t), Type: "powershell-transcript-ended",
					Message: "PowerShell transcript ended", Fields: map[string]any{"session": sessions}, Ref: fmt.Sprintf("line %d", i+1)}); err != nil {
					return err
				}
			}
			continue
		case strings.HasPrefix(l, "Command start time:"):
			if t, ok := transcriptTime(l[len("Command start time:"):]); ok {
				pendingAt, pendingLine, headers = &t, i+1, true
			}
			continue
		}
		if inHeader {
			if strings.HasPrefix(l, "*****") {
				// The header's closing line: say what was learnt.
				inHeader = false
				start, ok := transcriptTime(header["start time"])
				if !ok {
					continue
				}
				user = header["username"]
				fields := map[string]any{"session": sessions}
				for k, name := range map[string]string{"username": "username", "runas user": "runas_user", "machine": "machine",
					"host application": "host_application", "process id": "process_id", "psversion": "ps_version", "configuration name": "configuration"} {
					if v := header[k]; v != "" {
						fields[name] = v
					}
				}
				msg := "PowerShell transcript started"
				if user != "" {
					msg += " by " + user
				}
				if app := header["host application"]; app != "" {
					msg += ": " + trunc(app, 400)
				}
				if err := emit(Event{Stamp: local(start), Type: "powershell-transcript-started", Path: header["host application"],
					Message: msg, Fields: fields, Ref: fmt.Sprintf("line %d", i+1)}); err != nil {
					return err
				}
				continue
			}
			if k, v, ok := strings.Cut(l, ":"); ok && len(k) <= 40 {
				header[strings.ToLower(strings.TrimSpace(k))] = trunc(strings.TrimSpace(v), 1000)
			}
			continue
		}
		cmd, ok := promptLine(l)
		if !ok || cmd == "" {
			continue
		}
		if pendingAt == nil {
			if !headers {
				untimed++
			}
			continue
		}
		timed++
		if err := emit(Event{Stamp: local(*pendingAt), Type: "powershell-command", Path: "",
			Message: "PowerShell command: " + trunc(cmd, 1500),
			Fields:  map[string]any{"command": trunc(cmd, 8000), "session": sessions}, Ref: fmt.Sprintf("line %d (time on line %d)", i+1, pendingLine)}); err != nil {
			return err
		}
		pendingAt = nil
	}
	if sessions == 0 || events == 0 {
		return ErrNothingExtracted
	}
	ctx.Fact("powershell.transcript", fmt.Sprintf("%d session(s), %d command(s) with a time, %d without", sessions, timed, untimed), "a PowerShell transcript")
	if untimed > 0 {
		ctx.Note("%d commands in this transcript have no time of their own (invocation headers were off), so they are not on the timeline. The whole transcript is searchable text", untimed)
	}
	return nil
}
