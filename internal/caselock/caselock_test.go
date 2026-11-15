package caselock

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The lock must hold against another process, which is the case that
// matters, so the test binary re-runs itself as the second process.
func TestMain(m *testing.M) {
	if dir := os.Getenv("CASELOCK_TRY"); dir != "" {
		if _, err := Acquire(dir); err != nil {
			os.Stdout.WriteString("refused: " + err.Error())
			os.Exit(0)
		}
		os.Stdout.WriteString("acquired")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func other(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "CASELOCK_TRY="+dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestOnlyOneProcessHoldsACase(t *testing.T) {
	dir := t.TempDir()
	release, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if out := other(t, dir); !strings.HasPrefix(out, "refused") || !strings.Contains(out, "another Atropos process") {
		t.Errorf("a second process got: %q", out)
	}
	if _, err := Acquire(dir); err == nil {
		t.Error("the same process acquired the lock twice")
	}
	release()
	if out := other(t, dir); out != "acquired" {
		t.Errorf("after release a second process got: %q", out)
	}
	// A process that exits without releasing does not leave the case locked.
	if out := other(t, dir); out != "acquired" {
		t.Errorf("after a holder exited, the next process got: %q", out)
	}
	if note, _ := os.ReadFile(dir + "/case.lock"); !strings.HasPrefix(string(note), "pid ") {
		t.Errorf("lock file note: %q", note)
	}
}
