// Package caselock makes sure only one Atropos process works on a case at a
// time. Two writers would interleave submissions and audit entries; the lock
// turns that into a clear refusal. It is an operating-system lock on
// case.lock, so it is released when the process ends, however it ends.
package caselock

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Acquire takes the lock for the case in dir. The returned function releases it.
func Acquire(dir string) (release func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, "case.lock"), os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, err
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("this case is open in another Atropos process (a running \"serve\", for example); close it first")
	}
	// Informational only: the lock itself is what counts.
	f.Truncate(0)
	fmt.Fprintf(f, "pid %d since %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	return func() { unlock(f); f.Close() }, nil
}
