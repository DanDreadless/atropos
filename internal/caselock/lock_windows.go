//go:build windows

package caselock

import (
	"os"

	"golang.org/x/sys/windows"
)

// Byte 1<<40 is locked rather than the start of the file, so the note
// written at offset zero stays readable by anyone inspecting the lock.
const lockOffsetHigh = 1 << 8

func lock(f *os.File) error {
	ol := windows.Overlapped{OffsetHigh: lockOffsetHigh}
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
}

func unlock(f *os.File) {
	ol := windows.Overlapped{OffsetHigh: lockOffsetHigh}
	windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
}
