//go:build windows

package ingest

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstStreamW = kernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = kernel32.NewProc("FindNextStreamW")
)

// WIN32_FIND_STREAM_DATA: the size, then a name of the form ":name:$DATA".
type findStreamData struct {
	Size int64
	Name [windows.MAX_PATH + 36]uint16
}

// namedStreams lists the alternate data streams of a file on an NTFS volume:
// every $DATA stream other than the unnamed one that is the file's content.
// A file system without streams yields none.
func namedStreams(path string) ([]string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var d findStreamData
	h, _, e := procFindFirstStreamW.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&d)), 0)
	if windows.Handle(h) == windows.InvalidHandle {
		// No streams at all, or a file system that has none, is not a failure.
		if errors.Is(e, windows.ERROR_HANDLE_EOF) || errors.Is(e, windows.ERROR_INVALID_PARAMETER) ||
			errors.Is(e, windows.ERROR_INVALID_FUNCTION) || errors.Is(e, windows.ERROR_NOT_SUPPORTED) {
			return nil, nil
		}
		return nil, e
	}
	defer windows.FindClose(windows.Handle(h))
	var out []string
	for {
		full := syscall.UTF16ToString(d.Name[:])
		if name, ok := strings.CutSuffix(strings.TrimPrefix(full, ":"), ":$DATA"); ok && name != "" {
			out = append(out, name)
		}
		if len(out) >= maxStreamsPerFile {
			break
		}
		d = findStreamData{}
		r, _, e := procFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&d)))
		if r == 0 {
			if !errors.Is(e, windows.ERROR_HANDLE_EOF) {
				return out, e
			}
			break
		}
	}
	return out, nil
}
