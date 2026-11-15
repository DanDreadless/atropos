//go:build !windows

package ingest

// namedStreams lists a file's alternate data streams. They exist only on
// NTFS read through Windows; elsewhere a file copied off such a volume has
// already lost them.
func namedStreams(string) ([]string, error) { return nil, nil }
