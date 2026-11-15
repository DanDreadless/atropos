// mkiso writes a small disc image for the browser check to add as evidence.
package main

import (
	"os"

	"github.com/DanDreadless/atropos/internal/imagefs/imagetest"
)

func main() {
	img := imagetest.ISO(
		map[string][]byte{
			"APP.LOG":   []byte("2025-03-03T03:03:03Z discmarker one\n2025-03-03T03:03:04Z discmarker two\n"),
			"NOTES.TXT": []byte("nothing with a time in it\n"),
		},
		map[string][]byte{"DEEP.LOG": []byte("2025-03-04T04:04:04Z discmarker three\n")},
		[]string{"APP.LOG", "NOTES.TXT", "DEEP.LOG"})
	if err := os.WriteFile(os.Args[1], img, 0o600); err != nil {
		panic(err)
	}
}
