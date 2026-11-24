// Command mklateral writes a made-up set of Windows event logs from three
// hosts that connect to each other by Remote Desktop, a file share and
// PsExec, for trying the Connections view (see internal/evtxw/lateraldemo
// for the story).
//
//	go run ./scripts/mklateral -out DIR
//
// DIR gets one folder per host (WS-ALICE, SRV-FILE01, DC01) holding the logs
// as Windows names them, and README.txt saying what to state for each host
// and what the Connections view should show.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/DanDreadless/atropos/internal/evtxw/lateraldemo"
)

func main() {
	out := flag.String("out", "", "folder to write the hosts' logs into (made if missing)")
	flag.Parse()
	if *out == "" {
		log.Fatal("usage: go run ./scripts/mklateral -out DIR")
	}
	if err := lateraldemo.Write(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote the logs of WS-ALICE, SRV-FILE01 and DC01 to %s; see README.txt there\n", *out)
}
