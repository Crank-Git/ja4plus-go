// Command syncprocessor shares one SyncProcessor across four worker goroutines.
//
// This program mirrors the second fenced Go block of `docs/concurrency.md`, and
// `TestEveryGoSampleOfTheSiteIsARunnableProgram` holds the two equal. Edit the page and
// this file together.
//
// It reads `capture.pcap` from the working directory, and it reaches no network.
package main

import (
	"fmt"
	"os"
	"sync"

	ja4plus "github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func main() {
	f, err := os.Open("capture.pcap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Every worker shares this one SyncProcessor, and the mutex serializes each call.
	proc := ja4plus.NewSyncProcessor()

	queue := make(chan gopacket.Packet, 1024)
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkt := range queue {
				results, _ := proc.ProcessPacket(pkt)
				for _, r := range results {
					fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
				}
			}
		}()
	}

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp
		queue <- pkt
	}
	close(queue)
	wg.Wait()

	// Every worker has stopped, so one call closes every open window.
	for _, r := range proc.CloseOpenWindows() {
		fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
	}
}
