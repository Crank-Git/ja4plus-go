// Command shardedprocessors routes each packet to one of four Processor goroutines.
//
// This program mirrors the first fenced Go block of `docs/concurrency.md`, and
// `TestEveryGoSampleOfTheSiteIsARunnableProgram` holds the two equal. Edit the page and
// this file together.
//
// It reads `capture.pcap` from the working directory, and it reaches no network.
package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"sync"

	ja4plus "github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func main() {
	const shards = 4

	f, err := os.Open("capture.pcap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The page teaches the shard pattern, and a close error of a read-only file changes no
	// fingerprint. `docs_go_samples_test.go` holds this file equal to the page, and it
	// compares tokens rather than bytes, so this comment reaches no comparison.
	defer f.Close() //nolint:errcheck // The mirrored page states no error path here.

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// This Processor computes routing keys, and it processes no packet. GetShardKey
	// holds no state, so one goroutine may use it while the shards run.
	router := ja4plus.NewProcessor()

	queues := make([]chan gopacket.Packet, shards)
	var wg sync.WaitGroup

	for i := range queues {
		queues[i] = make(chan gopacket.Packet, 1024)

		wg.Add(1)
		go func(in <-chan gopacket.Packet) {
			defer wg.Done()

			// This goroutine owns the Processor, and no other goroutine touches it.
			proc := ja4plus.NewProcessor()
			for pkt := range in {
				results, _ := proc.ProcessPacket(pkt)
				for _, r := range results {
					fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
				}
			}
			// The goroutine that owns the Processor closes its windows.
			for _, r := range proc.CloseOpenWindows() {
				fmt.Printf("[%s] %s\n", r.Type, r.Fingerprint)
			}
		}(queues[i])
	}

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp

		// A packet that carries neither TCP nor UDP returns an empty key, and the hash
		// of an empty key sends it to one fixed shard. Every packet reaches one shard.
		h := fnv.New32a()
		_, _ = h.Write([]byte(router.GetShardKey(pkt)))
		queues[h.Sum32()%shards] <- pkt
	}

	for _, q := range queues {
		close(q)
	}
	wg.Wait()
}
