package ja4plus_test

// The examples below hold FR-documentation-28 of #87: every Go code sample of `docs/`
// appears here as a testable example.
//
// Each body is the body of `func main` of one fenced Go block, and
// `TestEveryGoSampleOfTheSiteIsATestableExample` in `docs_go_samples_test.go` holds the two
// equal. That test states the matching rule and the reason for it. **Edit the page and the
// example together.**
//
// **No example below carries an output comment, so the testing package compiles each one
// and runs none.** Each one opens `capture.pcap`, and this repository ships no capture
// file. `go test` therefore type-checks every sample of the site on every run, which is
// the property FR-documentation-28 asks for. The runnable half lives in `examples/`, and
// FR-documentation-27 builds it on every pull request.

import (
	"fmt"
	"hash/fnv"
	"os"
	"sync"

	ja4plus "github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

// ExampleProcessor_ProcessPacket reads every packet of one capture file through one
// Processor.
//
// It mirrors the fenced Go block of `docs/usage.md`.
func ExampleProcessor_ProcessPacket() {
	f, _ := os.Open("capture.pcap")
	// The page teaches the read path, and a close error of a read-only file changes no
	// fingerprint. This comment reaches no comparison, because the matching rule of
	// `docs_go_samples_test.go` drops every comment.
	defer f.Close() //nolint:errcheck // The mirrored page states no error path here.

	reader, _ := pcapgo.NewReader(f)
	proc := ja4plus.NewProcessor()

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		pkt.Metadata().Timestamp = ci.Timestamp

		results, _ := proc.ProcessPacket(pkt)
		for _, r := range results {
			fmt.Printf("[%s] %s:%d -> %s:%d  %s\n",
				r.Type, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.Fingerprint)
		}
	}
}

// ExampleProcessor_GetShardKey_shardedProcessors routes each packet to one of four
// Processor goroutines.
//
// It mirrors the first fenced Go block of `docs/concurrency.md`.
//
// `concurrency_doc_test.go` holds `ExampleProcessor_GetShardKey`, which runs the same
// pattern against packets it builds. This example carries the suffix because the two names
// share one package.
func ExampleProcessor_GetShardKey_shardedProcessors() {
	const shards = 4

	f, err := os.Open("capture.pcap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The page teaches the read path, and a close error of a read-only file changes no
	// fingerprint. This comment reaches no comparison, because the matching rule of
	// `docs_go_samples_test.go` drops every comment.
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

// ExampleSyncProcessor_ProcessPacket shares one SyncProcessor across four worker
// goroutines.
//
// It mirrors the second fenced Go block of `docs/concurrency.md`.
func ExampleSyncProcessor_ProcessPacket() {
	f, err := os.Open("capture.pcap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The page teaches the read path, and a close error of a read-only file changes no
	// fingerprint. This comment reaches no comparison, because the matching rule of
	// `docs_go_samples_test.go` drops every comment.
	defer f.Close() //nolint:errcheck // The mirrored page states no error path here.

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
