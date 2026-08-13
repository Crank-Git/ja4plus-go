//go:build racecontract

package ja4plus

import (
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
)

// This file holds the negative control for the concurrency contract. The test below
// shares one bare Processor between two goroutines, which the contract forbids, and it
// fails under the race detector.
//
// The `racecontract` build tag keeps it out of every gate. `go build ./...`,
// `go test -race ./...`, `make test` and the CI job all read the default tag set, and
// the compiler drops this file from that set. A run needs the tag by name:
//
//	go test -tags racecontract -race -run TestBareProcessor_ReportsARaceBetweenTwoGoroutines .
//
// The run reports `WARNING: DATA RACE` and exits non-zero. That result is the proof
// that the contract is real. `.claude/rules/concurrency.md` states that this test is
// expected to fail, and that nobody may repair it.

// TestBareProcessor_ReportsARaceBetweenTwoGoroutines proves that one Processor serves
// one goroutine. Two goroutines write the state of one connection through an unguarded
// map, so the race detector reports the write.
//
// This test is expected to fail. Do not add a lock, and do not give each goroutine its
// own Processor. Either change deletes the proof.
func TestBareProcessor_ReportsARaceBetweenTwoGoroutines(t *testing.T) {
	const goroutines = 2
	const packets = 200

	proc := NewProcessor()

	// Each goroutine owns its packets, so the detector reports the Processor state and
	// never a shared packet value.
	perGoroutine := make([][]gopacket.Packet, goroutines)
	for g := 0; g < goroutines; g++ {
		perGoroutine[g] = buildContendedPackets(t, packets)
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(mine []gopacket.Packet) {
			defer wg.Done()
			for _, pkt := range mine {
				_, _ = proc.ProcessPacket(pkt)
			}
		}(perGoroutine[g])
	}
	wg.Wait()
}
