package ja4plus

import (
	"hash/fnv"
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
)

// The race detector reports only a race that it observes. Goroutines that each touch a
// different connection reach a different map key, and the detector then sees nothing.
// Every test in this file makes the goroutines touch one connection, so a lost lock
// produces an unguarded map access that the detector reports.
//
// Each test below builds every packet on the test goroutine, before it starts a worker
// goroutine. A worker that built its own packet could reach a packet builder that calls
// t.Fatalf, and the test goroutine alone may call t.Fatalf.

// contendedTupleSrcIP is the client address that the contended connection uses.
const contendedTupleSrcIP = "192.168.1.1"

// contendedTupleDstIP is the server address that the contended connection uses.
const contendedTupleDstIP = "10.0.0.1"

// contendedTupleSrcPort is the client port that the contended connection uses.
const contendedTupleSrcPort uint16 = 54321

// contendedTupleDstPort is the server port that the contended connection uses.
const contendedTupleDstPort uint16 = 443

// buildContendedPackets returns count packets that carry one connection.
// It builds a separate packet for each goroutine, because two goroutines that read one
// packet value would report a race in gopacket rather than in this library.
func buildContendedPackets(tb testing.TB, count int) []gopacket.Packet {
	tb.Helper()
	packets := make([]gopacket.Packet, 0, count)
	for i := 0; i < count; i++ {
		packets = append(packets, buildSYNPacket(
			contendedTupleSrcIP, contendedTupleDstIP,
			contendedTupleSrcPort, contendedTupleDstPort))
	}
	return packets
}

// TestSyncProcessor_ProcessesOneConnectionFromEightGoroutines holds FR-concurrency-20.
// Every goroutine reads and writes the state of one connection, so each fingerprinter
// map reaches one key from eight goroutines.
func TestSyncProcessor_ProcessesOneConnectionFromEightGoroutines(t *testing.T) {
	const goroutines = 8
	const packets = 100

	sp := NewSyncProcessor()

	// Each goroutine owns its own packets, and every packet carries one connection.
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
				if _, errs := sp.ProcessPacket(pkt); len(errs) > 0 {
					t.Errorf("unexpected errors: %v", errs)
					return
				}
			}
		}(perGoroutine[g])
	}
	wg.Wait()

	// A run that produces no fingerprint measures an early return in every goroutine.
	results, errs := sp.ProcessPacket(buildContendedPackets(t, 1)[0])
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(results) == 0 {
		t.Fatal("the contended packet produced no fingerprint")
	}
}

// TestSyncProcessor_ResetsWhileEightGoroutinesProcessOneConnection holds
// FR-concurrency-22. Reset clears the map that the eight goroutines write, so the
// detector observes an unguarded write against an unguarded clear.
func TestSyncProcessor_ResetsWhileEightGoroutinesProcessOneConnection(t *testing.T) {
	const goroutines = 8
	const packets = 100

	sp := NewSyncProcessor()

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
				_, _ = sp.ProcessPacket(pkt)
			}
		}(perGoroutine[g])
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < packets; i++ {
			sp.Reset()
		}
	}()

	wg.Wait()
}

// TestSyncProcessor_CleansUpTheConnectionThatEightGoroutinesProcess holds
// FR-concurrency-23. The cleanup call names the tuple that the eight goroutines process,
// so it deletes the map entry that they write.
func TestSyncProcessor_CleansUpTheConnectionThatEightGoroutinesProcess(t *testing.T) {
	const goroutines = 8
	const packets = 100

	sp := NewSyncProcessor()

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
				_, _ = sp.ProcessPacket(pkt)
			}
		}(perGoroutine[g])
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < packets; i++ {
			sp.CleanupConnection(contendedTupleSrcIP, contendedTupleSrcPort,
				contendedTupleDstIP, contendedTupleDstPort, "tcp")
		}
	}()

	wg.Wait()
}

// shardIndex returns the shard that owns the key.
// The caller owns the routing rule, so this test states one. A key that reaches two
// shards would send one connection to two Processor values.
func shardIndex(key string, shards int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(shards))
}

// TestShardedProcessors_SendEachConnectionToOneShard holds FR-concurrency-21.
// It runs the sharded pattern that `docs/specs/features/03-concurrency.md` states: one
// Processor for each shard, one goroutine for each Processor, and GetShardKey as the
// routing rule. No goroutine reaches another goroutine's Processor, so a lost shard
// boundary produces a race that the detector reports.
func TestShardedProcessors_SendEachConnectionToOneShard(t *testing.T) {
	const shards = 4
	const connections = 12
	const rounds = 20

	// The router computes a key for every packet. It owns a Processor of its own,
	// because one Processor serves one goroutine.
	router := NewProcessor()

	type work struct {
		key    string
		packet gopacket.Packet
	}

	queues := make([]chan work, shards)
	for s := 0; s < shards; s++ {
		queues[s] = make(chan work, 64)
	}

	// Each shard records the keys it reads. The shard goroutine alone touches its map.
	seen := make([]map[string]int, shards)
	for s := 0; s < shards; s++ {
		seen[s] = make(map[string]int)
	}
	results := make([]int, shards)

	var wg sync.WaitGroup
	for s := 0; s < shards; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			proc := NewProcessor()
			for w := range queues[s] {
				seen[s][w.key]++
				r, _ := proc.ProcessPacket(w.packet)
				results[s] += len(r)
			}
		}(s)
	}

	// Every connection contributes a packet and the reply to that packet. Both carry
	// one key, so both reach one shard.
	routed := 0
	for round := 0; round < rounds; round++ {
		for c := 0; c < connections; c++ {
			port := uint16(40000 + c)
			request := buildSYNPacket(contendedTupleSrcIP, contendedTupleDstIP,
				port, contendedTupleDstPort)
			reply := buildSYNPacket(contendedTupleDstIP, contendedTupleSrcIP,
				contendedTupleDstPort, port)

			for _, pkt := range []gopacket.Packet{request, reply} {
				key := router.GetShardKey(pkt)
				if key == "" {
					// t.Fatalf would leave the shard goroutines blocked on a queue
					// that nobody closes, so report the packet and route the rest.
					t.Errorf("GetShardKey returned an empty key for a TCP packet")
					continue
				}
				queues[shardIndex(key, shards)] <- work{key: key, packet: pkt}
				routed++
			}
		}
	}

	for s := 0; s < shards; s++ {
		close(queues[s])
	}
	wg.Wait()

	owner := make(map[string]int)
	total := 0
	for s := 0; s < shards; s++ {
		for key, count := range seen[s] {
			total += count
			if other, ok := owner[key]; ok {
				t.Errorf("key %q reached shard %d and shard %d", key, other, s)
				continue
			}
			owner[key] = s
		}
	}

	if total != routed {
		t.Errorf("shards read %d packets, want %d", total, routed)
	}
	if len(owner) != connections {
		t.Errorf("shard key count = %d, want %d", len(owner), connections)
	}

	produced := 0
	for s := 0; s < shards; s++ {
		produced += results[s]
	}
	if produced == 0 {
		t.Error("the shards produced no fingerprint")
	}
}
