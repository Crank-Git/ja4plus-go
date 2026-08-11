package ja4plus

import (
	"sync"

	"github.com/google/gopacket"
)

// SyncProcessor wraps a Processor and serializes every call with one mutex.
// Every method is safe to call from any number of goroutines at the same time.
// One Processor for each shard gives higher throughput, because the per-packet path
// then acquires no lock. Route packets to the shards with GetShardKey.
// A SyncProcessor exposes no way to reach the inner Processor, because a caller who
// reaches it can break the contract.
type SyncProcessor struct {
	mu   sync.Mutex
	proc *Processor
}

// NewSyncProcessor returns a SyncProcessor that holds a new Processor.
func NewSyncProcessor() *SyncProcessor {
	return &SyncProcessor{proc: NewProcessor()}
}

// ProcessPacket runs every fingerprinter on the packet and returns the results with any
// non-fatal errors. It holds the mutex for the whole call, so a result never escapes
// while another goroutine changes the fingerprinter state.
func (p *SyncProcessor) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, []error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proc.ProcessPacket(packet)
}

// Reset clears the state of every fingerprinter.
// The mutex serializes it against a ProcessPacket call, so it runs before that call or
// after it, and never during it.
func (p *SyncProcessor) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proc.Reset()
}

// CleanupConnection removes the state of the connection from every fingerprinter.
// Call it when the monitor evicts a connection, because state with no removal path leaks
// in a long-running monitor.
func (p *SyncProcessor) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proc.CleanupConnection(srcIP, srcPort, dstIP, dstPort, proto)
}

// GetShardKey returns one routing key for both directions of the connection.
// It returns an empty string for a packet that carries neither a TCP layer nor a UDP
// layer, and the caller decides what to do with that key.
// It takes the mutex like every other exported method, because FR-concurrency-13 states
// that one rule for the whole type.
func (p *SyncProcessor) GetShardKey(packet gopacket.Packet) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proc.GetShardKey(packet)
}
