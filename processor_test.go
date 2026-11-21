package ja4plus

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func buildSYNPacket(srcIP, dstIP string, srcPort, dstPort uint16) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func TestProcessor_SYNPacket(t *testing.T) {
	proc := NewProcessor()
	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)

	results, errs := proc.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	// A SYN packet should produce at least a JA4T result
	found := false
	for _, r := range results {
		if r.Type == "ja4t" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected JA4T result from SYN packet")
	}
}

func TestProcessor_NonApplicablePacket(t *testing.T) {
	proc := NewProcessor()

	// Build a plain ACK packet with no payload — not part of any tracked connection
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("10.0.0.1"),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(80),
		ACK:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()

	results, errs := proc.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(results) > 0 {
		t.Errorf("expected no results for plain ACK, got %d: %+v", len(results), results)
	}
}

func TestProcessor_Reset(t *testing.T) {
	proc := NewProcessor()

	// Process a SYN so state accumulates
	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
	_, _ = proc.ProcessPacket(pkt)

	// Reset should not panic
	proc.Reset()

	// After reset, processing should still work
	results, errs := proc.ProcessPacket(pkt)
	if len(errs) > 0 {
		t.Errorf("unexpected errors after reset: %v", errs)
	}
	// Should still get JA4T
	found := false
	for _, r := range results {
		if r.Type == "ja4t" {
			found = true
		}
	}
	if !found {
		t.Error("expected JA4T result after reset")
	}
}

// FuzzProcessPacketReadsAnyFrame proves that Processor.ProcessPacket returns for any
// Ethernet frame. FR-fuzz-12 of `docs/specs/features/06-fuzz-testing.md` states the
// requirement.
//
// `FuzzNoExportedFunctionPanicsOnAnyFrame` in `audit_test.go` drives every exported
// function of this package over one frame, and it meets FR-audit-14. This target drives
// `ProcessPacket` alone, because a crash that the audit target reports names no function.
// A crash that this target reports names `ProcessPacket`.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, and those two calls
// carry FR-fuzz-14 through FR-fuzz-18. The package comment of `internal/fuzzprop` states
// which requirement each one meets, and it states why FR-fuzz-14 needs no code.
func FuzzProcessPacketReadsAnyFrame(f *testing.F) {
	// The processor accepts each seed below. Each one is a well-formed frame that carries
	// one payload a fingerprinter reads.
	f.Add(panicAuditFrame(f, "tcp", 12345, 443, []byte{
		0x16, 0x03, 0x01, 0x00, 0x2f,
		0x01, 0x00, 0x00, 0x2b, 0x03, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x02, 0x13, 0x01,
		0x01, 0x00,
		0x00, 0x00,
	}))
	f.Add(panicAuditFrame(f, "tcp", 12345, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))

	// The processor reads no fingerprint from each seed below. The first holds no byte.
	// The second is a frame that carries no payload.
	f.Add([]byte{})
	f.Add(panicAuditFrame(f, "udp", 12345, 443, nil))

	f.Fuzz(func(t *testing.T, frame []byte) {
		input := fuzzprop.ExactInput(frame)

		fuzzprop.Check(t, len(input), func() any {
			// Each call decodes one packet and builds one processor. A `gopacket` packet
			// caches the layer it decodes, and a processor holds per-connection state, so a
			// shared value would make the second call read state rather than the frame.
			//
			// FR-fuzz-18 depends on one more property of this line, and the property is not
			// obvious. `FingerprintResult` carries a `Timestamp`, and every fingerprinter
			// reads that field through `GetPacketTimestamp` in `internal/parser/packet.go`.
			// That function returns `packet.Metadata().Timestamp`, and `NewPacket` sets no
			// capture information here, so the field holds the zero time on both calls. A
			// later change that gives this target a `CaptureInfo`, or a fingerprinter that
			// reads the wall clock, makes every result of this target differ between two
			// calls.
			packet := gopacket.NewPacket(input, layers.LayerTypeEthernet, gopacket.Default)

			results, errs := NewProcessor().ProcessPacket(packet)

			return []any{results, errs}
		})
	})
}

// These tests hold the ruling of 2026-08-15 UTC. The maintainer ruled candidate 1, form 1b,
// and comment 5299963400 of issue #649 records the ruling. Issue #649 is the reversal path.
//
// The ruling accepts a functional option at construction, because Epic 10 (#100) freezes the
// exported surface next. Under this shape a later option costs one more `WithX` function
// against a type that already exists.

// keyLogFixture returns a KeyLog that holds one secret.
// The tests below need a KeyLog that a pointer comparison separates from nil, and the
// contents of the secret reach no assertion.
func keyLogFixture(t *testing.T) *KeyLog {
	t.Helper()

	const line = "CLIENT_HANDSHAKE_TRAFFIC_SECRET " +
		"0000000000000000000000000000000000000000000000000000000000000001 " +
		"aabbccdd\n"

	keyLog, err := ParseKeyLog(strings.NewReader(line))
	if err != nil {
		t.Fatalf("ParseKeyLog: %v", err)
	}

	if keyLog.Len() != 1 {
		t.Fatalf("the fixture holds %d secrets, want 1", keyLog.Len())
	}

	return keyLog
}

// TestNewProcessorTakesNoArgumentAndHoldsNoKeyLog holds the compatibility half of the
// ruling. Every existing caller writes `NewProcessor()`, and the variadic parameter keeps
// that call valid.
func TestNewProcessorTakesNoArgumentAndHoldsNoKeyLog(t *testing.T) {
	proc := NewProcessor()

	if proc.keyLog != nil {
		t.Errorf("NewProcessor() holds a key log, and the caller supplied none")
	}
}

// TestNewSyncProcessorTakesNoArgumentAndHoldsNoKeyLog holds the same half for the wrapper.
func TestNewSyncProcessorTakesNoArgumentAndHoldsNoKeyLog(t *testing.T) {
	sync := NewSyncProcessor()

	if sync.proc.keyLog != nil {
		t.Errorf("NewSyncProcessor() holds a key log, and the caller supplied none")
	}
}

// TestAProcessorWithNoKeyLogReadsAPacket proves that the zero-option construction reaches no
// nil dereference. A caller that supplies no key log runs every fingerprinter as before.
func TestAProcessorWithNoKeyLogReadsAPacket(t *testing.T) {
	proc := NewProcessor()
	packet := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)

	results, errs := proc.ProcessPacket(packet)
	if len(errs) > 0 {
		t.Errorf("ProcessPacket reports %v, and a Processor with no key log reports none", errs)
	}

	if len(results) == 0 {
		t.Error("ProcessPacket produces no result for a SYN packet")
	}
}

// TestWithKeyLogGivesTheProcessorTheKeyLog holds the route the ruling accepts.
// The Processor holds the pointer the caller supplied, so a later fingerprinter reads the
// same secrets the caller read.
func TestWithKeyLogGivesTheProcessorTheKeyLog(t *testing.T) {
	keyLog := keyLogFixture(t)

	proc := NewProcessor(WithKeyLog(keyLog))

	if proc.keyLog != keyLog {
		t.Errorf("NewProcessor(WithKeyLog(keyLog)) holds %v, want the key log the caller supplied", proc.keyLog)
	}
}

// TestWithKeyLogGivesTheSyncProcessorTheKeyLog proves that the option reaches the inner
// Processor of the wrapper. FR-concurrency-13 gives the wrapper the shape of the Processor,
// so the two constructors accept one option type.
func TestWithKeyLogGivesTheSyncProcessorTheKeyLog(t *testing.T) {
	keyLog := keyLogFixture(t)

	sync := NewSyncProcessor(WithKeyLog(keyLog))

	if sync.proc.keyLog != keyLog {
		t.Errorf("NewSyncProcessor(WithKeyLog(keyLog)) holds %v, want the key log the caller supplied", sync.proc.keyLog)
	}
}

// TestEnsureLeavesTheKeyLogOfAZeroValueProcessorNil proves that the repair path adds no
// secret. `ensure` fills a fingerprinter that the constructor fills, and no key log has a
// default value.
func TestEnsureLeavesTheKeyLogOfAZeroValueProcessorNil(t *testing.T) {
	var proc Processor
	proc.ensure()

	if proc.keyLog != nil {
		t.Error("ensure fills the keyLog field, and a caller that supplies no key log expects none")
	}
}

// TestEnsureKeepsTheKeyLogTheOptionSupplied proves that the repair path reads no key log
// away. `ensure` runs at every entry point, so a key log that it clears reaches no packet.
func TestEnsureKeepsTheKeyLogTheOptionSupplied(t *testing.T) {
	keyLog := keyLogFixture(t)
	proc := NewProcessor(WithKeyLog(keyLog))

	proc.ensure()

	if proc.keyLog != keyLog {
		t.Error("ensure clears the keyLog field, and every entry point calls ensure")
	}
}

// TestTheProcessorReadsOneKeyLogPointerForItsWholeLife holds the concurrency contract.
// One Processor serves one goroutine, and the core is lock-free. The constructor writes the
// key log once, and every later reader reads it. A setter that mutates a live Processor
// would break that contract, and the ruling adds none.
func TestTheProcessorReadsOneKeyLogPointerForItsWholeLife(t *testing.T) {
	first := keyLogFixture(t)
	second := keyLogFixture(t)

	proc := NewProcessor(WithKeyLog(first), WithKeyLog(second))

	// The last option wins, because each option writes the same field in order.
	if proc.keyLog != second {
		t.Error("the constructor applies the options out of order")
	}

	packet := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
	_, _ = proc.ProcessPacket(packet)

	if proc.keyLog != second {
		t.Error("ProcessPacket moves the key log, and the key log is read-only after construction")
	}
}

// TestANilOptionReachesNoPanic proves the bound on the variadic parameter.
// A caller builds an option slice, and a slot that the caller leaves empty holds nil.
func TestANilOptionReachesNoPanic(t *testing.T) {
	proc := NewProcessor(nil, WithKeyLog(keyLogFixture(t)), nil)

	if proc.keyLog == nil {
		t.Error("a nil option discards the key log of the option beside it")
	}
}

// TestWithKeyLogAcceptsANilKeyLog proves that the option needs no guard at the call site.
// A caller that reads no key log from its own configuration passes nil, and the Processor
// then behaves as a Processor with no option.
func TestWithKeyLogAcceptsANilKeyLog(t *testing.T) {
	proc := NewProcessor(WithKeyLog(nil))

	if proc.keyLog != nil {
		t.Error("WithKeyLog(nil) holds a key log")
	}

	packet := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)
	if _, errs := proc.ProcessPacket(packet); len(errs) > 0 {
		t.Errorf("ProcessPacket reports %v after WithKeyLog(nil)", errs)
	}
}
