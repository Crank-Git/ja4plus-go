package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// FuzzProcessPacketReadsAnyFrame proves that Processor.ProcessPacket returns for any
// Ethernet frame. FR-fuzz-12 of `docs/specs/features/06-fuzz-testing.md` states the
// requirement.
//
// `FuzzNoExportedFunctionPanicsOnAnyFrame` in `audit_panic_test.go` drives every exported
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
