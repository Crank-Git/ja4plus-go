package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
// The target reads no field of the result. A returned call is the whole proof, because
// the fuzz engine reports a panic and a hang. #45 adds the property assertions of
// FR-fuzz-14 through FR-fuzz-18.
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
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		processor := NewProcessor()
		processor.ProcessPacket(packet)
	})
}
