package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// FuzzComputeJA4D6ReadsAnyFrame proves that the DHCPv6 reader returns for any Ethernet
// frame. FR-fuzz-11 of `docs/specs/features/06-fuzz-testing.md` states the requirement.
//
// `ComputeJA4D6` is the entry point of the DHCPv6 reader of this library. `ja4d6.go`
// reads every option, and it descends into a relay message.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, and those two calls
// carry FR-fuzz-14 through FR-fuzz-18. The package comment of `internal/fuzzprop` states
// which requirement each one meets, and it states why FR-fuzz-14 needs no code.
func FuzzComputeJA4D6ReadsAnyFrame(f *testing.F) {
	// The reader accepts each seed below. The first carries one SOLICIT message. The
	// second carries one RELAY-FORW message that holds the SOLICIT message inside it, so
	// the fuzzer reaches the relay descent.
	f.Add(buildDHCPv6Packet(f, dhcpv6SolicitBytes()).Data())
	f.Add(buildDHCPv6Packet(f, dhcpv6RelayForwardBytes(1, dhcpv6SolicitBytes())).Data())

	// The reader writes no value for each seed below. The first holds no byte. The second
	// states an option length of 65535 bytes that the message does not hold.
	f.Add([]byte{})
	f.Add(buildDHCPv6Packet(f, []byte{
		0x01, 0xaa, 0xbb, 0xcc, 0x00, 0x01, 0xff, 0xff, 0x00,
	}).Data())

	f.Fuzz(func(t *testing.T, frame []byte) {
		input := fuzzprop.ExactInput(frame)

		fuzzprop.Check(t, len(input), func() any {
			// Each call decodes one packet of its own. A `gopacket` packet caches the layer
			// it decodes, so a shared packet would make the second call read a cache rather
			// than the frame.
			packet := gopacket.NewPacket(input, layers.LayerTypeEthernet, gopacket.Default)

			return ComputeJA4D6(packet)
		})
	})
}
