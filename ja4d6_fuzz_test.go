package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// FuzzComputeJA4D6ReadsAnyFrame proves that the DHCPv6 reader returns for any Ethernet
// frame. FR-fuzz-11 of `docs/specs/features/06-fuzz-testing.md` states the requirement.
//
// `ComputeJA4D6` is the entry point of the DHCPv6 reader of this library. `ja4d6.go`
// reads every option, and it descends into a relay message.
//
// The target reads no field of the result. A returned call is the whole proof, because
// the fuzz engine reports a panic and a hang. #45 adds the property assertions of
// FR-fuzz-14 through FR-fuzz-18.
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
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		_ = ComputeJA4D6(packet)
	})
}
