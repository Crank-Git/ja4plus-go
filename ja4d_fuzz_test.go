package ja4plus

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// fuzzDHCPv4Discover returns the bytes of one DHCPDISCOVER message.
//
// The fixed part of a DHCPv4 message is 236 bytes, and the magic cookie and the options
// follow it. The message names three options.
//   - Option 53, the message type.
//   - Option 55, the parameter request list.
//   - Option 255, the end.
func fuzzDHCPv4Discover() []byte {
	message := make([]byte, 236)
	message[0] = 0x01 // The operation code of a request.
	message[1] = 0x01 // The hardware type of Ethernet.
	message[2] = 0x06 // The hardware address length of Ethernet.
	copy(message[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(message[28:34], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})

	message = append(message, 0x63, 0x82, 0x53, 0x63)
	message = append(message, 0x35, 0x01, 0x01)
	message = append(message, 0x37, 0x04, 0x01, 0x03, 0x06, 0x0f)
	message = append(message, 0x3d, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01)

	return append(message, 0xff)
}

// FuzzComputeJA4DReadsAnyFrame proves that the DHCPv4 reader returns for any Ethernet
// frame. FR-fuzz-10 of `docs/specs/features/06-fuzz-testing.md` states the requirement.
//
// `ComputeJA4D` is the entry point of the DHCPv4 reader of this library. `gopacket`
// decodes the DHCPv4 layer, and `ja4d.go` reads every option of it.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, and those two calls
// carry FR-fuzz-14 through FR-fuzz-18. The package comment of `internal/fuzzprop` states
// which requirement each one meets, and it states why FR-fuzz-14 needs no code.
func FuzzComputeJA4DReadsAnyFrame(f *testing.F) {
	// The reader accepts this seed. It carries one DHCPDISCOVER message from the client
	// port to the server port.
	f.Add(panicAuditFrame(f, "udp", 68, 67, fuzzDHCPv4Discover()))

	// The reader writes no value for each seed below.
	//   - The first holds no byte.
	//   - The second holds a 34-byte message. `gopacket` at v1.6.1 refuses a DHCPv4
	//     message under 240 bytes at `layers/dhcpv4.go:126`, and it reads no option of
	//     this message at all.
	//   - The third carries the message on a port that is not a DHCP port.
	f.Add([]byte{})
	f.Add(panicAuditFrame(f, "udp", 68, 67, []byte{
		0x01, 0x01, 0x06, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	}))
	f.Add(panicAuditFrame(f, "udp", 12345, 443, fuzzDHCPv4Discover()))

	f.Fuzz(func(t *testing.T, frame []byte) {
		input := fuzzprop.ExactInput(frame)

		fuzzprop.Check(t, len(input), func() any {
			// Each call decodes one packet of its own. A `gopacket` packet caches the layer
			// it decodes, so a shared packet would make the second call read a cache rather
			// than the frame.
			packet := gopacket.NewPacket(input, layers.LayerTypeEthernet, gopacket.Default)

			return ComputeJA4D(packet)
		})
	})
}
