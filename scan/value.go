package scan

import (
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ResetValue is the value of a target whose first response carries RST.
//
// The FoxIO wrapper publishes this value at `ja4tscan/ja4tscan.py:44-45`, and the maintainer
// ruled it for every such target on 2026-09-30.
const ResetValue = "0_rst-ack"

// Response holds one TCP response of a target that the value reads.
type Response struct {
	// Time is the receive time of the response.
	Time time.Time
	// Header holds the TCP header as received, from the source port to the last option
	// byte. It holds no payload.
	Header []byte
}

// Value returns the JA4TScan value of one target, and false when the responses hold none.
//
// The responses answer the SYN of the target, in arrival order. A first response that
// carries RST produces ResetValue. Otherwise part a to part d come from the first SYN-ACK,
// and each later SYN-ACK adds one delay to part e. A RST after a SYN-ACK ends the value.
// A response that carries neither SYN and ACK nor RST adds nothing.
//
// The maintainer ruled on 2026-09-30 that the value uses the JA4TS form, at
// `Crank-Git/ja4plus#775`. So Value gives the responses to a JA4TS fingerprinter and keeps
// its last value, and one rule writes both methods. A scan value and the passive JA4TS
// value of the same responses are equal.
func Value(responses []Response) (string, bool) {
	fingerprinter := ja4plus.NewJA4TS()
	value := ""
	answered := false

	for _, response := range responses {
		packet := gopacket.NewPacket(response.Header, layers.LayerTypeTCP, gopacket.NoCopy)
		packet.Metadata().Timestamp = response.Time

		tcp, held := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !held {
			continue
		}

		if tcp.RST && !answered {
			return ResetValue, true
		}

		results, _ := fingerprinter.ProcessPacket(packet)
		if len(results) > 0 {
			value = results[0].Fingerprint
			answered = true
		}

		// R13 of `docs/specs/foxio/JA4T.md` reads the RST as the final packet, so a
		// response after it adds nothing.
		if tcp.RST {
			break
		}
	}

	return value, answered
}
