package parser

import (
	"encoding/binary"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The fixed length of an IPv4 header, in bytes.
const quotedIPHeaderLength = 20

// The fixed length of a TCP header, in bytes.
const quotedTCPHeaderLength = 20

// quotesAPacket reports whether the ICMP type carries the header of the packet that produced
// the message. RFC 792 gives that shape to an error message alone, so an echo message
// reaches no quoted header.
//
// The dissector reads the same set, because it decodes a quoted packet for an error message
// and it then matches the field abbreviation `tcp.flags` anywhere in the protocol tree at
// `wireshark/source/packet-ja4.c:1261`.
func quotesAPacket(icmpType uint8) bool {
	switch icmpType {
	case layers.ICMPv4TypeDestinationUnreachable,
		layers.ICMPv4TypeSourceQuench,
		layers.ICMPv4TypeRedirect,
		layers.ICMPv4TypeTimeExceeded,
		layers.ICMPv4TypeParameterProblem:
		return true
	default:
		return false
	}
}

// QuotedTCPHeader returns the TCP header that an ICMP error message of the packet quotes.
// It returns nil when the packet carries no ICMP error message, and it returns nil when the
// quoted bytes hold no complete TCP header.
//
// The maintainer ruled split T1 on 2026-08-14, under #484, and the library reads that
// header. `gopacket` decodes no IP layer and no TCP layer inside an ICMP payload, so
// GetTCPLayer reads none of them and this function reads the payload itself. #484 is the
// reversal path, and the port half is `Crank-Git/ja4plus#610`.
//
// The payload is untrusted input, so the read bounds the IP header length, the IP total
// length, the TCP data offset and the TCP option list before it slices. It reads an IPv4
// header alone, because no capture of the corpus carries an ICMPv6 error message.
func QuotedTCPHeader(packet gopacket.Packet) *layers.TCP {
	for _, layer := range innerLayers(packet) {
		icmp, held := layer.(*layers.ICMPv4)
		if !held {
			continue
		}
		if !quotesAPacket(icmp.TypeCode.Type()) {
			return nil
		}

		return decodeQuotedTCPHeader(icmp.LayerPayload())
	}

	return nil
}

// decodeQuotedTCPHeader returns the TCP header that the quoted IPv4 packet of the argument
// holds. It returns nil for every input that states a length the argument does not hold.
func decodeQuotedTCPHeader(quoted []byte) *layers.TCP {
	if len(quoted) < quotedIPHeaderLength {
		return nil
	}

	const ipVersion4 = 4
	if quoted[0]>>4 != ipVersion4 {
		return nil
	}

	// A declared total length above the carried length names bytes the message never
	// quotes, so the read keeps the carried length. A declared length below it ends the
	// datagram, and the trailing bytes belong to no quoted packet.
	end := len(quoted)
	const totalLengthOffset = 2
	if declared := int(binary.BigEndian.Uint16(quoted[totalLengthOffset : totalLengthOffset+2])); declared < end {
		end = declared
	}

	headerLength := int(quoted[0]&0x0F) * 4
	if headerLength < quotedIPHeaderLength || headerLength > end {
		return nil
	}

	// A later fragment of the quoted datagram carries no transport header, so the bytes at
	// the header offset hold payload.
	const fragmentOffsetMask = 0x1FFF
	const flagsOffset = 6
	if binary.BigEndian.Uint16(quoted[flagsOffset:flagsOffset+2])&fragmentOffsetMask != 0 {
		return nil
	}

	const protocolOffset = 9
	if layers.IPProtocol(quoted[protocolOffset]) != layers.IPProtocolTCP {
		return nil
	}

	transport := quoted[headerLength:end]
	if len(transport) < quotedTCPHeaderLength {
		return nil
	}

	const dataOffsetOffset = 12
	dataOffset := int(transport[dataOffsetOffset]>>4) * 4
	if dataOffset < quotedTCPHeaderLength || dataOffset > len(transport) {
		return nil
	}

	tcp := &layers.TCP{}
	// The three bounds above cover every structural error that DecodeFromBytes reports, so
	// the remaining error names one malformed TCP option. `layers/tcp.go:319` adds the layer
	// of an outer header that carries such an option, and a caller of GetTCPLayer reads it.
	// The read of a quoted header therefore keeps the read of an outer header.
	_ = tcp.DecodeFromBytes(transport[:dataOffset], gopacket.NilDecodeFeedback)

	return tcp
}
