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
		// The loop ends at the first ICMP layer, and it reads no second one. `gopacket` at
		// v1.6.1 returns `gopacket.LayerTypePayload` from `ICMPv4.NextLayerType` at
		// `layers/icmp4.go:261-263`, so one packet reaches one ICMPv4 layer and the decode
		// chain adds no second one.
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

	return readQuotedTCPFields(transport[:dataOffset])
}

// readQuotedTCPFields returns the TCP layer that the header bytes of the argument state. The
// caller bounds the argument to the length that the data offset states, and the argument
// holds at least 20 bytes.
//
// It reads no TCP option, and it leaves the `Options` field empty. `tcpOptionEntries` of
// `ja4t.go` reads the raw option region of `Contents`, because ruling #297 writes one part b
// entry for each option byte.
//
// It calls `layers.TCP.DecodeFromBytes` for no input, because that method panics on a
// truncated Multipath TCP option. `layers/tcp.go:347-353` at v1.6.1 reads `data[1]` and
// `data[2]` of the option without a length guard, and the `default` branch at
// `layers/tcp.go:534-538` guards the same read. The option kind `30` as the last byte of the
// option region therefore panics, and `CLAUDE.md` states that a fingerprinter returns a
// non-fatal error and never a panic.
// `TestQuotedTCPHeaderReadsATruncatedMultipathOption` holds that bound, and #510 records the
// `gopacket` defect.
func readQuotedTCPFields(header []byte) *layers.TCP {
	const (
		flagsOffset      = 13
		flagFIN     byte = 0x01
		flagSYN     byte = 0x02
		flagRST     byte = 0x04
		flagPSH     byte = 0x08
		flagACK     byte = 0x10
		flagURG     byte = 0x20
		flagECE     byte = 0x40
		flagCWR     byte = 0x80
	)

	flags := header[flagsOffset]

	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(binary.BigEndian.Uint16(header[0:2])),
		DstPort:    layers.TCPPort(binary.BigEndian.Uint16(header[2:4])),
		Seq:        binary.BigEndian.Uint32(header[4:8]),
		Ack:        binary.BigEndian.Uint32(header[8:12]),
		DataOffset: header[12] >> 4,
		NS:         header[12]&0x01 != 0,
		FIN:        flags&flagFIN != 0,
		SYN:        flags&flagSYN != 0,
		RST:        flags&flagRST != 0,
		PSH:        flags&flagPSH != 0,
		ACK:        flags&flagACK != 0,
		URG:        flags&flagURG != 0,
		ECE:        flags&flagECE != 0,
		CWR:        flags&flagCWR != 0,
		Window:     binary.BigEndian.Uint16(header[14:16]),
		Checksum:   binary.BigEndian.Uint16(header[16:18]),
		Urgent:     binary.BigEndian.Uint16(header[18:20]),
	}
	tcp.BaseLayer = layers.BaseLayer{Contents: header}

	return tcp
}
