package scan

import (
	"encoding/binary"
	"net/netip"
)

// The field sizes and values of the frames the scanner sends and reads.
const (
	ethernetHeaderBytes = 14
	etherTypeIPv4       = 0x0800
	ipHeaderBytes       = 20
	tcpHeaderBytes      = 20
	protocolTCP         = 6

	// S2 of the port's `docs/specs/foxio/JA4TScan.md` at tag `v1.3.0` cites
	// `zmap/src/probe_modules/packet.c:88-116` for these three values.
	ipIdentification = 54321
	ipTimeToLive     = 255
	synWindow        = 65535

	tcpFlagSYN = 0x02

	// A fragment carries a part of a segment, so the reader reads neither the first
	// fragment nor a later one.
	ipMoreFragments  = 0x2000
	ipFragmentOffset = 0x1FFF
)

// synOptionsHead holds the first 11 option bytes of the FoxIO SYN, from S3 of the port's
// `docs/specs/foxio/JA4TScan.md` at tag `v1.3.0`. They are Maximum Segment Size 1460,
// Window Scale 7, SACK Permitted, and the kind and length bytes of Timestamp. The timestamp
// value, an echo reply of 0 and one End of Option List byte follow, so the SYN carries 20
// option bytes.
var synOptionsHead = [11]byte{0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x04, 0x02, 0x08, 0x0a}

// synOptionBytes is the length of the option region of the SYN.
const synOptionBytes = len(synOptionsHead) + 4 + 4 + 1

// synFrame holds the fields of one SYN that vary between targets and between runs.
type synFrame struct {
	srcMAC, dstMAC [6]byte
	srcIP, dstIP   [4]byte
	srcPort        uint16
	dstPort        uint16
	// sequence is the sequence number. A response acknowledges it.
	sequence uint32
	// timestamp is the Timestamp option value. FoxIO writes the send time in whole seconds.
	timestamp uint32
}

// checksum returns the Internet checksum of RFC 1071 over the data.
func checksum(data []byte) uint16 {
	var total uint32
	for index := 0; index+1 < len(data); index += 2 {
		total += uint32(binary.BigEndian.Uint16(data[index:]))
	}

	if len(data)%2 == 1 {
		total += uint32(data[len(data)-1]) << 8
	}

	for total>>16 != 0 {
		total = total&0xFFFF + total>>16
	}

	return ^uint16(total)
}

// buildSYN returns the Ethernet frame of one FoxIO SYN: 74 bytes that hold the Ethernet
// header, the IPv4 header and a TCP header with 20 option bytes.
//
// The builder writes every byte itself, so a test compares the frame with S2 and S3 of the
// transcription byte for byte. FR-active-scan-25 of the port sends the SYN as a link-layer
// frame, because a SYN from a raw IP socket leaves state in the connection tracker of the
// host. The kernel then answers the SYN-ACK with a RST, and the RST stops the
// retransmissions that part e reads.
func buildSYN(syn synFrame) []byte {
	const tcpLength = tcpHeaderBytes + synOptionBytes

	frame := make([]byte, ethernetHeaderBytes+ipHeaderBytes+tcpLength)

	copy(frame[0:6], syn.dstMAC[:])
	copy(frame[6:12], syn.srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	ip := frame[ethernetHeaderBytes : ethernetHeaderBytes+ipHeaderBytes]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHeaderBytes+tcpLength))
	binary.BigEndian.PutUint16(ip[4:6], ipIdentification)
	ip[8] = ipTimeToLive
	ip[9] = protocolTCP
	copy(ip[12:16], syn.srcIP[:])
	copy(ip[16:20], syn.dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	tcp := frame[ethernetHeaderBytes+ipHeaderBytes:]
	binary.BigEndian.PutUint16(tcp[0:2], syn.srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], syn.dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], syn.sequence)
	tcp[12] = byte(tcpLength/4) << 4
	tcp[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], synWindow)

	options := tcp[tcpHeaderBytes:]
	copy(options, synOptionsHead[:])
	binary.BigEndian.PutUint32(options[len(synOptionsHead):], syn.timestamp)

	pseudo := make([]byte, 0, 12+tcpLength)
	pseudo = append(pseudo, syn.srcIP[:]...)
	pseudo = append(pseudo, syn.dstIP[:]...)
	pseudo = append(pseudo, 0, protocolTCP, 0, byte(tcpLength))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))

	return frame
}

// reply holds the fields of one received TCP segment that the scanner reads.
type reply struct {
	// srcIP names the target, and dstIP names the scanning host.
	srcIP, dstIP netip.Addr
	// srcPort is the scanned port, and dstPort is the source port of the SYN.
	srcPort, dstPort uint16
	acknowledgment   uint32
	flags            uint8
	// header holds the TCP header, from the source port to the last option byte.
	header []byte
}

// parseFrame returns the TCP fields of one received Ethernet frame, and false when the frame
// carries no whole unfragmented IPv4 TCP segment.
//
// Every frame is hostile input. The reader bounds each read on the frame and on the IP
// total length, so a length that reaches past the frame stops the reader, and the Ethernet
// padding of a short frame reaches no field. It never panics.
func parseFrame(frame []byte) (reply, bool) {
	if len(frame) < ethernetHeaderBytes+ipHeaderBytes {
		return reply{}, false
	}

	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
		return reply{}, false
	}

	ip := frame[ethernetHeaderBytes:]
	if ip[0]>>4 != 4 {
		return reply{}, false
	}

	ipLength := int(ip[0]&0x0F) * 4
	totalLength := int(binary.BigEndian.Uint16(ip[2:4]))

	if ipLength < ipHeaderBytes || totalLength < ipLength || totalLength > len(ip) {
		return reply{}, false
	}

	if binary.BigEndian.Uint16(ip[6:8])&(ipMoreFragments|ipFragmentOffset) != 0 {
		return reply{}, false
	}

	if ip[9] != protocolTCP {
		return reply{}, false
	}

	segment := ip[ipLength:totalLength]
	if len(segment) < tcpHeaderBytes {
		return reply{}, false
	}

	dataOffset := int(segment[12]>>4) * 4
	if dataOffset < tcpHeaderBytes || dataOffset > len(segment) {
		return reply{}, false
	}

	return reply{
		srcIP:          netip.AddrFrom4([4]byte(ip[12:16])),
		dstIP:          netip.AddrFrom4([4]byte(ip[16:20])),
		srcPort:        binary.BigEndian.Uint16(segment[0:2]),
		dstPort:        binary.BigEndian.Uint16(segment[2:4]),
		acknowledgment: binary.BigEndian.Uint32(segment[8:12]),
		flags:          segment[13],
		header:         segment[:dataOffset],
	}, true
}
