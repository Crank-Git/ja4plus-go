package ja4plus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// No capture of the FoxIO corpus carries QUIC inside a tunnel, so no vector separates the
// outer UDP layer from the inner one for JA4 and for JA4S. Every test in this file builds
// the separating packet instead. The tunnel is VXLAN and the methods are JA4 and JA4S.
//
// `docs/specs/spec.md` `## Changelog` row 12 records the ruling of 2026-08-11. The
// reported key holds the outer address pair with the inner port pair, and the grouping key
// holds the inner address pair with the inner port pair. Issue #170 repairs the two QUIC
// branches that read the outer layer.

// The outer address pair of every packet this file builds. A mirror sends both directions
// of one session from this pair, so the pair names no direction.
const (
	tunnelOuterSrcIP = "100.20.9.2"
	tunnelOuterDstIP = "100.20.9.1"
)

// The inner address pair and the inner port pair of every packet this file builds.
const (
	tunnelInnerSrcIP   = "10.16.27.12"
	tunnelInnerDstIP   = "10.16.27.131"
	tunnelInnerSrcPort = 54321
	tunnelInnerDstPort = 443
)

// vxlanUDPPort is the destination port that names a VXLAN tunnel. RFC 7348 section 5
// states it, and `gopacket` at v1.1.19 registers the VXLAN decoder under it.
const vxlanUDPPort = 4789

// quicVersion1 is the QUIC version that RFC 9000 specifies.
const quicVersion1 = 0x00000001

// quicCryptoFrameType is the frame type that carries the TLS handshake. RFC 9000
// section 19.6 states the value.
const quicCryptoFrameType = 0x06

// appendQUICVarint appends the variable-length integer form of the value.
// RFC 9000 section 16 states the two-bit prefix that names the encoded length.
func appendQUICVarint(out []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(out, byte(value))
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(out, uint16(value)|0x4000)
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(out, uint32(value)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(out, value|0xC000000000000000)
	}
}

// buildQUICClientInitial returns one QUIC version 1 client Initial packet that the library
// decrypts. The packet carries the handshake message in one CRYPTO frame.
//
// The Initial keys of QUIC version 1 come from the destination connection identifier and
// from a fixed salt. The packet therefore needs no key exchange and no key log.
// RFC 9001 section 5.2 states that derivation, and RFC 9001 section 5.4 states the header
// protection this function applies.
func buildQUICClientInitial(t *testing.T, dcid, scid, handshake []byte) []byte {
	t.Helper()

	frame := []byte{quicCryptoFrameType}
	frame = appendQUICVarint(frame, 0)
	frame = appendQUICVarint(frame, uint64(len(handshake)))
	frame = append(frame, handshake...)

	// The two low bits of the first byte hold the packet number length less one.
	const packetNumberBytes = 4
	const packetNumber = 1
	const authenticationTagBytes = 16
	const lengthFieldBytes = 2

	header := []byte{0xC3}
	header = binary.BigEndian.AppendUint32(header, quicVersion1)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00) // Token Length, a variable-length integer of value 0.

	// RFC 9000 section 14.1 states that a client Initial datagram holds 1200 bytes.
	// A PADDING frame is one zero byte, so the filler carries zero bytes.
	fill := quicInitialDatagramBytes - len(header) - lengthFieldBytes - packetNumberBytes - authenticationTagBytes
	if fill < len(frame) {
		t.Fatalf("the CRYPTO frame holds %d bytes, and the datagram leaves %d", len(frame), fill)
	}
	plaintext := make([]byte, fill)
	copy(plaintext, frame)

	// The Length field counts the Packet Number and the protected payload.
	// A two-byte variable-length integer carries the 0b01 prefix in its top bits.
	length := packetNumberBytes + len(plaintext) + authenticationTagBytes
	header = binary.BigEndian.AppendUint16(header, uint16(length)|0x4000)

	packetNumberOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, packetNumber)

	key, iv, hpKey, err := parser.DeriveInitialKeys(dcid, quicVersion1)
	if err != nil {
		t.Fatalf("DeriveInitialKeys returns the error %v", err)
	}

	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher returns the error %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM returns the error %v", err)
	}

	packet := aead.Seal(header, nonce, plaintext, header)

	// The header protection sample starts four bytes after the packet number field,
	// whatever length that field carries. RFC 9001 section 5.4.2 states the offset.
	sampleOffset := packetNumberOffset + 4
	maskBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		t.Fatalf("aes.NewCipher returns the error %v", err)
	}
	mask := make([]byte, aes.BlockSize)
	maskBlock.Encrypt(mask, packet[sampleOffset:sampleOffset+aes.BlockSize])

	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < packetNumberBytes; i++ {
		packet[packetNumberOffset+i] ^= mask[1+i]
	}

	return packet
}

// buildVXLANQUICPacket returns one VXLAN packet that carries the QUIC payload inside it.
// The outer UDP header names the tunnel on port 4789, and the inner UDP header names the
// connection.
func buildVXLANQUICPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()

	outerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	outerIP := &layers.IPv4{
		SrcIP:    net.ParseIP(tunnelOuterSrcIP),
		DstIP:    net.ParseIP(tunnelOuterDstIP),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      255,
	}
	outerUDP := &layers.UDP{SrcPort: vxlanUDPPort, DstPort: vxlanUDPPort}
	if err := outerUDP.SetNetworkLayerForChecksum(outerIP); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returns the error %v", err)
	}

	vxlan := &layers.VXLAN{ValidIDFlag: true, VNI: 100}

	innerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
		EthernetType: layers.EthernetTypeIPv4,
	}
	innerIP := &layers.IPv4{
		SrcIP:    net.ParseIP(tunnelInnerSrcIP),
		DstIP:    net.ParseIP(tunnelInnerDstIP),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
	}
	innerUDP := &layers.UDP{SrcPort: tunnelInnerSrcPort, DstPort: tunnelInnerDstPort}
	if err := innerUDP.SetNetworkLayerForChecksum(innerIP); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returns the error %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts,
		outerEth, outerIP, outerUDP, vxlan, innerEth, innerIP, innerUDP, gopacket.Payload(payload))
	if err != nil {
		t.Fatalf("SerializeLayers returns the error %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(1, 0)

	// A packet that decodes no inner UDP layer proves nothing about the two layers.
	if parser.TunnelDepth(packet) != 1 {
		t.Fatalf("the packet carries %d tunnel layers, and the test needs 1", parser.TunnelDepth(packet))
	}
	if udp := parser.GetUDPLayer(packet); udp == nil || uint16(udp.SrcPort) != tunnelInnerSrcPort {
		t.Fatalf("the packet decodes no inner UDP layer on port %d", tunnelInnerSrcPort)
	}

	return packet
}

// JA4 reads the inner UDP layer of a tunneled QUIC packet.
//
// The outer UDP header names the VXLAN tunnel on port 4789, and it carries no QUIC packet.
// A JA4 branch that read it would produce no fingerprint at all, and it would report the
// tunnel port. Issue #170 records the defect.
func TestJA4ReadsTheInnerUDPLayerOfAVXLANTunneledQUICInitial(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	handshake := buildClientHelloPayload()[5:]

	packet := buildVXLANQUICPacket(t, buildQUICClientInitial(t, dcid, scid, handshake))

	fingerprinter := NewJA4()
	results, err := fingerprinter.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returns %d results, and the packet carries one client hello", len(results))
	}

	result := results[0]

	// A QUIC fingerprint opens with `q`, so this check proves the inner payload decrypted.
	if !strings.HasPrefix(result.Fingerprint, "q") {
		t.Errorf("JA4 produces %q, and a QUIC fingerprint opens with q", result.Fingerprint)
	}

	// The reported key holds the inner port pair.
	if result.SrcPort != tunnelInnerSrcPort || result.DstPort != tunnelInnerDstPort {
		t.Errorf("JA4 reports the port pair %d and %d, and the inner pair is %d and %d",
			result.SrcPort, result.DstPort, tunnelInnerSrcPort, tunnelInnerDstPort)
	}
	if result.SrcPort == vxlanUDPPort || result.DstPort == vxlanUDPPort {
		t.Errorf("JA4 reports the port pair %d and %d, which names the VXLAN tunnel",
			result.SrcPort, result.DstPort)
	}

	// The reported key holds the outer address pair.
	if result.SrcIP != tunnelOuterSrcIP || result.DstIP != tunnelOuterDstIP {
		t.Errorf("JA4 reports the address pair %s and %s, and the outer pair is %s and %s",
			result.SrcIP, result.DstIP, tunnelOuterSrcIP, tunnelOuterDstIP)
	}
}

// The JA4 grouping key of a tunneled QUIC packet holds the inner address pair and the inner
// port pair.
//
// The CRYPTO frame of this packet delivers 40 bytes of the handshake message. Issue #42
// makes an absent fragment an ordinary intermediate state of the reassembly, so
// ProcessPacket returns no error and it keeps the entry that names the connection.
// `GetShardKey` reads the same pair, and issue #170 records the disagreement.
func TestJA4GroupsATunneledQUICPacketByTheInnerPair(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09}
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	handshake := buildClientHelloPayload()[5:45]

	packet := buildVXLANQUICPacket(t, buildQUICClientInitial(t, dcid, scid, handshake))

	fingerprinter := NewJA4()
	if _, err := fingerprinter.ProcessPacket(packet); err != nil {
		t.Fatalf("ProcessPacket returns the error %v, and an absent fragment is no error", err)
	}

	if len(fingerprinter.dcidToTuple) != 1 {
		t.Fatalf("the fingerprinter holds %d connection entries, and the packet opens one",
			len(fingerprinter.dcidToTuple))
	}

	want := "10.16.27.12:54321-10.16.27.131:443"
	for _, held := range fingerprinter.dcidToTuple {
		if held != want {
			t.Errorf("JA4 groups the packet under %q, and the inner pair gives %q", held, want)
		}
	}
}

// JA4S reads the inner UDP layer of a tunneled QUIC packet, and it groups the packet by the
// inner pair.
//
// The outer UDP header names the VXLAN tunnel on port 4789, and it carries no QUIC packet.
// A JA4S branch that read it would store no connection identifier, so it would decrypt no
// server Initial of the connection. Issue #170 records the defect.
func TestJA4SReadsTheInnerUDPLayerOfAVXLANTunneledQUICInitial(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x0a}
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	handshake := buildClientHelloPayload()[5:]

	packet := buildVXLANQUICPacket(t, buildQUICClientInitial(t, dcid, scid, handshake))

	fingerprinter := NewJA4S()
	results, err := fingerprinter.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returns the error %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("ProcessPacket returns %d results for a client Initial, and it produces none", len(results))
	}

	want := "10.16.27.12:54321-10.16.27.131:443"
	held, ok := fingerprinter.quicDCIDs[want]
	if !ok {
		t.Fatalf("JA4S holds the connection identifier under the keys %v, and the inner pair gives %q",
			ja4sConnectionKeys(fingerprinter), want)
	}
	if string(held) != string(dcid) {
		t.Errorf("JA4S holds the connection identifier %x, and the packet carries %x", held, dcid)
	}
}

// ja4sConnectionKeys returns the keys of the JA4S connection identifier table.
// A failure message that names them tells the reader which pair the fingerprinter read.
func ja4sConnectionKeys(f *JA4SFingerprinter) []string {
	keys := make([]string, 0, len(f.quicDCIDs))
	for key := range f.quicDCIDs {
		keys = append(keys, key)
	}
	return keys
}
