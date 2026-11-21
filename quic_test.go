package ja4plus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// quicReassemblyCaptureDir holds the FoxIO captures that `make corpus` fetches.
const quicReassemblyCaptureDir = "testdata/foxio/pcap"

// quicReassemblyRustJA4 is the JA4 value the FoxIO Rust implementation produces for
// `quic-with-several-tls-frames.pcapng` and for `quic-tls-handshake.pcapng`.
//
// The FoxIO Python implementation reads no QUIC handshake, so both FoxIO vector sets hold
// no value for either capture. The port records the same reading in its register under the
// keys `quic-with-several-tls-frames.pcapng/JA4` and `quic-tls-handshake.pcapng/JA4`, and
// port issue #138 holds the decision. The value below is verbatim from the corpus, at
// `testdata/foxio/reference/rust/ja4/src/snapshots/ja4__insta@quic-with-several-tls-frames.pcapng.snap:12`
// and at the same line of `ja4__insta@quic-tls-handshake.pcapng.snap`.
const quicReassemblyRustJA4 = "q13d0310h3_55b375c5d22e_cd85d2d88918"

// quicReassemblyJA4 returns every JA4 fingerprint the library produces for one capture.
// It skips the test when the corpus is absent.
func quicReassemblyJA4(t *testing.T, capture string) []FingerprintResult {
	t.Helper()

	packets := loadPCAP(t, filepath.Join(quicReassemblyCaptureDir, capture))

	fingerprinter := NewJA4()

	var produced []FingerprintResult

	for _, packet := range packets {
		// A QUIC datagram that the fingerprinter cannot decrypt returns a non-fatal error.
		// The client hello of these captures travels in a datagram the fingerprinter reads,
		// so the walk keeps every result and ignores the error.
		results, _ := fingerprinter.ProcessPacket(packet)
		produced = append(produced, results...)
	}

	return produced
}

// TestJA4ReassemblesTheClientHelloOfQuicWithSeveralTlsFramesPcapng holds FR-gaps-21.
//
// The client of `quic-with-several-tls-frames.pcapng` splits its client hello over three
// CRYPTO frames of one QUIC Initial packet, and it puts a PING frame in front of them.
// Issue #42 records that `ParseCryptoFrames` stopped at the PING frame, so the library
// produced no JA4 value for the capture.
func TestJA4ReassemblesTheClientHelloOfQuicWithSeveralTlsFramesPcapng(t *testing.T) {
	produced := quicReassemblyJA4(t, "quic-with-several-tls-frames.pcapng")

	if len(produced) != 1 {
		t.Fatalf("the library produces %d JA4 values, and the capture holds one client hello", len(produced))
	}

	if produced[0].Fingerprint != quicReassemblyRustJA4 {
		t.Errorf("the JA4 value is %q, and the FoxIO Rust implementation produces %q",
			produced[0].Fingerprint, quicReassemblyRustJA4)
	}

	if strings.Contains(produced[0].Fingerprint, parser.EmptyHash) {
		t.Errorf("the JA4 value is %q, and a whole client hello holds a cipher list and an extension list",
			produced[0].Fingerprint)
	}
}

// TestJA4ReassemblesTheClientHelloOfQuicTlsHandshakePcapng holds FR-gaps-21.
//
// The client of `quic-tls-handshake.pcapng` splits its client hello over eleven CRYPTO
// frames of one QUIC Initial packet, and it sends them out of offset order.
func TestJA4ReassemblesTheClientHelloOfQuicTlsHandshakePcapng(t *testing.T) {
	produced := quicReassemblyJA4(t, "quic-tls-handshake.pcapng")

	if len(produced) != 1 {
		t.Fatalf("the library produces %d JA4 values, and the capture holds one client hello", len(produced))
	}

	if produced[0].Fingerprint != quicReassemblyRustJA4 {
		t.Errorf("the JA4 value is %q, and the FoxIO Rust implementation produces %q",
			produced[0].Fingerprint, quicReassemblyRustJA4)
	}
}

// TestParseCryptoFramesReadsTheFrameBehindAPingFrame holds FR-gaps-21.
//
// RFC 9000 Section 19.2 gives the PING frame no field, so a reader steps over one byte.
// `internal/parser/quic.go` stepped over the PADDING frame alone, so a PING frame in
// front of a CRYPTO frame hid the whole client hello.
func TestParseCryptoFramesReadsTheFrameBehindAPingFrame(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x06, 0x00, 0x03, 'a', 'b', 'c'}

	fragments, err := parser.ParseCryptoFrames(payload)
	if err != nil {
		t.Fatalf("ParseCryptoFrames returns the error %v, and the payload holds a whole CRYPTO frame", err)
	}

	if len(fragments) != 1 {
		t.Fatalf("ParseCryptoFrames returns %d fragments, and the payload holds one", len(fragments))
	}

	if string(fragments[0].Data) != "abc" {
		t.Errorf("ParseCryptoFrames returns the data %q, and the frame holds %q", fragments[0].Data, "abc")
	}
}

// TestClientHelloFromCryptoFragmentsReadsTheFragmentsOfTwoInitialPackets holds FR-gaps-22.
//
// A client that fills its first QUIC Initial packet sends the rest of its client hello in
// a second one. The caller collects the fragments of both packets under one connection
// identifier, and reads the client hello when the last fragment arrives.
func TestClientHelloFromCryptoFragmentsReadsTheFragmentsOfTwoInitialPackets(t *testing.T) {
	hello := quicReassemblyClientHello()

	first := []parser.CryptoFragment{{Offset: 0, Data: hello[:40]}}
	second := []parser.CryptoFragment{{Offset: 40, Data: hello[40:]}}

	collected, err := parser.CollectCryptoFragments(nil, first)
	if err != nil {
		t.Fatalf("CollectCryptoFragments returns the error %v for the first packet", err)
	}

	partial, err := parser.ClientHelloFromCryptoFragments(collected)
	if err != nil {
		t.Fatalf("ClientHelloFromCryptoFragments returns the error %v for the first packet", err)
	}

	if partial != nil {
		t.Errorf("ClientHelloFromCryptoFragments returns a client hello, and the first packet holds a part of one")
	}

	collected, err = parser.CollectCryptoFragments(collected, second)
	if err != nil {
		t.Fatalf("CollectCryptoFragments returns the error %v for the second packet", err)
	}

	whole, err := parser.ClientHelloFromCryptoFragments(collected)
	if err != nil {
		t.Fatalf("ClientHelloFromCryptoFragments returns the error %v for the second packet", err)
	}

	if whole == nil {
		t.Fatalf("ClientHelloFromCryptoFragments returns no client hello, and the two packets hold a whole one")
	}

	if len(whole.CipherSuites) != 3 {
		t.Errorf("the client hello holds %d cipher suites, and the test builds three", len(whole.CipherSuites))
	}
}

// TestClientHelloFromCryptoFragmentsRefusesAFragmentSetWithAGap holds FR-gaps-22.
//
// ReassembleCryptoFrames writes a zero byte over a range that no fragment covers. A sender
// that names the first offset and the last offset, and no offset between them, would reach
// a fingerprint of bytes it never sent.
func TestClientHelloFromCryptoFragmentsRefusesAFragmentSetWithAGap(t *testing.T) {
	hello := quicReassemblyClientHello()

	// The two fragments hold the first 8 bytes and the last byte. The message length that
	// byte 1 to byte 3 names still reaches the end of the reassembled buffer.
	gapped := []parser.CryptoFragment{
		{Offset: 0, Data: hello[:8]},
		{Offset: uint64(len(hello) - 1), Data: hello[len(hello)-1:]},
	}

	produced, err := parser.ClientHelloFromCryptoFragments(gapped)
	if err != nil {
		t.Fatalf("ClientHelloFromCryptoFragments returns the error %v for a fragment set with a gap", err)
	}

	if produced != nil {
		t.Errorf("ClientHelloFromCryptoFragments returns a client hello, and no fragment covers the middle of the message")
	}
}

// TestCollectCryptoFragmentsRefusesAFragmentBufferAboveTheBound holds FR-gaps-23.
//
// RFC 9000 Section 16 lets a CRYPTO frame offset reach 4611686018427387903, and the
// reassembly allocates a buffer that reaches the highest offset. A sender that never
// completes a client hello would grow the buffer without a bound.
func TestCollectCryptoFragmentsRefusesAFragmentBufferAboveTheBound(t *testing.T) {
	fragment := []parser.CryptoFragment{{Offset: 0, Data: make([]byte, 4096)}}

	var collected []parser.CryptoFragment

	var err error
	for round := 0; round < 1000; round++ {
		collected, err = parser.CollectCryptoFragments(collected, fragment)
		if err != nil {
			break
		}
	}

	if err == nil {
		t.Fatalf("CollectCryptoFragments reaches no error, and the caller sent %d fragments", len(collected))
	}

	if !strings.Contains(err.Error(), "bound") {
		t.Errorf("CollectCryptoFragments returns the error %v, and the message names no bound", err)
	}

	total := 0
	for _, held := range collected {
		total += len(held.Data)
	}

	if total > parser.MaxCryptoBufferBytes {
		t.Errorf("the collected fragments hold %d bytes, and the bound is %d",
			total, parser.MaxCryptoBufferBytes)
	}
}

// TestCollectCryptoFragmentsRefusesAFragmentAboveTheBound holds FR-gaps-23.
//
// One fragment that names an offset above the bound describes no real client hello.
func TestCollectCryptoFragmentsRefusesAFragmentAboveTheBound(t *testing.T) {
	fragment := []parser.CryptoFragment{{Offset: 1 << 40, Data: []byte{0x01}}}

	collected, err := parser.CollectCryptoFragments(nil, fragment)
	if err != nil {
		t.Fatalf("CollectCryptoFragments returns the error %v, and one fragment above the bound is no failure", err)
	}

	if len(collected) != 0 {
		t.Errorf("CollectCryptoFragments keeps %d fragments, and the one fragment names an offset above the bound",
			len(collected))
	}
}

// TestJA4DropsTheConnectionOfAFragmentBufferAboveTheBound holds FR-gaps-23.
//
// The fingerprinter holds one fragment buffer for each QUIC connection identifier. A
// sender that never completes a client hello reaches the bound, and the fingerprinter
// drops the connection state rather than grow the buffer.
func TestJA4DropsTheConnectionOfAFragmentBufferAboveTheBound(t *testing.T) {
	fingerprinter := NewJA4()

	// The datagram holds one CRYPTO frame of 1000 bytes at offset 0. The client hello it
	// names is 16777215 bytes long, so the fingerprinter never reads a whole one.
	frame := make([]byte, 0, 1024)
	frame = append(frame, 0x06, 0x00, 0x43, 0xe8)
	frame = append(frame, make([]byte, 1000)...)
	frame[4] = parser.TLSHandshakeClientHello
	frame[5], frame[6], frame[7] = 0xff, 0xff, 0xff

	var errored bool

	for round := 0; round < 40; round++ {
		packet := quicReassemblyDatagram(t, frame, uint16(round))

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			errored = true
			break
		}
	}

	if !errored {
		t.Fatalf("the fingerprinter reaches no error, and the sender never completes a client hello")
	}

	if held := len(fingerprinter.quicFragments); held != 0 {
		t.Errorf("the fingerprinter holds %d fragment buffers, and it drops the connection at the bound", held)
	}
}

// TestJA4DropsTheConnectionOfAClientHelloParseError holds issue #533.
//
// ClientHelloFromCryptoFragments returns nil and no error while a fragment is missing.
// So an error of that function names a complete handshake message. No later packet repairs
// such a message. The fingerprinter drops the connection state, and it holds no entry for
// the life of the process.
func TestJA4DropsTheConnectionOfAClientHelloParseError(t *testing.T) {
	fingerprinter := NewJA4()

	// The handshake message counts 34 body bytes, and it carries the legacy version and the
	// random value alone. ParseClientHello reads the session identifier length behind them,
	// and the message ends first.
	message := []byte{parser.TLSHandshakeClientHello, 0x00, 0x00, 0x22}
	message = append(message, 0x03, 0x03)          // the legacy version
	message = append(message, make([]byte, 32)...) // the random value

	// The frame names the CRYPTO type, an offset of zero and the length of the message.
	frame := []byte{0x06, 0x00, byte(len(message))}
	frame = append(frame, message...)

	_, err := fingerprinter.ProcessPacket(quicReassemblyDatagram(t, frame, 0))
	if err == nil {
		t.Fatalf("the fingerprinter reaches no error, and the client hello holds no session identifier length")
	}

	if held := len(fingerprinter.quicFragments); held != 0 {
		t.Errorf("the fingerprinter holds %d fragment buffers, and it drops the connection at a parse error", held)
	}

	if held := len(fingerprinter.dcidToTuple); held != 0 {
		t.Errorf("the fingerprinter holds %d grouping key entries, and it drops the connection at a parse error", held)
	}

	if held := len(fingerprinter.dcidToReported); held != 0 {
		t.Errorf("the fingerprinter holds %d reported key entries, and it drops the connection at a parse error", held)
	}
}

// quicReassemblyClientHello returns the bytes of a TLS client hello handshake message.
// The message holds three cipher suites and no extension.
func quicReassemblyClientHello() []byte {
	body := make([]byte, 0, 128)

	body = append(body, 0x03, 0x03)          // the legacy version
	body = append(body, make([]byte, 32)...) // the random value
	body = append(body, 0x00)                // the session identifier
	body = append(body, 0x00, 0x06)          // the cipher suite list length
	body = append(body, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	body = append(body, 0x01, 0x00) // the compression method list
	body = append(body, 0x00, 0x00) // the extension list length

	message := []byte{parser.TLSHandshakeClientHello,
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}

	return append(message, body...)
}

// quicReassemblyInitial returns the bytes of one QUIC version 1 Initial packet that
// carries the frames. RFC 9001 Section 5 states the key derivation, and Section 5.4
// states the header protection this function applies.
func quicReassemblyInitial(t *testing.T, dcid []byte, frames []byte) []byte {
	t.Helper()

	key, iv, hpKey, err := parser.DeriveInitialKeys(dcid, 1)
	if err != nil {
		t.Fatalf("the test does not derive the Initial keys: %v", err)
	}

	// The first byte names a long header, the fixed bit, the Initial type and a packet
	// number of four bytes.
	header := []byte{0xc3, 0x00, 0x00, 0x00, 0x01}
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0x00) // the source connection identifier is empty
	header = append(header, 0x00) // the token is empty

	// The Length field counts the packet number, the frames and the 16-byte tag.
	length := 4 + len(frames) + 16
	header = append(header, 0x40|byte(length>>8), byte(length))

	pnOffset := len(header)
	header = append(header, 0x00, 0x00, 0x00, 0x00) // the packet number is zero

	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("the test does not build the payload cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("the test does not build the payload AEAD: %v", err)
	}

	packet := aead.Seal(header, nonce, frames, header)

	sample := packet[pnOffset+4 : pnOffset+20]

	protection, err := aes.NewCipher(hpKey)
	if err != nil {
		t.Fatalf("the test does not build the header cipher: %v", err)
	}

	mask := make([]byte, aes.BlockSize)
	protection.Encrypt(mask, sample)

	packet[0] ^= mask[0] & 0x0f
	for offset := 0; offset < 4; offset++ {
		packet[pnOffset+offset] ^= mask[1+offset]
	}

	return packet
}

// quicReassemblyDatagram returns one packet that carries the CRYPTO frames as a QUIC
// Initial packet of version 1. The source port names the datagram, so the caller sends
// several datagrams over one connection identifier.
func quicReassemblyDatagram(t *testing.T, frames []byte, index uint16) gopacket.Packet {
	t.Helper()

	datagram := quicReassemblyInitial(t, []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}, frames)

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(40000 + index), DstPort: 443}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the test does not set the network layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{SrcMAC: []byte{1, 1, 1, 1, 1, 1}, DstMAC: []byte{2, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeIPv4},
		ip, udp, gopacket.Payload(datagram)); err != nil {
		t.Fatalf("the test does not serialize the packet: %v", err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Issue #193 records the defect that every test in this file holds. JA4 and JA4S key their
// QUIC state with the grouping key, which reads the inner address pair. Each
// FingerprintResult carries the reported key, which reads the outer address pair.
// `types.go:20-25` documents the CleanupConnection tuple as the pair a FingerprintResult
// carries, so a caller that follows the document names the reported key. Without an index
// from the reported key to the grouping key, the removal reaches no entry, and one entry
// leaks for every tunneled connection.
//
// No capture of the FoxIO corpus carries QUIC inside a tunnel, so every test here builds the
// separating packet. `quic_tunnel_test.go` holds the packet builder, and the tunnel is VXLAN.
//
// #169 repaired JA4L, and `ja4plus/fingerprinters/ja4l.py:216` holds the same fallback in the
// Python port. The port carries no such index on its JA4 fingerprinter and on its JA4S
// fingerprinter, so this repository leads the port on those two methods.

// tunneledConnectionCount is the number of tunneled connections each leak test opens.
// One connection proves the removal, and three prove that one entry leaks for every
// connection.
const tunneledConnectionCount = 3

// tunneledClientPort returns the inner source port of one tunneled connection.
// Each connection reads its own port, so each one reaches its own state entry.
func tunneledClientPort(index int) uint16 {
	return uint16(tunnelInnerSrcPort + index)
}

// tunneledDCID returns the destination connection identifier of one tunneled connection.
// The QUIC Initial keys read this value, so each connection reads its own identifier.
func tunneledDCID(index int) []byte {
	return []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, byte(0x20 + index)}
}

// openTunneledJA4Connections processes one tunneled QUIC client Initial for every
// connection, and it returns the inner source port of each one.
//
// The CRYPTO frame of each packet delivers 40 bytes of the handshake message. Issue #42
// makes an absent fragment an ordinary intermediate state of the reassembly, so the
// fingerprinter keeps the entry that names the connection.
func openTunneledJA4Connections(t *testing.T, fingerprinter *JA4Fingerprinter) []uint16 {
	t.Helper()

	ports := make([]uint16, 0, tunneledConnectionCount)

	for index := 0; index < tunneledConnectionCount; index++ {
		port := tunneledClientPort(index)
		handshake := buildClientHelloPayload()[5:45]
		initial := buildQUICClientInitial(t, tunneledDCID(index), []byte{0x01, 0x02, 0x03, 0x04}, handshake)
		packet := buildVXLANQUICPacketOnPort(t, port, initial)

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("ProcessPacket returns the error %v, and an absent fragment is no error", err)
		}

		ports = append(ports, port)
	}

	return ports
}

// openTunneledJA4SConnections processes one tunneled QUIC client Initial for every
// connection, and it returns the inner source port of each one.
// JA4S stores the connection identifier of a client Initial, and it returns no result for it.
func openTunneledJA4SConnections(t *testing.T, fingerprinter *JA4SFingerprinter) []uint16 {
	t.Helper()

	ports := make([]uint16, 0, tunneledConnectionCount)

	for index := 0; index < tunneledConnectionCount; index++ {
		port := tunneledClientPort(index)
		handshake := buildClientHelloPayload()[5:]
		initial := buildQUICClientInitial(t, tunneledDCID(index), []byte{0x01, 0x02, 0x03, 0x04}, handshake)
		packet := buildVXLANQUICPacketOnPort(t, port, initial)

		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returns the error %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("ProcessPacket returns %d results for a client Initial, and it produces none", len(results))
		}

		ports = append(ports, port)
	}

	return ports
}

// cleanupByTheReportedKey removes each connection by the address pair a FingerprintResult
// carries. That pair holds the outer addresses and the inner ports.
// The last connection reads the two endpoints in the reverse order, because a caller names
// them in either order.
func cleanupByTheReportedKey(fingerprinter Fingerprinter, ports []uint16) {
	for index, port := range ports {
		if index == len(ports)-1 {
			fingerprinter.CleanupConnection(tunnelOuterDstIP, tunnelInnerDstPort, tunnelOuterSrcIP, port, "udp")

			continue
		}

		fingerprinter.CleanupConnection(tunnelOuterSrcIP, port, tunnelOuterDstIP, tunnelInnerDstPort, "udp")
	}
}

// JA4 removes every tunneled connection that a caller names by the reported key.
//
// The reported key holds the outer pair `100.20.9.2` and `100.20.9.1`, and the grouping key
// holds the inner pair `10.16.27.12` and `10.16.27.131`.
// `TestJA4ReadsTheInnerUDPLayerOfAVXLANTunneledQUICInitial` proves that a result reports the
// outer pair with the inner ports.
func TestJA4CleanupByTheReportedKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4()
	ports := openTunneledJA4Connections(t, fingerprinter)

	if got := len(fingerprinter.dcidToTuple); got != tunneledConnectionCount {
		t.Fatalf("the connection identifier table holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.quicFragments); got != tunneledConnectionCount {
		t.Fatalf("the fragment table holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.dcidToReported); got != tunneledConnectionCount {
		t.Fatalf("the index holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}

	cleanupByTheReportedKey(fingerprinter, ports)

	if got := len(fingerprinter.dcidToTuple); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.quicFragments); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the fragment table, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.dcidToReported); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the index, and one leaks for every tunneled connection",
			got)
	}
}

// JA4 removes a tunneled connection that a caller names by the grouping key.
//
// A caller that reads GetShardKey holds the grouping key, and the index holds the reported
// key alone. The removal therefore falls back to the key the caller gave.
// `ja4plus/fingerprinters/ja4l.py:216` falls back the same way.
func TestJA4CleanupByTheGroupingKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4()
	ports := openTunneledJA4Connections(t, fingerprinter)

	for _, port := range ports {
		fingerprinter.CleanupConnection(tunnelInnerSrcIP, port, tunnelInnerDstIP, tunnelInnerDstPort, "udp")
	}

	if got := len(fingerprinter.dcidToTuple); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table", got)
	}
	if got := len(fingerprinter.quicFragments); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the fragment table", got)
	}
	if got := len(fingerprinter.dcidToReported); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the index, and the caller cannot name the reported key",
			got)
	}
}

// JA4S removes every tunneled connection that a caller names by the reported key.
//
// `TestJA4SReadsTheInnerUDPLayerOfAVXLANTunneledQUICInitial` proves that JA4S stores the
// connection identifier under the grouping key, which holds the inner pair.
func TestJA4SCleanupByTheReportedKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4S()
	ports := openTunneledJA4SConnections(t, fingerprinter)

	if got := len(fingerprinter.quicDCIDs); got != tunneledConnectionCount {
		t.Fatalf("the connection identifier table holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.groupingKeys); got != tunneledConnectionCount {
		t.Fatalf("the grouping key index holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}
	if got := len(fingerprinter.reportedKeys); got != tunneledConnectionCount {
		t.Fatalf("the reported key index holds %d entries, and the test opens %d connections",
			got, tunneledConnectionCount)
	}

	cleanupByTheReportedKey(fingerprinter, ports)

	if got := len(fingerprinter.quicDCIDs); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.groupingKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the grouping key index, and one leaks for every tunneled connection",
			got)
	}
	if got := len(fingerprinter.reportedKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the reported key index, and one leaks for every tunneled connection",
			got)
	}
}

// JA4S removes a tunneled connection that a caller names by the grouping key.
func TestJA4SCleanupByTheGroupingKeyRemovesEveryTunneledConnection(t *testing.T) {
	fingerprinter := NewJA4S()
	ports := openTunneledJA4SConnections(t, fingerprinter)

	for _, port := range ports {
		fingerprinter.CleanupConnection(tunnelInnerSrcIP, port, tunnelInnerDstIP, tunnelInnerDstPort, "udp")
	}

	if got := len(fingerprinter.quicDCIDs); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the connection identifier table", got)
	}
	if got := len(fingerprinter.groupingKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the grouping key index, and the caller cannot name the reported key",
			got)
	}
	if got := len(fingerprinter.reportedKeys); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the reported key index", got)
	}
}

// JA4S holds one index entry for one connection that two outer addresses carry.
//
// Two tunnel endpoints of one path send one connection from two outer addresses, and a client
// repeats an Initial that no server acknowledges. The second packet moves the reported key of
// the connection, so the entry of the first reported key stays for the life of the process.
// `ja4plus/fingerprinters/ja4l.py:170` removes the previous entry for the same reason.
func TestJA4SHoldsOneIndexEntryForATunneledConnectionThatTwoOuterAddressesCarry(t *testing.T) {
	fingerprinter := NewJA4S()
	handshake := buildClientHelloPayload()[5:]
	initial := buildQUICClientInitial(t, tunneledDCID(0), []byte{0x01, 0x02, 0x03, 0x04}, handshake)

	// The second address is the outer source of a second tunnel endpoint. The inner pair holds
	// one connection, so the grouping key of the two packets holds one value.
	for _, outerSrcIP := range []string{tunnelOuterSrcIP, "100.20.9.3"} {
		packet := buildVXLANQUICPacketFrom(t, outerSrcIP, tunnelInnerSrcPort, initial)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("ProcessPacket returns the error %v", err)
		}
	}

	if got := len(fingerprinter.quicDCIDs); got != 1 {
		t.Fatalf("the connection identifier table holds %d entries, and the two packets carry one connection",
			got)
	}
	if got := len(fingerprinter.groupingKeys); got != 1 {
		t.Errorf("the grouping key index holds %d entries, and the two packets carry one connection",
			got)
	}
	if got := len(fingerprinter.reportedKeys); got != 1 {
		t.Errorf("the reported key index holds %d entries, and the two packets carry one connection",
			got)
	}
}

// Reset clears every JA4 table that a tunneled connection fills.
// A table the index does not reach is a table Reset may not clear.
func TestResetClearsEveryTunneledTableOfJA4(t *testing.T) {
	fingerprinter := NewJA4()
	openTunneledJA4Connections(t, fingerprinter)
	fingerprinter.Reset()

	if got := len(fingerprinter.dcidToTuple); got != 0 {
		t.Errorf("Reset leaves %d entries in the connection identifier table", got)
	}
	if got := len(fingerprinter.quicFragments); got != 0 {
		t.Errorf("Reset leaves %d entries in the fragment table", got)
	}
	if got := len(fingerprinter.dcidToReported); got != 0 {
		t.Errorf("Reset leaves %d entries in the index", got)
	}
}

// Reset clears every JA4S table that a tunneled connection fills.
func TestResetClearsEveryTunneledTableOfJA4S(t *testing.T) {
	fingerprinter := NewJA4S()
	openTunneledJA4SConnections(t, fingerprinter)
	fingerprinter.Reset()

	if got := len(fingerprinter.quicDCIDs); got != 0 {
		t.Errorf("Reset leaves %d entries in the connection identifier table", got)
	}
	if got := len(fingerprinter.groupingKeys); got != 0 {
		t.Errorf("Reset leaves %d entries in the grouping key index", got)
	}
	if got := len(fingerprinter.reportedKeys); got != 0 {
		t.Errorf("Reset leaves %d entries in the reported key index", got)
	}
}

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

	return buildVXLANQUICPacketOnPort(t, tunnelInnerSrcPort, payload)
}

// buildVXLANQUICPacketOnPort returns one VXLAN packet that carries the QUIC payload from the
// named inner source port. A test that opens more than one connection reads one port for
// each one, because the grouping key holds the port pair.
func buildVXLANQUICPacketOnPort(t *testing.T, innerSrcPort uint16, payload []byte) gopacket.Packet {
	t.Helper()

	return buildVXLANQUICPacketFrom(t, tunnelOuterSrcIP, innerSrcPort, payload)
}

// buildVXLANQUICPacketFrom returns one VXLAN packet that the named outer source address
// carries. Two tunnel endpoints of one path send one connection from two outer addresses, so a
// test that reads the index needs more than one outer address.
func buildVXLANQUICPacketFrom(t *testing.T, outerSrcIP string, innerSrcPort uint16, payload []byte) gopacket.Packet {
	t.Helper()

	outerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	outerIP := &layers.IPv4{
		SrcIP:    net.ParseIP(outerSrcIP),
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
	innerUDP := &layers.UDP{SrcPort: layers.UDPPort(innerSrcPort), DstPort: tunnelInnerDstPort}
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
	if udp := parser.GetUDPLayer(packet); udp == nil || uint16(udp.SrcPort) != innerSrcPort {
		t.Fatalf("the packet decodes no inner UDP layer on port %d", innerSrcPort)
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
