package ja4plus

import (
	"crypto/aes"
	"crypto/cipher"
	"path/filepath"
	"strings"
	"testing"

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
