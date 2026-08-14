package parser

import "testing"

// quicCryptoFrameAtOffset returns one CRYPTO frame that carries the data at the named
// offset.
// `quicCryptoFrame` writes offset 0 alone, and a gap needs two frames at two offsets.
func quicCryptoFrameAtOffset(offset uint64, data []byte) []byte {
	frame := []byte{quicFrameCrypto}
	frame = append(frame, encodeVarint4(offset)...)
	frame = append(frame, encodeVarint4(uint64(len(data)))...)

	return append(frame, data...)
}

// quicClientHelloHandshakeMessage returns the handshake message of one ClientHello.
// `BuildClientHello` returns a TLS record, and a CRYPTO frame carries the handshake
// message alone.
func quicClientHelloHandshakeMessage() []byte {
	record := BuildClientHello(0x0303, []uint16{0x1301, 0x1302, 0x1303}, nil)

	return record[5:]
}

// quicCipherSuitesOffset names the first cipher suite byte of the handshake message that
// `BuildClientHello` writes.
// Six fields sit in front of it, and the sum below writes one term for each one.
//   - The handshake type, of 1 byte.
//   - The handshake length, of 3 bytes.
//   - The version, of 2 bytes.
//   - The random, of 32 bytes.
//   - The session identifier length, of 1 byte.
//   - The cipher suites length, of 2 bytes.
const quicCipherSuitesOffset = 1 + 3 + 2 + 32 + 1 + 2

// TestParseQUICInitialProducesNoClientHelloFromAGapInTheHandshakeMessage holds the
// completeness rule of #532.
// The datagram carries two CRYPTO fragments, and the gap between them covers the first
// cipher suite. `ReassembleCryptoFrames` writes a zero byte over that gap, so a reader
// with no completeness check reports a cipher list the client never sent.
func TestParseQUICInitialProducesNoClientHelloFromAGapInTheHandshakeMessage(t *testing.T) {
	handshake := quicClientHelloHandshakeMessage()
	if handshake[quicCipherSuitesOffset] != 0x13 || handshake[quicCipherSuitesOffset+1] != 0x01 {
		t.Fatalf("the first cipher suite of the built message is 0x%02x%02x, and the test expects 0x1301",
			handshake[quicCipherSuitesOffset], handshake[quicCipherSuitesOffset+1])
	}

	dcid := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	key, iv, hpKey, err := DeriveInitialKeys(dcid, 1)
	if err != nil {
		t.Fatalf("the test does not derive the client Initial keys: %v", err)
	}

	// The second fragment starts two bytes past the end of the first one, so the first
	// cipher suite reaches no fragment.
	const gapEnd = quicCipherSuitesOffset + 2
	frames := quicCryptoFrameAtOffset(0, handshake[:quicCipherSuitesOffset])
	frames = append(frames, quicCryptoFrameAtOffset(gapEnd, handshake[gapEnd:])...)

	packet := quicInitialPacket(t, key, iv, hpKey, dcid, frames)

	ch, err := ParseQUICInitial(packet)
	if err != nil {
		t.Fatalf("the reader reports an error for a datagram with a gap: %v", err)
	}
	if ch != nil {
		t.Fatalf("the reader returns the cipher suites %v, and the fragments cover no complete handshake message",
			ch.CipherSuites)
	}
}

// TestParseQUICInitialReadsAHandshakeMessageThatTwoFragmentsCover holds the other side of
// the boundary of #532.
// Two fragments cover every byte of the handshake message, so the completeness check
// passes and the reader reports the cipher suites the client sent.
func TestParseQUICInitialReadsAHandshakeMessageThatTwoFragmentsCover(t *testing.T) {
	handshake := quicClientHelloHandshakeMessage()
	dcid := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	key, iv, hpKey, err := DeriveInitialKeys(dcid, 1)
	if err != nil {
		t.Fatalf("the test does not derive the client Initial keys: %v", err)
	}

	frames := quicCryptoFrameAtOffset(0, handshake[:quicCipherSuitesOffset])
	frames = append(frames, quicCryptoFrameAtOffset(quicCipherSuitesOffset, handshake[quicCipherSuitesOffset:])...)

	packet := quicInitialPacket(t, key, iv, hpKey, dcid, frames)

	ch, err := ParseQUICInitial(packet)
	if err != nil {
		t.Fatalf("the reader reports an error for a complete handshake message: %v", err)
	}
	if ch == nil {
		t.Fatal("the reader returns no ClientHello, and the two fragments cover every byte")
	}
	if len(ch.CipherSuites) != 3 || ch.CipherSuites[0] != 0x1301 {
		t.Fatalf("the reader returns the cipher suites %v, and the client sent 0x1301, 0x1302 and 0x1303",
			ch.CipherSuites)
	}
	if !ch.IsQUIC {
		t.Error("the reader returns a ClientHello whose IsQUIC field is false")
	}
}

// TestParseQUICInitialProducesNoErrorForAHandshakeMessageOfThreeBytes pins the one
// behavior difference of #532 that the completeness rule does not name.
// #532 replaced an inline reader, and that reader wrapped a handshake message of 1 to 3
// bytes in a TLS record and passed it to `ParseClientHello`. `ParseClientHello` reports
// `ClientHello truncated: too short for version` for such a record, so `ParseQUICInitial`
// returned that error. It now returns no client hello and no error, because a message of
// 3 bytes carries no 24-bit length that a reader can test.
// A reversal of this decision reverses #532.
func TestParseQUICInitialProducesNoErrorForAHandshakeMessageOfThreeBytes(t *testing.T) {
	dcid := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	key, iv, hpKey, err := DeriveInitialKeys(dcid, 1)
	if err != nil {
		t.Fatalf("the test does not derive the client Initial keys: %v", err)
	}

	frames := quicCryptoFrameAtOffset(0, []byte{TLSHandshakeClientHello, 0x00, 0x00})
	packet := quicInitialPacket(t, key, iv, hpKey, dcid, frames)

	ch, err := ParseQUICInitial(packet)
	if err != nil {
		t.Fatalf("the reader reports the error %v for a handshake message of 3 bytes", err)
	}
	if ch != nil {
		t.Fatal("the reader returns a ClientHello for a handshake message of 3 bytes")
	}
}
