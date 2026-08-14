package parser

import "testing"

// FuzzParseQUICInitialReadsAnyPayload proves that ParseQUICInitial returns for any UDP
// payload. FR-fuzz-3 states the requirement.
//
// No seed of this target decrypts. A packet the parser accepts to the end carries an
// AEAD tag over a key that the destination connection identifier derives, and a seed of
// that shape comes from the FoxIO corpus that #46 adds. Each seed below therefore reaches
// the header reader, the varint reader and the length check.
func FuzzParseQUICInitialReadsAnyPayload(f *testing.F) {
	// A version 1 Initial packet with an 8-byte destination connection identifier, an
	// empty token and a length that the datagram holds. The header reader accepts it.
	f.Add([]byte{
		0xc0, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00,
		0x00,
		0x40, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// The parser rejects each seed below. The first holds no byte. The second states a
	// destination connection identifier length of 255. The third states a token length
	// varint that runs past the datagram.
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0xff, 0x01, 0x02})
	f.Add([]byte{
		0xc0, 0x00, 0x00, 0x00, 0x01, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0xbf,
	})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseQUICInitial(payload)
	})
}

// FuzzParseCryptoFramesReadsAnyPayload proves that ParseCryptoFrames returns for any
// decrypted QUIC payload. FR-fuzz-4 states the requirement.
func FuzzParseCryptoFramesReadsAnyPayload(f *testing.F) {
	// The parser accepts each seed below. The first holds one CRYPTO frame at offset 0
	// that carries a whole client hello handshake message. The second holds one PADDING
	// byte in front of a second CRYPTO frame, because a client that fragments its client
	// hello sends that shape.
	f.Add(quicCryptoFrameAtOffset(0, quicClientHelloHandshakeMessage()))
	f.Add(append([]byte{0x00}, quicCryptoFrameAtOffset(8, []byte{0xaa, 0xbb, 0xcc})...))

	// The parser rejects each seed below. The first states a CRYPTO frame length that runs
	// past the payload. The second holds a truncated offset varint.
	f.Add([]byte{0x06, 0x00, 0x44, 0x00, 0x01, 0x02})
	f.Add([]byte{0x06, 0xc0})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseCryptoFrames(payload)
	})
}
