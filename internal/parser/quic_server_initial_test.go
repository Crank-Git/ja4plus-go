package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// quicInitialPacket returns the bytes of one QUIC version 1 Initial packet.
// The caller passes the key set of the sender role, so one builder writes a client packet
// and a server packet. `headerDCID` names the Destination Connection ID field of the
// packet, and it differs from the derivation input on a server packet.
// RFC 9001 Section 5.4.1 states the header protection this function applies.
func quicInitialPacket(t *testing.T, key, iv, hpKey, headerDCID, frames []byte) []byte {
	t.Helper()

	// The first byte names a long header, the fixed bit, the Initial type and a packet
	// number of four bytes.
	header := []byte{0xc3, 0x00, 0x00, 0x00, 0x01}
	header = append(header, byte(len(headerDCID)))
	header = append(header, headerDCID...)
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

// quicCryptoFrame returns one CRYPTO frame that carries the data at offset 0.
func quicCryptoFrame(data []byte) []byte {
	frame := []byte{quicFrameCrypto, 0x00, 0x40 | byte(len(data)>>8), byte(len(data))}

	return append(frame, data...)
}

// TestDecryptQUICInitialCryptoDeclinesAServerInitialPacket holds the decline that #501
// built. The server protects an Initial packet with the server keys of the Destination
// Connection ID that the client sent, and `DecryptQUICInitialCrypto` derives the client
// keys of the Destination Connection ID that the packet holds. So the derived key
// authenticates no server Initial packet, and the reader declines the packet.
// RFC 9001 Section 5.2 states the derivation input:
// `The connection ID used with HKDF-Expand-Label is the Destination Connection ID in the
// Initial packet sent by the client.`
func TestDecryptQUICInitialCryptoDeclinesAServerInitialPacket(t *testing.T) {
	clientDCID := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	key, iv, hpKey, err := DeriveServerInitialKeys(clientDCID, 1)
	if err != nil {
		t.Fatalf("the test does not derive the server Initial keys: %v", err)
	}

	// `chrome-cloudflare-quic-with-secrets.pcapng` frame 49 carries a zero-length
	// Destination Connection ID, and the packet of this test carries the same field.
	packet := quicInitialPacket(t, key, iv, hpKey, nil, quicCryptoFrame([]byte{0x02, 0x00, 0x00, 0x00}))

	fragments, _, err := DecryptQUICInitialCrypto(packet)
	if err != nil {
		t.Fatalf("the reader reports an error for a server Initial packet: %v", err)
	}
	if len(fragments) != 0 {
		t.Fatalf("the reader returns %d fragments for a server Initial packet", len(fragments))
	}
}

// TestDecryptQUICInitialCryptoReportsATruncatedCryptoFrame holds the other side of the
// boundary of #501. The derived key authenticates this packet, and the plaintext holds a
// CRYPTO frame whose Length field passes the end of the frame. A malformed packet keeps
// the error it reports.
func TestDecryptQUICInitialCryptoReportsATruncatedCryptoFrame(t *testing.T) {
	clientDCID := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	key, iv, hpKey, err := DeriveInitialKeys(clientDCID, 1)
	if err != nil {
		t.Fatalf("the test does not derive the client Initial keys: %v", err)
	}

	// The Length field states 16 bytes, and 4 bytes follow it.
	frame := []byte{quicFrameCrypto, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04}
	packet := quicInitialPacket(t, key, iv, hpKey, clientDCID, frame)

	_, _, err = DecryptQUICInitialCrypto(packet)
	if err == nil {
		t.Fatal("the reader reports no error for a truncated CRYPTO frame")
	}
}

// TestDecryptQUICInitialCryptoReportsAPayloadShorterThanTheTag holds the third case of the
// boundary of #501. The Length field of this packet leaves fewer bytes than the 16-byte
// authentication tag, so no key authenticates the packet and the length field is the
// defect. A malformed packet keeps the error it reports.
func TestDecryptQUICInitialCryptoReportsAPayloadShorterThanTheTag(t *testing.T) {
	clientDCID := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	// The first byte names a long header, the fixed bit, the Initial type and a packet
	// number of four bytes.
	packet := []byte{0xc3, 0x00, 0x00, 0x00, 0x01}
	packet = append(packet, byte(len(clientDCID)))
	packet = append(packet, clientDCID...)
	packet = append(packet, 0x00) // the source connection identifier is empty
	packet = append(packet, 0x00) // the token is empty

	// The Length field counts the 4-byte packet number and 8 bytes more, which is 8 bytes
	// below the tag length.
	packet = append(packet, 0x0c)
	packet = append(packet, make([]byte, 12)...)

	// The reader samples 16 bytes from 4 bytes after the packet number field, so the packet
	// carries those bytes.
	packet = append(packet, make([]byte, 16)...)

	_, _, err := DecryptQUICInitialCrypto(packet)
	if err == nil {
		t.Fatal("the reader reports no error for a payload shorter than the tag")
	}
}
