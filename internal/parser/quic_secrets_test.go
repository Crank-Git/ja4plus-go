package parser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"testing"
)

// quicTestProtect returns one protected QUIC packet that holds the frames.
// The test builds the packet, because the corpus is not tracked in git.
func quicTestProtect(t *testing.T, secret, frames []byte, short bool, dcid []byte) []byte {
	t.Helper()

	key, iv, hpKey, err := DeriveQUICKeys(secret)
	if err != nil {
		t.Fatalf("DeriveQUICKeys returned %v", err)
	}

	var header []byte
	if short {
		header = append([]byte{0x40}, dcid...)
	} else {
		header = []byte{0xE0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
		header = append(header, dcid...)
		header = append(header, 0x00)
		// The length covers the packet number and the protected frames plus the tag.
		total := 1 + len(frames) + 16
		header = append(header, 0x40|byte(total>>8), byte(total))
	}

	pnOffset := len(header)
	header = append(header, 0x00)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher returned %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM returned %v", err)
	}

	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	packet := aead.Seal(header, nonce, frames, header)

	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		t.Fatalf("the packet holds %d bytes, and the sample needs %d", len(packet), sampleOffset+16)
	}

	mask, err := aesECBEncryptBlock(hpKey, packet[sampleOffset:sampleOffset+16])
	if err != nil {
		t.Fatalf("aesECBEncryptBlock returned %v", err)
	}

	if short {
		packet[0] ^= mask[0] & 0x1f
	} else {
		packet[0] ^= mask[0] & 0x0f
	}

	packet[pnOffset] ^= mask[1]

	return packet
}

func TestDecryptQUICPacketWithSecretReadsALongHeaderPacket(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2b}, 32)
	frames := append([]byte{0x06, 0x00, 0x14}, bytes.Repeat([]byte{0x41}, 20)...)
	packet := quicTestProtect(t, secret, frames, false, []byte{1, 2, 3, 4})

	plaintext, err := DecryptQUICPacketWithSecret(packet, secret, 0)
	if err != nil {
		t.Fatalf("DecryptQUICPacketWithSecret returned %v", err)
	}

	if !bytes.Equal(plaintext, frames) {
		t.Errorf("DecryptQUICPacketWithSecret returned %x, and the packet holds %x", plaintext, frames)
	}
}

func TestDecryptQUICPacketWithSecretReadsAShortHeaderPacket(t *testing.T) {
	secret := bytes.Repeat([]byte{0x3c}, 32)
	frames := bytes.Repeat([]byte{0x08}, 24)
	dcid := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	packet := quicTestProtect(t, secret, frames, true, dcid)

	plaintext, err := DecryptQUICPacketWithSecret(packet, secret, len(dcid))
	if err != nil {
		t.Fatalf("DecryptQUICPacketWithSecret returned %v", err)
	}

	if !bytes.Equal(plaintext, frames) {
		t.Errorf("DecryptQUICPacketWithSecret returned %x, and the packet holds %x", plaintext, frames)
	}
}

func TestDecryptQUICPacketWithSecretRejectsAnEmptySecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2b}, 32)
	frames := bytes.Repeat([]byte{0x00}, 24)
	packet := quicTestProtect(t, secret, frames, false, []byte{1, 2, 3, 4})

	plaintext, err := DecryptQUICPacketWithSecret(packet, nil, 0)
	if !errors.Is(err, ErrNoSecret) {
		t.Errorf("DecryptQUICPacketWithSecret returned %v, and the caller supplied no secret", err)
	}

	if plaintext != nil {
		t.Errorf("DecryptQUICPacketWithSecret returned %x, and the caller supplied no secret", plaintext)
	}
}

func TestDecryptQUICPacketWithSecretRejectsAnotherSecret(t *testing.T) {
	frames := bytes.Repeat([]byte{0x00}, 24)
	packet := quicTestProtect(t, bytes.Repeat([]byte{0x2b}, 32), frames, false, []byte{1, 2, 3, 4})

	// A Decryption Secrets Block holds a secret for a connection the capture does not
	// carry. The library reads no frame from it.
	if _, err := DecryptQUICPacketWithSecret(packet, bytes.Repeat([]byte{0x5a}, 32), 0); err == nil {
		t.Error("DecryptQUICPacketWithSecret returned no error, and the secret belongs to another connection")
	}
}

func TestDecryptQUICPacketWithSecretRejectsACraftedPacket(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2b}, 32)
	cases := map[string][]byte{
		"one zero byte":                            {0x00},
		"a long header with no version":            {0xE0, 0x00},
		"a long header with a length past it":      {0xE0, 0x00, 0x00, 0x00, 0x01, 0x04, 1, 2, 3, 4, 0x00, 0x7f, 0xff},
		"a connection identifier past the packet":  {0xE0, 0x00, 0x00, 0x00, 0x01, 0xff, 1, 2},
		"a short header with no room for a sample": {0x40, 1, 2, 3, 4},
	}

	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			plaintext, err := DecryptQUICPacketWithSecret(packet, secret, 4)
			if err == nil {
				t.Errorf("DecryptQUICPacketWithSecret returned no error for a crafted packet")
			}

			if plaintext != nil {
				t.Errorf("DecryptQUICPacketWithSecret returned %x for a crafted packet", plaintext)
			}
		})
	}
}

func TestDecryptQUICPacketWithSecretRejectsARetryPacket(t *testing.T) {
	// RFC 9369 Section 3.2 gives QUIC version 2 the Retry type `0b00`, and RFC 9000
	// Section 17.2 gives QUIC version 1 the Retry type `0b11`.
	packets := map[string][]byte{
		"version 1": {0xF0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
		"version 2": {0xC0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00},
	}

	for name, packet := range packets {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptQUICPacketWithSecret(packet, bytes.Repeat([]byte{0x2b}, 32), 0)
			if err == nil || !strings.Contains(err.Error(), "Retry") {
				t.Errorf("DecryptQUICPacketWithSecret returned %v for a Retry packet", err)
			}
		})
	}
}

func TestDeriveQUICKeysRejectsASecretOfAnotherLength(t *testing.T) {
	if _, _, _, err := DeriveQUICKeys(bytes.Repeat([]byte{0x01}, 48)); err == nil {
		t.Error("DeriveQUICKeys returned no error, and the secret holds 48 bytes")
	}
}
