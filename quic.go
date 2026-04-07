package ja4plus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"golang.org/x/crypto/hkdf"
)

// QUIC version constants.
const (
	quicV1 uint32 = 0x00000001
	quicV2 uint32 = 0x6b3343cf
)

// QUIC Initial salts per RFC 9001 Section 5.2.
var (
	quicV1Salt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
		0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicV2Salt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
		0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
		0xf9, 0xbd, 0x2e, 0xd9,
	}
)

// QUIC frame type constants.
const (
	quicFramePadding = 0x00
	quicFrameCrypto  = 0x06
)

// decodeVarint decodes a QUIC variable-length integer from data at position pos.
// Returns the decoded value and the new position after the varint, or an error.
func decodeVarint(data []byte, pos int) (uint64, int, error) {
	if pos >= len(data) {
		return 0, pos, errors.New("varint: no data")
	}
	prefix := data[pos] >> 6
	switch prefix {
	case 0:
		return uint64(data[pos] & 0x3f), pos + 1, nil
	case 1:
		if pos+2 > len(data) {
			return 0, pos, errors.New("varint: need 2 bytes")
		}
		v := uint64(data[pos]&0x3f)<<8 | uint64(data[pos+1])
		return v, pos + 2, nil
	case 2:
		if pos+4 > len(data) {
			return 0, pos, errors.New("varint: need 4 bytes")
		}
		v := uint64(data[pos]&0x3f)<<24 | uint64(data[pos+1])<<16 |
			uint64(data[pos+2])<<8 | uint64(data[pos+3])
		return v, pos + 4, nil
	case 3:
		if pos+8 > len(data) {
			return 0, pos, errors.New("varint: need 8 bytes")
		}
		v := uint64(data[pos]&0x3f)<<56 | uint64(data[pos+1])<<48 |
			uint64(data[pos+2])<<40 | uint64(data[pos+3])<<32 |
			uint64(data[pos+4])<<24 | uint64(data[pos+5])<<16 |
			uint64(data[pos+6])<<8 | uint64(data[pos+7])
		return v, pos + 8, nil
	}
	return 0, pos, errors.New("varint: unreachable")
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// Build HkdfLabel struct:
	//   uint16 length
	//   opaque label<7..255> = "tls13 " + label
	//   opaque context<0..255>
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	r := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// deriveInitialKeys derives the client key, IV, and header protection key
// from the Destination Connection ID for a QUIC Initial packet.
func deriveInitialKeys(dcid []byte, version uint32) (key, iv, hpKey []byte, err error) {
	var salt []byte
	switch version {
	case quicV1:
		salt = quicV1Salt
	case quicV2:
		salt = quicV2Salt
	default:
		return nil, nil, nil, errors.New("unsupported QUIC version")
	}

	// initial_secret = HKDF-Extract(salt, DCID)
	initialSecret := hkdf.Extract(sha256.New, dcid, salt)

	// client_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	// key = HKDF-Expand-Label(client_secret, "quic key", "", 16)
	key, err = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	// iv = HKDF-Expand-Label(client_secret, "quic iv", "", 12)
	iv, err = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}

	// hp_key = HKDF-Expand-Label(client_secret, "quic hp", "", 16)
	hpKey, err = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, hpKey, nil
}

// aesECBEncryptBlock encrypts a single AES block using ECB mode (raw AES).
func aesECBEncryptBlock(key, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize)
	c.Encrypt(out, block)
	return out, nil
}

// cryptoFragment represents a CRYPTO frame fragment with offset and data.
type cryptoFragment struct {
	offset uint64
	data   []byte
}

// ParseQUICInitial parses a QUIC Initial packet and extracts the TLS ClientHello.
// Returns nil, nil if the payload is not a QUIC Initial packet.
// Returns nil, error if it looks like a QUIC Initial but decryption/parsing fails.
func ParseQUICInitial(payload []byte) (*ClientHello, error) {
	if len(payload) < 5 {
		return nil, nil
	}

	// Check long header form (bit 7 set) and fixed bit (bit 6 set)
	firstByte := payload[0]
	if firstByte&0x80 == 0 {
		return nil, nil // short header, not Initial
	}

	// Version (bytes 1-4)
	version := binary.BigEndian.Uint32(payload[1:5])
	if version == 0 {
		return nil, nil // version negotiation packet
	}

	// Check packet type: Initial = 0x00 in bits 4-5 for v1, 0x01 for v2
	var isInitial bool
	switch version {
	case quicV1:
		isInitial = (firstByte & 0x30) == 0x00
	case quicV2:
		isInitial = (firstByte & 0x30) == 0x10
	default:
		return nil, nil // unsupported version
	}
	if !isInitial {
		return nil, nil
	}

	pos := 5

	// DCID length + DCID
	if pos >= len(payload) {
		return nil, nil
	}
	dcidLen := int(payload[pos])
	pos++
	if pos+dcidLen > len(payload) {
		return nil, nil
	}
	dcid := make([]byte, dcidLen)
	copy(dcid, payload[pos:pos+dcidLen])
	pos += dcidLen

	// SCID length + SCID
	if pos >= len(payload) {
		return nil, nil
	}
	scidLen := int(payload[pos])
	pos++
	if pos+scidLen > len(payload) {
		return nil, nil
	}
	pos += scidLen

	// Token length (varint) + token
	tokenLen, newPos, err := decodeVarint(payload, pos)
	if err != nil {
		return nil, nil
	}
	pos = newPos
	if pos+int(tokenLen) > len(payload) {
		return nil, nil
	}
	pos += int(tokenLen)

	// Payload length (varint)
	payloadLen, newPos, err := decodeVarint(payload, pos)
	if err != nil {
		return nil, nil
	}
	pos = newPos

	// pos is now at the start of the packet number (protected)
	pnOffset := pos

	// Ensure we have enough data
	if pnOffset+4+int(payloadLen) > len(payload)+4 {
		// Be lenient: payloadLen includes pn bytes
		if pnOffset+int(payloadLen) > len(payload) {
			return nil, nil
		}
	}

	// Derive Initial keys
	key, iv, hpKey, err := deriveInitialKeys(dcid, version)
	if err != nil {
		return nil, err
	}

	// Remove header protection
	// Sample starts 4 bytes after the packet number offset
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(payload) {
		return nil, nil
	}
	sample := payload[sampleOffset : sampleOffset+16]

	// AES-ECB encrypt the sample to get the mask
	mask, err := aesECBEncryptBlock(hpKey, sample)
	if err != nil {
		return nil, err
	}

	// Make a mutable copy of the header for unmasking
	headerBuf := make([]byte, len(payload))
	copy(headerBuf, payload)

	// Unmask first byte (long header: mask with 0x0f)
	headerBuf[0] ^= mask[0] & 0x0f

	// Determine packet number length from unmasked first byte
	pnLength := int(headerBuf[0]&0x03) + 1

	// Unmask packet number bytes
	for i := 0; i < pnLength; i++ {
		headerBuf[pnOffset+i] ^= mask[1+i]
	}

	// Read packet number
	var pn uint64
	for i := 0; i < pnLength; i++ {
		pn = pn<<8 | uint64(headerBuf[pnOffset+i])
	}

	// Construct nonce: IV XOR packet_number (left-padded)
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	// Associated data = header bytes up to and including packet number
	ad := headerBuf[:pnOffset+pnLength]

	// Encrypted payload starts after the packet number
	encStart := pnOffset + pnLength
	// payloadLen includes the packet number bytes
	encLen := int(payloadLen) - pnLength
	if encLen <= 0 || encStart+encLen > len(payload) {
		return nil, nil
	}

	// Use original payload bytes for ciphertext (pn bytes already XORed in headerBuf, not in payload)
	// But we need to XOR the pn bytes in the ciphertext source too — actually the ciphertext
	// is after the pn bytes so we use original payload bytes for the ciphertext portion
	ciphertext := make([]byte, encLen)
	copy(ciphertext, payload[encStart:encStart+encLen])

	// Decrypt using AES-128-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}

	// Parse CRYPTO frames from plaintext
	fragments, err := parseCryptoFrames(plaintext)
	if err != nil {
		return nil, err
	}
	if len(fragments) == 0 {
		return nil, nil
	}

	// Reassemble CRYPTO frame data
	assembled := reassembleCryptoFrames(fragments)
	if len(assembled) == 0 {
		return nil, nil
	}

	// The reassembled data should be a TLS Handshake message.
	// Check for ClientHello (type 0x01)
	if assembled[0] != tlsHandshakeClientHello {
		return nil, nil
	}

	// Wrap in a fake TLS record header so ParseClientHello can process it.
	// TLS record: content_type(1) + version(2) + length(2) + handshake data
	tlsRecord := make([]byte, 5+len(assembled))
	tlsRecord[0] = tlsRecordTypeHandshake // 0x16
	tlsRecord[1] = 0x03
	tlsRecord[2] = 0x01
	tlsRecord[3] = byte(len(assembled) >> 8)
	tlsRecord[4] = byte(len(assembled))
	copy(tlsRecord[5:], assembled)

	ch, err := ParseClientHello(tlsRecord)
	if err != nil {
		return nil, err
	}
	if ch != nil {
		ch.IsQUIC = true
	}
	return ch, nil
}

// parseCryptoFrames extracts CRYPTO frame fragments from decrypted QUIC payload.
func parseCryptoFrames(data []byte) ([]cryptoFragment, error) {
	var fragments []cryptoFragment
	pos := 0

	for pos < len(data) {
		frameType := data[pos]

		if frameType == quicFramePadding {
			pos++
			continue
		}

		if frameType == quicFrameCrypto {
			pos++ // skip frame type

			// Offset (varint)
			offset, newPos, err := decodeVarint(data, pos)
			if err != nil {
				return fragments, err
			}
			pos = newPos

			// Length (varint)
			length, newPos, err := decodeVarint(data, pos)
			if err != nil {
				return fragments, err
			}
			pos = newPos

			if pos+int(length) > len(data) {
				return fragments, errors.New("CRYPTO frame truncated")
			}

			frag := cryptoFragment{
				offset: offset,
				data:   make([]byte, length),
			}
			copy(frag.data, data[pos:pos+int(length)])
			fragments = append(fragments, frag)
			pos += int(length)
			continue
		}

		// ACK frame (0x02, 0x03) — skip by parsing its structure
		if frameType == 0x02 || frameType == 0x03 {
			pos++
			// Largest Acknowledged (varint)
			_, newPos, err := decodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// ACK Delay (varint)
			_, newPos, err = decodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// ACK Range Count (varint)
			rangeCount, newPos, err := decodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// First ACK Range (varint)
			_, newPos, err = decodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// Additional ACK Ranges
			for i := uint64(0); i < rangeCount; i++ {
				// Gap (varint)
				_, newPos, err = decodeVarint(data, pos)
				if err != nil {
					return fragments, nil
				}
				pos = newPos
				// ACK Range (varint)
				_, newPos, err = decodeVarint(data, pos)
				if err != nil {
					return fragments, nil
				}
				pos = newPos
			}
			// ECN counts for type 0x03
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					_, newPos, err = decodeVarint(data, pos)
					if err != nil {
						return fragments, nil
					}
					pos = newPos
				}
			}
			continue
		}

		// Unknown frame type — we can't safely skip it, so stop parsing
		break
	}

	return fragments, nil
}

// reassembleCryptoFrames reassembles potentially fragmented CRYPTO frame data
// into a contiguous byte slice ordered by offset.
func reassembleCryptoFrames(fragments []cryptoFragment) []byte {
	if len(fragments) == 0 {
		return nil
	}

	// Sort by offset
	sort.Slice(fragments, func(i, j int) bool {
		return fragments[i].offset < fragments[j].offset
	})

	// Calculate total size
	var totalLen uint64
	for _, f := range fragments {
		end := f.offset + uint64(len(f.data))
		if end > totalLen {
			totalLen = end
		}
	}

	if totalLen == 0 || totalLen > 1<<20 { // sanity limit: 1MB
		return nil
	}

	result := make([]byte, totalLen)
	for _, f := range fragments {
		copy(result[f.offset:], f.data)
	}
	return result
}
