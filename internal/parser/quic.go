package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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

// DecodeVarint decodes a QUIC variable-length integer from data at position pos.
// Returns the decoded value and the new position after the varint, or an error.
func DecodeVarint(data []byte, pos int) (uint64, int, error) {
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

// deriveInitialKeysForRole derives key, IV, and header protection key
// for either client or server role from the Destination Connection ID.
func deriveInitialKeysForRole(dcid []byte, version uint32, role string) (key, iv, hpKey []byte, err error) {
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

	// role_secret = HKDF-Expand-Label(initial_secret, "<role> in", "", 32)
	roleSecret, err := hkdfExpandLabel(initialSecret, role+" in", nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err = hkdfExpandLabel(roleSecret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = hkdfExpandLabel(roleSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}
	hpKey, err = hkdfExpandLabel(roleSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hpKey, nil
}

// DeriveInitialKeys derives the client key, IV, and header protection key
// from the Destination Connection ID for a QUIC Initial packet.
func DeriveInitialKeys(dcid []byte, version uint32) (key, iv, hpKey []byte, err error) {
	return deriveInitialKeysForRole(dcid, version, "client")
}

// DeriveServerInitialKeys derives the server key, IV, and header protection key
// from the Destination Connection ID of the client's Initial packet.
func DeriveServerInitialKeys(dcid []byte, version uint32) (key, iv, hpKey []byte, err error) {
	return deriveInitialKeysForRole(dcid, version, "server")
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

// CryptoFragment represents a CRYPTO frame fragment with offset and data.
type CryptoFragment struct {
	Offset uint64
	Data   []byte
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
	tokenLen, newPos, err := DecodeVarint(payload, pos)
	if err != nil {
		return nil, nil
	}
	pos = newPos
	if pos+int(tokenLen) > len(payload) {
		return nil, nil
	}
	pos += int(tokenLen)

	// Payload length (varint)
	payloadLen, newPos, err := DecodeVarint(payload, pos)
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
	key, iv, hpKey, err := DeriveInitialKeys(dcid, version)
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
	// But we need to XOR the pn bytes in the ciphertext source too -- actually the ciphertext
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
	fragments, err := ParseCryptoFrames(plaintext)
	if err != nil {
		return nil, err
	}
	if len(fragments) == 0 {
		return nil, nil
	}

	// Reassemble CRYPTO frame data
	assembled := ReassembleCryptoFrames(fragments)
	if len(assembled) == 0 {
		return nil, nil
	}

	// The reassembled data should be a TLS Handshake message.
	// Check for ClientHello (type 0x01)
	if assembled[0] != TLSHandshakeClientHello {
		return nil, nil
	}

	// Wrap in a fake TLS record header so ParseClientHello can process it.
	// TLS record: content_type(1) + version(2) + length(2) + handshake data
	tlsRecord := make([]byte, 5+len(assembled))
	tlsRecord[0] = TLSRecordTypeHandshake // 0x16
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

// DecryptQUICInitialCrypto decrypts a QUIC Initial packet and returns the raw
// CRYPTO frame fragments without attempting to parse a ClientHello.
// Returns the DCID for key correlation across packets.
// Returns nil, nil, nil if the payload is not a QUIC Initial.
func DecryptQUICInitialCrypto(payload []byte) (fragments []CryptoFragment, dcid []byte, err error) {
	if len(payload) < 5 {
		return nil, nil, nil
	}
	firstByte := payload[0]
	if firstByte&0x80 == 0 {
		return nil, nil, nil
	}
	version := binary.BigEndian.Uint32(payload[1:5])
	if version == 0 {
		return nil, nil, nil
	}
	var isInitial bool
	switch version {
	case quicV1:
		isInitial = (firstByte & 0x30) == 0x00
	case quicV2:
		isInitial = (firstByte & 0x30) == 0x10
	default:
		return nil, nil, nil
	}
	if !isInitial {
		return nil, nil, nil
	}
	pos := 5
	if pos >= len(payload) {
		return nil, nil, nil
	}
	dcidLen := int(payload[pos])
	pos++
	if pos+dcidLen > len(payload) {
		return nil, nil, nil
	}
	dcid = make([]byte, dcidLen)
	copy(dcid, payload[pos:pos+dcidLen])
	pos += dcidLen
	if pos >= len(payload) {
		return nil, nil, nil
	}
	scidLen := int(payload[pos])
	pos++
	if pos+scidLen > len(payload) {
		return nil, nil, nil
	}
	pos += scidLen
	tokenLen, newPos, e := DecodeVarint(payload, pos)
	if e != nil {
		return nil, nil, nil
	}
	pos = newPos
	if pos+int(tokenLen) > len(payload) {
		return nil, nil, nil
	}
	pos += int(tokenLen)
	payloadLen, newPos, e := DecodeVarint(payload, pos)
	if e != nil {
		return nil, nil, nil
	}
	pos = newPos
	pnOffset := pos
	if pnOffset+int(payloadLen) > len(payload) {
		return nil, nil, nil
	}
	key, iv, hpKey, e := DeriveInitialKeys(dcid, version)
	if e != nil {
		return nil, dcid, e
	}
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(payload) {
		return nil, dcid, nil
	}
	sample := payload[sampleOffset : sampleOffset+16]
	mask, e := aesECBEncryptBlock(hpKey, sample)
	if e != nil {
		return nil, dcid, e
	}
	headerBuf := make([]byte, len(payload))
	copy(headerBuf, payload)
	headerBuf[0] ^= mask[0] & 0x0f
	pnLength := int(headerBuf[0]&0x03) + 1
	for i := 0; i < pnLength; i++ {
		headerBuf[pnOffset+i] ^= mask[1+i]
	}
	var pn uint64
	for i := 0; i < pnLength; i++ {
		pn = pn<<8 | uint64(headerBuf[pnOffset+i])
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	ad := headerBuf[:pnOffset+pnLength]
	encStart := pnOffset + pnLength
	encLen := int(payloadLen) - pnLength
	if encLen <= 0 || encStart+encLen > len(payload) {
		return nil, dcid, nil
	}
	ciphertext := make([]byte, encLen)
	copy(ciphertext, payload[encStart:encStart+encLen])
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, dcid, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, dcid, e
	}
	plaintext, e := aead.Open(nil, nonce, ciphertext, ad)
	if e != nil {
		return nil, dcid, e
	}
	fragments, e = ParseCryptoFrames(plaintext)
	return fragments, dcid, e
}

// ClientHelloFromCryptoFragments reassembles CRYPTO fragments and parses a ClientHello.
// Returns nil, nil if the data is not a ClientHello.
func ClientHelloFromCryptoFragments(fragments []CryptoFragment) (*ClientHello, error) {
	assembled := ReassembleCryptoFrames(fragments)
	if len(assembled) == 0 {
		return nil, nil
	}
	if assembled[0] != TLSHandshakeClientHello {
		return nil, nil
	}
	tlsRecord := make([]byte, 5+len(assembled))
	tlsRecord[0] = TLSRecordTypeHandshake
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

// ParseCryptoFrames extracts CRYPTO frame fragments from decrypted QUIC payload.
func ParseCryptoFrames(data []byte) ([]CryptoFragment, error) {
	var fragments []CryptoFragment
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
			offset, newPos, err := DecodeVarint(data, pos)
			if err != nil {
				return fragments, err
			}
			pos = newPos

			// Length (varint)
			length, newPos, err := DecodeVarint(data, pos)
			if err != nil {
				return fragments, err
			}
			pos = newPos

			if pos+int(length) > len(data) {
				return fragments, errors.New("CRYPTO frame truncated")
			}

			frag := CryptoFragment{
				Offset: offset,
				Data:   make([]byte, length),
			}
			copy(frag.Data, data[pos:pos+int(length)])
			fragments = append(fragments, frag)
			pos += int(length)
			continue
		}

		// ACK frame (0x02, 0x03) -- skip by parsing its structure
		if frameType == 0x02 || frameType == 0x03 {
			pos++
			// Largest Acknowledged (varint)
			_, newPos, err := DecodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// ACK Delay (varint)
			_, newPos, err = DecodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// ACK Range Count (varint)
			rangeCount, newPos, err := DecodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// First ACK Range (varint)
			_, newPos, err = DecodeVarint(data, pos)
			if err != nil {
				return fragments, nil
			}
			pos = newPos
			// Additional ACK Ranges
			for i := uint64(0); i < rangeCount; i++ {
				// Gap (varint)
				_, newPos, err = DecodeVarint(data, pos)
				if err != nil {
					return fragments, nil
				}
				pos = newPos
				// ACK Range (varint)
				_, newPos, err = DecodeVarint(data, pos)
				if err != nil {
					return fragments, nil
				}
				pos = newPos
			}
			// ECN counts for type 0x03
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					_, newPos, err = DecodeVarint(data, pos)
					if err != nil {
						return fragments, nil
					}
					pos = newPos
				}
			}
			continue
		}

		// Unknown frame type -- we can't safely skip it, so stop parsing
		break
	}

	return fragments, nil
}

// ReassembleCryptoFrames reassembles potentially fragmented CRYPTO frame data
// into a contiguous byte slice ordered by offset.
func ReassembleCryptoFrames(fragments []CryptoFragment) []byte {
	if len(fragments) == 0 {
		return nil
	}

	// Sort by offset.
	// The sort is stable, because the offset alone is the key and two fragments can share
	// one offset. An unstable sort left such a pair in an order that the wire does not
	// state. The copy loop below then wrote the bytes of either fragment.
	sort.SliceStable(fragments, func(i, j int) bool {
		return fragments[i].Offset < fragments[j].Offset
	})

	// Calculate total size
	var totalLen uint64
	for _, f := range fragments {
		end := f.Offset + uint64(len(f.Data))
		if end > totalLen {
			totalLen = end
		}
	}

	if totalLen == 0 || totalLen > 1<<20 { // sanity limit: 1MB
		return nil
	}

	result := make([]byte, totalLen)
	for _, f := range fragments {
		copy(result[f.Offset:], f.Data)
	}
	return result
}

// ParseQUICServerInitial parses a QUIC server Initial packet and extracts the TLS ServerHello.
// The clientDCID is the Destination Connection ID from the client's Initial packet,
// needed to derive the server's decryption keys.
// Returns nil, nil if the payload is not a QUIC Initial packet.
func ParseQUICServerInitial(payload []byte, clientDCID []byte) (*ServerHello, error) {
	if len(payload) < 5 || len(clientDCID) == 0 {
		return nil, nil
	}

	firstByte := payload[0]
	if firstByte&0x80 == 0 {
		return nil, nil
	}

	version := binary.BigEndian.Uint32(payload[1:5])
	if version == 0 {
		return nil, nil
	}

	var isInitial bool
	switch version {
	case quicV1:
		isInitial = (firstByte & 0x30) == 0x00
	case quicV2:
		isInitial = (firstByte & 0x30) == 0x10
	default:
		return nil, nil
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

	// Token length (varint) + token — server Initials have zero-length token
	tokenLen, newPos, err := DecodeVarint(payload, pos)
	if err != nil {
		return nil, nil
	}
	pos = newPos
	if pos+int(tokenLen) > len(payload) {
		return nil, nil
	}
	pos += int(tokenLen)

	// Payload length (varint)
	payloadLen, newPos, err := DecodeVarint(payload, pos)
	if err != nil {
		return nil, nil
	}
	pos = newPos
	pnOffset := pos

	if pnOffset+int(payloadLen) > len(payload) {
		return nil, nil
	}

	// Derive server keys using the CLIENT's original DCID
	key, iv, hpKey, err := DeriveServerInitialKeys(clientDCID, version)
	if err != nil {
		return nil, err
	}

	// Remove header protection
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(payload) {
		return nil, nil
	}
	sample := payload[sampleOffset : sampleOffset+16]

	mask, err := aesECBEncryptBlock(hpKey, sample)
	if err != nil {
		return nil, err
	}

	headerBuf := make([]byte, len(payload))
	copy(headerBuf, payload)
	headerBuf[0] ^= mask[0] & 0x0f
	pnLength := int(headerBuf[0]&0x03) + 1

	for i := 0; i < pnLength; i++ {
		headerBuf[pnOffset+i] ^= mask[1+i]
	}

	var pn uint64
	for i := 0; i < pnLength; i++ {
		pn = pn<<8 | uint64(headerBuf[pnOffset+i])
	}

	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	ad := headerBuf[:pnOffset+pnLength]

	encStart := pnOffset + pnLength
	encLen := int(payloadLen) - pnLength
	if encLen <= 0 || encStart+encLen > len(payload) {
		return nil, nil
	}

	ciphertext := make([]byte, encLen)
	copy(ciphertext, payload[encStart:encStart+encLen])

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

	fragments, err := ParseCryptoFrames(plaintext)
	if err != nil {
		return nil, err
	}
	if len(fragments) == 0 {
		return nil, nil
	}

	assembled := ReassembleCryptoFrames(fragments)
	if len(assembled) == 0 {
		return nil, nil
	}

	// Check for ServerHello (type 0x02)
	if assembled[0] != TLSHandshakeServerHello {
		return nil, nil
	}

	// Wrap in fake TLS record for ParseServerHello
	tlsRecord := make([]byte, 5+len(assembled))
	tlsRecord[0] = TLSRecordTypeHandshake
	tlsRecord[1] = 0x03
	tlsRecord[2] = 0x01
	tlsRecord[3] = byte(len(assembled) >> 8)
	tlsRecord[4] = byte(len(assembled))
	copy(tlsRecord[5:], assembled)

	sh, err := ParseServerHello(tlsRecord)
	if err != nil {
		return nil, err
	}
	if sh != nil {
		sh.IsQUIC = true
	}
	return sh, nil
}

// ErrNoSecret reports that the caller supplied no secret for the connection.
var ErrNoSecret = errors.New("parser: the caller supplied no secret for the connection")

// The packet protection sizes of TLS_AES_128_GCM_SHA256, which RFC 9001 Section 5.1
// derives from the cipher suite.
const (
	// quicSecretLength is the byte count of a SHA-256 traffic secret.
	quicSecretLength = 32
	// quicKeyLength is the byte count of an AES-128 key.
	quicKeyLength = 16
	// quicIVLength is the byte count of the initialization vector.
	quicIVLength = 12
	// quicSampleLength is the byte count of the header protection sample.
	quicSampleLength = 16
	// quicTagLength is the byte count of the AEAD tag.
	quicTagLength = 16
)

// quicMaxConnectionIDLength is the largest Destination Connection ID that RFC 9000
// Section 17.2 allows.
const quicMaxConnectionIDLength = 20

// quicPacketTypeRetry names the long header packet type that carries no protection.
const quicPacketTypeRetry = 0x30

// DeriveQUICKeys returns the packet protection key, the initialization vector and the
// header protection key of one TLS traffic secret.
// RFC 9001 Section 5.1 states the three labels `quic key`, `quic iv` and `quic hp`.
// It returns an error for a secret of another length, because the library reads the
// SHA-256 key schedule of TLS_AES_128_GCM_SHA256 only.
func DeriveQUICKeys(secret []byte) (key, iv, hpKey []byte, err error) {
	if len(secret) == 0 {
		return nil, nil, nil, ErrNoSecret
	}

	if len(secret) != quicSecretLength {
		return nil, nil, nil, fmt.Errorf("parser: the secret holds %d bytes, and the library reads %d",
			len(secret), quicSecretLength)
	}

	key, err = hkdfExpandLabel(secret, "quic key", nil, quicKeyLength)
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err = hkdfExpandLabel(secret, "quic iv", nil, quicIVLength)
	if err != nil {
		return nil, nil, nil, err
	}

	hpKey, err = hkdfExpandLabel(secret, "quic hp", nil, quicKeyLength)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, hpKey, nil
}

// DecryptQUICPacketWithSecret returns the frame bytes of one QUIC packet, which the
// caller's traffic secret protects.
// The payload starts at the first byte of the packet, and a longer buffer is allowed,
// because one datagram carries more than one packet.
// connectionIDLength states the Destination Connection ID length of a short header
// packet. A long header packet carries its own lengths, so it ignores that argument.
// It returns ErrNoSecret when the caller supplies no secret.
// It returns a non-fatal error for a packet it cannot read, and it never panics.
func DecryptQUICPacketWithSecret(payload, secret []byte, connectionIDLength int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrNoSecret
	}

	pnOffset, end, headerMask, err := quicProtectedRange(payload, connectionIDLength)
	if err != nil {
		return nil, err
	}

	key, iv, hpKey, err := DeriveQUICKeys(secret)
	if err != nil {
		return nil, err
	}

	sampleOffset := pnOffset + 4
	if sampleOffset+quicSampleLength > end {
		return nil, fmt.Errorf("parser: the packet holds %d bytes, and the header protection sample needs %d",
			end, sampleOffset+quicSampleLength)
	}

	mask, err := aesECBEncryptBlock(hpKey, payload[sampleOffset:sampleOffset+quicSampleLength])
	if err != nil {
		return nil, err
	}

	header := make([]byte, end)
	copy(header, payload[:end])
	header[0] ^= mask[0] & headerMask

	packetNumberLength := int(header[0]&0x03) + 1
	if pnOffset+packetNumberLength > end {
		return nil, errors.New("parser: the packet number passes the packet")
	}

	var packetNumber uint64

	for i := range packetNumberLength {
		header[pnOffset+i] ^= mask[1+i]
		packetNumber = packetNumber<<8 | uint64(header[pnOffset+i])
	}

	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}

	start := pnOffset + packetNumberLength
	if end-start <= quicTagLength {
		return nil, errors.New("parser: the packet carries no protected frame")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, payload[start:end], header[:start])
	if err != nil {
		return nil, fmt.Errorf("parser: the secret does not open the packet: %w", err)
	}

	return plaintext, nil
}

// quicProtectedRange returns the packet number offset, the end of the packet and the
// first-byte mask of the header protection.
// RFC 9001 Section 5.4.1 masks four bits of the first byte of a long header packet, and
// five bits of the first byte of a short header packet.
func quicProtectedRange(payload []byte, connectionIDLength int) (pnOffset, end int, headerMask byte, err error) {
	if len(payload) < 1 {
		return 0, 0, 0, errors.New("parser: the packet holds no byte")
	}

	if payload[0]&0x80 == 0 {
		if connectionIDLength < 0 || connectionIDLength > quicMaxConnectionIDLength {
			return 0, 0, 0, fmt.Errorf("parser: the caller states the connection identifier length %d",
				connectionIDLength)
		}

		pnOffset = 1 + connectionIDLength
		if pnOffset >= len(payload) {
			return 0, 0, 0, errors.New("parser: the connection identifier passes the packet")
		}

		return pnOffset, len(payload), 0x1f, nil
	}

	if len(payload) < 5 {
		return 0, 0, 0, errors.New("parser: the long header holds no version")
	}

	version := binary.BigEndian.Uint32(payload[1:5])
	if version != quicV1 && version != quicV2 {
		return 0, 0, 0, fmt.Errorf("parser: the packet states the QUIC version %#08x", version)
	}

	if quicIsRetry(payload[0], version) {
		return 0, 0, 0, errors.New("parser: a Retry packet carries no protected frame")
	}

	pos := 5

	for range 2 {
		if pos >= len(payload) {
			return 0, 0, 0, errors.New("parser: the connection identifier length passes the packet")
		}

		length := int(payload[pos])
		if length > quicMaxConnectionIDLength {
			return 0, 0, 0, fmt.Errorf("parser: the packet states the connection identifier length %d", length)
		}

		pos += 1 + length
		if pos > len(payload) {
			return 0, 0, 0, errors.New("parser: the connection identifier passes the packet")
		}
	}

	// An Initial packet carries a token, and every other long header packet carries none.
	if quicIsInitial(payload[0], version) {
		tokenLength, next, e := DecodeVarint(payload, pos)
		if e != nil {
			return 0, 0, 0, fmt.Errorf("parser: the token length is unreadable: %w", e)
		}

		pos = next
		if tokenLength > uint64(len(payload)-pos) {
			return 0, 0, 0, errors.New("parser: the token passes the packet")
		}

		pos += int(tokenLength)
	}

	length, next, err := DecodeVarint(payload, pos)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("parser: the length is unreadable: %w", err)
	}

	pos = next
	if length > uint64(len(payload)-pos) {
		return 0, 0, 0, errors.New("parser: the length passes the packet")
	}

	return pos, pos + int(length), 0x0f, nil
}

// quicIsRetry reports whether the first byte names a Retry packet.
// RFC 9369 Section 3.2 states the type `0b00` for QUIC version 2, and RFC 9000
// Section 17.2 states the type `0b11` for QUIC version 1.
func quicIsRetry(firstByte byte, version uint32) bool {
	if version == quicV2 {
		return firstByte&0x30 == 0x00
	}

	return firstByte&0x30 == quicPacketTypeRetry
}

// quicIsInitial reports whether the first byte names an Initial packet.
// RFC 9369 Section 3.2 gives QUIC version 2 another type value for each packet type.
func quicIsInitial(firstByte byte, version uint32) bool {
	if version == quicV2 {
		return firstByte&0x30 == 0x10
	}

	return firstByte&0x30 == 0x00
}
