package ja4plus

import (
	"encoding/binary"
	"testing"
)

func TestDecodeVarint_1Byte(t *testing.T) {
	// 1-byte encoding: prefix 00, value = 37
	data := []byte{37}
	val, pos, err := decodeVarint(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 37 {
		t.Errorf("value = %d, want 37", val)
	}
	if pos != 1 {
		t.Errorf("pos = %d, want 1", pos)
	}
}

func TestDecodeVarint_2Byte(t *testing.T) {
	// 2-byte encoding: prefix 01, value = 15293
	// 0x40 | (15293 >> 8) = 0x40 | 0x3b = 0x7b, low byte = 0xbd
	data := []byte{0x7b, 0xbd}
	val, pos, err := decodeVarint(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 15293 {
		t.Errorf("value = %d, want 15293", val)
	}
	if pos != 2 {
		t.Errorf("pos = %d, want 2", pos)
	}
}

func TestDecodeVarint_4Byte(t *testing.T) {
	// 4-byte encoding: prefix 10, value = 494878333
	// 0x80 | (494878333 >> 24) = 0x80 | 0x1d = 0x9d
	// remaining: 0x7f, 0x3e, 0x7d
	data := []byte{0x9d, 0x7f, 0x3e, 0x7d}
	val, pos, err := decodeVarint(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 494878333 {
		t.Errorf("value = %d, want 494878333", val)
	}
	if pos != 4 {
		t.Errorf("pos = %d, want 4", pos)
	}
}

func TestDecodeVarint_8Byte(t *testing.T) {
	// 8-byte encoding: prefix 11, value = 151288809941952652
	// From RFC 9000 Appendix A: 0xc2197c5eff14e88c
	data := []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}
	val, pos, err := decodeVarint(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 151288809941952652 {
		t.Errorf("value = %d, want 151288809941952652", val)
	}
	if pos != 8 {
		t.Errorf("pos = %d, want 8", pos)
	}
}

func TestDecodeVarint_Zero(t *testing.T) {
	data := []byte{0x00}
	val, pos, err := decodeVarint(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 0 {
		t.Errorf("value = %d, want 0", val)
	}
	if pos != 1 {
		t.Errorf("pos = %d, want 1", pos)
	}
}

func TestDecodeVarint_EmptyData(t *testing.T) {
	_, _, err := decodeVarint([]byte{}, 0)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestDecodeVarint_Truncated2Byte(t *testing.T) {
	// 2-byte prefix but only 1 byte available
	data := []byte{0x40}
	_, _, err := decodeVarint(data, 0)
	if err == nil {
		t.Error("expected error for truncated 2-byte varint")
	}
}

func TestDecodeVarint_WithOffset(t *testing.T) {
	data := []byte{0xff, 0xff, 0x05} // varint at position 2
	val, pos, err := decodeVarint(data, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 5 {
		t.Errorf("value = %d, want 5", val)
	}
	if pos != 3 {
		t.Errorf("pos = %d, want 3", pos)
	}
}

func TestDeriveInitialKeys_V1(t *testing.T) {
	// RFC 9001 Appendix A test vector
	// DCID = 0x8394c8f03e515708
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

	key, iv, hpKey, err := deriveInitialKeys(dcid, quicV1)
	if err != nil {
		t.Fatalf("deriveInitialKeys error: %v", err)
	}

	// Expected client key from RFC 9001 Appendix A.1
	expectedKey := []byte{
		0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
		0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
	}
	expectedIV := []byte{
		0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
		0x46, 0xfb, 0x25, 0x5c,
	}
	expectedHP := []byte{
		0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
		0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
	}

	if !bytesEqual(key, expectedKey) {
		t.Errorf("key mismatch:\n  got  %x\n  want %x", key, expectedKey)
	}
	if !bytesEqual(iv, expectedIV) {
		t.Errorf("iv mismatch:\n  got  %x\n  want %x", iv, expectedIV)
	}
	if !bytesEqual(hpKey, expectedHP) {
		t.Errorf("hp key mismatch:\n  got  %x\n  want %x", hpKey, expectedHP)
	}
}

func TestDeriveInitialKeys_UnsupportedVersion(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	_, _, _, err := deriveInitialKeys(dcid, 0x12345678)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestParseQUICInitial_NonQUIC(t *testing.T) {
	// Random UDP payload — not a QUIC packet
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ch, err := ParseQUICInitial(payload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for non-QUIC payload")
	}
}

func TestParseQUICInitial_ShortPacket(t *testing.T) {
	// Too short for any QUIC header
	payload := []byte{0xc0, 0x00}
	ch, err := ParseQUICInitial(payload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for short packet")
	}
}

func TestParseQUICInitial_VersionNegotiation(t *testing.T) {
	// Long header form but version = 0x00000000 (version negotiation)
	payload := make([]byte, 20)
	payload[0] = 0xc0 // long header
	// version bytes 1-4 already zero
	ch, err := ParseQUICInitial(payload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for version negotiation")
	}
}

func TestParseQUICInitial_ShortHeader(t *testing.T) {
	// Short header form (bit 7 clear)
	payload := make([]byte, 20)
	payload[0] = 0x40 // short header
	ch, err := ParseQUICInitial(payload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for short header")
	}
}

func TestParseQUICInitial_NotInitialType(t *testing.T) {
	// Long header, QUIC v1, but type = Handshake (0x02 in bits 4-5 = 0x20)
	payload := make([]byte, 30)
	payload[0] = 0xc0 | 0x20 // long header + Handshake type
	binary.BigEndian.PutUint32(payload[1:5], quicV1)
	payload[5] = 4  // DCID length
	payload[10] = 0 // SCID length
	ch, err := ParseQUICInitial(payload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for non-Initial packet type")
	}
}

func TestParseQUICInitial_UnsupportedVersion(t *testing.T) {
	payload := make([]byte, 30)
	payload[0] = 0xc0
	binary.BigEndian.PutUint32(payload[1:5], 0xff000020) // draft version
	ch, err := ParseQUICInitial(payload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ch != nil {
		t.Error("expected nil for unsupported QUIC version")
	}
}

func TestParseCryptoFrames_PaddingOnly(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00}
	frags, err := parseCryptoFrames(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frags) != 0 {
		t.Errorf("expected 0 fragments, got %d", len(frags))
	}
}

func TestParseCryptoFrames_SingleCrypto(t *testing.T) {
	// CRYPTO frame: type=0x06, offset=0x00, length=0x03, data="abc"
	data := []byte{0x06, 0x00, 0x03, 'a', 'b', 'c'}
	frags, err := parseCryptoFrames(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
	if frags[0].offset != 0 {
		t.Errorf("offset = %d, want 0", frags[0].offset)
	}
	if string(frags[0].data) != "abc" {
		t.Errorf("data = %q, want %q", frags[0].data, "abc")
	}
}

func TestReassembleCryptoFrames(t *testing.T) {
	frags := []cryptoFragment{
		{offset: 3, data: []byte("def")},
		{offset: 0, data: []byte("abc")},
	}
	result := reassembleCryptoFrames(frags)
	if string(result) != "abcdef" {
		t.Errorf("reassembled = %q, want %q", result, "abcdef")
	}
}

func TestReassembleCryptoFrames_Empty(t *testing.T) {
	result := reassembleCryptoFrames(nil)
	if result != nil {
		t.Errorf("expected nil for empty fragments")
	}
}

func TestHkdfExpandLabel(t *testing.T) {
	// Verify hkdfExpandLabel produces non-nil output of correct length
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	out, err := hkdfExpandLabel(secret, "test label", nil, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 16 {
		t.Errorf("output length = %d, want 16", len(out))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
