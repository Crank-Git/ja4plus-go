package parser

import (
	"bytes"
	"testing"
)

// craftedCryptoDatagram returns the decrypted payload of one QUIC Initial packet that
// carries one CRYPTO frame at the named offset.
// The frame holds one byte of data, and padding frames fill the payload to 100 bytes.
// #168 names this datagram: it costs the sender about 100 bytes, and
// ReassembleCryptoFrames allocated 1048576 bytes for it before the bound.
func craftedCryptoDatagram(offset uint64) []byte {
	payload := []byte{quicFrameCrypto}
	payload = append(payload, encodeVarint4(offset)...)
	payload = append(payload, 0x01, 0xaa)
	for len(payload) < 100 {
		payload = append(payload, quicFramePadding)
	}
	return payload
}

// encodeVarint4 returns the 4-byte QUIC variable-length integer form of the value.
// RFC 9000 Section 16 gives that form a 2-bit prefix of 0b10, and it reaches 1073741823.
func encodeVarint4(v uint64) []byte {
	return []byte{
		0x80 | byte(v>>24&0x3f),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

// TestReassembleCryptoFramesBoundsTheBufferOfACraftedOffset holds FR-gaps-30.
// A datagram of 100 bytes names an offset of 1048575, and ReassembleCryptoFrames
// allocated one byte of buffer for each byte up to that offset. #168 measured the
// amplification at about 10000 to 1.
func TestReassembleCryptoFramesBoundsTheBufferOfACraftedOffset(t *testing.T) {
	const craftedOffset = 1048575

	datagram := craftedCryptoDatagram(craftedOffset)
	if len(datagram) != 100 {
		t.Fatalf("the crafted datagram holds %d bytes, and the test builds 100", len(datagram))
	}

	fragments, err := ParseCryptoFrames(datagram)
	if err != nil {
		t.Fatalf("ParseCryptoFrames returns the error %v for the crafted datagram", err)
	}
	if len(fragments) != 1 {
		t.Fatalf("ParseCryptoFrames returns %d fragments, and the datagram holds 1", len(fragments))
	}
	if fragments[0].Offset != craftedOffset {
		t.Fatalf("ParseCryptoFrames reads the offset %d, and the datagram names %d",
			fragments[0].Offset, craftedOffset)
	}

	assembled := ReassembleCryptoFrames(fragments)
	if len(assembled) > MaxCryptoBufferBytes {
		t.Errorf("ReassembleCryptoFrames allocates %d bytes, and the bound is %d",
			len(assembled), MaxCryptoBufferBytes)
	}
}

// TestReassembleCryptoFramesDropsTheFragmentThatPassesTheBound holds FR-gaps-30.
// The port drops one fragment and keeps the rest at
// `ja4plus/utils/quic_utils.py:322`, so this library drops one fragment too.
func TestReassembleCryptoFramesDropsTheFragmentThatPassesTheBound(t *testing.T) {
	fragments := []CryptoFragment{
		{Offset: 0, Data: []byte("abc")},
		{Offset: MaxCryptoBufferBytes, Data: []byte{0xaa}},
	}

	assembled := ReassembleCryptoFrames(fragments)
	if !bytes.Equal(assembled, []byte("abc")) {
		t.Errorf("ReassembleCryptoFrames returns %q, and the fragment inside the bound holds %q",
			assembled, "abc")
	}
}

// TestReassembleCryptoFramesDropsTheFragmentThatOverflowsTheOffsetSum holds FR-gaps-30.
// RFC 9000 Section 16 lets an offset reach 4611686018427387903, so the sum of the offset
// and the length wraps in a uint64 addition. The reader tests the offset alone first.
func TestReassembleCryptoFramesDropsTheFragmentThatOverflowsTheOffsetSum(t *testing.T) {
	fragments := []CryptoFragment{
		{Offset: 1<<64 - 1, Data: []byte{0xaa, 0xbb}},
	}

	if assembled := ReassembleCryptoFrames(fragments); assembled != nil {
		t.Errorf("ReassembleCryptoFrames returns %d bytes, and every fragment passes the bound",
			len(assembled))
	}
}
