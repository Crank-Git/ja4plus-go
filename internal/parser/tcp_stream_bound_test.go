package parser

import (
	"bytes"
	"testing"
)

// The tests below hold the stored-byte bound of one stream. Issue #567 records the defect:
// `AddSegment` appended every segment, and `MaxBytes` truncated the run that `GetStream`
// returns and never the stored segments. So one stream grew without a bound.
//
// The measurement of #567 reads `testdata/foxio/pcap/http2-with-cookies.pcapng`. The JA4H
// reassembler stored 1853328 bytes in 1336 segments on one stream of that capture, which is
// 1.77 times the 1048576 that `ja4h.go` passes as `MaxBytes`.

// storedBytesOfStream returns the bytes that the segments of one stream hold.
//
// It adds the lengths of the segment data rather than reading the storedBytes field. The
// memory is the quantity the bound must hold, and a counter that drifts from the segments
// bounds nothing. It also reports a counter that disagrees with the segments.
func storedBytesOfStream(t *testing.T, r *TCPStreamReassembler, key string) int {
	t.Helper()

	stream, held := r.streams[key]
	if !held {
		t.Fatalf("the reassembler holds no stream for key %q", key)
	}

	measured := 0
	for _, seg := range stream.segments {
		measured += len(seg.data)
	}

	if stream.storedBytes != measured {
		t.Errorf("the stream counts %d stored bytes, and its segments hold %d",
			stream.storedBytes, measured)
	}

	return measured
}

func TestAddSegmentStoresNoByteAfterOneStreamReachesTheByteBound(t *testing.T) {
	const bound = 1000

	r := NewTCPStreamReassembler(10, bound)

	// Each segment carries a distinct sequence number, so the deduplication never fires and
	// every refusal comes from the byte bound alone.
	for i := range 100 {
		r.AddSegment("flow1", uint32(i*100), bytes.Repeat([]byte("a"), 100))
	}

	// 100 segments of 100 bytes offer 10000 bytes, and the bound admits 1000 of them.
	if stored := storedBytesOfStream(t, r, "flow1"); stored > bound {
		t.Errorf("the stream stores %d bytes, and the bound is %d", stored, bound)
	}
}

func TestAddSegmentStoresTheSegmentThatReachesTheByteBoundExactly(t *testing.T) {
	const bound = 300

	r := NewTCPStreamReassembler(10, bound)

	// Three segments of 100 bytes reach the bound exactly, so the reassembler stores each one.
	for i := range 3 {
		r.AddSegment("flow1", uint32(i*100), bytes.Repeat([]byte("a"), 100))
	}

	if stored := storedBytesOfStream(t, r, "flow1"); stored != bound {
		t.Errorf("the stream stores %d bytes, and three segments of 100 bytes reach %d", stored, bound)
	}

	// The fourth segment finds the stream at the bound, so the reassembler refuses it.
	r.AddSegment("flow1", 300, bytes.Repeat([]byte("a"), 100))

	if stored := storedBytesOfStream(t, r, "flow1"); stored != bound {
		t.Errorf("the stream stores %d bytes after the fourth segment, and the bound is %d",
			stored, bound)
	}
}

// TestTheByteBoundKeepsTheRunThatGetStreamReturns separates the two shapes of the bound.
//
// The reassembler refuses a new segment, and it drops no stored segment. `GetStream` returns
// the contiguous run that starts at the lowest sequence number, so the low sequence numbers
// carry the TLS Certificate message and the HTTP request line. A bound that dropped the
// oldest segment would remove exactly that prefix, and the value would move.
func TestTheByteBoundKeepsTheRunThatGetStreamReturns(t *testing.T) {
	const bound = 100

	r := NewTCPStreamReassembler(10, bound)

	r.AddSegment("flow1", 0, bytes.Repeat([]byte("A"), 50))
	r.AddSegment("flow1", 50, bytes.Repeat([]byte("B"), 50))

	// The stream now holds the bound, so the reassembler refuses each later segment.
	for i := range 20 {
		r.AddSegment("flow1", uint32(100+i*50), bytes.Repeat([]byte("C"), 50))
	}

	want := append(bytes.Repeat([]byte("A"), 50), bytes.Repeat([]byte("B"), 50)...)
	if got := r.GetStream("flow1"); !bytes.Equal(got, want) {
		t.Errorf("GetStream returns %d bytes starting %q, and the bound keeps the first 100 bytes",
			len(got), firstBytes(got, 8))
	}
}

// TestAddSegmentStoresOneSegmentThatIsLargerThanTheByteBound holds the contract of
// `GetStream`, which returns the run up to the first gap or `MaxBytes`.
//
// The bound refuses a segment only after the stream reaches it. An empty stream is below the
// bound, so it admits one segment of any size and `GetStream` truncates the run as before.
func TestAddSegmentStoresOneSegmentThatIsLargerThanTheByteBound(t *testing.T) {
	r := NewTCPStreamReassembler(10, 10)

	r.AddSegment("flow1", 0, []byte("12345678901234567890"))

	if got := r.GetStream("flow1"); len(got) != 10 {
		t.Errorf("GetStream returns %d bytes, and MaxBytes truncates the run to 10", len(got))
	}
}

// TestRemoveStreamReturnsTheByteBoundToOneStream holds the removal path of the bound.
// `ja4h.go` removes a stream after each value, so the next request of that connection must
// reach a stream that stores bytes again.
func TestRemoveStreamReturnsTheByteBoundToOneStream(t *testing.T) {
	const bound = 100

	r := NewTCPStreamReassembler(10, bound)

	r.AddSegment("flow1", 0, bytes.Repeat([]byte("A"), 100))
	r.RemoveStream("flow1")
	r.AddSegment("flow1", 200, bytes.Repeat([]byte("B"), 50))

	if stored := storedBytesOfStream(t, r, "flow1"); stored != 50 {
		t.Errorf("the stream stores %d bytes after the removal, and the segment carries 50", stored)
	}
}

// TestAddSegmentStoresNoSegmentWhenTheByteBoundIsZero holds the bound of 0.
// An empty stream already reaches a bound of 0, so the reassembler stores no segment.
func TestAddSegmentStoresNoSegmentWhenTheByteBoundIsZero(t *testing.T) {
	r := NewTCPStreamReassembler(10, 0)

	r.AddSegment("flow1", 0, []byte("hello"))

	if stored := storedBytesOfStream(t, r, "flow1"); stored != 0 {
		t.Errorf("the stream stores %d bytes, and the bound is 0", stored)
	}

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("GetStream returns %q, and a bound of 0 stores no byte", got)
	}
}

// TestGetStreamClampsAByteLimitThatFallsBelowZeroAfterOneStore holds the clamp of
// `GetStream`, which the closure of F-22-8 added.
//
// `TestF22_8_GetStreamReturnsNoByteWhenTheByteLimitIsBelowZero` in `audit_parser_test.go`
// built a reassembler with a limit below 0 and added one segment. The byte bound now refuses
// that segment, so `GetStream` returns at its empty-segment exit and it never reaches the
// slice expression that F-22-8 closed. That test still holds its assertion, and it no longer
// reads the clamp.
//
// This test reaches the clamp with a stored segment. `MaxBytes` is an exported field, so a
// caller lowers it after the reassembler stores a segment. A `GetStream` that read the
// negative value would panic at `result[:maxBytes]`.
func TestGetStreamClampsAByteLimitThatFallsBelowZeroAfterOneStore(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)

	r.AddSegment("flow1", 1, []byte("hello"))

	if stored := storedBytesOfStream(t, r, "flow1"); stored != 5 {
		t.Fatalf("the stream stores %d bytes, and the segment carries 5", stored)
	}

	r.MaxBytes = -1

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("GetStream returns %q, and a byte limit below 0 holds no byte", got)
	}
}

// The tests below hold the segment count bound of one stream. The maintainer ruled it on
// 2026-08-14, and issue #596 holds the ruling and the reversal path.
//
// The byte bound of #567 bounds the bytes and it does not bound the count. A sender of
// one-byte segments therefore reaches 1048576 segments inside a byte bound of 1048576, and
// the deduplication index of #596 costs 53.3 bytes for each stored segment.
//
// The Python port ships the rule and the value at `ja4plus/utils/tcp_stream.py:45` of tag
// v1.1.0. No vector reaches the bound: a conformance run on 2026-08-14 read 703 stream keys
// and the largest held 788 segments.

// segmentCountOfStream returns the segments that one stream holds.
func segmentCountOfStream(t *testing.T, r *TCPStreamReassembler, key string) int {
	t.Helper()

	stream, held := r.streams[key]
	if !held {
		t.Fatalf("the reassembler holds no stream for key %q", key)
	}

	return len(stream.segments)
}

// TestNewTCPStreamReassemblerSetsTheDefaultSegmentBound holds the default that the
// constructor states. `ja4h.go` and `ja4x.go` each build a reassembler through it, so the
// default is the bound that the library runs with.
func TestNewTCPStreamReassemblerSetsTheDefaultSegmentBound(t *testing.T) {
	r := NewTCPStreamReassembler(10, 1048576)

	if r.MaxSegments != DefaultMaxSegments {
		t.Errorf("the constructor sets MaxSegments to %d, and the default is %d",
			r.MaxSegments, DefaultMaxSegments)
	}

	if DefaultMaxSegments != 4096 {
		t.Errorf("DefaultMaxSegments is %d, and the ruling of #596 states 4096",
			DefaultMaxSegments)
	}
}

// TestAddSegmentStoresNoSegmentAfterOneStreamReachesTheSegmentBound holds the bound against
// the sender that earned it. One byte in each segment reaches the segment bound long before
// the byte bound, which is the case that #596 measured.
func TestAddSegmentStoresNoSegmentAfterOneStreamReachesTheSegmentBound(t *testing.T) {
	// The byte bound of the production reassembler. A stream of one-byte segments stores
	// 4096 bytes at this bound, which is 0.4 percent of it, so the byte bound refuses
	// nothing here.
	r := NewTCPStreamReassembler(10, 1048576)

	// The offer exceeds the bound, so the reassembler refuses the last 904 segments.
	for i := range DefaultMaxSegments + 904 {
		r.AddSegment("flow1", uint32(i), []byte("a"))
	}

	if stored := segmentCountOfStream(t, r, "flow1"); stored != DefaultMaxSegments {
		t.Errorf("the stream stores %d segments, and the bound is %d",
			stored, DefaultMaxSegments)
	}

	if stored := storedBytesOfStream(t, r, "flow1"); stored != DefaultMaxSegments {
		t.Errorf("the stream stores %d bytes, and 4096 segments of one byte hold %d",
			stored, DefaultMaxSegments)
	}
}

// TestTheSegmentBoundRefusesWhileTheByteBoundAdmits separates the two bounds in the
// direction the ruling names. The stream reaches the segment bound with 4096 stored bytes,
// and the byte bound admits 1048576, so the byte bound refuses nothing.
func TestTheSegmentBoundRefusesWhileTheByteBoundAdmits(t *testing.T) {
	const byteBound = 1048576

	r := NewTCPStreamReassembler(10, byteBound)
	r.MaxSegments = 100

	for i := range 500 {
		r.AddSegment("flow1", uint32(i), []byte("a"))
	}

	if stored := segmentCountOfStream(t, r, "flow1"); stored != 100 {
		t.Errorf("the stream stores %d segments, and the segment bound is 100", stored)
	}

	// The stream sits far below the byte bound, so the segment bound alone refused.
	if stored := storedBytesOfStream(t, r, "flow1"); stored >= byteBound {
		t.Errorf("the stream stores %d bytes, and the byte bound of %d must refuse nothing here",
			stored, byteBound)
	}
}

// TestTheByteBoundRefusesWhileTheSegmentBoundAdmits separates the two bounds in the other
// direction. The stream reaches the byte bound with 10 stored segments, and the segment
// bound admits 4096, so the segment bound refuses nothing.
func TestTheByteBoundRefusesWhileTheSegmentBoundAdmits(t *testing.T) {
	const byteBound = 1000

	r := NewTCPStreamReassembler(10, byteBound)

	// Each segment carries 100 bytes, so 10 of them reach the byte bound.
	for i := range 50 {
		r.AddSegment("flow1", uint32(i*100), bytes.Repeat([]byte("a"), 100))
	}

	if stored := storedBytesOfStream(t, r, "flow1"); stored != byteBound {
		t.Errorf("the stream stores %d bytes, and the byte bound is %d", stored, byteBound)
	}

	// The stream sits far below the segment bound, so the byte bound alone refused.
	if stored := segmentCountOfStream(t, r, "flow1"); stored != 10 {
		t.Errorf("the stream stores %d segments, and 10 segments of 100 bytes reach the byte bound",
			stored)
	}
}

// TestAddSegmentStoresNoSegmentWhenTheSegmentBoundIsZero holds the bound of 0. An empty
// stream already reaches it, so the reassembler stores no segment. The byte bound of 0
// reads the same way.
func TestAddSegmentStoresNoSegmentWhenTheSegmentBoundIsZero(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.MaxSegments = 0

	r.AddSegment("flow1", 0, []byte("hello"))

	if stored := segmentCountOfStream(t, r, "flow1"); stored != 0 {
		t.Errorf("the stream stores %d segments, and the segment bound is 0", stored)
	}

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("GetStream returns %q, and a segment bound of 0 stores no segment", got)
	}
}

// TestAddSegmentStoresNoSegmentWhenTheSegmentBoundFallsBelowZero holds the clamp. A
// segment limit below 0 holds no segment, and `storedSegmentBound` states that rule.
// MaxSegments is an exported field, so a caller states a negative value.
func TestAddSegmentStoresNoSegmentWhenTheSegmentBoundFallsBelowZero(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.MaxSegments = -1

	r.AddSegment("flow1", 0, []byte("hello"))

	if stored := segmentCountOfStream(t, r, "flow1"); stored != 0 {
		t.Errorf("the stream stores %d segments, and a segment limit below 0 holds none", stored)
	}
}

// TestRemoveStreamReturnsTheSegmentBoundToOneStream holds the removal path of the bound.
// `ja4h.go` removes a stream after each value, so the next request of that connection must
// reach a stream that stores segments again. A refused segment leaves no trace.
func TestRemoveStreamReturnsTheSegmentBoundToOneStream(t *testing.T) {
	r := NewTCPStreamReassembler(10, 1048576)
	r.MaxSegments = 4

	for i := range 10 {
		r.AddSegment("flow1", uint32(i), []byte("a"))
	}

	if stored := segmentCountOfStream(t, r, "flow1"); stored != 4 {
		t.Fatalf("the stream stores %d segments, and the segment bound is 4", stored)
	}

	r.RemoveStream("flow1")
	r.AddSegment("flow1", 100, []byte("b"))

	if stored := segmentCountOfStream(t, r, "flow1"); stored != 1 {
		t.Errorf("the stream stores %d segments after the removal, and the call added one",
			stored)
	}
}

// firstBytes returns the first n bytes, so a failure message names a short prefix.
func firstBytes(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}

	return data[:n]
}
