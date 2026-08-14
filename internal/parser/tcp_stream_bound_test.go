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

// firstBytes returns the first n bytes, so a failure message names a short prefix.
func firstBytes(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}

	return data[:n]
}
