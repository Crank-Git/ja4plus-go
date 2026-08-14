package parser

import (
	"bytes"
	"slices"
	"testing"
)

func TestTCPStreamReassembler_Basic(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 100, []byte("Hello"))
	r.AddSegment("flow1", 105, []byte("World"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_OutOfOrder(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	// Add second segment first
	r.AddSegment("flow1", 105, []byte("World"))
	r.AddSegment("flow1", 100, []byte("Hello"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_Duplicate(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 100, []byte("Hello"))
	r.AddSegment("flow1", 100, []byte("Hello")) // duplicate
	r.AddSegment("flow1", 105, []byte("World"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_Overlap(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 100, []byte("HelloWo"))
	r.AddSegment("flow1", 105, []byte("World"))

	got := r.GetStream("flow1")
	want := []byte("HelloWorld")
	if !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

// equalSeqGroupSize is the segment count of each of the two groups that the tests below
// build. The two groups hold 26 segments over two sequence numbers.
//
// Go sorts 12 elements or fewer with an insertion sort, so a smaller total would reach no
// unstable path. A slice that holds one sequence number alone is already sorted, and Go
// detects that and moves nothing, so one group would also pin nothing. Two groups of 13
// reach the case that separates a stable sort from an unstable one.
const equalSeqGroupSize = 13

// addEqualSeqGroups adds 26 segments over the two sequence numbers 0 and 13.
//
// Segment i of a group carries i+1 copies of one letter, so every segment of a group holds
// a distinct length. The deduplication key is the sequence number and the length together,
// so the reassembler stores all 26 of them. The order argument gives the arrival order
// inside each group.
//
// The two groups arrive interleaved, which a reordered network delivers. An arrival order
// that already ascends by sequence number would pin nothing, because Go detects a sorted
// slice and moves no element.
func addEqualSeqGroups(r *TCPStreamReassembler, key string, order []int) {
	for _, i := range order {
		r.AddSegment(key, equalSeqGroupSize, bytes.Repeat([]byte{byte('n' + i)}, i+1))
		r.AddSegment(key, 0, bytes.Repeat([]byte{byte('a' + i)}, i+1))
	}
}

// ascendingLengths returns the arrival order that puts the shortest segment first.
func ascendingLengths() []int {
	order := make([]int, 0, equalSeqGroupSize)
	for i := range equalSeqGroupSize {
		order = append(order, i)
	}

	return order
}

// TestGetStreamAssemblesSegmentsOfOneSequenceNumberInArrivalOrder pins the order that
// `GetStream` gives the segments that carry one sequence number. Issue #596 replaces the
// insertion sort of `sortSegments`, and this test states what the replacement must keep.
//
// The deduplication key holds the sequence number and the length, so one stream legally
// holds two segments of one sequence number. `GetStream` trims each later segment against
// the run it already assembled, so the arrival order decides the assembled bytes. A sort
// that is not stable therefore moves a JA4H value and a JA4X value.
//
// The segments of each group arrive shortest first. The first segment of a group
// contributes its one byte, and every later segment of that group contributes its last byte
// alone. So the run spells the alphabet, and it spells the arrival order.
func TestGetStreamAssemblesSegmentsOfOneSequenceNumberInArrivalOrder(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)

	addEqualSeqGroups(r, "flow1", ascendingLengths())

	want := []byte("abcdefghijklmnopqrstuvwxyz")
	if got := r.GetStream("flow1"); !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

// TestGetStreamReadsTheArrivalOrderOfSegmentsThatShareOneSequenceNumber proves that the
// arrival order decides the assembled bytes. Issue #596 names the property.
//
// This test reverses the arrival order inside each group, and it expects a different run.
// The longest segment of a group arrives first and it covers every later segment of that
// group, so each later segment contributes nothing. A test that expected one run for both
// orders would accept an unstable sort.
func TestGetStreamReadsTheArrivalOrderOfSegmentsThatShareOneSequenceNumber(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)

	longestFirst := ascendingLengths()
	slices.Reverse(longestFirst)

	addEqualSeqGroups(r, "flow1", longestFirst)

	want := append(bytes.Repeat([]byte("m"), equalSeqGroupSize),
		bytes.Repeat([]byte("z"), equalSeqGroupSize)...)
	if got := r.GetStream("flow1"); !bytes.Equal(got, want) {
		t.Errorf("GetStream = %q, want %q", got, want)
	}
}

func TestTCPStreamReassembler_Eviction(t *testing.T) {
	r := NewTCPStreamReassembler(2, 4096)
	r.AddSegment("flow1", 0, []byte("aaa"))
	r.AddSegment("flow2", 0, []byte("bbb"))
	// Adding flow3 should evict flow1 (oldest)
	r.AddSegment("flow3", 0, []byte("ccc"))

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("expected flow1 to be evicted, got %q", got)
	}
	if got := r.GetStream("flow2"); !bytes.Equal(got, []byte("bbb")) {
		t.Errorf("flow2 = %q, want %q", got, "bbb")
	}
	if got := r.GetStream("flow3"); !bytes.Equal(got, []byte("ccc")) {
		t.Errorf("flow3 = %q, want %q", got, "ccc")
	}
}

func TestTCPStreamReassembler_MaxBytes(t *testing.T) {
	r := NewTCPStreamReassembler(10, 10)
	r.AddSegment("flow1", 0, []byte("12345678901234567890"))

	got := r.GetStream("flow1")
	if len(got) > 10 {
		t.Errorf("expected at most 10 bytes, got %d", len(got))
	}
}

func TestTCPStreamReassembler_RemoveStream(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 0, []byte("data"))
	r.RemoveStream("flow1")

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("expected nil after RemoveStream, got %q", got)
	}
}

func TestTCPStreamReassembler_EmptyData(t *testing.T) {
	r := NewTCPStreamReassembler(10, 4096)
	r.AddSegment("flow1", 0, []byte{})
	r.AddSegment("flow1", 0, nil)

	if got := r.GetStream("flow1"); got != nil {
		t.Errorf("expected nil for empty data, got %q", got)
	}
}
