package parser

import (
	"cmp"
	"slices"
)

// TCPStreamReassembler reassembles TCP streams using sequence numbers.
// Handles out-of-order segments, duplicates, and overlaps.
// Evicts oldest streams (LRU) when MaxStreams is exceeded.
//
// One TCPStreamReassembler serves one goroutine. It holds state that no lock guards, and
// `.claude/rules/concurrency.md` states that contract.
type TCPStreamReassembler struct {
	streams map[string]*tcpStream
	order   []string // LRU order, oldest first
	// MaxStreams bounds the count of the streams the table holds.
	MaxStreams int
	// MaxBytes bounds one stream twice. It bounds the bytes that the stream stores, and it
	// bounds the run that GetStream returns. Issue #567 added the first of the two, because
	// a stream that stored every segment grew without a bound.
	MaxBytes int
}

type tcpStream struct {
	segments []tcpSegment
	baseSeq  uint32
	// storedBytes counts the bytes of every segment this stream holds.
	storedBytes int
	// stored indexes the segments that this stream holds, so the deduplication reads one
	// map lookup rather than a scan of every segment. Issue #596 measured the scan as a
	// quadratic path: a stream of one byte per segment reaches 1048576 segments inside the
	// byte bound, and the scan then costs the square of that count.
	//
	// The index is a second view of `segments`, and it never replaces the slice. `GetStream`
	// walks the slice, because the assembled run reads the arrival order.
	//
	// The index lives in the stream rather than in the reassembler, so the removal of a
	// stream releases it. `RemoveStream` and the eviction each delete the stream from the
	// table, and no second release path can fall out of step with the first.
	stored map[tcpSegmentKey]struct{}
}

type tcpSegment struct {
	seq  uint32
	data []byte
}

// tcpSegmentKey identifies one stored segment for the deduplication.
//
// The key holds the length beside the sequence number, because one stream legally holds two
// segments of one sequence number. A retransmission that coalesces produces one, and a
// re-segmentation produces one. A key of the sequence number alone would refuse the second
// of them and move a JA4H value and a JA4X value.
type tcpSegmentKey struct {
	seq    uint32
	length int
}

// NewTCPStreamReassembler creates a reassembler with the given limits.
func NewTCPStreamReassembler(maxStreams, maxBytes int) *TCPStreamReassembler {
	return &TCPStreamReassembler{
		streams:    make(map[string]*tcpStream),
		MaxStreams: maxStreams,
		MaxBytes:   maxBytes,
	}
}

// AddSegment adds a TCP segment to a stream identified by key.
func (r *TCPStreamReassembler) AddSegment(key string, seq uint32, data []byte) {
	if len(data) == 0 {
		return
	}

	stream, exists := r.streams[key]
	if !exists {
		// Evict oldest if at capacity.
		// A stream limit of 0 makes the comparison true before the order slice holds a
		// key, so the eviction needs the second condition.
		if len(r.streams) >= r.MaxStreams && len(r.order) > 0 {
			oldest := r.order[0]
			delete(r.streams, oldest)
			r.order = r.order[1:]
		}
		stream = &tcpStream{
			baseSeq: seq,
			stored:  make(map[tcpSegmentKey]struct{}),
		}
		r.streams[key] = stream
		r.order = append(r.order, key)
	} else {
		// Move to end of LRU
		r.moveToEnd(key)
	}

	// Deduplicate: skip if exact same seq and length already exists.
	// The index holds one key for each stored segment, so this lookup reads the same
	// condition that the earlier scan of every segment read.
	segKey := tcpSegmentKey{seq: seq, length: len(data)}
	if _, held := stream.stored[segKey]; held {
		return
	}

	// A stream that reached the byte bound stores no further segment. Every packet is
	// untrusted input, and a sender that never completes a request otherwise grows one
	// stream without a bound. Issue #567 measured 1853328 stored bytes on one stream of
	// `testdata/foxio/pcap/http2-with-cookies.pcapng`, against the 1048576 that `ja4h.go`
	// passes as MaxBytes.
	//
	// The reassembler refuses the new segment, and it drops no stored segment. `GetStream`
	// reads the contiguous run from the lowest sequence number, so the stored prefix carries
	// the TLS Certificate message and the HTTP request line. A bound that dropped the oldest
	// segment would remove that prefix and move a fingerprint value.
	//
	// The condition reads the stored bytes against the bound, and it never adds the length of
	// the segment this call carries. A stream below the bound admits one segment of any size,
	// and `GetStream` then truncates the run at MaxBytes as it always has.
	//
	// A bound of 0 admits no segment, because an empty stream already reaches it. A bound
	// below 0 reads the same way, and `storedByteBound` states that rule.
	if stream.storedBytes >= r.storedByteBound() {
		return
	}

	segData := make([]byte, len(data))
	copy(segData, data)
	stream.segments = append(stream.segments, tcpSegment{seq: seq, data: segData})
	stream.storedBytes += len(data)

	// The index gains a key only where the slice gains a segment. The byte bound above
	// refuses a segment that the stream never stores, and the earlier scan read the stored
	// segments alone, so a key written before the bound would deduplicate a segment that
	// the stream does not hold.
	stream.stored[segKey] = struct{}{}
}

// storedByteBound returns the bytes that one stream stores at most.
// A byte limit below 0 holds no byte, and `GetStream` reads the same rule.
func (r *TCPStreamReassembler) storedByteBound() int {
	if r.MaxBytes < 0 {
		return 0
	}

	return r.MaxBytes
}

// GetStream reassembles and returns contiguous data from the lowest sequence number.
// Returns data up to the first gap or MaxBytes, whichever comes first.
func (r *TCPStreamReassembler) GetStream(key string) []byte {
	stream, exists := r.streams[key]
	if !exists || len(stream.segments) == 0 {
		return nil
	}

	// Sort by sequence number
	sorted := make([]tcpSegment, len(stream.segments))
	copy(sorted, stream.segments)
	sortSegments(sorted)

	// A byte limit below 0 holds no byte, so the bound is 0 and not the negative value.
	// A negative bound makes the slice expression below panic.
	maxBytes := r.MaxBytes
	if maxBytes < 0 {
		maxBytes = 0
	}

	result := make([]byte, 0, 4096)
	nextSeq := sorted[0].seq

	for _, seg := range sorted {
		if seg.seq <= nextSeq {
			overlap := int(nextSeq - seg.seq)
			if overlap < len(seg.data) {
				result = append(result, seg.data[overlap:]...)
				nextSeq = seg.seq + uint32(len(seg.data))
			}
		} else {
			break // gap
		}
		if len(result) > maxBytes {
			result = result[:maxBytes]
			break
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// RemoveStream removes a stream from tracking.
func (r *TCPStreamReassembler) RemoveStream(key string) {
	delete(r.streams, key)
	for i, k := range r.order {
		if k == key {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func (r *TCPStreamReassembler) moveToEnd(key string) {
	for i, k := range r.order {
		if k == key {
			r.order = append(r.order[:i], r.order[i+1:]...)
			r.order = append(r.order, key)
			return
		}
	}
}

// sortSegments sorts segments by sequence number, and it keeps the arrival order of two
// segments that carry one sequence number.
//
// The sort is stable, and that is a correctness requirement rather than a preference.
// `GetStream` trims each later segment against the run it already assembled, so two
// segments of one sequence number assemble to different bytes in the two orders.
// `ja4h.go` and `ja4x.go` read those bytes, so an unstable sort moves a fingerprint value.
// `slices.SortFunc` is the unstable call, and issue #596 measured the moved bytes.
//
// The earlier insertion sort was stable, because it compared with a strict `>`. It cost the
// square of the segment count on a reversed arrival order, and issue #596 records that
// measurement.
func sortSegments(segs []tcpSegment) {
	slices.SortStableFunc(segs, func(a, b tcpSegment) int {
		return cmp.Compare(a.seq, b.seq)
	})
}
