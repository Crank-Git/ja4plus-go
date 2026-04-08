package parser

// TCPStreamReassembler reassembles TCP streams using sequence numbers.
// Handles out-of-order segments, duplicates, and overlaps.
// Evicts oldest streams (LRU) when MaxStreams is exceeded.
type TCPStreamReassembler struct {
	streams    map[string]*tcpStream
	order      []string // LRU order, oldest first
	MaxStreams int
	MaxBytes   int
}

type tcpStream struct {
	segments []tcpSegment
	baseSeq  uint32
}

type tcpSegment struct {
	seq  uint32
	data []byte
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
		// Evict oldest if at capacity
		if len(r.streams) >= r.MaxStreams {
			oldest := r.order[0]
			delete(r.streams, oldest)
			r.order = r.order[1:]
		}
		stream = &tcpStream{baseSeq: seq}
		r.streams[key] = stream
		r.order = append(r.order, key)
	} else {
		// Move to end of LRU
		r.moveToEnd(key)
	}

	// Deduplicate: skip if exact same seq and length already exists
	for _, seg := range stream.segments {
		if seg.seq == seq && len(seg.data) == len(data) {
			return
		}
	}

	segData := make([]byte, len(data))
	copy(segData, data)
	stream.segments = append(stream.segments, tcpSegment{seq: seq, data: segData})
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
		if len(result) > r.MaxBytes {
			result = result[:r.MaxBytes]
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

// sortSegments sorts segments by sequence number using insertion sort (small N).
func sortSegments(segs []tcpSegment) {
	for i := 1; i < len(segs); i++ {
		key := segs[i]
		j := i - 1
		for j >= 0 && segs[j].seq > key.seq {
			segs[j+1] = segs[j]
			j--
		}
		segs[j+1] = key
	}
}
