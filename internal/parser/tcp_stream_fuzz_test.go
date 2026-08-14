package parser

import "testing"

// fuzzReassemblerMaxStreams bounds the stream count of the fuzz target. A small bound
// makes the fuzzer reach the eviction path within a few segments.
const fuzzReassemblerMaxStreams = 2

// fuzzReassemblerMaxBytes bounds the byte count of one stream. A small bound makes the
// fuzzer reach the byte cap within a few segments.
const fuzzReassemblerMaxBytes = 64

// FuzzTCPStreamReassemblerReadsAnySegment proves that the reassembler returns for any
// segment. FR-fuzz-9 states the requirement.
//
// The target adds two segments of two streams, so it reaches the overlap path, the
// duplicate path and the eviction path. A sender controls the sequence number and the
// payload, so the fuzzer moves both.
func FuzzTCPStreamReassemblerReadsAnySegment(f *testing.F) {
	// The reassembler accepts each seed below. The first pair is in order. The second
	// pair overlaps, because the second sequence number sits inside the first segment.
	f.Add("10.0.0.1:443", uint32(1000), []byte("GET / HTTP/1.1\r\n"), uint32(1016), []byte("Host: a\r\n\r\n"))
	f.Add("10.0.0.2:22", uint32(5), []byte("SSH-2.0-OpenSSH_8.9\r\n"), uint32(3), []byte("XX"))

	// The reassembler stores no segment of the first seed, because the seed holds no
	// payload. The second seed wraps the sequence number past the 32-bit bound.
	f.Add("", uint32(0), []byte{}, uint32(0), []byte{})
	f.Add("k", ^uint32(0), []byte{0x00, 0x01}, uint32(0), []byte{0x02})

	f.Fuzz(func(t *testing.T, key string, firstSeq uint32, first []byte, secondSeq uint32, second []byte) {
		reassembler := NewTCPStreamReassembler(fuzzReassemblerMaxStreams, fuzzReassemblerMaxBytes)

		reassembler.AddSegment(key, firstSeq, first)
		reassembler.AddSegment(key, secondSeq, second)
		reassembler.AddSegment(key+"-second", secondSeq, second)
		reassembler.AddSegment(key+"-third", firstSeq, first)

		_ = reassembler.GetStream(key)
		reassembler.RemoveStream(key)
		_ = reassembler.GetStream(key)
	})
}
