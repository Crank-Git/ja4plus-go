package ja4plus

import (
	"fmt"
	"sort"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The four bounds below hold the partial ClientHello table of JA4. Every TCP segment is
// untrusted input, and a sender opens a new connection at the cost of one segment.
// No FoxIO source addresses a state table, so `.claude/rules/parity.md` rule 2 gives the port
// the interface. `ja4plus/fingerprinters/ja4.py` of the port at tag `v1.3.0` states each
// value and each reason. Crank-Git/ja4plus#784 added them, under Crank-Git/ja4plus#772.

// maxJA4TCPHelloStreams bounds the number of connections whose partial ClientHello one
// fingerprinter holds. The QUIC fragment table holds the same bound.
const maxJA4TCPHelloStreams = 1000

// ja4TCPHelloAge drops a connection that sends no segment for 30 seconds. The segments of
// one hello arrive inside one round trip. The QUIC fragment table holds the same age.
//
// A segment that a cap refuses still counts, because the connection still sends.
// `add_segment` of `ja4plus/utils/tcp_stream.py` of the port at tag `v1.3.0` reads the age
// the same way, so the two age bounds agree. The recency order differs. Here each segment
// that reaches the table moves its connection to the most recent position. The port moves
// a connection only on a segment that it stores, so the entry bound of the two can remove
// a different connection.
const ja4TCPHelloAge = 30 * time.Second

// ja4TCPHelloEvictionInterval runs the age pass on each segment that reaches the table,
// whether the table stores it or refuses it. The table holds 1000 entries at most, so one
// pass reads 1000 keys at most.
const ja4TCPHelloEvictionInterval = 1

// maxJA4TCPHelloBytes bounds the bytes of one partial ClientHello. RFC 8446 Section 5.1
// limits the plaintext of one record to 2^14 bytes, and the record header adds 5. The last
// 6 bytes hold the ChangeCipherSpec record that a client sends before its second hello.
const maxJA4TCPHelloBytes = 1<<14 + 5 + 6

// maxJA4TCPHelloSegments bounds the segments of one partial ClientHello. A hello at the byte
// cap spans 31 segments of 536 bytes, which is the least segment size that RFC 9293 lets a
// host assume. The cap stops a sender of one-byte segments from holding 16395 entries.
const maxJA4TCPHelloSegments = 64

// ja4TCPHelloSegment holds one stored TCP segment of a partial ClientHello.
type ja4TCPHelloSegment struct {
	seq  uint32
	data []byte
}

// ja4TCPHello holds the client-to-server segments of one connection until they complete
// the ClientHello that the first segment opens.
type ja4TCPHello struct {
	segments []ja4TCPHelloSegment
	bytes    int
}

// tcpSequenceBefore reports whether the sequence number a comes before the sequence number
// b. A TCP sequence number is 32 bits and wraps to zero, so RFC 1982 orders two numbers on
// the difference between them. `sequence_before` of `ja4plus/utils/tcp_stream.py` of the
// port at tag `v1.3.0` holds the same comparison.
func tcpSequenceBefore(a, b uint32) bool {
	return a-b > 1<<31
}

// add stores one segment. It refuses a duplicate, a segment past the byte cap and a segment
// past the segment cap. A refused segment leaves no trace.
func (h *ja4TCPHello) add(seq uint32, payload []byte) {
	for _, segment := range h.segments {
		if segment.seq == seq && len(segment.data) == len(payload) {
			return
		}
	}

	if h.bytes+len(payload) > maxJA4TCPHelloBytes || len(h.segments) >= maxJA4TCPHelloSegments {
		return
	}

	// The caller can reuse the packet buffer, and the table holds the bytes across packets.
	data := make([]byte, len(payload))
	copy(data, payload)

	h.segments = append(h.segments, ja4TCPHelloSegment{seq: seq, data: data})
	h.bytes += len(data)
}

// ordered returns the segments in sequence order, earliest first, across a wrap of the
// sequence number.
//
// A stream occupies one arc of the sequence space, and the widest step between two
// neighbors closes that arc. The segment after the widest step holds the first byte. The
// order depends on the sequence numbers alone, and never on the arrival order.
// `_ordered_segments` of `ja4plus/utils/tcp_stream.py` of the port at tag `v1.3.0` holds the
// same rule.
func (h *ja4TCPHello) ordered() []ja4TCPHelloSegment {
	bySeq := make([]ja4TCPHelloSegment, len(h.segments))
	copy(bySeq, h.segments)

	if len(bySeq) < 2 {
		return bySeq
	}

	sort.SliceStable(bySeq, func(i, j int) bool { return bySeq[i].seq < bySeq[j].seq })

	start := 0
	widest := bySeq[0].seq - bySeq[len(bySeq)-1].seq

	for i := 1; i < len(bySeq); i++ {
		if step := bySeq[i].seq - bySeq[i-1].seq; step > widest {
			widest = step
			start = i
		}
	}

	return append(bySeq[start:], bySeq[:start]...)
}

// base returns the sequence number of the first byte that the stream holds. It reports
// false for a stream that holds no segment, because such a stream holds no first byte.
func (h *ja4TCPHello) base() (uint32, bool) {
	segments := h.ordered()
	if len(segments) == 0 {
		return 0, false
	}

	return segments[0].seq, true
}

// assemble returns the bytes from the first stored byte up to the first byte that no
// segment carries. A gap therefore never reads as zeros, and an overlap adds each byte once.
// A stream that holds no segment returns no byte, as `get_stream` of
// `ja4plus/utils/tcp_stream.py` of the port at tag `v1.3.0` does.
func (h *ja4TCPHello) assemble() []byte {
	segments := h.ordered()
	if len(segments) == 0 {
		return nil
	}

	result := make([]byte, 0, h.bytes)
	next := segments[0].seq

	for _, segment := range segments {
		if segment.seq != next && !tcpSequenceBefore(segment.seq, next) {
			break
		}

		overlap := next - segment.seq
		if uint64(overlap) < uint64(len(segment.data)) {
			result = append(result, segment.data[overlap:]...)
			next = segment.seq + uint32(len(segment.data))
		}
	}

	return result
}

// ja4TCPHelloKey names one direction of one connection. It reads the address pair that a
// FingerprintResult reports, so CleanupConnection reaches the entry from a result.
func ja4TCPHelloKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// collectTCPHello adds one TCP segment to the partial ClientHello of its direction.
//
// It returns the ClientHello on the segment that completes it. It reports true when the
// segment belongs to a hello that the table follows. These segments each report true:
//   - A segment that opens a stream.
//   - A segment that continues a stream, whether the table stores it or refuses it.
//   - A duplicate.
//   - A segment past a cap.
//   - A segment whose stream the age pass removed first.
//
// The caller then reports the error of the assembled bytes, and never the truncation error
// of the segment alone. So a retransmitted first segment returns the result that the first
// transmission returned. `_try_tcp_segments` of `ja4plus/fingerprinters/ja4.py` of the port
// at tag `v1.3.0` returns no value for each of these segments, and the port raises no error.
//
// A segment with FIN or RST removes both directions of the connection, because no later
// segment completes a hello on a closed connection.
func (f *JA4Fingerprinter) collectTCPHello(
	packet gopacket.Packet, tcp *layers.TCP,
) (*parser.ClientHello, bool, error) {
	// Most TCP segments open no hello. This test keeps the address formatting off that path
	// while the table holds no connection.
	if len(f.tcpHellos) == 0 {
		if end, opens := parser.ClientHelloEnd(tcp.Payload); !opens || end <= len(tcp.Payload) {
			return nil, false, nil
		}
	}

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)
	srcPort, dstPort := uint16(tcp.SrcPort), uint16(tcp.DstPort)
	key := ja4TCPHelloKey(srcIP, srcPort, dstIP, dstPort)

	var (
		hello    *parser.ClientHello
		followed bool
		err      error
	)

	if len(tcp.Payload) > 0 {
		hello, followed, err = f.addTCPHelloSegment(key, tcp.Seq, tcp.Payload, parser.GetPacketTimestamp(packet))
	}

	if tcp.FIN || tcp.RST {
		f.dropTCPHello(key)
		f.dropTCPHello(ja4TCPHelloKey(dstIP, dstPort, srcIP, srcPort))
	}

	return hello, followed, err
}

// addTCPHelloSegment stores one segment, and it parses the hello that the stored bytes
// complete. `_add_tcp_segment` of `ja4plus/fingerprinters/ja4.py` of the port at tag
// `v1.3.0` holds the same steps.
func (f *JA4Fingerprinter) addTCPHelloSegment(
	key string, seq uint32, payload []byte, now time.Time,
) (*parser.ClientHello, bool, error) {
	if stream, open := f.tcpHellos[key]; !open {
		// A hello that the segment holds whole needs no stream, because the reader of one
		// segment already read it.
		end, opens := parser.ClientHelloEnd(payload)
		if !opens || end <= len(payload) || end > maxJA4TCPHelloBytes {
			return nil, false, nil
		}
	} else if first, held := stream.base(); held && tcpSequenceBefore(seq, first) {
		// A byte before the first hello byte would move the start of the stream, and the
		// stream would then open with no TLS record.
		return nil, false, nil
	}

	// The age pass can remove the stream of this segment. The segment then opens a new
	// stream, and that stream holds no hello start, so it ends below. A cap can refuse the
	// segment, and the new stream then holds no segment. `assemble` returns no byte for that
	// stream, so it ends below too.
	f.tcpHelloKeys.admit(key, now, maxJA4TCPHelloStreams, ja4TCPHelloAge,
		ja4TCPHelloEvictionInterval, f.dropTCPHello)

	stream := f.tcpHellos[key]
	if stream == nil {
		stream = &ja4TCPHello{}
		f.tcpHellos[key] = stream
	}

	stream.add(seq, payload)

	data := stream.assemble()
	end, opens := parser.ClientHelloEnd(data)

	// A stream at the segment cap accepts no further segment, so it waits for nothing that
	// can arrive.
	if opens && len(data) < end && end <= maxJA4TCPHelloBytes && len(stream.segments) < maxJA4TCPHelloSegments {
		return nil, true, nil
	}

	f.dropTCPHello(key)

	if !opens || end > len(data) {
		return nil, true, nil
	}

	hello, err := parser.ParseClientHello(data)

	return hello, true, err
}

// dropTCPHello removes the partial ClientHello of one direction of one connection.
func (f *JA4Fingerprinter) dropTCPHello(key string) {
	delete(f.tcpHellos, key)
	f.tcpHelloKeys.remove(key)
}
