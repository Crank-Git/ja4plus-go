package ja4plus

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// The fuzz input of `FuzzJA4ReadsAnySequenceOfTCPSegments` holds a list of segment records.
// Each record opens with a header of tcpHelloFuzzHeader bytes:
//   - Bytes 0 and 1 hold a signed sequence offset from tcpHelloFuzzBaseSeq, big-endian.
//   - Byte 2 holds the seconds that the capture clock moves before the segment.
//   - Byte 3 holds the flags of tcpHelloFuzzFlag.
//   - Bytes 4 and 5 hold the payload length, big-endian, below tcpHelloFuzzMaxPayload.
//   - Bytes 6 and 7 hold the count of literal payload bytes that follow the header.
//
// Zero bytes fill the payload past the literal bytes. So a short input reaches a payload past
// the byte cap of the partial ClientHello table, and the batch #805 panic needed one.
const (
	tcpHelloFuzzHeader     = 8
	tcpHelloFuzzMaxRecords = 16
	tcpHelloFuzzMaxPayload = 1 << 15
	// The base sits below the wrap of the sequence number, so an offset reaches the wrap.
	tcpHelloFuzzBaseSeq = 0xffffc000
)

// tcpHelloFuzzFlag names one bit of byte 3 of a record header.
const (
	tcpHelloFuzzFIN      = 1 << 0
	tcpHelloFuzzRST      = 1 << 1
	tcpHelloFuzzToClient = 1 << 2
	tcpHelloFuzzPortTwo  = 1 << 3
)

// tcpHelloFuzzSegments returns the segments that the input encodes. A record that the input
// cuts ends the list.
func tcpHelloFuzzSegments(input []byte) []tcpHelloSegment {
	var segments []tcpHelloSegment

	at := time.Unix(1000, 0)

	for len(input) >= tcpHelloFuzzHeader && len(segments) < tcpHelloFuzzMaxRecords {
		offset := int16(binary.BigEndian.Uint16(input[0:2]))
		at = at.Add(time.Duration(input[2]) * time.Second)
		flags := input[3]
		length := int(binary.BigEndian.Uint16(input[4:6])) % tcpHelloFuzzMaxPayload
		literal := min(int(binary.BigEndian.Uint16(input[6:8])), len(input)-tcpHelloFuzzHeader, length)

		payload := make([]byte, length)
		copy(payload, input[tcpHelloFuzzHeader:tcpHelloFuzzHeader+literal])
		input = input[tcpHelloFuzzHeader+literal:]

		segment := tcpHelloSegment{
			payload:  payload,
			seq:      uint32(tcpHelloFuzzBaseSeq + int64(offset)),
			fin:      flags&tcpHelloFuzzFIN != 0,
			rst:      flags&tcpHelloFuzzRST != 0,
			toClient: flags&tcpHelloFuzzToClient != 0,
			at:       at,
		}
		if flags&tcpHelloFuzzPortTwo != 0 {
			segment.srcPort = tcpHelloClientPort + 1
		}

		segments = append(segments, segment)
	}

	return segments
}

// tcpHelloFuzzRecord returns one record of the fuzz input. The payload holds the literal
// bytes, and zero bytes fill it to the length.
func tcpHelloFuzzRecord(offset int16, seconds byte, flags byte, length int, literal []byte) []byte {
	record := make([]byte, tcpHelloFuzzHeader, tcpHelloFuzzHeader+len(literal))
	binary.BigEndian.PutUint16(record[0:2], uint16(offset))
	record[2] = seconds
	record[3] = flags
	binary.BigEndian.PutUint16(record[4:6], uint16(length))
	binary.BigEndian.PutUint16(record[6:8], uint16(len(literal)))

	return append(record, literal...)
}

// tcpHelloFuzzCompletedSeed returns two segments that complete one hello. The second
// segment emits the value.
func tcpHelloFuzzCompletedSeed() []byte {
	hello := tcpHelloLongClientHello()

	return append(
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400]),
		tcpHelloFuzzRecord(1400, 1, 0, len(hello)-1400, hello[1400:])...)
}

// tcpHelloFuzzAgedSeed returns the sequence of the batch #805 panic. The stream ages, and
// the next segment passes the byte cap.
func tcpHelloFuzzAgedSeed() []byte {
	hello := tcpHelloLongClientHello()

	return append(
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400]),
		tcpHelloFuzzRecord(1400, byte(ja4TCPHelloAge/time.Second)+1, 0, maxJA4TCPHelloBytes+1, nil)...)
}

// FuzzJA4ReadsAnySequenceOfTCPSegments proves that `JA4Fingerprinter.ProcessPacket` returns
// for any sequence of TCP segments. The partial ClientHello table holds state across
// packets, so a target that reads one frame never reaches a defect that two segments make.
// The batch #805 cross-member review found such a defect: an aged stream and a segment past
// the byte cap made `assemble` read the first segment of an empty stream.
//
// The target calls `ExactInput` and `Check` of `internal/fuzzprop`, as every target of this
// package does, so it carries FR-fuzz-14 through FR-fuzz-18.
func FuzzJA4ReadsAnySequenceOfTCPSegments(f *testing.F) {
	hello := tcpHelloLongClientHello()

	f.Add(tcpHelloFuzzCompletedSeed())
	f.Add(tcpHelloFuzzAgedSeed())

	// A duplicate, a segment before the hello and a server reset.
	f.Add(append(append(append(
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400]),
		tcpHelloFuzzRecord(0, 0, 0, 1400, hello[:1400])...),
		tcpHelloFuzzRecord(-10, 0, 0, 10, nil)...),
		tcpHelloFuzzRecord(0, 0, tcpHelloFuzzRST|tcpHelloFuzzToClient, 0, nil)...))

	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		input := fuzzprop.ExactInput(data)
		segments := tcpHelloFuzzSegments(input)

		// Each call builds one fingerprinter, because the table holds state across packets
		// and a shared value would make the second call read the state of the first.
		fuzzprop.Check(t, len(input), func() any {
			fingerprinter := NewJA4()
			outcomes := make([]any, 0, 2*len(segments)+2)

			for _, segment := range segments {
				results, err := fingerprinter.ProcessPacket(segment.build(t))
				outcomes = append(outcomes, results, err)
			}

			// The table holds its bounds after any sequence.
			if held := len(fingerprinter.tcpHellos); held > maxJA4TCPHelloStreams ||
				held != fingerprinter.tcpHelloKeys.count() {
				t.Fatalf("the table holds %d partial hellos and the recency order names %d",
					held, fingerprinter.tcpHelloKeys.count())
			}

			for key, stream := range fingerprinter.tcpHellos {
				if len(stream.segments) == 0 || len(stream.segments) > maxJA4TCPHelloSegments ||
					stream.bytes > maxJA4TCPHelloBytes {
					t.Fatalf("the partial hello %s holds %d segments and %d bytes",
						key, len(stream.segments), stream.bytes)
				}
			}

			return outcomes
		})
	})
}
