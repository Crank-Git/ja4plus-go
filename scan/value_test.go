package scan

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The cases below port `tests/test_ja4tscan_value.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. FoxIO publishes no JA4TScan capture, so each case builds the responses that
// one example value of `ja4tscan/README.md:21-28` describes. The port's
// `docs/specs/foxio/JA4TScan.md` at the same tag holds the reading of each value.

const (
	flagSynAck = 0x12
	flagRST    = 0x04
	flagRSTAck = 0x14
	flagACK    = 0x10
)

// The option bytes that the examples need, one option in wire form each.
var (
	optEOL           = []byte{0x00}
	optNOP           = []byte{0x01}
	optSACKPermitted = []byte{0x04, 0x02}
	optTimestamp     = append([]byte{0x08, 0x0a}, make([]byte, 8)...)
)

func optMSS(value uint16) []byte {
	return []byte{0x02, 0x04, byte(value >> 8), byte(value)}
}

func optWindowScale(value byte) []byte {
	return []byte{0x03, 0x03, value}
}

func joinOptions(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}

	return out
}

// tcpHeader returns a TCP header that carries the flags, the window and the options.
// A header holds whole 32-bit words, so the helper refuses an option region of another
// length rather than pad it with bytes that part b would read.
func tcpHeader(t testing.TB, flags byte, window uint16, options []byte) []byte {
	t.Helper()

	if len(options)%4 != 0 {
		t.Fatalf("the option region holds %d bytes, and a TCP header holds whole words", len(options))
	}

	header := make([]byte, 20+len(options))
	binary.BigEndian.PutUint16(header[0:2], 443)
	binary.BigEndian.PutUint16(header[2:4], 40112)
	header[12] = byte((20+len(options))/4) << 4
	header[13] = flags
	binary.BigEndian.PutUint16(header[14:16], window)
	copy(header[20:], options)

	return header
}

var exampleStart = time.Unix(1000, 0)

func seconds(value float64) time.Duration {
	return time.Duration(value * float64(time.Second))
}

// exampleResponses returns a SYN-ACK, one retransmission after each delay, and a RST when
// rstDelay is at or above zero.
func exampleResponses(t testing.TB, window uint16, options []byte, delays []float64, rstDelay float64) []Response {
	t.Helper()

	now := exampleStart
	responses := []Response{{Time: now, Header: tcpHeader(t, flagSynAck, window, options)}}

	for _, delay := range delays {
		now = now.Add(seconds(delay))
		responses = append(responses, Response{Time: now, Header: tcpHeader(t, flagSynAck, window, options)})
	}

	if rstDelay >= 0 {
		responses = append(responses, Response{Time: now.Add(seconds(rstDelay)), Header: tcpHeader(t, flagRST, 0, nil)})
	}

	return responses
}

const noRST = -1

func mustValue(t *testing.T, responses []Response) string {
	t.Helper()

	value, ok := Value(responses)
	if !ok {
		t.Fatalf("Value reports no value for %d responses", len(responses))
	}

	return value
}

func TestTheResponsesOfEachPublishedExampleProduceItsValue(t *testing.T) {
	examples := []struct {
		system   string
		window   uint16
		options  []byte
		delays   []float64
		rstDelay float64
		want     string
	}{
		{"Windows 10", 64240, joinOptions(optMSS(1460), optNOP, optWindowScale(8), optNOP, optNOP, optSACKPermitted),
			[]float64{1, 2, 4, 8}, 6, "64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6"},
		{"Windows 2003", 16384, joinOptions(optMSS(1460), optNOP, optWindowScale(0), optNOP, optNOP, optTimestamp, optNOP, optNOP, optSACKPermitted),
			[]float64{2, 7}, noRST, "16384_2-1-3-1-1-8-1-1-4_1460_00_2-7"},
		{"Amazon AWS Linux 2", 62727, joinOptions(optMSS(8961), optSACKPermitted, optTimestamp, optNOP, optWindowScale(7)),
			[]float64{1, 2, 4, 8, 16}, noRST, "62727_2-4-8-1-3_8961_7_1-2-4-8-16"},
		{"Mac OSX / iPhone", 65535, joinOptions(optMSS(1460), optNOP, optWindowScale(6), optNOP, optNOP, optTimestamp, optSACKPermitted, optEOL, optEOL),
			[]float64{1, 2, 4, 8, 16, 32, 12}, noRST, "65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12"},
		{"HP ILO", 5840, optMSS(1460),
			[]float64{3, 6, 12, 24, 48, 60, 60, 60, 60, 60}, noRST, "5840_2_1460_00_3-6-12-24-48-60-60-60-60-60"},
		{"Epson Printer", 28960, joinOptions(optMSS(1460), optSACKPermitted, optTimestamp, optNOP, optWindowScale(3)),
			[]float64{1, 4, 8, 16}, noRST, "28960_2-4-8-1-3_1460_3_1-4-8-16"},
		{"Ubiquiti Router", 43440, joinOptions(optMSS(1460), optSACKPermitted, optTimestamp, optNOP, optWindowScale(12)),
			[]float64{1, 2, 4, 8, 17}, noRST, "43440_2-4-8-1-3_1460_12_1-2-4-8-17"},
		{"F5 Big IP", 4380, joinOptions(optMSS(1460), optSACKPermitted, optTimestamp),
			[]float64{3, 6, 12}, noRST, "4380_2-4-8_1460_00_3-6-12"},
	}

	for _, example := range examples {
		t.Run(example.system, func(t *testing.T) {
			got := mustValue(t, exampleResponses(t, example.window, example.options, example.delays, example.rstDelay))
			if got != example.want {
				t.Errorf("Value = %q, want %q", got, example.want)
			}
		})
	}
}

// The maintainer ruled the JA4TS form on 2026-09-30, so part d writes `00` for a zero
// scale. The FoxIO README publishes `0` for this example.
func TestTheF5ExampleWritesAZeroScaleAsTwoDigitsAndNotAsPublished(t *testing.T) {
	got := mustValue(t, exampleResponses(t, 4380, joinOptions(optMSS(1460), optSACKPermitted, optTimestamp), []float64{3, 6, 12}, noRST))
	if got == "4380_2-4-8_1460_0_3-6-12" {
		t.Fatalf("Value writes the published FoxIO form %q, and the ruled form writes part d as 00", got)
	}
}

// The header helper needs whole words, so two NOP bytes precede the two End of Option List
// bytes that the case reads.
func TestTwoEndOfOptionListBytesWriteTwoZeroKinds(t *testing.T) {
	options := joinOptions(optMSS(1460), optNOP, optNOP, optEOL, optEOL)
	got := mustValue(t, []Response{{Time: exampleStart, Header: tcpHeader(t, flagSynAck, 1024, options)}})

	partB := strings.Split(got, "_")[1]
	if partB != "2-1-1-0-0" {
		t.Errorf("part b = %q, want 2-1-1-0-0", partB)
	}
}

func TestARetransmissionOneAndAHalfSecondsLaterWritesTheDelayTwo(t *testing.T) {
	got := mustValue(t, exampleResponses(t, 1024, optMSS(1460), []float64{1.5}, noRST))
	if got != "1024_2_1460_00_2" {
		t.Errorf("Value = %q, want 1024_2_1460_00_2", got)
	}
}

func TestEachDelayCountsFromThePreviousResponseOfTheTarget(t *testing.T) {
	got := mustValue(t, exampleResponses(t, 1024, optMSS(1460), []float64{1, 3}, noRST))
	if got != "1024_2_1460_00_1-3" {
		t.Errorf("Value = %q, want 1024_2_1460_00_1-3", got)
	}
}

func TestOneSynAckProducesFourPartsAndNoPartE(t *testing.T) {
	got := mustValue(t, exampleResponses(t, 29200, optMSS(1460), nil, noRST))
	if got != "29200_2_1460_00" {
		t.Errorf("Value = %q, want 29200_2_1460_00", got)
	}
}

func TestAFirstResponseThatCarriesRSTProducesTheResetValue(t *testing.T) {
	got := mustValue(t, []Response{{Time: exampleStart, Header: tcpHeader(t, flagRST, 0, nil)}})
	if got != "0_rst-ack" || ResetValue != "0_rst-ack" {
		t.Errorf("Value = %q and ResetValue = %q, want 0_rst-ack for both", got, ResetValue)
	}
}

func TestAFirstResponseThatCarriesRSTAndACKWithAWindowProducesTheResetValue(t *testing.T) {
	got := mustValue(t, []Response{{Time: exampleStart, Header: tcpHeader(t, flagRSTAck, 512, nil)}})
	if got != ResetValue {
		t.Errorf("Value = %q, want %q", got, ResetValue)
	}
}

// R13 rule 2 of `docs/specs/foxio/JA4T.md` writes no reset letter where no retransmission
// came before the RST.
func TestARSTAfterOneSynAckWritesFourPartsAndNoResetLetter(t *testing.T) {
	got := mustValue(t, exampleResponses(t, 1024, optMSS(1460), nil, 3))
	if got != "1024_2_1460_00" {
		t.Errorf("Value = %q, want 1024_2_1460_00", got)
	}
}

func TestAResponseAfterAFirstRSTChangesNothing(t *testing.T) {
	responses := []Response{
		{Time: exampleStart, Header: tcpHeader(t, flagRSTAck, 0, nil)},
		{Time: exampleStart.Add(3 * time.Second), Header: tcpHeader(t, flagSynAck, 1024, optMSS(1460))},
	}
	if got := mustValue(t, responses); got != ResetValue {
		t.Errorf("Value = %q, want %q", got, ResetValue)
	}
}

func TestAResponseAfterALaterRSTChangesNothing(t *testing.T) {
	responses := exampleResponses(t, 1024, optMSS(1460), []float64{1}, 2)
	last := responses[len(responses)-1].Time
	responses = append(responses, Response{Time: last.Add(5 * time.Second), Header: tcpHeader(t, flagSynAck, 1024, optMSS(1460))})

	if got := mustValue(t, responses); got != "1024_2_1460_00_1-R2" {
		t.Errorf("Value = %q, want 1024_2_1460_00_1-R2", got)
	}
}

func TestPartECountsTenRetransmissionsAndNoMore(t *testing.T) {
	delays := make([]float64, 12)
	for index := range delays {
		delays[index] = 1
	}

	want := "1024_2_1460_00_" + strings.Repeat("1-", 9) + "1"
	if got := mustValue(t, exampleResponses(t, 1024, optMSS(1460), delays, noRST)); got != want {
		t.Errorf("Value = %q, want %q", got, want)
	}
}

// The two uncounted retransmissions arrive 1 and 2 seconds after the tenth, and the RST
// arrives 4 seconds after the last of them. The JA4TS rule reads the delay from the tenth
// retransmission, which is the last SYN-ACK it stores. #369 question 2 holds that ruling.
func TestARSTAfterTenRetransmissionsCountsFromTheTenth(t *testing.T) {
	delays := make([]float64, 12)
	for index := range delays {
		delays[index] = 1
	}

	got := mustValue(t, exampleResponses(t, 1024, optMSS(1460), delays, 4))
	if !strings.HasSuffix(got, "-1-R6") {
		t.Errorf("Value = %q, want a value that ends with -1-R6", got)
	}
}

func TestNoResponseProducesNoValue(t *testing.T) {
	if got, ok := Value(nil); ok || got != "" {
		t.Errorf("Value(nil) = %q, %v, want no value", got, ok)
	}
}

func TestAnOptionLengthPastTheEndStopsPartBAndRaisesNothing(t *testing.T) {
	options := joinOptions(optMSS(1460), []byte{0x03, 0x09, 0x07, 0x00})
	if got := mustValue(t, []Response{{Time: exampleStart, Header: tcpHeader(t, flagSynAck, 1024, options)}}); got != "1024_2_1460_00" {
		t.Errorf("Value = %q, want 1024_2_1460_00", got)
	}
}

// A response that carries neither SYN and ACK nor RST answers no SYN, so it adds no delay.
// The scanner drops such a segment before Value reads it, and this case holds the same
// answer for a caller of the exported function.
func TestASegmentWithACKAloneAddsNoDelay(t *testing.T) {
	responses := []Response{
		{Time: exampleStart, Header: tcpHeader(t, flagSynAck, 1024, optMSS(1460))},
		{Time: exampleStart.Add(time.Second), Header: tcpHeader(t, flagACK, 1024, nil)},
	}
	if got := mustValue(t, responses); got != "1024_2_1460_00" {
		t.Errorf("Value = %q, want 1024_2_1460_00", got)
	}
}

func TestAResponseShorterThanATCPHeaderRaisesNothing(t *testing.T) {
	header := tcpHeader(t, flagSynAck, 1024, optMSS(1460))
	for end := range len(header) + 1 {
		_, _ = Value([]Response{{Time: exampleStart, Header: header[:end]}})
	}
}

// The ruling of 2026-09-30 reuses the JA4TS form, so a scan prefix equals the passive JA4TS
// value of the same SYN-ACK.
func TestAScanValueHoldsThePartsAToDOfThePassiveJA4TSValue(t *testing.T) {
	options := joinOptions(optMSS(1460), optNOP, optWindowScale(7), optSACKPermitted, optEOL, optEOL)
	header := tcpHeader(t, flagSynAck, 65160, options)

	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: []byte{192, 0, 2, 10}, DstIP: []byte{198, 51, 100, 1},
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, ip, gopacket.Payload(header)); err != nil {
		t.Fatalf("serialize the IPv4 packet: %v", err)
	}

	passive := ja4plus.ComputeJA4TS(gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default))
	if passive == "" {
		t.Fatal("ComputeJA4TS returns no value for the SYN-ACK")
	}

	if got := mustValue(t, []Response{{Time: exampleStart, Header: header}}); got != passive {
		t.Errorf("Value = %q, and the passive JA4TS value is %q", got, passive)
	}
}
