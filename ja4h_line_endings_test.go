package ja4plus

import (
	"net"
	"testing"
)

// A sender ends a header line with the two bytes `\r\n`, or with one line feed.
// `testdata/foxio/pcap/http-empty-useragent.pcap` holds a request that ends each line with
// one line feed, and it splits that request over three TCP segments. FoxIO publishes a
// JA4H value for it, so the reference reads both line endings and it waits for the
// terminating empty line. #286 records the defect that this file holds.
//
// The Python port fixed the same defect in its issue #193.
// `ja4plus/utils/http_utils.py:40` holds the pattern `re.compile(r"\r\n|\n")`, and
// `ja4plus/fingerprinters/ja4h.py:149-151` returns no value until the header block ends.

// The values `testdata/foxio/python/http-empty-useragent.pcap.json` holds for stream 0.
const (
	emptyUserAgentJA4H   = "ge10nn010000_b8bcd45ac095_000000000000_000000000000"
	emptyUserAgentJA4HRO = "ge10nn010000_User-Agent_"
)

// The three TCP segments of the request that `http-empty-useragent.pcap` carries.
// Each line ends with one line feed, and the third segment carries the empty line alone.
const (
	lineFeedRequestLine  = "GET / HTTP/1.0\n"
	lineFeedHeaderLine   = "User-Agent:\n"
	lineFeedBlockEndLine = "\n"
)

// TestJA4H_ReadsAHeaderBlockThatEndsEachLineWithOneLineFeed proves that the parser reads a
// line feed as a line ending.
//
// The parser split the payload on `\r\n` alone, so it read the whole request as one line.
// It found no header, and part a counted `00`.
func TestJA4H_ReadsAHeaderBlockThatEndsEachLineWithOneLineFeed(t *testing.T) {
	raw := lineFeedRequestLine + lineFeedHeaderLine + lineFeedBlockEndLine

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	if results[0].Fingerprint != emptyUserAgentJA4H {
		t.Errorf("the JA4H value is %q, and the FoxIO vector holds %q",
			results[0].Fingerprint, emptyUserAgentJA4H)
	}
	if results[0].RawOriginalOrder != emptyUserAgentJA4HRO {
		t.Errorf("the JA4H_ro value is %q, and the FoxIO vector holds %q",
			results[0].RawOriginalOrder, emptyUserAgentJA4HRO)
	}
}

// TestJA4H_KeepsAHeaderThatCarriesAnEmptyValue proves that a header with no value reaches
// part a and part b.
//
// The reference counts `User-Agent:` as one header, so part a reads `01`.
func TestJA4H_KeepsAHeaderThatCarriesAnEmptyValue(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent:\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11nn020000_Host,User-Agent_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// TestJA4H_ReachesTheReferenceValueOfTheThreeSegmentLineFeedRequest proves that the
// fingerprinter waits for every segment of the header block.
//
// The fingerprinter answered on the first segment, which carries the request line alone.
// That answer counted no header, and it removed the stream before the header arrived.
func TestJA4H_ReachesTheReferenceValueOfTheThreeSegmentLineFeedRequest(t *testing.T) {
	fingerprinter := NewJA4H()
	source := net.IP{192, 168, 1, 1}
	destination := net.IP{10, 0, 0, 1}
	var sequence uint32 = 1000

	segments := []string{lineFeedRequestLine, lineFeedHeaderLine}
	for _, segment := range segments {
		packet := buildTCPPacketWithSeq(t, source, destination, 57722, 9200, sequence, []byte(segment))
		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned an error on segment %q: %v", segment, err)
		}
		if len(results) != 0 {
			t.Fatalf("segment %q produced %d results, and the header block has not ended",
				segment, len(results))
		}
		sequence += uint32(len(segment))
	}

	last := buildTCPPacketWithSeq(t, source, destination, 57722, 9200, sequence, []byte(lineFeedBlockEndLine))
	results, err := fingerprinter.ProcessPacket(last)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the reassembled stream produced %d results, and the test expects 1", len(results))
	}

	if results[0].Fingerprint != emptyUserAgentJA4H {
		t.Errorf("the JA4H value is %q, and the FoxIO vector holds %q",
			results[0].Fingerprint, emptyUserAgentJA4H)
	}
	if results[0].RawOriginalOrder != emptyUserAgentJA4HRO {
		t.Errorf("the JA4H_ro value is %q, and the FoxIO vector holds %q",
			results[0].RawOriginalOrder, emptyUserAgentJA4HRO)
	}
}

// TestJA4H_ProducesNoValueBeforeTheHeaderBlockEnds proves that an unterminated header block
// reaches no value.
//
// A later segment carries a header that changes part a and part b, so an early value is a
// value of a request the sender never sent.
// `ja4plus/fingerprinters/ja4h.py:149-151` of the Python port states the same rule.
func TestJA4H_ProducesNoValueBeforeTheHeaderBlockEnds(t *testing.T) {
	requests := []struct {
		name string
		raw  string
	}{
		{
			name: "the request line arrives alone",
			raw:  "GET /p HTTP/1.1\r\n",
		},
		{
			name: "one header arrives and the empty line does not",
			raw:  "GET /p HTTP/1.1\r\nHost: example.com\r\n",
		},
	}

	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			packet := buildTCPPacketWithPayload(t, []byte(request.raw))
			results, err := NewJA4H().ProcessPacket(packet)
			if err != nil {
				t.Fatalf("ProcessPacket returned an error: %v", err)
			}
			if len(results) != 0 {
				t.Fatalf("ProcessPacket returned %d results, and the test expects 0", len(results))
			}
		})
	}
}

// TestJA4H_ReadsAHeaderBlockThatEndsWithACarriageReturnAndTwoLineFeeds holds the second half
// of the ruling of #298.
//
// **This path passed by coincidence before the ruling, and it passes by design now.** `\n\n`
// is a substring of `\r\n\n`, so the two literals found the terminator one byte late. The
// last header line then carried a trailing carriage return, and the value trim removed it. A
// later change to the value handling would have broken that path silently.
//
// The ruled pattern starts the match at the carriage return, so the header block holds no
// part of the line ending and no trim is load-bearing.
// `TestParseHTTPRequestReadsABlockThatEndsCarriageReturnLineFeedThenLineFeed` of
// `internal/parser` states the offset, and this test states the value.
//
// **Reversal path: #298 and `Crank-Git/ja4plus#614`, together.**
func TestJA4H_ReadsAHeaderBlockThatEndsWithACarriageReturnAndTwoLineFeeds(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11nn010000_Host_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// TestJA4H_ReadsAHeaderBlockThatEndsWithALineFeedAndACarriageReturn holds the ruling of
// #298.
//
// The maintainer ruled the header block terminator on 2026-08-13 UTC, in the port, and
// re-confirmed it on 2026-08-15 UTC. **The terminator is one line ending followed by
// another.** `Crank-Git/ja4plus#614` and `Crank-Git/ja4plus#604` hold the Python half.
//
// This request ends its last header line with one line feed, and it ends the empty line with
// `\r\n`. The terminator is then `\n\r\n`, which neither `\r\n\r\n` nor `\n\n` matches. This
// request reached no JA4H value before the ruling. **No capture of the FoxIO corpus holds a
// mixed terminator**, so this constructed packet is the only thing that separates the two
// candidate answers.
//
// **Reversal path: #298 and `Crank-Git/ja4plus#614`, together.**
func TestJA4H_ReadsAHeaderBlockThatEndsWithALineFeedAndACarriageReturn(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	// The value matches the value of the same request under an unmixed terminator, because
	// the line ending reaches no part of the JA4H value.
	const expectedRaw = "ge11nn010000_Host_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// TestJA4H_DropsAHeaderWithAnEmptyNameFromPartAAndFromPartB proves that one filter serves
// the header count and the header list.
//
// Part a counted a header name that part b dropped, so the count named one more header than
// the hash held. No capture of the corpus reaches the case, so this test builds the
// separating packet. #286 owns the rule, and
// `ja4plus/fingerprinters/ja4h.py:445-449` of the Python port holds the same filter.
func TestJA4H_DropsAHeaderWithAnEmptyNameFromPartAAndFromPartB(t *testing.T) {
	// The second line carries one space before the colon, so the header name trims to the
	// empty string.
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		" : orphan\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	expected := "ge11nn010000_" + truncHash("Host") +
		"_" + truncHash("") + "_" + truncHash("")
	if results[0].Fingerprint != expected {
		t.Errorf("the JA4H value is %q, and the test expects %q", results[0].Fingerprint, expected)
	}

	const expectedRaw = "ge11nn010000_Host_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}
