package ja4plus

import (
	"testing"
)

// The second request of a pipelined pair. It declares no body, so the header block completes
// it under the gate of #455.
//
// A pipelined pair is one byte range that holds a complete request and then a second request.
// `ja4hDeclaredBodyRequest` of `ja4h_body_gate_test.go` is the first request of each pair
// below, because it declares a body and the pipelined case needs a declared body.
const ja4hPipelinedSecondRequest = "GET /second HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Accept: */*\r\n" +
	"\r\n"

// Each test of this file records the measurement of #463, and none of them holds a ruling.
//
// **The maintainer rules the value count of a pipelined pair, and #463 carries the question.**
// The FoxIO implementations disagree, so `.claude/rules/rulings.md` `## Stop conditions` sends
// the question to the maintainer. Three readings of the reference state the disagreement.
//
//   - The Rust implementation produces one value. `rust/ja4/src/http.rs:22` selects the layer
//     with `pkt.find_proto("http")`, and `rust/ja4/src/pcap.rs:51` states
//     `/// Gets the first protocol with the given name.`
//   - The Python implementation produces one value. `python/ja4.py:414` reads
//     `l = l[0] if isinstance(l, list) else l`, so it keeps the first layer alone.
//   - The Zeek package produces two values. `zeek/ja4h/main.zeek:186` computes the value in
//     `event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)`, and
//     `zeek/ja4h/main.zeek:124` clears the state in `event http_request`.
//
// Zeek raises `http_message_done` for each HTTP message. The Zeek documentation states
// `Generated once at the end of parsing an HTTP message.`, and it states
// `A "message" is one top-level HTTP entity, such as a complete request or reply.`
// Verified against <https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_HTTP.events.bif.zeek.html>,
// retrieved 2026-08-14 UTC.
//
// **The count of the Wireshark dissector is unverified.**
// `wireshark/source/packet-ja4.c:1756` reads `register_postdissector(ja4_handle);`, and no
// documentation this project reached states how often Wireshark calls a postdissector. The
// three readings above state the disagreement without it.
//
// No capture of the corpus reaches a pipelined pair, so no register entry records this
// question and these tests record it. Each test fails when the count moves, and the
// maintainer's ruling at #463 is the reversal path.

// TestJA4H_ProducesOneValueForASegmentThatHoldsTwoRequests records the count of one segment
// that holds a pipelined pair.
//
// The library produces the value of the first request. It reads no byte past that request, so
// the second request reaches no value.
func TestJA4H_ProducesOneValueForASegmentThatHoldsTwoRequests(t *testing.T) {
	fingerprinter := NewJA4H()

	segment := ja4hDeclaredBodyRequest + ja4hDeclaredBody + ja4hPipelinedSecondRequest
	results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, segment))
	if err != nil {
		t.Fatalf("the segment returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the pipelined segment produced %d values, and the measurement of #463 states 1",
			len(results))
	}
	if results[0].Fingerprint != "po11nn030000_51b2f3543123_000000000000_000000000000" {
		t.Fatalf("the pipelined segment produced %q, and the value of the first request is po11nn030000_51b2f3543123_000000000000_000000000000",
			results[0].Fingerprint)
	}
}

// TestJA4H_ProducesTwoValuesForTwoRequestsInTwoSegments states the limit of the defect of
// #463.
//
// The consumed range ends at the last byte of the emitting segment, so a segment that starts
// at that byte reaches the parse path. A pipelined pair that one segment holds is therefore
// the one arrangement that loses a value.
func TestJA4H_ProducesTwoValuesForTwoRequestsInTwoSegments(t *testing.T) {
	fingerprinter := NewJA4H()

	first := ja4hDeclaredBodyRequest + ja4hDeclaredBody
	one, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, first))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the first segment produced %d values, and the reference holds 1", len(one))
	}

	two, err := fingerprinter.ProcessPacket(
		ja4hSegmentAt(t, uint32(1000+len(first)), 1, ja4hPipelinedSecondRequest))
	if err != nil {
		t.Fatalf("the second segment returned an error: %v", err)
	}
	if len(two) != 1 {
		t.Fatalf("the second segment produced %d values, and the reference holds 1", len(two))
	}
}

// TestJA4H_ProducesNoValueForASecondRequestThatTwoSegmentsSplit records the second
// arrangement of #463.
//
// The emission removes the stream, so the head of the second request leaves the reassembler
// with it. The segment that carries the tail starts with no request line, so
// `parser.IsHTTPRequest` declines it and the second request reaches no value.
func TestJA4H_ProducesNoValueForASecondRequestThatTwoSegmentsSplit(t *testing.T) {
	fingerprinter := NewJA4H()

	first := ja4hDeclaredBodyRequest + ja4hDeclaredBody
	head := ja4hPipelinedSecondRequest[:10]
	tail := ja4hPipelinedSecondRequest[10:]

	one, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, first+head))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the first segment produced %d values, and the measurement of #463 states 1",
			len(one))
	}

	two, err := fingerprinter.ProcessPacket(
		ja4hSegmentAt(t, uint32(1000+len(first)+len(head)), 1, tail))
	if err != nil {
		t.Fatalf("the tail segment returned an error: %v", err)
	}
	if len(two) != 0 {
		t.Fatalf("the tail segment produced %d values, and the measurement of #463 states 0",
			len(two))
	}
}

// TestJA4H_ProducesNoDuplicateForARetransmissionOfAPipelinedSegment holds the repair of #446
// on a pipelined segment.
//
// **This test fails under the candidate repair that #463 names, and that is why it exists.**
// A consumed range that ends at the first request leaves the rest of the segment outside
// itself. The retransmission then reaches the parse path, and it produces the value of the
// first request a second time. A worker of #463 measured that duplicate on 2026-08-14 UTC,
// and pull request #499 records the measurement.
// So a repair of #463 keeps the consumed range over every byte the emission read.
func TestJA4H_ProducesNoDuplicateForARetransmissionOfAPipelinedSegment(t *testing.T) {
	fingerprinter := NewJA4H()

	segment := ja4hDeclaredBodyRequest + ja4hDeclaredBody + ja4hPipelinedSecondRequest
	one, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, segment))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the first segment produced %d values, and the measurement of #463 states 1",
			len(one))
	}

	repeat, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 1, segment))
	if err != nil {
		t.Fatalf("the retransmission returned an error: %v", err)
	}
	if len(repeat) != 0 {
		t.Fatalf("the retransmission produced %d values, and the repair of #446 states 0: %q",
			len(repeat), repeat[0].Fingerprint)
	}
}
