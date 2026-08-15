package ja4plus

import (
	"net"
	"testing"
)

// The FoxIO per-packet vector set publishes `ja4.ja4h_r` on 126 records, and the
// per-stream vector set publishes no `JA4H_r` value. #274 read the per-stream set and left
// `Raw` empty, #290 recorded that the two sets differ, and #310 fills the field.
//
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:603` builds the value as
// `<part a>_<header names>_<sorted cookie names>_<sorted cookie pairs>`, and
// `testdata/foxio/reference/python/ja4h.py:78` builds the same four fields.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:525` sorts the cookie by name,
// and `testdata/foxio/reference/python/ja4h.py:68` sorts it by name too. The two cookie
// fields of the raw sorted form therefore hold the two strings the base value hashes.
//
// The two references disagree on one point, and #285 holds that question. Wireshark writes
// four fields always, and the FoxIO Python reference writes three when the request holds no
// cookie. `Raw` follows `RawOriginalOrder`, which #274 built in the Python shape, so one
// ruling on #285 moves both fields together.

// TestJA4H_RawHoldsTheSortedCookieOrder holds the per-packet vector value verbatim.
//
// The expected value is the `ja4.ja4h_r` value of
// `testdata/foxio/wireshark/http1-with-cookies.pcapng.json`, reproduced verbatim.
func TestJA4H_RawHoldsTheSortedCookieOrder(t *testing.T) {
	raw := "GET /?file=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: text/html\r\n" +
		"Accept-Language: da, en-gb;q=0.8, en;q=0.7\r\n" +
		"Referer: http://example.com/\r\n" +
		"Cookie: yummy_cookie=choco; tasty_cookie=strawberry\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_tasty_cookie,yummy_cookie_tasty_cookie=strawberry,yummy_cookie=choco"
	if results[0].Raw != expectedRaw {
		t.Errorf("Raw is %q, and the FoxIO per-packet vector holds %q", results[0].Raw, expectedRaw)
	}

	// The raw sorted form moves no other field. This assertion fails when the new field
	// changes the wire-order form that #274 built.
	const expectedRawOriginalOrder = "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry"
	if results[0].RawOriginalOrder != expectedRawOriginalOrder {
		t.Errorf("RawOriginalOrder is %q, and it must stay %q",
			results[0].RawOriginalOrder, expectedRawOriginalOrder)
	}

	// The base value hashes the two strings that the raw sorted form writes, so the two
	// forms read one input. This assertion fails when the shared builder changes either.
	expectedBase := "ge11cr04da00_" + truncHash("Host,User-Agent,Accept,Accept-Language") +
		"_" + truncHash("tasty_cookie,yummy_cookie") +
		"_" + truncHash("tasty_cookie=strawberry,yummy_cookie=choco")
	if results[0].Fingerprint != expectedBase {
		t.Errorf("the base JA4H value is %q, and it must stay %q",
			results[0].Fingerprint, expectedBase)
	}
}

// TestJA4H_RawEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie holds the three-field
// shape that `RawOriginalOrder` already carries.
//
// `testdata/foxio/reference/python/ja4h.py:82` appends the two cookie fields under
// `if 'cookie_fields' in x`, so a request with no cookie ends after one underscore.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:603` writes two trailing
// underscores for the same request. **#285 held that reference split, and the maintainer
// ruled it on 2026-08-12. The library keeps the per-stream shape.** This test fails when a
// later ruling reverses the shape, which is the point of it.
//
// `Crank-Git/ja4plus` holds no issue for this question, and the port needs no change. The
// port writes the same three-field shape. `ja4plus/fingerprinters/ja4h.py:532` builds
// `f"{part_a}_{headers_str}_"`. Lines 535 to 538 append the two cookie fields only when the
// request carries a cookie. The docstring at lines 516 to 518 states the same rule.
func TestJA4H_RawEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: t\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expected = "ge11nn020000_Host,User-Agent_"
	if results[0].Raw != expected {
		t.Errorf("Raw is %q, and the test expects %q", results[0].Raw, expected)
	}
	if results[0].RawOriginalOrder != expected {
		t.Errorf("RawOriginalOrder is %q, and it must equal the raw sorted form here, because"+
			" a request with no cookie holds no field that a sort reorders: %q",
			results[0].RawOriginalOrder, expected)
	}
}

// TestJA4H_RawReachesTheReassembledPath proves that the multi-segment path fills the field
// that the single-packet path fills.
//
// The two paths build one result each, and a field that one path fills alone reports a
// value for one capture and no value for another.
func TestJA4H_RawReachesTheReassembledPath(t *testing.T) {
	request := "GET /p HTTP/1.1\r\nHost: example.com\r\nCookie: zeta=1; alpha=2\r\n\r\n"
	// The split falls inside the request line, so the first segment alone parses as no
	// request. `TestJA4H_StreamReassembly` splits at the same point for the same reason.
	head := request[:6]
	tail := request[6:]

	fingerprinter := NewJA4H()
	source := net.IP{192, 168, 1, 1}
	destination := net.IP{10, 0, 0, 1}

	first := buildTCPPacketWithSeq(t, source, destination, 12345, 80, 1000, []byte(head))
	if results, err := fingerprinter.ProcessPacket(first); err != nil || len(results) != 0 {
		t.Fatalf("the first segment produced %d results and error %v", len(results), err)
	}

	second := buildTCPPacketWithSeq(t, source, destination, 12345, 80, 1000+uint32(len(head)), []byte(tail))
	results, err := fingerprinter.ProcessPacket(second)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the reassembled stream produced %d results, and the test expects 1", len(results))
	}

	const expected = "ge11cn010000_Host_alpha,zeta_alpha=2,zeta=1"
	if results[0].Raw != expected {
		t.Errorf("Raw is %q, and the test expects %q", results[0].Raw, expected)
	}
}
