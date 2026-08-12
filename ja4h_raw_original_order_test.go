package ja4plus

import (
	"net"
	"testing"
)

// The FoxIO per-stream vector set publishes `JA4H_ro`, and it publishes no `JA4H_r`
// value. `testdata/foxio/reference/python/ja4h.py` builds both keys, and the vector
// writer records only the original-order one. #274 fills `RawOriginalOrder` for that key.
//
// The reference builds the value as `<part a>_<header names>_<cookie names>_<cookie
// pairs>`. A request that carries no cookie ends after the header names and one
// underscore, because `testdata/foxio/reference/python/ja4h.py` appends the two cookie
// fields only when the request holds a cookie.

// TestJA4H_RawOriginalOrderEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie holds the
// three-field shape that 68 of the 89 per-stream vector values carry.
//
// The expected value is the `JA4H_ro` value of
// `testdata/foxio/python/CVE-2018-6794.pcap.json`, reproduced verbatim.
func TestJA4H_RawOriginalOrderEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie(t *testing.T) {
	raw := "GET /index.php HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"Accept: text/html\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Accept-Language: ru-RU,ru;q=0.9\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expected = "ge11nn07ruru_Host,Connection,User-Agent,Upgrade-Insecure-Requests,Accept,Accept-Encoding,Accept-Language_"
	if results[0].RawOriginalOrder != expected {
		t.Errorf("RawOriginalOrder is %q, and the FoxIO vector holds %q",
			results[0].RawOriginalOrder, expected)
	}
}

// TestJA4H_RawOriginalOrderHoldsTheCookieWireOrder proves that the raw form keeps the
// wire order of the cookie while the base value sorts it.
//
// The base value hashes the sorted cookie names and the sorted cookie pairs, so a raw
// form that sorted them would carry no information the base value lacks.
func TestJA4H_RawOriginalOrderHoldsTheCookieWireOrder(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: zeta=1; alpha=2\r\n" +
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

	const expectedRaw = "ge11cn020000_Host,User-Agent_zeta,alpha_zeta=1,alpha=2"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("RawOriginalOrder is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}

	// The base value sorts the cookie name and the cookie pair, and #274 moves no base
	// value. This assertion fails when the raw form changes the base value.
	expectedBase := "ge11cn020000_" + truncHash("Host,User-Agent") +
		"_" + truncHash("alpha,zeta") + "_" + truncHash("alpha=2,zeta=1")
	if results[0].Fingerprint != expectedBase {
		t.Errorf("the base JA4H value is %q, and it must stay %q",
			results[0].Fingerprint, expectedBase)
	}
}

// TestJA4H_RawStaysEmpty holds the rule that JA4H produces no sorted raw form.
//
// The FoxIO per-stream vector set publishes 89 `JA4H_ro` values and no `JA4H_r` value, so
// a sorted form matches no per-stream vector. `ja4plus/fingerprinters/ja4h.py:70` of the
// Python port states the same rule. #274 owns this decision.
//
// `conformance_adapters_test.go` emits a `JA4H_r` key only for a non-empty `Raw`, so an
// empty field reports no value rather than a wrong one.
func TestJA4H_RawStaysEmpty(t *testing.T) {
	requests := []struct {
		name string
		raw  string
	}{
		{
			name: "the request holds no cookie",
			raw: "GET /p HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
		},
		{
			name: "the request holds a cookie",
			raw: "GET /p HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Cookie: zeta=1; alpha=2\r\n" +
				"\r\n",
		},
	}

	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			packet := buildTCPPacketWithPayload(t, []byte(request.raw))
			results, err := NewJA4H().ProcessPacket(packet)
			if err != nil {
				t.Fatalf("ProcessPacket returned an error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
			}
			if results[0].Raw != "" {
				t.Errorf("Raw is %q, and JA4H fills no sorted raw form", results[0].Raw)
			}
		})
	}
}

// TestJA4H_RawOriginalOrderReachesTheReassembledPath proves that the multi-segment path
// fills the field that the single-packet path fills.
//
// The two paths build one result each, and a field that one path fills alone reports a
// value for one capture and no value for another.
func TestJA4H_RawOriginalOrderReachesTheReassembledPath(t *testing.T) {
	request := "GET /p HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"
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

	const expected = "ge11nn020000_Host,User-Agent_"
	if results[0].RawOriginalOrder != expected {
		t.Errorf("RawOriginalOrder is %q, and the test expects %q",
			results[0].RawOriginalOrder, expected)
	}
}
