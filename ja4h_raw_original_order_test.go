package ja4plus

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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

// TestJA4H_ThePerStreamVectorSetPublishesNoRawKey holds the reading that #274 recorded.
//
// The FoxIO per-stream vector set publishes 89 `JA4H_ro` values and no `JA4H_r` value.
// `ja4plus/fingerprinters/ja4h.py:70` of the Python port states the same rule, and #274
// left `Raw` empty for it.
//
// **The per-packet vector set disagrees, and it publishes 126 `ja4.ja4h_r` values.** #290
// recorded that difference, and #310 fills `Raw` for the per-packet set. This test states
// the per-stream half alone, so it names no rule about the per-packet set.
//
// The test reads the vector files rather than the library, because the claim is about the
// reference and not about this code. A later FoxIO release that publishes the key fails
// this test, and the reader then learns that the per-stream comparison gained a key.
func TestJA4H_ThePerStreamVectorSetPublishesNoRawKey(t *testing.T) {
	// The conformance suite carries a build tag, so this test names the directory itself.
	// `keylog_test.go` and `tunnel_keys_test.go` skip on an absent corpus the same way.
	const streamVectorDir = "testdata/foxio/python"

	if _, statErr := os.Stat(streamVectorDir); statErr != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", streamVectorDir)
	}

	paths, err := filepath.Glob(filepath.Join(streamVectorDir, "*.json"))
	if err != nil {
		t.Fatalf("the glob of %s returned an error: %v", streamVectorDir, err)
	}
	if len(paths) == 0 {
		t.Fatalf("%s holds no vector file", streamVectorDir)
	}

	originalOrderKeys := 0
	rawKeys := 0

	for _, path := range paths {
		content, readErr := os.ReadFile(path) // #nosec G304 -- the path comes from the corpus glob.
		if readErr != nil {
			t.Fatalf("reading %s returned an error: %v", path, readErr)
		}

		var entries []map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal(content, &entries); unmarshalErr != nil {
			t.Fatalf("parsing %s returned an error: %v", path, unmarshalErr)
		}

		for _, entry := range entries {
			if _, held := entry["JA4H_ro"]; held {
				originalOrderKeys++
			}
			if _, held := entry["JA4H_r"]; held {
				rawKeys++
			}
		}
	}

	if originalOrderKeys != 89 {
		t.Errorf("the per-stream set holds %d `JA4H_ro` keys, and #274 measured 89", originalOrderKeys)
	}
	if rawKeys != 0 {
		t.Errorf("the per-stream set holds %d `JA4H_r` keys, and #274 measured 0", rawKeys)
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
