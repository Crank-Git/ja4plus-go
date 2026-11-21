//go:build conformance

package ja4plus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/deviations"
)

// These tests hold FR-conformance-20 through FR-conformance-26. They run over fixture
// values, because the corpus reaches no unrecognized key and no adapter failure.
//
// `conformance_adapters_test.go` holds the two adapters. An adapter returns an error, and
// the caller fails the test, so a fixture proves the failure without a corpus.

// oneConformanceStreamEntry returns one per-stream vector entry that holds the four
// address fields and the named method keys.
func oneConformanceStreamEntry(methods map[string]string) conformanceStreamEntry {
	entry := conformanceStreamEntry{
		"stream":  json.RawMessage(`0`),
		"src":     json.RawMessage(`"192.168.133.129"`),
		"dst":     json.RawMessage(`"34.117.237.239"`),
		"srcport": json.RawMessage(`"36372"`),
		"dstport": json.RawMessage(`"443"`),
	}

	for key, value := range methods {
		encoded, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}

		entry[key] = encoded
	}

	return entry
}

// FR-conformance-22 matches a stream by the `src`, `dst`, `srcport` and `dstport` fields.
// A JA4 value travels from the client, and a JA4S value travels from the server, so the
// two directions of one stream must produce one key.
func TestTheStreamAdapterMatchesTheTwoDirectionsOfAStreamToOneKey(t *testing.T) {
	client := conformanceEndpointKey("192.168.133.129", 36372, "34.117.237.239", 443)
	server := conformanceEndpointKey("34.117.237.239", 443, "192.168.133.129", 36372)

	if client != server {
		t.Errorf("the adapter writes %q for the client direction and %q for the server direction, and FR-conformance-22 names one stream",
			client, server)
	}
}

// The adapter separates two streams that share an address and differ by one port.
func TestTheStreamAdapterSeparatesTwoStreamsThatDifferByOnePort(t *testing.T) {
	first := conformanceEndpointKey("192.168.1.191", 48456, "192.168.1.1", 8080)
	second := conformanceEndpointKey("192.168.1.191", 48458, "192.168.1.1", 8080)

	if first == second {
		t.Errorf("the adapter writes %q for two streams that differ by the source port", first)
	}
}

// FR-conformance-20 reads `JA4.1`, `JA4_r.1`, `JA4_o.1` and `JA4_ro.1`, and it maps each
// one to the matching field.
func TestTheStreamAdapterReadsTheFourJA4Keys(t *testing.T) {
	values := map[string]string{
		"JA4.1":    "t13d1715h2_5b57614c22b0_3d5424432f57",
		"JA4_r.1":  "t13d1715h2_002f,0035,009c,009d,1301,1302",
		"JA4_o.1":  "t13d1715h2_5b234860e130_014157ec0da2",
		"JA4_ro.1": "t13d1715h2_1301,1303,1302,c02b,c02f,cca9",
	}

	shape, err := conformanceExpectedFromStreamVector("tls12.pcap", []conformanceStreamEntry{
		oneConformanceStreamEntry(values),
	})
	if err != nil {
		t.Fatalf("the adapter rejects the four JA4 keys: %v", err)
	}

	for key, value := range values {
		got, held := shape.Expected[conformanceKey{Capture: "tls12.pcap", Stream: "0", Method: key}]
		if !held {
			t.Errorf("the adapter reads no value for the key %q", key)

			continue
		}

		if got != value {
			t.Errorf("the adapter reads %q for the key %q, and the vector holds %q", got, key, value)
		}
	}
}

// FR-conformance-21 reads the keys for JA4S, JA4H, JA4X and JA4SSH in the same way.
func TestTheStreamAdapterReadsTheKeysForJA4SAndJA4HAndJA4XAndJA4SSH(t *testing.T) {
	values := map[string]string{
		"JA4S":     "t120400_c02f_4993ccf7354b",
		"JA4S_r":   "t120400_c02f_0017,ff01,000b,0023",
		"JA4H":     "ge11nn07ruru_6cd0fb54989b_000000000000_000000000000",
		"JA4H_ro":  "ge11nn07ruru_Host,Accept,User-Agent",
		"JA4X.1":   "a373a9f83c6b_2bab15409345_7bf9a7bf7029",
		"JA4X.2":   "7d5dbb3783b4_a373a9f83c6b_a83ffcd6e6c2",
		"JA4SSH.1": "c76s76_c71s59_c0s72",
		"JA4L-C":   "414_128",
		"JA4L-S":   "12517_53",
	}

	shape, err := conformanceExpectedFromStreamVector("ssh2.pcapng", []conformanceStreamEntry{
		oneConformanceStreamEntry(values),
	})
	if err != nil {
		t.Fatalf("the adapter rejects a key of the corpus: %v", err)
	}

	if len(shape.Expected) != len(values) {
		t.Fatalf("the adapter reads %d values, and the fixture holds %d", len(shape.Expected), len(values))
	}

	// A key that carries an occurrence number and a key that carries none must both reach
	// the expected map under the form the vector writes.
	for key, value := range values {
		got := shape.Expected[conformanceKey{Capture: "ssh2.pcapng", Stream: "0", Method: key}]
		if got != value {
			t.Errorf("the adapter reads %q for the key %q, and the vector holds %q", got, key, value)
		}
	}

	// The library names a method without the occurrence number, so the adapter records
	// which form the vector writes for each method on each stream.
	if !shape.UsesOccurrence[conformanceKey{Capture: "ssh2.pcapng", Stream: "0", Method: "JA4X"}] {
		t.Errorf("the adapter reports that `JA4X` carries no occurrence number, and the vector writes `JA4X.1`")
	}

	if shape.UsesOccurrence[conformanceKey{Capture: "ssh2.pcapng", Stream: "0", Method: "JA4S"}] {
		t.Errorf("the adapter reports that `JA4S` carries an occurrence number, and the vector writes `JA4S`")
	}
}

// FoxIO writes one entry for each HTTP request, so more than one entry names one stream.
// `testdata/foxio/python/http2-with-cookies.pcapng.json` holds 16 entries for stream 0 that
// each carry the bare key `JA4H` with a different value. The adapter numbers them in entry
// order, because a single map write would keep the last value alone.
func TestTheStreamAdapterNumbersRepeatedValuesOfOneStreamInEntryOrder(t *testing.T) {
	values := []string{
		"ge11nn07ruru_6cd0fb54989b_000000000000_000000000000",
		"ge11nn08ruru_7cd0fb54989c_000000000000_000000000000",
		"po11nn050000_530ceba2075f_000000000000_000000000000",
	}

	entries := make([]conformanceStreamEntry, 0, len(values))
	for _, value := range values {
		entries = append(entries, oneConformanceStreamEntry(map[string]string{"JA4H": value}))
	}

	shape, err := conformanceExpectedFromStreamVector("http2-with-cookies.pcapng", entries)
	if err != nil {
		t.Fatalf("the adapter rejects three entries that name one stream: %v", err)
	}

	if len(shape.Expected) != len(values) {
		t.Fatalf("the adapter reads %d values, and the three entries hold %d", len(shape.Expected), len(values))
	}

	for index, value := range values {
		key := conformanceKey{
			Capture: "http2-with-cookies.pcapng",
			Stream:  "0",
			Method:  "JA4H." + strconv.Itoa(index+1),
		}

		got, held := shape.Expected[key]
		if !held {
			t.Errorf("the adapter writes no value under the key %q", key)

			continue
		}

		if got != value {
			t.Errorf("the adapter writes %q under the key %q, and entry %d holds %q", got, key, index, value)
		}
	}

	// The produced key must follow the same form, so the producer reads the decision under
	// the capture, the stream and the method.
	if !shape.UsesOccurrence[conformanceKey{Capture: "http2-with-cookies.pcapng", Stream: "0", Method: "JA4H"}] {
		t.Errorf("the adapter reports that `JA4H` on stream 0 carries no occurrence number, and three entries name that stream")
	}
}

// One stream that holds one value keeps the bare key, because that is the form the vector
// writes. The decision is per stream, so one capture can hold both forms.
func TestTheStreamAdapterKeepsTheBareKeyForAStreamThatHoldsOneValue(t *testing.T) {
	first := oneConformanceStreamEntry(map[string]string{"JA4H": "a"})
	second := oneConformanceStreamEntry(map[string]string{"JA4H": "b"})
	second["stream"] = json.RawMessage(`1`)
	second["srcport"] = json.RawMessage(`"36373"`)
	third := oneConformanceStreamEntry(map[string]string{"JA4H": "c"})
	third["stream"] = json.RawMessage(`1`)
	third["srcport"] = json.RawMessage(`"36373"`)

	shape, err := conformanceExpectedFromStreamVector("http1.pcapng", []conformanceStreamEntry{first, second, third})
	if err != nil {
		t.Fatalf("the adapter rejects the entries: %v", err)
	}

	wanted := map[conformanceKey]string{
		{Capture: "http1.pcapng", Stream: "0", Method: "JA4H"}:   "a",
		{Capture: "http1.pcapng", Stream: "1", Method: "JA4H.1"}: "b",
		{Capture: "http1.pcapng", Stream: "1", Method: "JA4H.2"}: "c",
	}

	if len(shape.Expected) != len(wanted) {
		t.Fatalf("the adapter reads %d values, and the three entries hold %d", len(shape.Expected), len(wanted))
	}

	for key, value := range wanted {
		if got := shape.Expected[key]; got != value {
			t.Errorf("the adapter writes %q under the key %q, and the vector holds %q", got, key, value)
		}
	}
}

// oneConformanceQuicStreamEntry returns one per-stream vector entry of
// `chrome-cloudflare-quic-with-secrets.pcapng`. The two connections of that capture share
// the two addresses and the destination port, and the source port keeps them apart.
func oneConformanceQuicStreamEntry(sourcePort string, methods map[string]string) conformanceStreamEntry {
	entry := oneConformanceStreamEntry(methods)
	entry["src"] = json.RawMessage(`"2001:db8:1::1"`)
	entry["dst"] = json.RawMessage(`"2606:4700:10::6816:826"`)
	entry["srcport"] = json.RawMessage(`"` + sourcePort + `"`)

	return entry
}

// `tcp.stream` and `udp.stream` are two counters, and both start at 0. One capture
// therefore names a TCP connection and a UDP connection with the stream number `0`.
// `chrome-cloudflare-quic-with-secrets.pcapng` holds such a pair on the source ports
// `57098` and `50280`, and the vector keeps the two apart by the source port.
//
// A stream name that holds the stream number alone merges the two connections. The harness
// then reports a value of the second connection as a later occurrence of the first, and the
// report names a connection that produced no such value. Issue #250 holds the reading.
func TestTheStreamAdapterKeepsTwoConnectionsOfOneStreamNumberApart(t *testing.T) {
	const capture = "chrome-cloudflare-quic-with-secrets.pcapng"

	shape, err := conformanceExpectedFromStreamVector(capture, []conformanceStreamEntry{
		oneConformanceQuicStreamEntry("57098", map[string]string{"JA4L-C": "149_64"}),
		oneConformanceQuicStreamEntry("50280", map[string]string{"JA4L-C": "113_64"}),
	})
	if err != nil {
		t.Fatalf("the adapter rejects the two entries: %v", err)
	}

	wanted := map[conformanceKey]string{
		{Capture: capture, Stream: "0:57098", Method: "JA4L-C"}: "149_64",
		{Capture: capture, Stream: "0:50280", Method: "JA4L-C"}: "113_64",
	}

	if len(shape.Expected) != len(wanted) {
		t.Fatalf("the adapter reads %d values, and the two connections hold %d", len(shape.Expected), len(wanted))
	}

	for key, value := range wanted {
		if got := shape.Expected[key]; got != value {
			t.Errorf("the adapter writes %q under the key %q, and the vector holds %q", got, key, value)
		}
	}

	// The producer reads the stream name from this map, so a name the two sides do not
	// share produces a deviation on every value of the capture.
	for port, stream := range map[uint16]string{57098: "0:57098", 50280: "0:50280"} {
		endpoint := conformanceEndpointKey("2001:db8:1::1", port, "2606:4700:10::6816:826", 443)
		if got := shape.StreamOfEndpoint[endpoint]; got != stream {
			t.Errorf("the adapter names the connection on the source port %d %q, and the expected key holds %q",
				port, got, stream)
		}
	}
}

// FoxIO writes one entry for each HTTP request, and it swaps the two ends between a request
// and a response. `http2-with-cookies.pcapng` writes the source port `58847` and then `443`
// for one connection, so the source port of one entry names no connection.
//
// The stream name reads the source port of the first entry of the connection. A name that
// read the source port of each entry would give one connection two names, and the values of
// that connection would then reach two keys.
func TestTheStreamNameReadsTheSourcePortOfTheFirstEntryOfAConnection(t *testing.T) {
	const capture = "chrome-cloudflare-quic-with-secrets.pcapng"

	request := oneConformanceQuicStreamEntry("57098", map[string]string{"JA4": "a"})

	response := oneConformanceStreamEntry(map[string]string{"JA4S": "b"})
	response["src"] = json.RawMessage(`"2606:4700:10::6816:826"`)
	response["dst"] = json.RawMessage(`"2001:db8:1::1"`)
	response["srcport"] = json.RawMessage(`"443"`)
	response["dstport"] = json.RawMessage(`"57098"`)

	shape, err := conformanceExpectedFromStreamVector(capture, []conformanceStreamEntry{
		request,
		response,
		oneConformanceQuicStreamEntry("50280", map[string]string{"JA4L-C": "113_64"}),
	})
	if err != nil {
		t.Fatalf("the adapter rejects the three entries: %v", err)
	}

	wanted := map[conformanceKey]string{
		{Capture: capture, Stream: "0:57098", Method: "JA4"}:    "a",
		{Capture: capture, Stream: "0:57098", Method: "JA4S"}:   "b",
		{Capture: capture, Stream: "0:50280", Method: "JA4L-C"}: "113_64",
	}

	if len(shape.Expected) != len(wanted) {
		t.Fatalf("the adapter reads %d values, and the three entries hold %d", len(shape.Expected), len(wanted))
	}

	for key, value := range wanted {
		if got := shape.Expected[key]; got != value {
			t.Errorf("the adapter writes %q under the key %q, and the vector holds %q", got, key, value)
		}
	}
}

// A stream number that names one connection keeps the bare number. A register key of
// `testdata/deviations.json` therefore names the comparison it named before, and the
// disambiguation reaches the colliding stream number alone.
func TestTheStreamAdapterKeepsTheBareNumberForAStreamNumberOfOneConnection(t *testing.T) {
	shape, err := conformanceExpectedFromStreamVector("tls12.pcap", []conformanceStreamEntry{
		oneConformanceStreamEntry(map[string]string{"JA4S": "t130200_1301_234ea6891581"}),
	})
	if err != nil {
		t.Fatalf("the adapter rejects the entry: %v", err)
	}

	key := conformanceKey{Capture: "tls12.pcap", Stream: "0", Method: "JA4S"}
	if _, held := shape.Expected[key]; !held {
		t.Errorf("the adapter writes no value under the key %q", key)
	}
}

// The adapter keeps the occurrence number that the vector writes, and it never renumbers
// one. `JA4X.1` and `JA4X.2` on one stream stay `JA4X.1` and `JA4X.2`.
func TestTheStreamAdapterKeepsTheOccurrenceNumberTheVectorWrites(t *testing.T) {
	entry := oneConformanceStreamEntry(map[string]string{
		"JA4X.1": "a373a9f83c6b_2bab15409345_7bf9a7bf7029",
		"JA4X.2": "7d5dbb3783b4_a373a9f83c6b_a83ffcd6e6c2",
	})

	shape, err := conformanceExpectedFromStreamVector("ssh2.pcapng", []conformanceStreamEntry{entry})
	if err != nil {
		t.Fatalf("the adapter rejects the entry: %v", err)
	}

	for method, value := range map[string]string{
		"JA4X.1": "a373a9f83c6b_2bab15409345_7bf9a7bf7029",
		"JA4X.2": "7d5dbb3783b4_a373a9f83c6b_a83ffcd6e6c2",
	} {
		got := shape.Expected[conformanceKey{Capture: "ssh2.pcapng", Stream: "0", Method: method}]
		if got != value {
			t.Errorf("the adapter writes %q under the method %q, and the vector holds %q", got, method, value)
		}
	}
}

// The adapter recognizes every stream field that the corpus holds. A stream field names
// the connection or the capture, and it is not a fingerprint.
func TestTheStreamAdapterRecognizesEveryStreamFieldOfTheCorpus(t *testing.T) {
	// The nine fields come from a count over `testdata/foxio/python/` at the pinned
	// commit. `domain`, `client_ttl`, `server_ttl` and `ssh_extras` carry an input of a
	// fingerprint, and never a fingerprint.
	fields := []string{
		"stream", "src", "dst", "srcport", "dstport",
		"domain", "client_ttl", "server_ttl", "ssh_extras",
	}

	for _, field := range fields {
		_, _, isMethod, err := conformanceRecognizeStreamKey(field)
		if err != nil {
			t.Errorf("the adapter rejects the stream field %q: %v", field, err)
		}

		if isMethod {
			t.Errorf("the adapter reads the stream field %q as a method", field)
		}
	}
}

// FR-conformance-26 fails the test when an adapter meets a key it does not recognize. A
// skipped key hides a method that FoxIO added.
func TestTheStreamAdapterReturnsAnErrorForAKeyItDoesNotRecognize(t *testing.T) {
	cases := []string{"JA4Q.1", "ja4", "JA4.0", "JA4.x", "tls_version"}

	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			if _, _, _, err := conformanceRecognizeStreamKey(key); err == nil {
				t.Errorf("the adapter accepts the key %q, and FR-conformance-26 fails the test for a key it does not recognize", key)
			}
		})
	}
}

// FR-conformance-26 covers the per-packet adapter as well.
func TestThePacketAdapterReturnsAnErrorForAFieldItDoesNotRecognize(t *testing.T) {
	cases := []string{"ja4.ja4q", "frame.time", "ja4"}

	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			if _, _, err := conformanceRecognizePacketField(field); err == nil {
				t.Errorf("the adapter accepts the field %q, and FR-conformance-26 fails the test for a field it does not recognize", field)
			}
		})
	}
}

// `ja4.ja4l_delta` and `ja4.ja4ls_delta` hold a ratio of two durations, and neither is a
// fingerprint. `docs/specs/foxio/JA4L.md` R23 and R24 record the reading, and
// `docs/specs/foxio/zeek.md:95` records that this project declines both as a reference
// value. The adapter therefore recognizes each one as a field that names no method.
func TestThePacketAdapterReadsTheTwoLatencyRatiosAsFieldsThatNameNoMethod(t *testing.T) {
	for _, field := range []string{"ja4.ja4l_delta", "ja4.ja4ls_delta"} {
		t.Run(field, func(t *testing.T) {
			_, isMethod, err := conformanceRecognizePacketField(field)
			if err != nil {
				t.Errorf("the adapter rejects the field %q: %v", field, err)
			}

			if isMethod {
				t.Errorf("the adapter reads the field %q as a method, and the field holds a ratio of two durations", field)
			}
		})
	}
}

// FR-conformance-25 makes the per-packet adapter authoritative for JA4D and JA4D6. FoxIO
// writes the two under the single field `ja4.ja4d`, and this library writes the types
// `ja4d` and `ja4d6`. The per-stream vector for `dhcpv6.pcap` is an empty list, so no
// other vector reaches JA4D6.
func TestThePacketAdapterCompares_TheJA4D6TypeAgainstTheSingleJA4DField(t *testing.T) {
	method, _, held := conformanceMethodOfResultType(FingerprintResult{
		Type:        "ja4d6",
		Fingerprint: "sold0000in_1-3-6-42_1-2-3",
	})
	if !held {
		t.Fatalf("the suite compares no value for the type `ja4d6`, and FR-conformance-25 makes the per-packet adapter authoritative for JA4D6")
	}

	if method != conformancePacketMethods["ja4.ja4d"] {
		t.Errorf("the suite maps the type `ja4d6` to the method %q, and FoxIO writes JA4D6 under the field `ja4.ja4d`", method)
	}
}

// The per-stream adapter reads no method for a type that the per-stream vector never
// names. The per-stream set holds no key for JA4D, JA4D6, JA4T or JA4TS.
func TestTheStreamAdapterReadsNoMethodForATypeThePerStreamVectorNeverNames(t *testing.T) {
	for _, resultType := range []string{"ja4d", "ja4d6", "ja4t", "ja4ts"} {
		t.Run(resultType, func(t *testing.T) {
			if _, _, held := conformanceStreamMethodOfResult(FingerprintResult{Type: resultType, Fingerprint: "value"}); held {
				t.Errorf("the adapter reads a per-stream method for the type %q, and the per-stream set names none", resultType)
			}
		})
	}
}

// The library writes the form `JA4L-C=<latency>_<ttl>`, and the per-stream vector writes
// the key `JA4L-C` with the value alone. A comparison that kept the label would never
// match.
func TestTheStreamAdapterReadsTheLabelOfAJA4LFingerprintAsTheMethod(t *testing.T) {
	cases := []struct {
		fingerprint string
		method      string
		value       string
	}{
		{"JA4L-C=414_128", "JA4L-C", "414_128"},
		{"JA4L-S=12517_53", "JA4L-S", "12517_53"},
	}

	for _, testCase := range cases {
		t.Run(testCase.method, func(t *testing.T) {
			method, value, held := conformanceStreamMethodOfResult(FingerprintResult{
				Type:        "ja4l",
				Fingerprint: testCase.fingerprint,
			})
			if !held {
				t.Fatalf("the adapter reads no method for the fingerprint %q", testCase.fingerprint)
			}

			if method != testCase.method || value != testCase.value {
				t.Errorf("the adapter reads the method %q and the value %q, and the vector names %q and %q",
					method, value, testCase.method, testCase.value)
			}
		})
	}
}

// A per-stream vector that holds an empty list produces no comparison. The vector for
// `dhcpv6.pcap` is exactly `[]` at the pinned commit.
func TestTheStreamAdapterReadsAnEmptyVectorAsNoValue(t *testing.T) {
	shape, err := conformanceExpectedFromStreamVector("dhcpv6.pcap", nil)
	if err != nil {
		t.Fatalf("the adapter rejects an empty per-stream vector: %v", err)
	}

	if len(shape.Expected) != 0 {
		t.Errorf("the adapter reads %d values from an empty per-stream vector", len(shape.Expected))
	}
}

// The adapter fails when one capture writes one method in the two key forms. The
// produced key form follows the vector, so two forms for one method name two different
// comparisons for one value.
func TestTheStreamAdapterReturnsAnErrorWhenOneMethodCarriesTwoKeyForms(t *testing.T) {
	_, err := conformanceExpectedFromStreamVector("mixed.pcap", []conformanceStreamEntry{
		oneConformanceStreamEntry(map[string]string{"JA4S": "a"}),
		oneConformanceStreamEntry(map[string]string{"JA4S.1": "b"}),
	})
	if err == nil {
		t.Errorf("the adapter accepts `JA4S` and `JA4S.1` in one capture, and the two forms name one method")
	}
}

// The adapter names the stream of an entry by the `stream` field, so a register key reads
// as `testdata/README.md` writes it.
func TestTheStreamAdapterNamesTheStreamByTheStreamField(t *testing.T) {
	entry := oneConformanceStreamEntry(map[string]string{"JA4S": "t120400_c02f_4993ccf7354b"})
	entry["stream"] = json.RawMessage(`15`)

	shape, err := conformanceExpectedFromStreamVector("ssh2.pcapng", []conformanceStreamEntry{entry})
	if err != nil {
		t.Fatalf("the adapter rejects the entry: %v", err)
	}

	key := conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4S"}
	if _, held := shape.Expected[key]; !held {
		t.Fatalf("the adapter writes no value under the key %q", key)
	}

	if err := deviations.CheckKey(key.String()); err != nil {
		t.Errorf("the register reader rejects the key %q: %v", key.String(), err)
	}
}

// One vector entry names one connection, so the last-emission rule of issue #196 reads one
// connection and never one stream number. FoxIO writes the stream number `0` for two
// connections of `chrome-cloudflare-quic-with-secrets.pcapng`. The first one carries TCP on
// the source port `57098`, and the second one carries QUIC on the source port `50280`. The
// client point of the TCP connection moves, so the library reports `30_64` and then `149_64`
// for it. Issue #215 holds the reading.
//
// Issue #250 separates the two connections, so each one keeps the bare key `JA4L-C` and the
// stream name carries the source port.
func TestTheStreamAdapterReportsOneJA4LCValuePerConnectionOnChromeCloudflareQuic(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	const capture = "chrome-cloudflare-quic-with-secrets.pcapng"

	path := conformanceVectorPath(conformanceStreamVectorDir, capture)
	if path == "" {
		t.Fatalf("the corpus holds no per-stream vector for %s", capture)
	}

	shape, err := conformanceExpectedFromStreamVector(capture, conformanceReadStreamVector(t, path))
	if err != nil {
		t.Fatalf("the per-stream adapter fails: %v", err)
	}

	packets := loadPCAP(t, filepath.Join(conformanceCaptureDir, capture))
	produced := conformanceProducedByStream(t, capture, packets, shape)

	tcp := conformanceKey{Capture: capture, Stream: "0:57098", Method: "JA4L-C"}
	if produced[tcp] != "149_64" {
		t.Errorf("the harness reports %q for %q, and the last value of the TCP connection is `149_64`",
			produced[tcp], tcp)
	}

	quic := conformanceKey{Capture: capture, Stream: "0:50280", Method: "JA4L-C"}
	if produced[quic] != "113_64_quic" {
		t.Errorf("the harness reports %q for %q, and the last value of the QUIC connection is `113_64_quic`",
			produced[quic], quic)
	}

	// A value of one connection numbered as a later occurrence of the other is the defect
	// that issue #250 repairs. Each connection reports one JA4L-C value, so no occurrence
	// number reaches the key.
	for _, method := range []string{"JA4L-C.1", "JA4L-C.2", "JA4L-C.3"} {
		for _, stream := range []string{"0", "0:57098", "0:50280"} {
			numbered := conformanceKey{Capture: capture, Stream: stream, Method: method}
			if value, held := produced[numbered]; held {
				t.Errorf("the harness reports %q for %q, and each connection reports one JA4L-C value",
					value, numbered)
			}
		}
	}
}

// These tests hold FR-conformance-27 through FR-conformance-33.
//
// They run over fixture values, because the corpus reaches only the cases the corpus
// holds. `conformance_report_test.go` holds the renderer, and `conformance_test.go` fills
// it from the corpus.

// oneConformanceReport returns a report over one capture, one match and one deviation.
func oneConformanceReport() *conformanceReport {
	report := newConformanceReport("27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8")
	report.readCapture("tls12.pcap")

	report.recordComparison("tls12.pcap", "per-stream", conformanceComparison{
		Matches: 1,
		Matched: []conformanceKey{{Capture: "tls12.pcap", Stream: "0", Method: "JA4.1"}},
		Deviations: []conformanceDeviation{{
			Key:      conformanceKey{Capture: "tls12.pcap", Stream: "0", Method: "JA4_o.1"},
			Kind:     conformanceAbsentValue,
			Expected: "t13d1715h2_5b234860e130_014157ec0da2",
		}},
	})

	return report
}

// conformanceRowOf returns the row of one capture and one method.
func conformanceRowOf(t *testing.T, report *conformanceReport, capture, method string) conformanceReportRow {
	t.Helper()

	for _, row := range report.rows() {
		if row.Capture == capture && row.Method == method {
			return row
		}
	}

	t.Fatalf("the report holds no row for the capture %q and the method %q", capture, method)

	return conformanceReportRow{}
}

// The raw form of a method is a form of that method, and never a method of its own. The
// `## Terms` table of `docs/specs/spec.md` names twelve methods, and `raw form` names
// `JA4_r` as a form of JA4.
func TestTheReportReadsARawFormKeyAsItsMethod(t *testing.T) {
	cases := map[string]string{
		"JA4.1":     "JA4",
		"JA4_r.1":   "JA4",
		"JA4_o.1":   "JA4",
		"JA4_ro.1":  "JA4",
		"JA4S":      "JA4S",
		"JA4S_r.2":  "JA4S",
		"JA4H_ro.3": "JA4H",
		"JA4X_r":    "JA4X",
		"JA4SSH.11": "JA4SSH",
		"JA4T.1":    "JA4T",
		"JA4TS.1":   "JA4TS",
		"JA4D.1":    "JA4D",
		// The per-stream vector names the two JA4L methods `JA4L-C` and `JA4L-S`, and the
		// per-packet vector names them `ja4.ja4l` and `ja4.ja4ls`.
		"JA4L-C":  "JA4L",
		"JA4L-S":  "JA4LS",
		"JA4L.1":  "JA4L",
		"JA4LS.1": "JA4LS",
	}

	for key, wanted := range cases {
		t.Run(key, func(t *testing.T) {
			method, err := conformanceReportMethodOf(key)
			if err != nil {
				t.Fatalf("the report rejects the key %q: %v", key, err)
			}

			if method != wanted {
				t.Errorf("the report reads the key %q as the method %q, and it names %q", key, method, wanted)
			}
		})
	}
}

// A key the report cannot place is a defect of the harness. A silent drop would lose a
// comparison from the table that FR-conformance-28 states.
func TestTheReportRejectsAMethodKeyItDoesNotRecognize(t *testing.T) {
	if _, err := conformanceReportMethodOf("JA4TScan.1"); err == nil {
		t.Error("the report reads the key `JA4TScan.1`, and the FoxIO corpus holds no vector for that method")
	}
}

// FR-conformance-28 holds one row for each capture and each method.
func TestTheReportHoldsOneRowForEachCaptureAndEachMethod(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("tls12.pcap")
	report.readCapture("dhcp.pcapng")

	rows := report.rows()

	wanted := 2 * len(conformanceReportMethods)
	if len(rows) != wanted {
		t.Fatalf("the report holds %d rows, and 2 captures times %d methods make %d",
			len(rows), len(conformanceReportMethods), wanted)
	}

	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		key := row.Capture + "/" + row.Method
		if seen[key] {
			t.Errorf("the report holds the row %q twice", key)
		}

		seen[key] = true
	}
}

// FR-conformance-29 records `match`, `deviation` or `not applicable` in each row.
func TestTheReportRecordsOneOfTheThreeResultsInEachRow(t *testing.T) {
	report := oneConformanceReport()

	held := map[conformanceReportResult]bool{
		conformanceReportMatch:         true,
		conformanceReportDeviation:     true,
		conformanceReportNotApplicable: true,
	}

	for _, row := range report.rows() {
		if !held[row.Result] {
			t.Errorf("the row %s/%s records the result %q, and FR-conformance-29 names three",
				row.Capture, row.Method, row.Result)
		}
	}
}

// FR-conformance-33 records `not applicable` only when the vector holds no value for the
// method on the capture. A comparison that fails is a deviation, and never `not
// applicable`.
func TestTheReportRecordsNotApplicableOnlyWhereNoVectorHoldsAValue(t *testing.T) {
	report := oneConformanceReport()

	// The fixture compares JA4 on the capture, and the comparison holds one match and one
	// deviation. A deviation outranks a match, because a row that reads `match` while a
	// deviation stands hides the deviation.
	if row := conformanceRowOf(t, report, "tls12.pcap", "JA4"); row.Result != conformanceReportDeviation {
		t.Errorf("the JA4 row records %q, and the comparison holds one deviation", row.Result)
	}

	// No vector of the fixture holds a JA4SSH value, so the row records `not applicable`.
	if row := conformanceRowOf(t, report, "tls12.pcap", "JA4SSH"); row.Result != conformanceReportNotApplicable {
		t.Errorf("the JA4SSH row records %q, and no vector holds a JA4SSH value", row.Result)
	}
}

// A row that holds every match and no deviation records `match`.
func TestTheReportRecordsAMatchWhereEveryComparisonMatches(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("dhcp.pcapng")
	report.recordComparison("dhcp.pcapng", "per-packet", conformanceComparison{
		Matches: 2,
		Matched: []conformanceKey{
			{Capture: "dhcp.pcapng", Stream: "1", Method: "JA4D.1"},
			{Capture: "dhcp.pcapng", Stream: "2", Method: "JA4D.1"},
		},
	})

	row := conformanceRowOf(t, report, "dhcp.pcapng", "JA4D")

	if row.Result != conformanceReportMatch {
		t.Errorf("the JA4D row records %q, and the two comparisons match", row.Result)
	}

	if row.Matches != 2 || row.Deviations != 0 {
		t.Errorf("the JA4D row counts %d matches and %d deviations, and the comparison holds 2 and 0",
			row.Matches, row.Deviations)
	}

	if row.Set != "per-packet" {
		t.Errorf("the JA4D row names the vector set %q, and the per-packet vector holds the value", row.Set)
	}
}

// A `not applicable` row states why the suite compares nothing. A reader who meets an
// empty row cannot tell an absent vector from a defect of the harness.
func TestTheReportStatesTheReasonOfEachNotApplicableRow(t *testing.T) {
	report := oneConformanceReport()

	for _, row := range report.rows() {
		if row.Result == conformanceReportNotApplicable && row.Reason == "" {
			t.Errorf("the row %s/%s records `not applicable` and states no reason", row.Capture, row.Method)
		}
	}
}

// FoxIO marks one capture `notest`, and the suite compares no value on it. Every row of
// that capture names the marker as the reason.
func TestTheReportNamesTheNotestMarkerAsTheReasonOfADeclinedCapture(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.declineCapture("dtls-udp.notest.cap", conformanceReportNotestReason)

	row := conformanceRowOf(t, report, "dtls-udp.notest.cap", "JA4")

	if row.Result != conformanceReportNotApplicable {
		t.Errorf("the row records %q, and FoxIO marks the capture `notest`", row.Result)
	}

	if !strings.Contains(row.Reason, "notest") {
		t.Errorf("the row states the reason %q, and it does not name the marker", row.Reason)
	}
}

// FR-conformance-30 names the fetched FoxIO commit.
func TestTheReportNamesTheFetchedFoxIOCommit(t *testing.T) {
	commit := "27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8"

	if text := oneConformanceReport().render(); !strings.Contains(text, commit) {
		t.Errorf("the report does not name the fetched FoxIO commit %s", commit)
	}
}

// FR-conformance-31 names the count of captures, the count of matches and the count of
// deviations.
func TestTheReportNamesTheCountOfCapturesMatchesAndDeviations(t *testing.T) {
	text := oneConformanceReport().render()

	for _, line := range []string{
		"| Captures | 1 |",
		"| Matches | 1 |",
		"| Deviations | 1 |",
	} {
		if !strings.Contains(text, line) {
			t.Errorf("the report holds no summary line %q", line)
		}
	}
}

// FR-conformance-32 records the expected value and the produced value of each deviation.
func TestTheReportWritesTheExpectedValueAndTheProducedValueOfEachDeviation(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh2.pcapng")
	report.recordComparison("ssh2.pcapng", "per-packet", conformanceComparison{
		Deviations: []conformanceDeviation{{
			Key:      conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4SSH.1"},
			Kind:     conformanceChangedValue,
			Expected: "c36s36_c55s53_c14s14",
			Produced: "c36s36_c55s53_c13s14",
		}},
	})

	text := report.render()

	for _, value := range []string{"c36s36_c55s53_c14s14", "c36s36_c55s53_c13s14"} {
		if !strings.Contains(text, value) {
			t.Errorf("the report does not hold the value %q", value)
		}
	}
}

// The report is tracked in git, so its size lands in every future diff. The corpus reports
// 3431 deviations at the pinned commit. The three SSH captures carry more than half of
// them. The report therefore holds at most `conformanceReportSampleLimit` deviation rows
// for one capture, one method and one vector set. It states the full count of the group.
// `conformance.log` holds every deviation, and the CI job uploads it.
func TestTheReportBoundsTheDeviationRowsOfOneGroup(t *testing.T) {
	deviations := make([]conformanceDeviation, 0, 10)

	for index := range 10 {
		deviations = append(deviations, conformanceDeviation{
			Key:      conformanceKey{Capture: "ssh-r.pcap", Stream: "0", Method: conformanceMethodOccurrence("JA4SSH", index+1)},
			Kind:     conformanceAbsentValue,
			Expected: "c36s36_c55s53_c14s14",
		})
	}

	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh-r.pcap")
	report.recordComparison("ssh-r.pcap", "per-stream", conformanceComparison{Deviations: deviations})

	groups := report.deviationGroups()
	if len(groups) != 1 {
		t.Fatalf("the report holds %d deviation groups, and the fixture holds one", len(groups))
	}

	if groups[0].Count != 10 {
		t.Errorf("the group counts %d deviations, and the fixture holds 10", groups[0].Count)
	}

	if len(groups[0].Samples) != conformanceReportSampleLimit {
		t.Errorf("the group holds %d deviation rows, and the report bounds a group at %d",
			len(groups[0].Samples), conformanceReportSampleLimit)
	}

	// A reader must find the deviations the report leaves out.
	if !strings.Contains(report.render(), "conformance.log") {
		t.Error("the report does not name `conformance.log`, which holds every deviation")
	}
}

// A report that changes between two runs over one corpus fills every future diff with
// noise. A range over a map orders nothing, so the renderer sorts every table.
func TestTheReportRendersTheSameTextForTheSameRun(t *testing.T) {
	if first, second := oneConformanceReport().render(), oneConformanceReport().render(); first != second {
		t.Error("the report renders two different texts for one run")
	}
}

// The engine counts a match, and the report needs the key of each one to place it in a
// row.
func TestTheComparisonNamesEveryKeyThatMatches(t *testing.T) {
	key := oneConformanceKey("JA4")
	value := "t13d1715h2_5b57614c22b0_3d5424432f57"

	result := compareConformance(
		map[conformanceKey]string{key: value},
		map[conformanceKey]string{key: value},
		nil,
	)

	if len(result.Matched) != 1 || result.Matched[0] != key {
		t.Fatalf("the comparison names %v as the keys that match, and the fixture holds %q", result.Matched, key)
	}
}

// #307 makes a stale register entry a fourth kind. The report names the key, the recorded
// value and the produced value, so a reader repairs the entry without a rerun.
func TestTheReportNamesEveryStaleRegisterEntry(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh2.pcapng")
	report.recordComparison("ssh2.pcapng", "per-packet", conformanceComparison{
		Stale: []conformanceStaleEntry{{
			Key:      conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4SSH.1"},
			Recorded: "c36s36_c55s53_c14s14",
			Produced: "c36s36_c55s53_c13s14",
		}},
	})

	text := report.render()

	for _, wanted := range []string{
		"## Stale register entries",
		"| Stale register entries | 1 |",
		"ssh2.pcapng/15/JA4SSH.1",
		"c36s36_c55s53_c14s14",
		"c36s36_c55s53_c13s14",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// The report collects a stale entry in the order the run reaches each capture, and it sorts
// the section by key. An unsorted section changes on a run that reads the captures in
// another order.
func TestTheReportSortsTheStaleRegisterEntriesByKey(t *testing.T) {
	report := newConformanceReport("27f0cbf")

	for _, capture := range []string{"tls12.pcap", "dhcp.pcapng"} {
		report.readCapture(capture)
		report.recordComparison(capture, "per-stream", conformanceComparison{
			Stale: []conformanceStaleEntry{{
				Key:      conformanceKey{Capture: capture, Stream: "1", Method: "JA4"},
				Recorded: "recorded-" + capture,
				Produced: "produced-" + capture,
			}},
		})
	}

	text := report.render()

	first := strings.Index(text, "`dhcp.pcapng/1/JA4`")
	second := strings.Index(text, "`tls12.pcap/1/JA4`")

	if first < 0 || second < 0 {
		t.Fatalf("the report holds %d stale rows, and the fixture holds 2", len(report.stale))
	}

	if first > second {
		t.Errorf("the report writes `tls12.pcap/1/JA4` before `dhcp.pcapng/1/JA4`, and the sorted order names `dhcp.pcapng` first")
	}
}

// A run that reaches every recorded value states that result. A section a reader finds
// empty says nothing about the register.
func TestTheReportStatesThatARunReportsNoStaleRegisterEntry(t *testing.T) {
	text := oneConformanceReport().render()

	for _, wanted := range []string{
		"| Stale register entries | 0 |",
		"The run reports no stale register entry.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// #328 makes an orphan register entry a fifth kind. The report names the key and the
// recorded value, so a reader repairs the entry without a rerun.
func TestTheReportNamesEveryOrphanRegisterEntry(t *testing.T) {
	orphan := conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4SSH.9"}

	report := newConformanceReport("27f0cbf")
	report.readCapture("ssh2.pcapng")
	report.recordOrphans(map[conformanceKey]deviations.Entry{
		orphan: {Key: orphan.String(), Ours: "c36s36_c55s53_c14s14", Theirs: "c36s36_c55s53_c13s14", Ruling: "#19"},
	})

	text := report.render()

	for _, wanted := range []string{
		"## Orphan register entries",
		"| Orphan register entries | 1 |",
		"ssh2.pcapng/15/JA4SSH.9",
		"c36s36_c55s53_c14s14",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// The report subtracts the keys of every comparison from the register. An entry whose key
// one comparison reaches is no orphan entry.
func TestTheReportNamesNoOrphanEntryForAKeyAComparisonReaches(t *testing.T) {
	reached := conformanceKey{Capture: "tls12.pcap", Stream: "0", Method: "JA4_o.1"}

	report := oneConformanceReport()
	report.recordComparison("tls12.pcap", "per-stream", conformanceComparison{Reached: []conformanceKey{reached}})
	report.recordOrphans(map[conformanceKey]deviations.Entry{
		reached: {Key: reached.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
	})

	text := report.render()

	for _, wanted := range []string{
		"| Orphan register entries | 0 |",
		"The run reports no orphan register entry.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// A run that reaches every register key states that result. A section a reader finds empty
// says nothing about the register.
func TestTheReportStatesThatARunReportsNoOrphanRegisterEntry(t *testing.T) {
	text := oneConformanceReport().render()

	for _, wanted := range []string{
		"| Orphan register entries | 0 |",
		"The run reports no orphan register entry.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// The report is tracked, and FR-conformance-27 rewrites it on every run. This test reads
// the tracked file and proves its path and its shape. `TestConformance` fails the run when
// the write itself fails, and the two checks together hold FR-conformance-27.
func TestTheTrackedConformanceReportHoldsTheReportShape(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	content, err := os.ReadFile(conformanceReportPath)
	if err != nil {
		t.Fatalf("read %s: %v", conformanceReportPath, err)
	}

	text := string(content)

	for _, wanted := range []string{"# FoxIO conformance report", "| Captures |", "## Results"} {
		if !strings.Contains(text, wanted) {
			t.Errorf("%s does not hold %q", conformanceReportPath, wanted)
		}
	}
}

// FR-conformance-33q names the count of uncovered values, and FR-conformance-33s states the
// count of each capture, each vector set and each method. A reader therefore reads the count
// of one method without a rerun.
func TestTheReportStatesTheUncoveredValueCountOfEachMethod(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("https-connect.pcap")
	report.recordComparison("https-connect.pcap", conformanceReportPacketSet, conformanceComparison{
		Uncovered: []conformanceUncoveredValue{
			{Key: conformanceKey{Capture: "https-connect.pcap", Stream: "3", Method: "JA4L.1"}, Produced: "45_64"},
			{
				Key:      conformanceKey{Capture: "https-connect.pcap", Stream: "5", Method: "JA4LS.1"},
				Produced: "13532_57",
				Accepted: true,
			},
		},
	})

	text := report.render()

	for _, wanted := range []string{
		"## Uncovered values",
		"| Unaccepted uncovered values | 1 |",
		"| Accepted uncovered values | 1 |",
		"https-connect.pcap/3/JA4L.1",
		"https-connect.pcap/5/JA4LS.1",
		"45_64",
		"13532_57",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// FR-conformance-33t states the result of every run. A section a reader finds empty says
// nothing about the coverage of the corpus.
func TestTheReportStatesThatARunReportsNoUncoveredValue(t *testing.T) {
	text := oneConformanceReport().render()

	for _, wanted := range []string{
		"| Unaccepted uncovered values | 0 |",
		"| Accepted uncovered values | 0 |",
		"The run reports no uncovered value.",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// FR-conformance-33r counts an accepted uncovered value apart from an accepted deviation,
// because an uncovered value is neither a match nor a deviation. The register holds one entry
// for each accepted comparison, so the two counts add up to the register key count.
func TestTheReportCountsAnAcceptedUncoveredValueApartFromAnAcceptedDeviation(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("tls-handshake.pcapng")
	report.recordComparison("tls-handshake.pcapng", conformanceReportStreamSet, conformanceComparison{
		Deviations: []conformanceDeviation{{
			Key:      conformanceKey{Capture: "tls-handshake.pcapng", Stream: "0", Method: "JA4S"},
			Kind:     conformanceChangedValue,
			Expected: "t120300_c030_4e8089b5d0f3",
			Produced: "t120300_c030_4e8089b5d0f4",
			Accepted: true,
		}},
		Uncovered: []conformanceUncoveredValue{{
			Key:      conformanceKey{Capture: "tls-handshake.pcapng", Stream: "0", Method: "JA4L-S"},
			Produced: "13532_57",
			Accepted: true,
		}},
	})

	text := report.render()

	for _, wanted := range []string{
		"| Accepted deviations | 1 |",
		"| Accepted uncovered values | 1 |",
		"| Accepted comparisons | 2 |",
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("the report does not hold %q", wanted)
		}
	}
}

// An uncovered value reaches no row of the result table. The vector file holds no value for
// the method, and FR-conformance-33 records `not applicable` for that cell.
func TestTheReportRecordsNotApplicableForAMethodThatReachesUncoveredValuesAlone(t *testing.T) {
	report := newConformanceReport("27f0cbf")
	report.readCapture("https-connect.pcap")
	report.recordComparison("https-connect.pcap", conformanceReportPacketSet, conformanceComparison{
		Uncovered: []conformanceUncoveredValue{
			{Key: conformanceKey{Capture: "https-connect.pcap", Stream: "3", Method: "JA4L.1"}, Produced: "45_64"},
		},
	})

	row := conformanceRowOf(t, report, "https-connect.pcap", "JA4L")

	if row.Result != conformanceReportNotApplicable {
		t.Errorf("the row records %q, and the vector file holds no value for the method", row.Result)
	}

	if row.Deviations != 0 {
		t.Errorf("the row counts %d deviations, and an uncovered value is no deviation", row.Deviations)
	}
}

// These tests hold the comparison scope of the bare vector key. Issue #209 states the
// defect, and round 20 of the `## Changelog` of `docs/specs/spec.md` records the narrower
// rule.
//
// A method emits twice on one stream for two different reasons, and one rule cannot serve
// both. A measurement point that moves reports the same connection twice, and the last
// report holds the value the reference publishes. A method that emits once per protocol, or
// once per request, reports two different values, and the second is a surplus.
//
// The tests read `conformanceStreamMethodKey` with a fixture, because the producer counts
// the occurrence and the key form decides which value reaches the comparison.

// The library produces a TLS value and a QUIC value for JA4S on stream 0 of
// `chrome-cloudflare-quic-with-secrets.pcapng`. The per-stream vector writes the bare key
// `JA4S`, and it holds the TLS value `t130200_1301_234ea6891581`.
//
// `docs/audit/conformance.md` recorded the deviation `the two values differ` with the vector
// value `t130200_1301_234ea6891581` and the library value `q130200_1301_234ea6891581`. The
// bare key kept the last value, so the correct value never reached the comparison.
func TestTheHarnessNumbersTheSecondJA4SValueOfOneStream(t *testing.T) {
	if got := conformanceStreamMethodKey("JA4S", 1, false); got != "JA4S" {
		t.Errorf("the harness writes %q for the first JA4S value of one stream, and the vector writes `JA4S`", got)
	}

	if got := conformanceStreamMethodKey("JA4S", 2, false); got != "JA4S.2" {
		t.Errorf("the harness writes %q for the second JA4S value of one stream, and a surplus value reports as `JA4S.2`", got)
	}
}

// FoxIO writes one per-stream entry for each HTTP request. A vector that holds one entry for
// a stream still reaches a stream that carries more than one request.
//
// The `CVE-2018-6794.pcap` example below is history, and it is not the state of the tree.
// `CVE-2018-6794.pcap/0/JA4H` fell from 12 deviations to 2 under the bare key, and the
// second value and each later one reached no comparison. Those surplus values are
// retransmission values, and never request values. Each HTTP connection of that capture
// carries one request and five TCP retransmissions of it, and #233 holds the measurement.
// `segmentCarriesNoNewRequest` of `ja4h.go` now drops each retransmission, so the library
// emits one JA4H value per HTTP connection of that capture and `docs/audit/conformance.md`
// holds no `CVE-2018-6794.pcap/0/JA4H.2` key.
// `ja4h_retransmitted_capture_test.go` holds the count the library produces today.
//
// `http2-with-cookies.pcapng` is the live example, and #233 named it.
// `testdata/foxio/python/http2-with-cookies.pcapng.json` holds 16 entries for stream 0, and
// 15 of them hold a JA4H key. The vector group therefore holds more than one value, so the
// harness numbers each one from `http2-with-cookies.pcapng/0/JA4H.1`.
// Round 52 of the `## Changelog` of `docs/specs/spec.md` records this reading.
func TestTheHarnessNumbersTheSecondAndLaterJA4HValuesOfOneStream(t *testing.T) {
	for occurrence, want := range map[int]string{
		1: "JA4H",
		2: "JA4H.2",
		3: "JA4H.3",
		4: "JA4H.4",
	} {
		if got := conformanceStreamMethodKey("JA4H", occurrence, false); got != want {
			t.Errorf("the harness writes %q for JA4H value %d of one stream, and the value reports as %q",
				got, occurrence, want)
		}
	}
}

// The maintainer ruled on 2026-08-12 in issue #196 that the harness compares the last JA4L
// emission of one stream. Round 15 states the ruling, and round 20 reverses no part of it.
//
// `docs/specs/foxio/JA4L.md` R33 names the measurement point that moves. The reference is a
// batch program that publishes the final state of its cache, so the last report holds the
// value the reference publishes.
func TestTheHarnessComparesTheLastJA4LValueOfOneStream(t *testing.T) {
	for _, method := range []string{"JA4L-C", "JA4L-S"} {
		t.Run(method, func(t *testing.T) {
			for _, occurrence := range []int{1, 2, 7} {
				if got := conformanceStreamMethodKey(method, occurrence, false); got != method {
					t.Errorf("the harness writes %q for value %d of %s, and round 15 compares the last emission",
						got, occurrence, method)
				}
			}
		})
	}
}

// A vector key that carries an occurrence number keeps that form for every method. The
// last-emission rule therefore reaches no stream whose vector numbers the values.
func TestTheHarnessKeepsTheOccurrenceFormForEveryMethodTheVectorNumbers(t *testing.T) {
	for _, method := range []string{"JA4L-C", "JA4S", "JA4X"} {
		t.Run(method, func(t *testing.T) {
			if got := conformanceStreamMethodKey(method, 3, true); got != method+".3" {
				t.Errorf("the harness writes %q for value 3 of %s, and the vector writes %q", got, method, method+".3")
			}
		})
	}
}

// conformanceCollapsingMethods returns every per-stream method whose second value of one
// stream replaces the first under a bare vector key.
//
// The set derives from `conformanceStreamMethodKeys` and from `conformanceStreamMethodKey`,
// so no third list states it. Issue #148 requires a derived list, because a hardcoded one
// leaves a new method behind.
//
// `conformanceStreamMethodKeys` already holds each raw form as its own key, for example
// `JA4H_r`. This loop therefore synthesizes no suffix. A synthesized form could repeat a key
// the map already holds. The caller compares two sorted lists, so one repeated member would
// fail the test for the wrong reason.
func conformanceCollapsingMethods() []string {
	var collapsing []string

	for method := range conformanceStreamMethodKeys {
		if conformanceStreamMethodKey(method, 2, false) == method {
			collapsing = append(collapsing, method)
		}
	}

	slices.Sort(collapsing)

	return collapsing
}

// The last-emission rule reaches the two JA4L methods and no other method.
//
// This test fails when a second method joins the bare-key set. A method that joins it hides
// every value after the first, and the suite then reports a count it does not measure.
// Issue #209 measured that: one match was lost and three JA4H values reached no comparison.
func TestTheLastEmissionSetHoldsTheTwoJA4LMethodsAlone(t *testing.T) {
	want := []string{"JA4L-C", "JA4L-S"}

	if got := conformanceCollapsingMethods(); !slices.Equal(got, want) {
		t.Errorf("the harness compares the last emission of %v, and round 15 rules that for %v", got, want)
	}
}

// Every member of the last-emission set names a per-stream vector key. A typo in the set
// therefore fails the suite, and it widens the rule on no method.
func TestEveryLastEmissionMethodNamesAPerStreamVectorKey(t *testing.T) {
	for method := range conformanceLastEmissionMethods {
		if !conformanceStreamMethodKeys[method] {
			t.Errorf("the last-emission set names %q, and the per-stream vector key set does not hold it", method)
		}
	}
}

// Every member of the last-emission set names the fingerprinter whose measurement point
// moves. The stem derives from `Processor.fingerprinters`. A rename of that fingerprinter
// therefore fails this test, and the rule stays on no name that the processor no longer runs.
func TestEveryLastEmissionMethodNamesTheFingerprinterWhosePointMoves(t *testing.T) {
	stem := methodNameOfFingerprinter(conformanceMovingPointFingerprinter)

	if !slices.Contains(processorFingerprinterNames(), conformanceMovingPointFingerprinter) {
		t.Fatalf("the processor runs no %s, and the last-emission rule names it", conformanceMovingPointFingerprinter)
	}

	for method := range conformanceLastEmissionMethods {
		label, _, _ := strings.Cut(method, "-")
		if strings.ToLower(label) != stem {
			t.Errorf("the last-emission set names %q, and the rule covers the fingerprinter %q alone",
				method, conformanceMovingPointFingerprinter)
		}
	}
}

// A surplus value keeps the match of the value the vector names.
//
// This is the behavior that issue #209 repairs. The bare key lost a real match on
// `chrome-cloudflare-quic-with-secrets.pcapng/0/JA4S`, and the loss is what made #209 a
// defect and not a missing guard.
//
// The surplus value still reports, which FR-conformance-17 names. Over-emission is a defect
// this project has had, and issue #33 measured 617 values for `ssh-r.pcap` where the vector
// holds 11.
func TestASurplusValueKeepsTheMatch(t *testing.T) {
	capture := "chrome-cloudflare-quic-with-secrets.pcapng"

	produced := map[conformanceKey]string{
		{Capture: capture, Stream: "0", Method: "JA4S"}:   "t130200_1301_234ea6891581",
		{Capture: capture, Stream: "0", Method: "JA4S.2"}: "q130200_1301_234ea6891581",
	}
	expected := map[conformanceKey]string{
		{Capture: capture, Stream: "0", Method: "JA4S"}: "t130200_1301_234ea6891581",
	}

	comparison := compareConformance(produced, expected, nil)

	if comparison.Matches != 1 {
		t.Errorf("the engine reports %d matches, and the vector value reaches the bare key", comparison.Matches)
	}

	if len(comparison.Deviations) != 1 {
		t.Fatalf("the engine reports %d deviations, and the surplus value is the one deviation", len(comparison.Deviations))
	}

	if kind := comparison.Deviations[0].Kind; kind != conformanceExtraValue {
		t.Errorf("the engine reports the surplus value as %q, and FR-conformance-17 names it %q", kind, conformanceExtraValue)
	}
}
