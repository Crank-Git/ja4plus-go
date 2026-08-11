//go:build conformance

package ja4plus

import (
	"encoding/json"
	"testing"
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
	// which form the vector writes for each method.
	if !shape.UsesOccurrence["JA4X"] {
		t.Errorf("the adapter reports that `JA4X` carries no occurrence number, and the vector writes `JA4X.1`")
	}

	if shape.UsesOccurrence["JA4S"] {
		t.Errorf("the adapter reports that `JA4S` carries an occurrence number, and the vector writes `JA4S`")
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

	if err := checkDeviationKey(key.String()); err != nil {
		t.Errorf("the register reader rejects the key %q: %v", key.String(), err)
	}
}
