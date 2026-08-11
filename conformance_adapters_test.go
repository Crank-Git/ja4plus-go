//go:build conformance

package ja4plus

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The two vector adapters of the conformance suite. They hold FR-conformance-20 through
// FR-conformance-26.
//
// An adapter turns one FoxIO vector into the expected map that `compareConformance` reads.
// It changes no character of a value. FR-conformance-16 compares as an exact string match,
// so an adapter that trimmed, lowercased or sorted a value would report a match this
// project does not hold.
//
// An adapter returns an error rather than a test failure, so a fixture proves every
// failure without the corpus. `conformance_test.go` fails the test for each error.
//
// The adapters stay in the test build. `v1.0.0` freezes the exported API of the library,
// and a measurement of the library is no part of that API.

// conformanceStreamNonMethodKeys names every per-stream vector key that holds no
// fingerprint.
//
// A count over `testdata/foxio/python/` at the commit in `testdata/foxio.pin` reports these
// nine keys and no other. `stream`, `src`, `dst`, `srcport` and `dstport` name the
// connection. `domain`, `client_ttl`, `server_ttl` and `ssh_extras` hold an input of a
// fingerprint, and never a fingerprint.
var conformanceStreamNonMethodKeys = map[string]bool{
	"stream":     true,
	"src":        true,
	"dst":        true,
	"srcport":    true,
	"dstport":    true,
	"domain":     true,
	"client_ttl": true,
	"server_ttl": true,
	"ssh_extras": true,
}

// conformanceStreamMethodKeys names every JA4+ method that a per-stream vector key names.
//
// The FoxIO Python tool writes the key, and this project writes the method name in the
// `## Terms` table of `docs/specs/spec.md`. The two names are equal for the per-stream set,
// so this table is a set and not a map. `JA4H_r` and `JA4X_r` reach no vector at the pinned
// commit, and the set holds each one so that a later FoxIO release does not fail the suite
// for a key the reference already defines.
var conformanceStreamMethodKeys = map[string]bool{
	"JA4":     true,
	"JA4_r":   true,
	"JA4_o":   true,
	"JA4_ro":  true,
	"JA4S":    true,
	"JA4S_r":  true,
	"JA4H":    true,
	"JA4H_r":  true,
	"JA4H_ro": true,
	"JA4X":    true,
	"JA4X_r":  true,
	"JA4SSH":  true,
	"JA4L-C":  true,
	"JA4L-S":  true,
}

// conformancePacketNonMethodFields names every per-packet vector field that holds no
// fingerprint.
//
// `frame.number` names the frame. `ja4.ja4l_delta` and `ja4.ja4ls_delta` each hold a ratio
// of two durations. `docs/specs/foxio/JA4L.md` R23 records that no FoxIO image states the
// ratio, and R24 records the formula that Wireshark writes at
// `wireshark/source/packet-ja4.c:1389`. `docs/specs/foxio/zeek.md:95` records that this
// project declines both as a reference value for any method.
//
// FR-conformance-26 forbids a skipped key, so the adapter recognizes each one here.
var conformancePacketNonMethodFields = map[string]bool{
	conformanceFrameNumberField: true,
	"ja4.ja4l_delta":            true,
	"ja4.ja4ls_delta":           true,
}

// conformanceRecognizeStreamKey returns the method and the occurrence that a per-stream
// vector key names.
//
// It reports false for a key that names a stream field rather than a method. It returns an
// error for a key that names neither, because FR-conformance-26 fails the test on a key the
// adapter does not recognize.
//
// The occurrence is zero when the key carries no occurrence number. The vector writes
// `JA4.1` and it writes `JA4S`, so the two forms both reach the corpus.
func conformanceRecognizeStreamKey(key string) (string, int, bool, error) {
	if conformanceStreamNonMethodKeys[key] {
		return "", 0, false, nil
	}

	method, occurrence := key, 0

	if base, suffix, held := strings.Cut(key, "."); held {
		number, err := strconv.Atoi(suffix)
		if err != nil || number < 1 {
			return "", 0, false, fmt.Errorf(
				"the per-stream vector key %q carries the occurrence %q, and an occurrence is a whole number of 1 or more", key, suffix)
		}

		method, occurrence = base, number
	}

	if !conformanceStreamMethodKeys[method] {
		return "", 0, false, fmt.Errorf(
			"the per-stream vector key %q names no JA4+ method and no stream field, and FR-conformance-26 fails the test for it", key)
	}

	return method, occurrence, true, nil
}

// conformanceRecognizePacketField returns the method that a per-packet vector field names.
//
// It reports false for a field that names no method. It returns an error for a field that
// the adapter does not recognize, which holds FR-conformance-26 for the per-packet set.
func conformanceRecognizePacketField(field string) (string, bool, error) {
	if conformancePacketNonMethodFields[field] {
		return "", false, nil
	}

	method, mapped := conformancePacketMethods[field]
	if !mapped {
		return "", false, fmt.Errorf(
			"the per-packet vector field %q names no JA4+ method and no frame field, and FR-conformance-26 fails the test for it", field)
	}

	return method, true, nil
}

// conformanceEndpointKey returns one key for the two directions of a connection.
//
// FR-conformance-22 matches a stream by the `src`, `dst`, `srcport` and `dstport` fields. A
// vector entry names the client as the source, and the library names the sender of the
// packet as the source. A JA4S value therefore arrives with the two addresses reversed, so
// the key sorts the two endpoints. `Processor.GetShardKey` at `processor.go:132` sorts them
// the same way.
func conformanceEndpointKey(firstIP string, firstPort uint16, secondIP string, secondPort uint16) string {
	if firstIP > secondIP || (firstIP == secondIP && firstPort > secondPort) {
		firstIP, secondIP = secondIP, firstIP
		firstPort, secondPort = secondPort, firstPort
	}

	return fmt.Sprintf("%s:%d-%s:%d", firstIP, firstPort, secondIP, secondPort)
}

// conformanceStreamShape holds everything the per-stream adapter reads from one vector.
type conformanceStreamShape struct {
	// Expected maps each comparison to the value the vector holds. The method of the key
	// is the vector key, written exactly as the vector writes it.
	Expected map[conformanceKey]string
	// StreamOfEndpoint maps the endpoint key of a connection to the stream that names it.
	StreamOfEndpoint map[string]string
	// UsesOccurrence reports whether the vector writes an occurrence number for a method.
	// The library names a method without one, so the produced key follows the vector.
	UsesOccurrence map[string]bool
	// Covered names every method the vector holds. The suite compares no method that the
	// vector never names.
	Covered map[string]bool
}

// conformanceExpectedFromStreamVector returns the shape of one per-stream vector.
//
// It holds FR-conformance-20, FR-conformance-21 and FR-conformance-22. It returns an error
// for a key it does not recognize, which holds FR-conformance-26.
//
// An entry names its stream by the `stream` field, so a register key reads as
// `testdata/README.md` writes it, for example `ssh2.pcapng/15/JA4L-S`.
func conformanceExpectedFromStreamVector(
	capture string,
	entries []conformanceStreamEntry,
) (conformanceStreamShape, error) {
	shape := conformanceStreamShape{
		Expected:         make(map[conformanceKey]string),
		StreamOfEndpoint: make(map[string]string),
		UsesOccurrence:   make(map[string]bool),
		Covered:          make(map[string]bool),
	}

	for index, entry := range entries {
		stream, endpoint, err := conformanceStreamIdentity(entry)
		if err != nil {
			return shape, fmt.Errorf("entry %d of the per-stream vector for %s: %w", index, capture, err)
		}

		shape.StreamOfEndpoint[endpoint] = stream

		for key, raw := range entry {
			method, occurrence, isMethod, err := conformanceRecognizeStreamKey(key)
			if err != nil {
				return shape, fmt.Errorf("entry %d of the per-stream vector for %s: %w", index, capture, err)
			}

			if !isMethod {
				continue
			}

			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return shape, fmt.Errorf("entry %d of the per-stream vector for %s holds a value for %q that is no string: %w",
					index, capture, key, err)
			}

			if shape.Covered[method] && shape.UsesOccurrence[method] != (occurrence > 0) {
				return shape, fmt.Errorf(
					"the per-stream vector for %s writes the method %q with an occurrence number and without one, and the two forms name one method",
					capture, method)
			}

			shape.Covered[method] = true
			shape.UsesOccurrence[method] = occurrence > 0
			shape.Expected[conformanceKey{Capture: capture, Stream: stream, Method: key}] = value
		}
	}

	return shape, nil
}

// conformanceStreamIdentity returns the stream number and the endpoint key of one entry.
func conformanceStreamIdentity(entry conformanceStreamEntry) (string, string, error) {
	stream, held := entry["stream"]
	if !held {
		return "", "", fmt.Errorf("the entry holds no %q field, and FR-conformance-22 names the stream", "stream")
	}

	source, err := conformanceStreamEndpoint(entry, "src", "srcport")
	if err != nil {
		return "", "", err
	}

	destination, err := conformanceStreamEndpoint(entry, "dst", "dstport")
	if err != nil {
		return "", "", err
	}

	return string(stream), conformanceEndpointKey(source.address, source.port, destination.address, destination.port), nil
}

// conformanceStreamAddress is one end of a connection that a per-stream entry names.
type conformanceStreamAddress struct {
	address string
	port    uint16
}

// conformanceStreamEndpoint returns one end of the connection that the entry names.
func conformanceStreamEndpoint(entry conformanceStreamEntry, addressKey, portKey string) (conformanceStreamAddress, error) {
	var end conformanceStreamAddress

	raw, held := entry[addressKey]
	if !held {
		return end, fmt.Errorf("the entry holds no %q field, and FR-conformance-22 names the four address fields", addressKey)
	}

	if err := json.Unmarshal(raw, &end.address); err != nil {
		return end, fmt.Errorf("the entry holds a %q field that is no string: %w", addressKey, err)
	}

	raw, held = entry[portKey]
	if !held {
		return end, fmt.Errorf("the entry holds no %q field, and FR-conformance-22 names the four address fields", portKey)
	}

	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		// FoxIO writes the port as a JSON string at the pinned commit. A number is read
		// here as well, so a later release does not fail the suite for the change alone.
		text = string(raw)
	}

	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return end, fmt.Errorf("the entry holds the %q field %q, and a port is a whole number from 0 to 65535", portKey, text)
	}

	end.port = uint16(port)

	return end, nil
}

// conformanceStreamMethodOfResult returns the per-stream method name and the value that
// the result carries. It reports false when the per-stream vector set names no key for the
// method.
//
// JA4L writes both JA4L-C and JA4L-S, and it reports the type `ja4l` for the two.
// `ja4l.go:194` writes the form `JA4L-C=<latency>_<ttl>`, and the per-stream vector writes
// the key `JA4L-C` with the value alone. The split reads the library output form, and it
// changes no character of the value.
//
// The per-stream set names no key for JA4D, JA4D6, JA4T or JA4TS. FR-conformance-25 makes
// the per-packet adapter authoritative for JA4D and JA4D6.
func conformanceStreamMethodOfResult(result FingerprintResult) (string, string, bool) {
	if result.Type == "ja4l" {
		label, value, held := strings.Cut(result.Fingerprint, "=")
		if !held || !conformanceStreamMethodKeys[label] {
			return "", "", false
		}

		return label, value, true
	}

	names := map[string]string{
		"ja4":    "JA4",
		"ja4s":   "JA4S",
		"ja4h":   "JA4H",
		"ja4x":   "JA4X",
		"ja4ssh": "JA4SSH",
	}

	name, held := names[result.Type]

	return name, result.Fingerprint, held
}

// conformanceStreamValuesOfResult returns every per-stream method value that the result
// carries.
//
// One result carries three fields, because a fingerprinter reports the fingerprint, the raw
// form and the wire-order raw form together. An empty field states that the fingerprinter
// produced nothing, so this function reports no value for it. A JA4L result carries the
// fingerprint alone, and the two raw fields of it are empty.
//
// The library produces no value for `JA4_o`, which FoxIO hashes from the wire-order form.
// The per-stream vector holds `JA4_o.1` on 150 entries, so the suite reports each one as a
// value the library does not produce. That is a finding for Epic 5, and never a reason to
// change a fingerprinter here.
func conformanceStreamValuesOfResult(result FingerprintResult) []conformanceMethodValue {
	method, fingerprint, held := conformanceStreamMethodOfResult(result)
	if !held {
		return nil
	}

	var values []conformanceMethodValue

	for _, value := range []conformanceMethodValue{
		{Method: method, Value: fingerprint},
		{Method: method + "_r", Value: result.Raw},
		{Method: method + "_ro", Value: result.RawOriginalOrder},
	} {
		if value.Value != "" {
			values = append(values, value)
		}
	}

	return values
}

// conformanceStreamMethodKey returns the key form that the vector writes for the method.
//
// The vector writes `JA4.1` and it writes `JA4S`, so the produced key follows the form the
// vector uses for that method. A method that the vector writes without an occurrence number
// still gains one for the second value on one stream, so an extra value reports as a
// deviation rather than replacing the first.
func conformanceStreamMethodKey(method string, occurrence int, usesOccurrence bool) string {
	if usesOccurrence || occurrence > 1 {
		return conformanceMethodOccurrence(method, occurrence)
	}

	return method
}
