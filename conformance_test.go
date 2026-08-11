//go:build conformance

package ja4plus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/gopacket"
)

// The conformance suite. It holds FR-conformance-10 through FR-conformance-19, and it
// holds FR-reference-25 and FR-reference-26.
//
// The suite runs the library over the FoxIO corpus and compares each value with the FoxIO
// vector. `make corpus` fetches the corpus at the commit in `testdata/foxio.pin`, and
// `.gitignore` keeps the corpus out of the repository.
//
// # What this slice compares
//
// The suite compares the per-packet vector set. A per-packet record names its frame, so a
// key needs the frame number alone.
//
// The suite reads the per-stream vector set and reports its size, and it compares no value
// there yet. A per-stream entry names a stream by the `src`, `dst`, `srcport` and `dstport`
// fields, and FR-conformance-22 states that match. Issue #34 owns FR-conformance-20
// through FR-conformance-26, and the per-stream comparison lands with it.

const (
	// conformanceCorpusDir holds the fetched FoxIO corpus.
	conformanceCorpusDir = "testdata/foxio"
	// conformanceCaptureDir holds one capture for each test case FoxIO publishes.
	conformanceCaptureDir = conformanceCorpusDir + "/pcap"
	// conformanceStreamVectorDir holds the per-stream vectors.
	conformanceStreamVectorDir = conformanceCorpusDir + "/python"
	// conformancePacketVectorDir holds the per-packet vectors.
	conformancePacketVectorDir = conformanceCorpusDir + "/wireshark"
	// conformanceFetchedFile records the commit that `make corpus` fetched.
	conformanceFetchedFile = conformanceCorpusDir + "/.fetched"
)

// conformanceNotestMarker names a capture that FoxIO excludes from its own tests.
// The suite records such a capture as not applicable.
const conformanceNotestMarker = ".notest."

// conformancePacketMethods maps a per-packet vector field to a JA4+ method name.
//
// FoxIO writes the field names in the Wireshark dissector, and this project writes the
// method names in the `## Terms` table of `docs/specs/spec.md`. The two `_delta` fields
// carry a number of milliseconds and not a fingerprint, so this table names neither.
// `conformanceReportTotals` names them on every run, and #34 rules on them under
// FR-conformance-23 and FR-conformance-26.
var conformancePacketMethods = map[string]string{
	"ja4.ja4d":    "JA4D",
	"ja4.ja4h":    "JA4H",
	"ja4.ja4h_r":  "JA4H_r",
	"ja4.ja4h_ro": "JA4H_ro",
	"ja4.ja4l":    "JA4L",
	"ja4.ja4ls":   "JA4LS",
	"ja4.ja4s":    "JA4S",
	"ja4.ja4s_r":  "JA4S_r",
	"ja4.ja4ssh":  "JA4SSH",
	"ja4.ja4t":    "JA4T",
	"ja4.ja4ts":   "JA4TS",
	"ja4.ja4x":    "JA4X",
	"ja4.ja4x_r":  "JA4X_r",
}

// conformanceFrameNumberField names the per-packet field that holds the frame number.
const conformanceFrameNumberField = "frame.number"

// conformancePacketRecord is one record of a per-packet vector.
// The suite reads `_source.layers` and no other part of the record.
type conformancePacketRecord struct {
	Source struct {
		Layers map[string][]string `json:"layers"`
	} `json:"_source"`
}

// conformanceStreamEntry is one entry of a per-stream vector.
// The suite reads the size of the entry list and the method fields, and #34 adds the
// stream match that FR-conformance-22 states.
type conformanceStreamEntry map[string]json.RawMessage

// conformanceCorpusIsAbsent reports whether the corpus directory is absent.
func conformanceCorpusIsAbsent() bool {
	_, err := os.Stat(conformanceCorpusDir)

	return err != nil
}

// conformanceSkipWithoutCorpus skips the test when the corpus is absent.
// FR-conformance-11 requires a message that names `make corpus`.
func conformanceSkipWithoutCorpus(t *testing.T) {
	t.Helper()

	if conformanceCorpusIsAbsent() {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", conformanceCorpusDir)
	}
}

// conformanceCaptureNames returns the file name of every capture, sorted.
// FR-conformance-12 reads every capture in `testdata/foxio/pcap/`.
func conformanceCaptureNames(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(conformanceCaptureDir)
	if err != nil {
		t.Fatalf("read %s: %v", conformanceCaptureDir, err)
	}

	names := make([]string, 0, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}

	sort.Strings(names)

	return names
}

// conformanceVectorPath returns the vector path for the capture in the directory.
// It returns the empty string when the directory holds no vector for the capture.
func conformanceVectorPath(directory, capture string) string {
	path := filepath.Join(directory, capture+".json")
	if _, err := os.Stat(path); err != nil {
		return ""
	}

	return path
}

// conformanceReadPacketVector returns the records of the per-packet vector.
// It fails the test when the file does not decode, because a vector the suite cannot read
// is a defect of the harness and never a deviation of the library.
func conformanceReadPacketVector(t *testing.T, path string) []conformancePacketRecord {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var records []conformancePacketRecord
	if err := json.Unmarshal(content, &records); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	return records
}

// conformanceReadStreamVector returns the entries of the per-stream vector.
// It fails the test when the file does not decode.
func conformanceReadStreamVector(t *testing.T, path string) []conformanceStreamEntry {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var entries []conformanceStreamEntry
	if err := json.Unmarshal(content, &entries); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	return entries
}

// conformanceExpectedFromPacketVector returns the value of every method the per-packet
// vector holds, and the count of each field the suite does not map.
//
// A packet that carries more than one certificate produces more than one value for a
// method. The method name therefore carries the occurrence number. The port writes the
// same form, for example `gre-erspan-vxlan.pcap/0:65174/JA4T.1`.
func conformanceExpectedFromPacketVector(
	t *testing.T,
	capture string,
	records []conformancePacketRecord,
) (map[conformanceKey]string, map[string]int) {
	t.Helper()

	expected := make(map[conformanceKey]string)
	unmapped := make(map[string]int)

	for index, record := range records {
		frames := record.Source.Layers[conformanceFrameNumberField]
		if len(frames) != 1 {
			t.Fatalf("record %d of the per-packet vector for %s holds %d frame numbers, and a record names one frame",
				index, capture, len(frames))
		}

		for field, values := range record.Source.Layers {
			if field == conformanceFrameNumberField {
				continue
			}

			method, mapped := conformancePacketMethods[field]
			if !mapped {
				unmapped[field]++

				continue
			}

			for occurrence, value := range values {
				key := conformanceKey{
					Capture: capture,
					Stream:  frames[0],
					Method:  conformanceMethodOccurrence(method, occurrence+1),
				}
				expected[key] = value
			}
		}
	}

	return expected, unmapped
}

// conformanceMethodOccurrence returns the method name with the occurrence number.
func conformanceMethodOccurrence(method string, occurrence int) string {
	return method + "." + strconv.Itoa(occurrence)
}

// conformanceProducedByFrame runs one Processor over every packet of the capture and
// returns the value of every method the library produces, keyed by frame number.
//
// FR-conformance-15 runs one Processor over every packet in capture order. The
// concurrency contract of `.claude/rules/concurrency.md` gives one Processor to one
// goroutine, so this function creates the Processor and never shares it.
//
// The `covered` set names the methods the vector holds. A method the vector never names
// produces no key, because the behavior rules of the feature file compare only the
// methods a vector holds. The per-packet set names neither JA4 nor JA4D6.
func conformanceProducedByFrame(
	t *testing.T,
	capture string,
	packets []gopacket.Packet,
	covered map[string]bool,
) map[conformanceKey]string {
	t.Helper()

	produced := make(map[conformanceKey]string)
	processor := NewProcessor()

	for index, packet := range packets {
		frame := strconv.Itoa(index + 1)

		results, errs := processor.ProcessPacket(packet)
		for _, err := range errs {
			// A fingerprinter returns a non-fatal error, so the suite records it and
			// reads the next packet. An error is not a deviation.
			t.Logf("%s frame %s: %v", capture, frame, err)
		}

		occurrences := make(map[string]int)

		for _, result := range results {
			for _, value := range conformanceValuesOfResult(result) {
				if !covered[value.Method] {
					continue
				}

				occurrences[value.Method]++

				key := conformanceKey{
					Capture: capture,
					Stream:  frame,
					Method:  conformanceMethodOccurrence(value.Method, occurrences[value.Method]),
				}
				produced[key] = value.Value
			}
		}
	}

	return produced
}

// conformanceMethodValue is one method name and the value the library produced for it.
type conformanceMethodValue struct {
	Method string
	Value  string
}

// conformanceValuesOfResult returns every method value that the result carries.
//
// One result carries three fields, because a fingerprinter reports the fingerprint, the
// raw form and the wire-order raw form together. An empty field states that the
// fingerprinter produced nothing, so this function reports no value for it.
//
// `ja4.go:96` and `ja4.go:97` set the two raw fields, and no other fingerprinter sets
// either. The per-packet vector set names no field for JA4, so the two raw branches report
// nothing at the pinned commit. The two branches hold the comparison that a filled raw
// field needs. Without them the suite reports every new raw value as absent for ever.
func conformanceValuesOfResult(result FingerprintResult) []conformanceMethodValue {
	method, fingerprint, held := conformanceMethodOfResultType(result)
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

// conformanceMethodOfResultType returns the method name and the value that the result
// carries. It reports false when the per-packet vector set names no field for the method.
//
// JA4L writes both JA4L and JA4LS, and it reports the type `ja4l` for the two. The label
// of the fingerprint names which one, so this function reads the label and returns the
// value that follows it. `ja4l.go:194` writes the form `JA4L-C=<latency>_<ttl>`, and
// `testdata/foxio/wireshark/https-connect.pcap.json` holds `"ja4.ja4l": ["45_64_66"]`,
// which carries the value alone. A comparison that kept the label would never match.
//
// The split reads the library output form, and it changes no character of the value.
func conformanceMethodOfResultType(result FingerprintResult) (string, string, bool) {
	if result.Type == "ja4l" {
		label, value, held := strings.Cut(result.Fingerprint, "=")
		if !held {
			return "", "", false
		}

		switch label {
		case "JA4L-C":
			return "JA4L", value, true
		case "JA4L-S":
			return "JA4LS", value, true
		default:
			return "", "", false
		}
	}

	// The per-packet vector set names no field for JA4 and none for JA4D6, so the suite
	// compares neither here. The per-stream set holds JA4, and #34 compares it.
	names := map[string]string{
		"ja4d":   "JA4D",
		"ja4h":   "JA4H",
		"ja4s":   "JA4S",
		"ja4ssh": "JA4SSH",
		"ja4t":   "JA4T",
		"ja4ts":  "JA4TS",
		"ja4x":   "JA4X",
	}

	name, held := names[result.Type]

	return name, result.Fingerprint, held
}

// conformanceCoveredMethods returns the method name of every key the expected map holds.
// The name carries no occurrence number, so a method the vector holds once covers every
// occurrence the library produces.
func conformanceCoveredMethods(expected map[conformanceKey]string) map[string]bool {
	covered := make(map[string]bool)

	for key := range expected {
		method, _, held := strings.Cut(key.Method, ".")
		if !held {
			method = key.Method
		}

		covered[method] = true
	}

	return covered
}

// conformanceRegisterByKey returns the register, keyed by the comparison each entry names.
// FR-reference-25 reads `testdata/deviations.json`, and the suite expects the named
// comparison to differ.
func conformanceRegisterByKey(t *testing.T) map[conformanceKey]deviationEntry {
	t.Helper()

	register := make(map[conformanceKey]deviationEntry)

	for _, entry := range readDeviationRegister(t) {
		parts := strings.Split(entry.Key, "/")
		if len(parts) != 3 {
			t.Fatalf("the register entry %q does not name the capture, the stream and the method", entry.Key)
		}

		register[conformanceKey{Capture: parts[0], Stream: parts[1], Method: parts[2]}] = entry
	}

	return register
}

// conformanceRunTotals counts the outcome of the whole run.
type conformanceRunTotals struct {
	Captures         int
	NotApplicable    int
	Matches          int
	Deviations       int
	AcceptedDeviants int
	Closed           int
	StreamValues     int
}

func TestConformance(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	register := conformanceRegisterByKey(t)
	totals := conformanceRunTotals{}
	unmapped := map[string]int{}

	if fetched, err := os.ReadFile(conformanceFetchedFile); err == nil {
		t.Logf("the corpus holds the FoxIO commit %s", strings.TrimSpace(string(fetched)))
	}

	// The subtests run one after the other. `.claude/rules/concurrency.md` gives one
	// Processor to one goroutine, and a parallel subtest would share the corpus reader
	// and the totals as well.
	for _, capture := range conformanceCaptureNames(t) {
		totals.Captures++

		t.Run(capture, func(t *testing.T) {
			conformanceRunOneCapture(t, capture, register, &totals, unmapped)
		})
	}

	conformanceReportTotals(t, totals, unmapped)
}

// conformanceRunOneCapture compares one capture and adds its outcome to the totals.
func conformanceRunOneCapture(
	t *testing.T,
	capture string,
	register map[conformanceKey]deviationEntry,
	totals *conformanceRunTotals,
	unmapped map[string]int,
) {
	t.Helper()

	// `loadPCAP` of `integration_test.go` reads the two capture formats and keeps the
	// capture order. It reads the magic bytes, because the corpus names one pcap file
	// `http1.pcapng`.
	packets := loadPCAP(t, filepath.Join(conformanceCaptureDir, capture))
	t.Logf("the capture holds %d packets", len(packets))

	if streamPath := conformanceVectorPath(conformanceStreamVectorDir, capture); streamPath != "" {
		entries := conformanceReadStreamVector(t, streamPath)
		totals.StreamValues += len(entries)

		t.Logf("the per-stream vector holds %d entries, and #34 compares them under FR-conformance-22", len(entries))
	} else {
		t.Logf("the corpus holds no per-stream vector for this capture")
	}

	// FoxIO marks this capture `notest`, so FoxIO runs no test over it. The suite reads
	// it, which proves that the library decodes it without a panic, and compares nothing.
	if strings.Contains(capture, conformanceNotestMarker) {
		totals.NotApplicable++

		t.Logf("FoxIO marks this capture `%s`, so the suite records it as not applicable",
			strings.Trim(conformanceNotestMarker, "."))

		conformanceProducedByFrame(t, capture, packets, map[string]bool{})

		return
	}

	packetPath := conformanceVectorPath(conformancePacketVectorDir, capture)
	if packetPath == "" {
		totals.NotApplicable++

		t.Logf("the corpus holds no per-packet vector for this capture, so the suite records it as not applicable")

		return
	}

	expected, captureUnmapped := conformanceExpectedFromPacketVector(t, capture, conformanceReadPacketVector(t, packetPath))
	for field, count := range captureUnmapped {
		unmapped[field] += count
	}

	if len(expected) == 0 {
		totals.NotApplicable++

		t.Logf("the per-packet vector holds no value, so the suite records it as not applicable")

		return
	}

	produced := conformanceProducedByFrame(t, capture, packets, conformanceCoveredMethods(expected))
	comparison := compareConformance(produced, expected, register)

	totals.Matches += comparison.Matches
	totals.Closed += len(comparison.Closed)

	for _, deviation := range comparison.Deviations {
		if deviation.Accepted {
			totals.AcceptedDeviants++

			t.Logf("accepted deviation %s: %s (the register names it)", deviation.Key, deviation.Kind)

			continue
		}

		totals.Deviations++

		t.Logf("deviation %s: %s\n  expected: %q\n  produced: %q",
			deviation.Key, deviation.Kind, deviation.Expected, deviation.Produced)
	}

	// FR-reference-26 fails the suite when a comparison the register names now matches.
	for _, key := range comparison.Closed {
		t.Errorf("the register names %s, and the comparison now matches, so the entry is closed and must leave the register", key)
	}

	t.Logf("the capture reports %d matches and %d deviations", comparison.Matches, len(comparison.Deviations))
}

// conformanceReportTotals writes the summary and fails the run when a deviation remains.
func conformanceReportTotals(t *testing.T, totals conformanceRunTotals, unmapped map[string]int) {
	t.Helper()

	t.Logf("the run read %d captures, %d of them not applicable, and %d per-stream entries",
		totals.Captures, totals.NotApplicable, totals.StreamValues)
	t.Logf("the run reports %d matches, %d deviations and %d accepted deviations",
		totals.Matches, totals.Deviations, totals.AcceptedDeviants)

	if len(unmapped) > 0 {
		fields := make([]string, 0, len(unmapped))
		for field := range unmapped {
			fields = append(fields, fmt.Sprintf("%s (%d records)", field, unmapped[field]))
		}

		sort.Strings(fields)

		t.Logf("the suite maps no method to these per-packet fields, and #34 rules on them: %s",
			strings.Join(fields, ", "))
	}

	if totals.Deviations > 0 {
		t.Errorf("the run reports %d deviations that the register does not hold, and Epic 5 closes them",
			totals.Deviations)
	}
}

func TestTheSuiteReadsEveryCaptureOfTheCorpus(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	// The acceptance criteria of `docs/specs/features/04-conformance-harness.md` name 38
	// captures, 37 per-stream vectors and 37 per-packet vectors at the pinned commit.
	captures := conformanceCaptureNames(t)
	if len(captures) != 38 {
		t.Errorf("the corpus holds %d captures, and the pinned commit publishes 38", len(captures))
	}

	streams, packetVectors := 0, 0

	for _, capture := range captures {
		if conformanceVectorPath(conformanceStreamVectorDir, capture) != "" {
			streams++
		}

		if conformanceVectorPath(conformancePacketVectorDir, capture) != "" {
			packetVectors++
		}
	}

	if streams != 37 {
		t.Errorf("the corpus holds %d per-stream vectors, and the pinned commit publishes 37", streams)
	}

	if packetVectors != 37 {
		t.Errorf("the corpus holds %d per-packet vectors, and the pinned commit publishes 37", packetVectors)
	}
}
