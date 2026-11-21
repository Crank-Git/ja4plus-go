//go:build conformance

package ja4plus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/deviations"
	"github.com/gopacket/gopacket"
)

// The conformance suite. It holds FR-conformance-10 through FR-conformance-19, and it
// holds FR-reference-25 and FR-reference-26.
//
// The suite runs the library over the FoxIO corpus and compares each value with the FoxIO
// vector. `make corpus` fetches the corpus at the commit in `testdata/foxio.pin`, and
// `.gitignore` keeps the corpus out of the repository.
//
// # What this suite compares
//
// The suite compares the two vector sets, and it compares each one on its own. A
// per-packet record names its frame, so a per-packet key holds the frame number. A
// per-stream entry names a connection by the `src`, `dst`, `srcport` and `dstport` fields,
// so a per-stream key holds the stream name of that connection.
// `conformanceStreamNames` of `conformance_test.go` states the two forms of the
// stream name, and issue #250 states why a stream number alone names no connection.
//
// `conformance_test.go` holds the two adapters and FR-conformance-20 through
// FR-conformance-26.

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
// method names in the `## Terms` table of `docs/specs/spec.md`. This table holds
// FR-conformance-23.
//
// FoxIO writes both JA4D and JA4D6 under the single field `ja4.ja4d`, and this library
// writes the two types `ja4d` and `ja4d6`. FR-conformance-25 makes this adapter
// authoritative for the two, so `conformanceMethodOfResultType` maps each type to `JA4D`.
//
// `conformancePacketNonMethodFields` of `conformance_test.go` names every field
// that holds no fingerprint.
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
//
// The marker line goes to the log first. Three untagged tests write the same skip
// message when one capture is absent, so the message alone cannot tell the CI job which
// skip it reads. `conformance_skip_marker_test.go` holds the constant and the reason.
func conformanceSkipWithoutCorpus(t *testing.T) {
	t.Helper()

	if conformanceCorpusIsAbsent() {
		t.Log(conformanceSkipMarker)
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
// vector holds.
//
// A packet that carries more than one certificate produces more than one value for a
// method. The method name therefore carries the occurrence number. The port writes the
// same form, for example `gre-erspan-vxlan.pcap/0:65174/JA4T.1`.
//
// FR-conformance-26 fails the test on a field the adapter does not recognize, so this
// function reads every field through `conformanceRecognizePacketField`.
func conformanceExpectedFromPacketVector(
	t *testing.T,
	capture string,
	records []conformancePacketRecord,
) map[conformanceKey]string {
	t.Helper()

	expected := make(map[conformanceKey]string)

	for index, record := range records {
		frames := record.Source.Layers[conformanceFrameNumberField]
		if len(frames) != 1 {
			t.Fatalf("record %d of the per-packet vector for %s holds %d frame numbers, and a record names one frame",
				index, capture, len(frames))
		}

		for field, values := range record.Source.Layers {
			method, isMethod, err := conformanceRecognizePacketField(field)
			if err != nil {
				t.Fatalf("record %d of the per-packet vector for %s: %v", index, capture, err)
			}

			if !isMethod {
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

	return expected
}

// conformanceMethodOccurrence returns the method name with the occurrence number.
func conformanceMethodOccurrence(method string, occurrence int) string {
	return method + "." + strconv.Itoa(occurrence)
}

// conformanceKeyLog returns the TLS secrets that the Decryption Secrets Blocks of one
// capture carry, and nil for a capture that carries none.
//
// A FoxIO reference implementation reads the plaintext that its host supplies, and that
// host decrypts the capture from those blocks. So the suite gives the library the same key
// material, and a capture without a block reaches the library unchanged.
// #492 added this reader, because `http2-with-cookies.pcapng` writes the Certificate
// message inside a protected TLS 1.3 record.
func conformanceKeyLog(t *testing.T, capture string) *KeyLog {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(conformanceCaptureDir, capture))
	if err != nil {
		return nil
	}

	// A pcap file holds no Decryption Secrets Block, and the reader reports that format as
	// an error. The suite reads the capture in both formats, so the error is expected.
	keyLog, err := ReadKeyLogFromCapture(bytes.NewReader(raw))
	if err != nil {
		return nil
	}

	return keyLog
}

// conformanceProducedByFrame runs one Processor over every packet of the capture and
// returns the value of every method the library produces, keyed by frame number.
//
// FR-conformance-15 runs one Processor over every packet in capture order. The
// concurrency contract of `.claude/rules/concurrency.md` gives one Processor to one
// goroutine, so this function creates the Processor and never shares it.
//
// The map holds every value the library produces, and never the values of the covered
// methods alone. The maintainer ruled on 2026-08-13 in #361. A value whose vector file names
// no key for its method reaches a comparison, and that comparison reports it as an uncovered
// value. A filter here would drop the value first, and the run would then report nothing for
// it. `conformanceSplitUncovered` reads the covered set instead.
func conformanceProducedByFrame(
	t *testing.T,
	capture string,
	packets []gopacket.Packet,
) map[conformanceKey]string {
	t.Helper()

	produced := make(map[conformanceKey]string)
	processor := NewProcessor(WithKeyLog(conformanceKeyLog(t, capture)))

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
// One result carries four value fields, and this function emits each one. An empty field
// states that the fingerprinter produced nothing, so this function reports no value for it.
//
// Four fingerprinters fill a raw field. `JA4Fingerprinter` fills `Raw`, `OriginalOrder`
// and `RawOriginalOrder`, `JA4SFingerprinter` and `JA4XFingerprinter` each fill `Raw`, and
// `JA4HFingerprinter` fills `RawOriginalOrder`. Issues #274 through #277 added the four.
//
// The `_o` branch reaches no comparison at the pinned commit, and #290 added it for
// symmetry with `conformanceStreamValuesOfResult`. The per-packet vector set names no JA4
// field, so `conformanceMethodOfResultType` maps no result type to `JA4`. A `JA4_o` value
// therefore reaches this function and no vector. A branch that is absent instead reports
// every later value as absent for ever, and the suite then states no cause.
func conformanceValuesOfResult(result FingerprintResult) []conformanceMethodValue {
	method, fingerprint, held := conformanceMethodOfResultType(result)
	if !held {
		return nil
	}

	var values []conformanceMethodValue

	for _, value := range []conformanceMethodValue{
		{Method: method, Value: fingerprint},
		{Method: method + "_r", Value: result.Raw},
		{Method: method + "_o", Value: result.OriginalOrder},
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

	// The per-packet vector set names no field for JA4, so the suite compares JA4 in the
	// per-stream set alone.
	//
	// FoxIO writes both JA4D and JA4D6 under the single field `ja4.ja4d`, and
	// FR-conformance-25 makes this adapter authoritative for the two. The per-stream vector
	// for `dhcpv6.pcap` is an empty list, so no other vector reaches JA4D6. The two types
	// therefore share the method name `JA4D`. One frame carries one DHCP message, so the
	// two types never meet on one frame.
	names := map[string]string{
		"ja4d":   "JA4D",
		"ja4d6":  "JA4D",
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

// conformanceProducedByStream runs one Processor over every packet of the capture and
// returns the value of every method the library produces, keyed by stream.
//
// FR-conformance-15 runs one Processor over every packet in capture order. The concurrency
// contract of `.claude/rules/concurrency.md` gives one Processor to one goroutine, so this
// function creates the Processor and never shares it.
//
// The capture ends, so the function calls Processor.CloseOpenWindows and reads the window
// that each connection holds open. FR-parity-32 states the same call for `cmd/ja4plus`, and
// the per-stream vector of `ssh-r.pcap` holds `"JA4SSH.5": "c76s76_c66s65_c9s51"`, which
// reads 131 SSH packets and reaches no window of 200. The per-packet vector holds no such
// value, so `conformanceProducedByFrame` makes no such call.
//
// The map holds every value the library produces, and never the values of the covered
// methods alone. #361 states the reason, and `conformanceProducedByFrame` carries the same
// rule for the per-packet set.
//
// FR-conformance-22 names the connection by the four address fields. The shape maps the
// endpoint key of each vector entry to the stream name of that connection. A value whose
// endpoint key reaches no entry keeps the endpoint key as its stream name, so the deviation
// names the connection that produced it. The endpoint key holds no `/`, so the register key
// form of `testdata/README.md` still reads in three parts.
func conformanceProducedByStream(
	t *testing.T,
	capture string,
	packets []gopacket.Packet,
	shape conformanceStreamShape,
) map[conformanceKey]string {
	t.Helper()

	produced := make(map[conformanceKey]string)
	occurrences := make(map[conformanceKey]int)
	moved := newConformanceMovedPoints()
	processor := NewProcessor(WithKeyLog(conformanceKeyLog(t, capture)))

	record := func(results []FingerprintResult) {
		for _, result := range results {
			endpoint := conformanceEndpointKey(result.SrcIP, result.SrcPort, result.DstIP, result.DstPort)

			stream, named := shape.StreamOfEndpoint[endpoint]
			if !named {
				stream = endpoint
			}

			for _, value := range conformanceStreamValuesOfResult(result) {
				counter := conformanceKey{Capture: capture, Stream: stream, Method: value.Method}

				// A method whose measurement point moves reports more than once for one
				// connection, and the reference publishes the last of those values. The
				// collapse therefore counts connections, and never emissions.
				if conformanceLastEmissionMethods[value.Method] {
					moved.record(counter, endpoint, value.Value)

					continue
				}

				occurrences[counter]++

				method := conformanceStreamMethodKey(value.Method, occurrences[counter], shape.UsesOccurrence[counter])
				produced[conformanceKey{Capture: capture, Stream: stream, Method: method}] = value.Value
			}
		}
	}

	for index, packet := range packets {
		results, errs := processor.ProcessPacket(packet)
		for _, err := range errs {
			// A fingerprinter returns a non-fatal error, so the suite records it and reads
			// the next packet. An error is not a deviation.
			t.Logf("%s frame %d: %v", capture, index+1, err)
		}

		record(results)
	}

	record(processor.CloseOpenWindows())

	moved.write(produced, shape)

	return produced
}

// conformanceConnectionKey names one connection of one method of one stream.
// The group holds the capture, the stream name and the method. The endpoint holds the
// address pair. Issue #250 gives one stream name to one connection, and this type keeps the
// endpoint so that a later vector that groups two connections still reads each one apart.
type conformanceConnectionKey struct {
	group    conformanceKey
	endpoint string
}

// conformanceMovedPoints collects the values of every method whose measurement point moves.
//
// FoxIO writes one per-stream entry for one connection. It numbers two entries of
// `chrome-cloudflare-quic-with-secrets.pcapng` with the stream number `0`. One of those two
// connections carries TCP, and the other carries QUIC. Issue #215 read the merged group,
// and issue #250 gives each connection its own stream name. The client point of the TCP
// connection moves, and the library reports `30_64` and then `149_64` for it. This
// collection keeps the last value of the connection, so the first value shifts no
// occurrence number.
type conformanceMovedPoints struct {
	// last holds the last value of one connection.
	last map[conformanceConnectionKey]string
	// order holds the endpoint of each connection of one group, in the order in which the
	// connection first reported a value.
	order map[conformanceKey][]string
	// streamLast holds the last value of the whole group, which the bare key compares.
	streamLast map[conformanceKey]string
}

// newConformanceMovedPoints returns an empty collection.
func newConformanceMovedPoints() *conformanceMovedPoints {
	return &conformanceMovedPoints{
		last:       make(map[conformanceConnectionKey]string),
		order:      make(map[conformanceKey][]string),
		streamLast: make(map[conformanceKey]string),
	}
}

// record keeps one value that the connection of the endpoint reports for the group.
func (m *conformanceMovedPoints) record(group conformanceKey, endpoint, value string) {
	connection := conformanceConnectionKey{group: group, endpoint: endpoint}

	if _, held := m.last[connection]; !held {
		m.order[group] = append(m.order[group], endpoint)
	}

	m.last[connection] = value
	m.streamLast[group] = value
}

// write adds the collected values to the produced map.
//
// A group whose vector key carries an occurrence number holds one value for each
// connection, in the order in which the connections first reported. A group whose vector
// key carries none keeps the last value of the whole group, because one bare key compares
// one value.
func (m *conformanceMovedPoints) write(produced map[conformanceKey]string, shape conformanceStreamShape) {
	// A range over a map orders nothing. Each group writes its own keys, so the result is
	// the same on every run.
	for group, endpoints := range m.order {
		if !shape.UsesOccurrence[group] {
			key := conformanceKey{
				Capture: group.Capture,
				Stream:  group.Stream,
				Method:  conformanceStreamMethodKey(group.Method, 1, false),
			}
			produced[key] = m.streamLast[group]

			continue
		}

		for index, endpoint := range endpoints {
			key := conformanceKey{
				Capture: group.Capture,
				Stream:  group.Stream,
				Method:  conformanceStreamMethodKey(group.Method, index+1, true),
			}
			produced[key] = m.last[conformanceConnectionKey{group: group, endpoint: endpoint}]
		}
	}
}

// conformanceRegisterByKey returns the register, keyed by the comparison each entry names.
// FR-reference-25 reads `testdata/deviations.json`, and the suite expects the named
// comparison to differ.
func conformanceRegisterByKey(t *testing.T) map[conformanceKey]deviations.Entry {
	t.Helper()

	register := make(map[conformanceKey]deviations.Entry)

	for _, entry := range readDeviationRegister(t) {
		parts := strings.Split(entry.Key, "/")
		if len(parts) != 3 {
			t.Fatalf("the register entry %q does not name the capture, the stream and the method", entry.Key)
		}

		register[conformanceKey{Capture: parts[0], Stream: parts[1], Method: parts[2]}] = entry
	}

	return register
}

// conformanceSetTotals counts the outcome of one vector set.
type conformanceSetTotals struct {
	Matches          int
	Deviations       int
	AcceptedDeviants int
	Closed           int
	Stale            int
	// Uncovered counts the uncovered values that the register does not name, and
	// AcceptedUncovered counts the uncovered values that the register names. #361 makes an
	// uncovered value a third category, so the two counts stand apart from Deviations and
	// from AcceptedDeviants.
	Uncovered         int
	AcceptedUncovered int
}

// conformanceRunTotals counts the outcome of the whole run.
// The two vector sets cover different methods, so the summary reports each one on its own.
type conformanceRunTotals struct {
	Captures      int
	NotApplicable int
	StreamValues  int
	Stream        conformanceSetTotals
	Packet        conformanceSetTotals
	// Reached names every register key that a comparison of the run reaches. #328 reads it
	// once, after the last capture, because one comparison reads one capture and one vector
	// set.
	Reached map[conformanceKey]bool
	// Orphan counts the register entries that no comparison of the run reaches. The count
	// belongs to the run and to neither vector set, because one entry names one comparison
	// of one set.
	Orphan int
}

// recordReached keeps every register key that the comparison reaches.
func (totals *conformanceRunTotals) recordReached(comparison conformanceComparison) {
	for _, key := range comparison.Reached {
		totals.Reached[key] = true
	}
}

// conformanceFetchedCommit returns the FoxIO commit that `make corpus` fetched.
// It returns the empty string when the corpus records none.
func conformanceFetchedCommit(t *testing.T) string {
	t.Helper()

	fetched, err := os.ReadFile(conformanceFetchedFile)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(fetched))
}

func TestConformance(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	register := conformanceRegisterByKey(t)
	totals := conformanceRunTotals{Reached: make(map[conformanceKey]bool, len(register))}

	commit := conformanceFetchedCommit(t)
	if commit != "" {
		t.Logf("the corpus holds the FoxIO commit %s", commit)
	}

	report := newConformanceReport(commit)

	// The subtests run one after the other. `.claude/rules/concurrency.md` gives one
	// Processor to one goroutine, and a parallel subtest would share the corpus reader
	// and the totals as well.
	for _, capture := range conformanceCaptureNames(t) {
		totals.Captures++

		t.Run(capture, func(t *testing.T) {
			conformanceRunOneCapture(t, capture, register, &totals, report)
		})
	}

	// FR-conformance-33k reads the register once the last capture has run. A key that one
	// capture never reaches is a key another capture reaches, so the check waits for the
	// whole run.
	orphans := conformanceOrphanEntries(register, totals.Reached)
	totals.Orphan = len(orphans)

	report.recordOrphans(register)

	// FR-conformance-27 writes the report on every run. The write comes before the
	// deviation check below, because that check fails the test and a failed run must still
	// leave a current report.
	if err := conformanceWriteReport(report); err != nil {
		t.Fatalf("the run does not write %s: %v", conformanceReportPath, err)
	}

	conformanceCheckReportTotals(t, report, totals)
	conformanceCheckOrphans(t, orphans)
	conformanceReportTotals(t, totals)
}

// conformanceCheckOrphans fails the run for each register entry that no comparison reaches.
// It holds FR-conformance-33j.
//
// The project fails a gate rather than print a warning, as #227 and #306 do, because an
// orphan entry accepts a difference that the run never measures. #250 already proved the
// key case reachable, and the count of accepted deviations then falls without a failure.
func conformanceCheckOrphans(t *testing.T, orphans []conformanceOrphanEntry) {
	t.Helper()

	for _, orphan := range orphans {
		t.Errorf("the register names %s and records the value %q, and no comparison of the run reaches that key, so the entry accepts a difference this run never measures",
			orphan.Key, orphan.Recorded)
	}
}

// conformanceCheckReportTotals fails the run when the report and the suite count it
// differently.
//
// The report counts the run from the comparisons it recorded, and the suite counts it from
// the comparisons it made. A renderer that drops a comparison passes one count and fails
// the other, and one count alone would report a smaller run as a healthy one.
func conformanceCheckReportTotals(t *testing.T, report *conformanceReport, totals conformanceRunTotals) {
	t.Helper()

	counted := report.totals()

	wanted := conformanceRunTotalsAsCounts(totals)
	if counted != wanted {
		t.Errorf("the report counts the run as %+v, and the suite counts it as %+v", counted, wanted)
	}
}

// conformanceRunTotalsAsCounts returns the run totals in the form the report counts them.
func conformanceRunTotalsAsCounts(totals conformanceRunTotals) conformanceReportCounts {
	return conformanceReportCounts{
		Captures:      totals.Captures,
		Compared:      totals.Captures - totals.NotApplicable,
		NotApplicable: totals.NotApplicable,
		Matches:       totals.Stream.Matches + totals.Packet.Matches,
		Deviations:    totals.Stream.Deviations + totals.Packet.Deviations,
		Accepted:      totals.Stream.AcceptedDeviants + totals.Packet.AcceptedDeviants,
		Stale:         totals.Stream.Stale + totals.Packet.Stale,
		Orphan:        totals.Orphan,

		Uncovered:         totals.Stream.Uncovered + totals.Packet.Uncovered,
		AcceptedUncovered: totals.Stream.AcceptedUncovered + totals.Packet.AcceptedUncovered,
	}
}

// conformanceRunOneCapture compares one capture against the two vector sets and adds its
// outcome to the totals.
func conformanceRunOneCapture(
	t *testing.T,
	capture string,
	register map[conformanceKey]deviations.Entry,
	totals *conformanceRunTotals,
	report *conformanceReport,
) {
	t.Helper()

	report.readCapture(capture)

	// `loadPCAP` of `integration_test.go` reads the two capture formats and keeps the
	// capture order. It reads the magic bytes, because the corpus names one pcap file
	// `http1.pcapng`.
	packets := loadPCAP(t, filepath.Join(conformanceCaptureDir, capture))
	t.Logf("the capture holds %d packets", len(packets))

	// FoxIO marks this capture `notest`, so FoxIO runs no test over it. The suite reads
	// it, which proves that the library decodes it without a panic, and compares nothing.
	if strings.Contains(capture, conformanceNotestMarker) {
		totals.NotApplicable++

		report.declineCapture(capture, conformanceReportNotestReason)

		// The count of per-stream entries reports the size of the corpus, so it counts a
		// capture the suite compares and a capture the suite skips alike.
		if path := conformanceVectorPath(conformanceStreamVectorDir, capture); path != "" {
			totals.StreamValues += len(conformanceReadStreamVector(t, path))
		}

		t.Logf("FoxIO marks this capture `%s`, so the suite records it as not applicable",
			strings.Trim(conformanceNotestMarker, "."))

		conformanceProducedByFrame(t, capture, packets)

		return
	}

	compared := conformanceRunStreamSet(t, capture, packets, register, totals, report)
	compared = conformanceRunPacketSet(t, capture, packets, register, totals, report) || compared

	if !compared {
		totals.NotApplicable++

		report.declineCapture(capture, conformanceReportNoVectorReason)

		t.Logf("no vector of the corpus holds a value for this capture, so the suite records it as not applicable")
	}
}

// conformanceRunStreamSet compares the capture against the per-stream vector.
// It reports whether the suite compared a value.
func conformanceRunStreamSet(
	t *testing.T,
	capture string,
	packets []gopacket.Packet,
	register map[conformanceKey]deviations.Entry,
	totals *conformanceRunTotals,
	report *conformanceReport,
) bool {
	t.Helper()

	// FR-conformance-13 reads the per-stream vector for a capture when one exists.
	path := conformanceVectorPath(conformanceStreamVectorDir, capture)
	if path == "" {
		t.Logf("the corpus holds no per-stream vector for this capture")

		return false
	}

	entries := conformanceReadStreamVector(t, path)
	totals.StreamValues += len(entries)

	shape, err := conformanceExpectedFromStreamVector(capture, entries)
	if err != nil {
		t.Fatalf("the per-stream adapter fails: %v", err)
	}

	if len(shape.Expected) == 0 {
		t.Logf("the per-stream vector holds %d entries and no value, so the suite compares nothing in the per-stream set",
			len(entries))

		return false
	}

	produced := conformanceProducedByStream(t, capture, packets, shape)
	comparison := conformanceSplitUncovered(compareConformance(produced, shape.Expected, register), shape.Covered)

	report.recordComparison(capture, conformanceReportStreamSet, comparison)
	conformanceRecordComparison(t, conformanceReportStreamSet, comparison, &totals.Stream)
	totals.recordReached(comparison)

	return true
}

// conformanceRunPacketSet compares the capture against the per-packet vector.
// It reports whether the suite compared a value.
func conformanceRunPacketSet(
	t *testing.T,
	capture string,
	packets []gopacket.Packet,
	register map[conformanceKey]deviations.Entry,
	totals *conformanceRunTotals,
	report *conformanceReport,
) bool {
	t.Helper()

	// FR-conformance-14 reads the per-packet vector for a capture when one exists.
	path := conformanceVectorPath(conformancePacketVectorDir, capture)
	if path == "" {
		t.Logf("the corpus holds no per-packet vector for this capture")

		return false
	}

	expected := conformanceExpectedFromPacketVector(t, capture, conformanceReadPacketVector(t, path))
	if len(expected) == 0 {
		t.Logf("the per-packet vector holds no value, so the suite compares nothing in the per-packet set")

		return false
	}

	produced := conformanceProducedByFrame(t, capture, packets)
	comparison := conformanceSplitUncovered(
		compareConformance(produced, expected, register), conformanceCoveredMethods(expected))

	report.recordComparison(capture, conformanceReportPacketSet, comparison)
	conformanceRecordComparison(t, conformanceReportPacketSet, comparison, &totals.Packet)
	totals.recordReached(comparison)

	return true
}

// conformanceRecordComparison logs one comparison and adds its outcome to the set totals.
func conformanceRecordComparison(
	t *testing.T,
	set string,
	comparison conformanceComparison,
	totals *conformanceSetTotals,
) {
	t.Helper()

	totals.Matches += comparison.Matches
	totals.Closed += len(comparison.Closed)
	totals.Stale += len(comparison.Stale)

	// #361 counts an uncovered value apart from a deviation. An unaccepted uncovered value
	// fails no gate, because the difference measures the coverage of the reference file.
	for _, uncovered := range comparison.Uncovered {
		if uncovered.Accepted {
			totals.AcceptedUncovered++

			t.Logf("accepted %s uncovered value %s: %q (the register names it)",
				set, uncovered.Key, uncovered.Produced)

			continue
		}

		totals.Uncovered++

		t.Logf("%s uncovered value %s: the vector file names no key for the method\n  produced: %q",
			set, uncovered.Key, uncovered.Produced)
	}

	for _, deviation := range comparison.Deviations {
		if deviation.Accepted {
			totals.AcceptedDeviants++

			t.Logf("accepted %s deviation %s: %s (the register names it)", set, deviation.Key, deviation.Kind)

			continue
		}

		totals.Deviations++

		t.Logf("%s deviation %s: %s\n  expected: %q\n  produced: %q",
			set, deviation.Key, deviation.Kind, deviation.Expected, deviation.Produced)
	}

	// FR-reference-26 fails the suite when a comparison the register names now matches.
	for _, key := range comparison.Closed {
		t.Errorf("the register names %s, and the comparison now matches, so the entry is closed and must leave the register", key)
	}

	// #307 fails the suite when a register entry records a value the run no longer produces.
	// The project fails a gate rather than print a warning, as #227 and #306 do, because a
	// stale entry accepts a difference the maintainer never ruled on.
	for _, stale := range comparison.Stale {
		t.Errorf("the register names %s and records the value %q, and the run produces %q, so the entry records a comparison this run does not make",
			stale.Key, stale.Recorded, stale.Produced)
	}

	t.Logf("the capture reports %d matches and %d deviations in the %s set",
		comparison.Matches, len(comparison.Deviations), set)
}

// conformanceReportTotals writes the summary and fails the run when a deviation remains.
func conformanceReportTotals(t *testing.T, totals conformanceRunTotals) {
	t.Helper()

	t.Logf("the run read %d captures, %d of them not applicable, and %d per-stream entries",
		totals.Captures, totals.NotApplicable, totals.StreamValues)
	t.Logf("the per-stream set reports %d matches, %d deviations and %d accepted deviations",
		totals.Stream.Matches, totals.Stream.Deviations, totals.Stream.AcceptedDeviants)
	t.Logf("the per-packet set reports %d matches, %d deviations and %d accepted deviations",
		totals.Packet.Matches, totals.Packet.Deviations, totals.Packet.AcceptedDeviants)

	matches := totals.Stream.Matches + totals.Packet.Matches
	deviations := totals.Stream.Deviations + totals.Packet.Deviations

	t.Logf("the run reports %d matches, %d deviations and %d accepted deviations",
		matches, deviations, totals.Stream.AcceptedDeviants+totals.Packet.AcceptedDeviants)

	// #361 states the two counts on every run. An uncovered value is neither a match nor a
	// deviation. A reader of the two counts above alone therefore reads fewer values than the
	// library produces.
	t.Logf("the run reports %d unaccepted uncovered values and %d accepted uncovered values",
		totals.Stream.Uncovered+totals.Packet.Uncovered,
		totals.Stream.AcceptedUncovered+totals.Packet.AcceptedUncovered)

	// #307 states the count on every run. A count of 0 is the measurement that proves the
	// register records the values this run produces.
	t.Logf("the run reports %d stale register entries", totals.Stream.Stale+totals.Packet.Stale)

	// #328 states the two counts on every run. `Accepted == |register|` proved the register
	// before this check, and the two counts below replace that identity with a measurement.
	t.Logf("the run reaches %d register keys and reports %d orphan register entries",
		len(totals.Reached), totals.Orphan)

	if deviations > 0 {
		t.Errorf("the run reports %d deviations that the register does not hold, and Epic 5 closes them", deviations)
	}
}

func TestTheSuiteReadsEveryCaptureOfTheCorpus(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	// The acceptance criteria of `docs/specs/features/04-conformance-harness.md` name 38
	// captures, 37 per-stream vectors and 37 per-packet vectors at commit `27f0cbf`. The pin
	// move of #797 to `16b96d95` adds `sigalg-grease.pcapng` and its two vectors.
	captures := conformanceCaptureNames(t)
	if len(captures) != 39 {
		t.Errorf("the corpus holds %d captures, and the pinned commit publishes 39", len(captures))
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

	if streams != 38 {
		t.Errorf("the corpus holds %d per-stream vectors, and the pinned commit publishes 38", streams)
	}

	if packetVectors != 38 {
		t.Errorf("the corpus holds %d per-packet vectors, and the pinned commit publishes 38", packetVectors)
	}
}

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

// conformanceMovingPointFingerprinter names the fingerprinter whose measurement point moves.
//
// `methodNameOfFingerprinter` reads the stem `ja4l` from this name, and every member of
// `conformanceLastEmissionMethods` carries that stem. A test derives the tie. A rename of
// the fingerprinter therefore fails the suite, and the rule reaches no name that the
// processor no longer runs.
const conformanceMovingPointFingerprinter = "JA4LFingerprinter"

// conformanceLastEmissionMethods names every per-stream method whose bare vector key
// compares the last value the library reports.
//
// The maintainer ruled on 2026-08-12 in issue #196 that the harness compares the last JA4L
// emission of one stream. `docs/specs/foxio/JA4L.md` R33 names the measurement point that
// moves, and `ja4l_test.go` holds the rule that point B never moves.
//
// The collapse reads one connection, and never one stream number. FoxIO writes one
// per-stream entry for one connection, and two entries of one capture can carry one stream
// number. `conformanceMovedPoints` in `conformance_test.go` holds the collapse, and issue
// #215 holds the reading.
//
// Round 20 of the `## Changelog` of `docs/specs/spec.md` narrows the ruling to this set, and
// it reverses no part of round 15. A method that emits once per protocol reaches no entry
// here, and a method that emits once per request reaches none either. The second value of
// such a method is a surplus value, and a surplus value reports as a deviation. Issue #209
// measured what the wider rule cost.
var conformanceLastEmissionMethods = map[string]bool{
	"JA4L-C": true,
	"JA4L-S": true,
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
	// StreamOfEndpoint maps the endpoint key of a connection to the stream name that the
	// key of a comparison holds. `conformanceStreamNames` states the two forms of the name.
	StreamOfEndpoint map[string]string
	// UsesOccurrence reports whether the key of a method carries an occurrence number on
	// one stream. The library names a method without one, so the produced key follows the
	// vector. The map is keyed by the capture, the stream and the method with no
	// occurrence number, which is the key the producer counts on.
	//
	// The decision is per stream, and never per capture. FoxIO writes one entry for each
	// HTTP request, so `http2-with-cookies.pcapng` holds 16 entries for stream 0 that each
	// carry the bare key `JA4H`, and `tls12.pcap` holds one entry that carries `JA4.1`.
	UsesOccurrence map[conformanceKey]bool
	// Covered names every method the vector holds.
	//
	// It filtered the comparison before #361, and it names the split instead. The suite
	// compares every value the library produces, and `conformanceSplitUncovered` reads this
	// map to decide which of them the vector covers. A value of a method this map does not
	// name is an uncovered value, which is neither a match nor a deviation.
	Covered map[string]bool
}

// conformanceStreamValue is one value that a per-stream vector entry holds for a method.
type conformanceStreamValue struct {
	// occurrence is the number the vector key carries, and zero when the key carries none.
	occurrence int
	// value is the fingerprint, exactly as the vector writes it.
	value string
}

// conformanceExpectedFromStreamVector returns the shape of one per-stream vector.
//
// It holds FR-conformance-20, FR-conformance-21 and FR-conformance-22. It returns an error
// for a key it does not recognize, which holds FR-conformance-26.
//
// An entry names its stream by the `stream` field, so a register key reads as
// `testdata/README.md` writes it, for example `ssh2.pcapng/15/JA4L-S`.
//
// More than one entry can name one stream. FoxIO writes one entry for each HTTP request,
// so `http2-with-cookies.pcapng` holds 16 entries for stream 0 that each carry the bare key
// `JA4H` with a different value. The adapter therefore collects the values of one stream
// and one method in entry order, and it numbers them when there is more than one. A single
// map write would keep the last value alone and compare the other 15 against the wrong
// value.
func conformanceExpectedFromStreamVector(
	capture string,
	entries []conformanceStreamEntry,
) (conformanceStreamShape, error) {
	shape := conformanceStreamShape{
		Expected:         make(map[conformanceKey]string),
		StreamOfEndpoint: make(map[string]string),
		UsesOccurrence:   make(map[conformanceKey]bool),
		Covered:          make(map[string]bool),
	}

	collected := make(map[conformanceKey][]conformanceStreamValue)

	connections := make([]conformanceStreamConnection, len(entries))

	for index, entry := range entries {
		connection, err := conformanceStreamIdentity(entry)
		if err != nil {
			return shape, fmt.Errorf("entry %d of the per-stream vector for %s: %w", index, capture, err)
		}

		connections[index] = connection
	}

	names, err := conformanceStreamNames(connections)
	if err != nil {
		return shape, fmt.Errorf("the per-stream vector for %s: %w", capture, err)
	}

	shape.StreamOfEndpoint = names

	for index, entry := range entries {
		stream := names[connections[index].endpoint]

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

			shape.Covered[method] = true

			group := conformanceKey{Capture: capture, Stream: stream, Method: method}
			collected[group] = append(collected[group], conformanceStreamValue{occurrence: occurrence, value: value})
		}
	}

	// A range over a map orders nothing, so the values of one stream and one method arrive
	// in entry order and the groups arrive in no order. Each group is independent, so the
	// result is the same on every run.
	for group, values := range collected {
		if err := conformanceWriteStreamGroup(shape, group, values); err != nil {
			return shape, err
		}
	}

	return shape, nil
}

// conformanceWriteStreamGroup writes the values of one stream and one method into the
// expected map, and it records which key form the vector uses for them.
//
// The vector writes an explicit occurrence number for some methods, such as `JA4X.1`. Where
// it writes none, the adapter numbers the values itself when the stream holds more than
// one. A stream that holds one value keeps the bare key, which is the form the vector
// writes.
func conformanceWriteStreamGroup(
	shape conformanceStreamShape,
	group conformanceKey,
	values []conformanceStreamValue,
) error {
	explicit := values[0].occurrence > 0

	for _, held := range values {
		if (held.occurrence > 0) != explicit {
			return fmt.Errorf(
				"the per-stream vector for %s writes the method %q on stream %s with an occurrence number and without one, and the two forms name one method",
				group.Capture, group.Method, group.Stream)
		}
	}

	shape.UsesOccurrence[group] = explicit || len(values) > 1

	for index, held := range values {
		occurrence := index + 1
		if explicit {
			occurrence = held.occurrence
		}

		key := conformanceKey{
			Capture: group.Capture,
			Stream:  group.Stream,
			Method:  conformanceStreamMethodKey(group.Method, occurrence, shape.UsesOccurrence[group]),
		}

		if seen, held2 := shape.Expected[key]; held2 {
			return fmt.Errorf(
				"the per-stream vector for %s writes the key %q twice on stream %s, and it holds %q and %q",
				group.Capture, key.Method, group.Stream, seen, held.value)
		}

		shape.Expected[key] = held.value
	}

	return nil
}

// conformanceStreamConnection names the connection that one per-stream vector entry holds.
type conformanceStreamConnection struct {
	// stream is the value of the `stream` field, written exactly as the vector writes it.
	stream string
	// endpoint is the key that the two directions of the connection share.
	endpoint string
	// sourcePort is the value of the `srcport` field. It separates two connections that
	// carry one stream number.
	sourcePort uint16
}

// conformanceStreamIdentity returns the connection that one entry names.
func conformanceStreamIdentity(entry conformanceStreamEntry) (conformanceStreamConnection, error) {
	var connection conformanceStreamConnection

	stream, held := entry["stream"]
	if !held {
		return connection, fmt.Errorf("the entry holds no %q field, and FR-conformance-22 names the stream", "stream")
	}

	source, err := conformanceStreamEndpoint(entry, "src", "srcport")
	if err != nil {
		return connection, err
	}

	destination, err := conformanceStreamEndpoint(entry, "dst", "dstport")
	if err != nil {
		return connection, err
	}

	connection.stream = string(stream)
	connection.endpoint = conformanceEndpointKey(source.address, source.port, destination.address, destination.port)
	connection.sourcePort = source.port

	return connection, nil
}

// conformanceStreamNames returns the stream name of every connection, keyed by the endpoint
// key of the connection.
//
// **A stream number names no connection on its own.** `tcp.stream` and `udp.stream` are two
// counters, and both start at 0, so one capture holds a TCP connection and a UDP connection
// that carry the stream number `0`. `chrome-cloudflare-quic-with-secrets.pcapng` holds such
// a pair, and the vector keeps the two apart by the source port. A name that holds the
// stream number alone merges the two connections, and the harness then reports a value of
// one connection as a later occurrence of the other. Issue #250 holds the reading.
//
// A stream number that names one connection keeps the bare number, so a register key of
// `testdata/deviations.json` still names the comparison it named before. A stream number
// that names more than one connection gains the source port, in the form `0:50280`. The
// name holds no `/`, so the register key form of `testdata/README.md` still reads in three
// parts.
//
// The name reads the source port of the first entry of the connection, and never the source
// port of each entry. FoxIO writes one entry for each HTTP request, and it swaps the two
// ends between a request and a response. `http2-with-cookies.pcapng` writes the source port
// `58847` and then `443` for one connection, so the source port of one entry names no
// connection.
func conformanceStreamNames(connections []conformanceStreamConnection) (map[string]string, error) {
	endpointsOfStream := make(map[string]map[string]bool)
	portOfEndpoint := make(map[string]uint16, len(connections))

	for _, connection := range connections {
		endpoints, held := endpointsOfStream[connection.stream]
		if !held {
			endpoints = make(map[string]bool)
			endpointsOfStream[connection.stream] = endpoints
		}

		endpoints[connection.endpoint] = true

		if _, held := portOfEndpoint[connection.endpoint]; !held {
			portOfEndpoint[connection.endpoint] = connection.sourcePort
		}
	}

	names := make(map[string]string, len(connections))
	owners := make(map[string]string, len(connections))

	for _, connection := range connections {
		name := connection.stream
		if len(endpointsOfStream[connection.stream]) > 1 {
			name = connection.stream + ":" + strconv.FormatUint(uint64(portOfEndpoint[connection.endpoint]), 10)
		}

		// Two connections that reach one name would collapse again, and the collapse is the
		// defect this function repairs. The suite fails rather than report a merged count.
		if owner, held := owners[name]; held && owner != connection.endpoint {
			return nil, fmt.Errorf(
				"the connections %q and %q both reach the stream name %q, and one name compares one connection",
				owner, connection.endpoint, name)
		}

		owners[name] = connection.endpoint
		names[connection.endpoint] = name
	}

	return names, nil
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
// One result carries four fields, because a fingerprinter reports the fingerprint, the raw
// form, the hashed wire-order form and the raw wire-order form together. An empty field
// states that the fingerprinter produced nothing, so this function reports no value for it.
// A JA4L result carries the fingerprint alone, and the three other fields of it are empty.
//
// `ja4.go` fills `OriginalOrder`, which FoxIO hashes from the wire-order form, and no other
// fingerprinter fills it. Issue #277 added the field, and the per-stream vector holds
// `JA4_o` on 160 entries.
func conformanceStreamValuesOfResult(result FingerprintResult) []conformanceMethodValue {
	method, fingerprint, held := conformanceStreamMethodOfResult(result)
	if !held {
		return nil
	}

	var values []conformanceMethodValue

	for _, value := range []conformanceMethodValue{
		{Method: method, Value: fingerprint},
		{Method: method + "_r", Value: result.Raw},
		{Method: method + "_o", Value: result.OriginalOrder},
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
// vector uses for that method.
//
// A method emits twice on one stream for two different reasons, and one rule cannot serve
// both.
//
// A method of `conformanceLastEmissionMethods` keeps the bare key for every value of one
// stream, so the last value the library reports replaces the earlier ones. The reference is a
// batch program that publishes the final state of its cache, and this library is a streaming
// interface that reports a value for each packet. A moved measurement point therefore
// reports twice, and the last report holds the value that the reference publishes.
// `docs/specs/foxio/JA4L.md` R33 names the measurement point that moves, and the maintainer
// ruled on 2026-08-12 in issue #196.
//
// Every other method gains an occurrence number for the second value and for each value
// after it. Such a method emits once per protocol, or once per request, so the second value
// is a surplus value and not a moved point. The bare key then keeps the value the vector
// names, and the surplus value reports as the deviation kind of FR-conformance-17. Round 20
// of the `## Changelog` of `docs/specs/spec.md` records the narrower rule, and issue #209
// measured what the wider rule cost.
//
// Three callers reach this function, and each one reaches a different branch.
// `conformanceProducedByStream` at `conformance_test.go:460` builds the produced map, and it
// counts the emissions of the library, so it reaches the second branch below.
// `conformanceMovedPoints.write` at `conformance_test.go:547` builds the produced map for a
// method of `conformanceLastEmissionMethods`, and it counts the connections of one group. It
// reaches the first branch or the third one. This function builds the expected map through
// `conformanceWriteStreamGroup`, which forces
// `usesOccurrence` true whenever one vector group holds more than one value. The occurrence
// of an expected value is therefore always 1, and the expected map reaches the second branch
// on no input. **Keep the branch.** The produced map needs it, and no special case in this
// function bars the expected map from it.
func conformanceStreamMethodKey(method string, occurrence int, usesOccurrence bool) string {
	if usesOccurrence {
		return conformanceMethodOccurrence(method, occurrence)
	}

	if occurrence > 1 && !conformanceLastEmissionMethods[method] {
		return conformanceMethodOccurrence(method, occurrence)
	}

	return method
}

// These tests hold FR-conformance-16 through FR-conformance-19, FR-reference-25 and
// FR-reference-26. They run over fixture values, because a corpus comparison proves the
// engine only where the corpus reaches the case. The register is empty today, so a
// fixture register is the only way to exercise the two reference requirements.
//
// `.claude/rules/rulings.md` reserves a register entry to the maintainer. These fixtures
// live in the test and reach `testdata/deviations.json` never.

// oneConformanceKey returns the key of one comparison the fixtures use.
func oneConformanceKey(method string) conformanceKey {
	return conformanceKey{Capture: "tls12.pcap", Stream: "1", Method: method}
}

func TestTheComparisonReportsAMatchWhenTheTwoValuesAreEqual(t *testing.T) {
	key := oneConformanceKey("JA4")
	value := "t13d1715h2_5b57614c22b0_3d5424432f57"

	result := compareConformance(
		map[conformanceKey]string{key: value},
		map[conformanceKey]string{key: value},
		nil,
	)

	if result.Matches != 1 {
		t.Errorf("the comparison reports %d matches, and the two values are equal", result.Matches)
	}

	if len(result.Deviations) != 0 {
		t.Errorf("the comparison reports %d deviations, and the two values are equal", len(result.Deviations))
	}
}

// FR-conformance-17 makes an extra fingerprint a deviation.
func TestTheComparisonReportsADeviationWhenTheLibraryProducesAValueTheVectorLacks(t *testing.T) {
	key := oneConformanceKey("JA4T")

	result := compareConformance(
		map[conformanceKey]string{key: "8192_2-1-3-1-1-4_1460_8"},
		map[conformanceKey]string{},
		nil,
	)

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the library produces one extra value", len(result.Deviations))
	}

	deviation := result.Deviations[0]

	if deviation.Kind != conformanceExtraValue {
		t.Errorf("the comparison reports the kind %q, and FR-conformance-17 names %q", deviation.Kind, conformanceExtraValue)
	}

	if deviation.Produced != "8192_2-1-3-1-1-4_1460_8" {
		t.Errorf("the deviation holds the produced value %q, and the library produced `8192_2-1-3-1-1-4_1460_8`", deviation.Produced)
	}

	if deviation.Expected != "" {
		t.Errorf("the deviation holds the expected value %q, and the vector holds no value", deviation.Expected)
	}
}

// FR-conformance-18 makes an absent fingerprint a deviation.
func TestTheComparisonReportsADeviationWhenTheVectorHoldsAValueTheLibraryLacks(t *testing.T) {
	key := oneConformanceKey("JA4S")

	result := compareConformance(
		map[conformanceKey]string{},
		map[conformanceKey]string{key: "t130200_1301_a56c5b993250"},
		nil,
	)

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the vector holds one value the library lacks", len(result.Deviations))
	}

	deviation := result.Deviations[0]

	if deviation.Kind != conformanceAbsentValue {
		t.Errorf("the comparison reports the kind %q, and FR-conformance-18 names %q", deviation.Kind, conformanceAbsentValue)
	}

	if deviation.Expected != "t130200_1301_a56c5b993250" {
		t.Errorf("the deviation holds the expected value %q, and the vector holds `t130200_1301_a56c5b993250`", deviation.Expected)
	}

	if deviation.Produced != "" {
		t.Errorf("the deviation holds the produced value %q, and the library produced no value", deviation.Produced)
	}
}

// FR-conformance-19 makes one character a deviation. The acceptance criteria name a
// fingerprint that a test changes by one character, and this test holds that case.
func TestTheComparisonReportsADeviationWhenTheTwoValuesDifferByOneCharacter(t *testing.T) {
	key := oneConformanceKey("JA4")

	result := compareConformance(
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f58"},
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f57"},
		nil,
	)

	if result.Matches != 0 {
		t.Errorf("the comparison reports %d matches, and the two values differ by one character", result.Matches)
	}

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the two values differ by one character", len(result.Deviations))
	}

	deviation := result.Deviations[0]

	if deviation.Kind != conformanceChangedValue {
		t.Errorf("the comparison reports the kind %q, and FR-conformance-19 names %q", deviation.Kind, conformanceChangedValue)
	}

	// FR-conformance-32 requires both values, and #35 writes them into the report.
	if deviation.Expected != "t13d1715h2_5b57614c22b0_3d5424432f57" || deviation.Produced != "t13d1715h2_5b57614c22b0_3d5424432f58" {
		t.Errorf("the deviation holds the expected value %q and the produced value %q", deviation.Expected, deviation.Produced)
	}
}

// FR-conformance-16 compares as an exact string match. A comparison that trims, lowercases
// or sorts a value reports a match this project does not hold.
func TestTheComparisonReportsADeviationForACaseChangeAndForAWhitespaceChange(t *testing.T) {
	cases := []struct {
		name     string
		produced string
		expected string
	}{
		{"the case differs", "T13D1715H2_5B57614C22B0_3D5424432F57", "t13d1715h2_5b57614c22b0_3d5424432f57"},
		{"a trailing space is present", "t13d1715h2_5b57614c22b0_3d5424432f57 ", "t13d1715h2_5b57614c22b0_3d5424432f57"},
		{"a leading space is present", " t13d1715h2_5b57614c22b0_3d5424432f57", "t13d1715h2_5b57614c22b0_3d5424432f57"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key := oneConformanceKey("JA4")

			result := compareConformance(
				map[conformanceKey]string{key: testCase.produced},
				map[conformanceKey]string{key: testCase.expected},
				nil,
			)

			if result.Matches != 0 {
				t.Errorf("the comparison reports a match where %s, and FR-conformance-16 requires an exact string match", testCase.name)
			}
		})
	}
}

// FR-reference-25 expects the comparison the register names to differ. An accepted
// deviation is a recorded ruling, and it is not a failure.
func TestTheComparisonAcceptsADeviationTheRegisterNames(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_58"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Deviations) != 1 {
		t.Fatalf("the comparison reports %d deviations, and the two values differ", len(result.Deviations))
	}

	if !result.Deviations[0].Accepted {
		t.Errorf("the comparison reports an unaccepted deviation, and the register names the comparison %q", key)
	}

	if len(result.Closed) != 0 {
		t.Errorf("the comparison reports %d closed entries, and the comparison still differs", len(result.Closed))
	}
}

// FR-reference-26 fails the suite when a comparison the register names now matches. A
// closed deviation that sits in the register unnoticed hides a repair.
func TestTheComparisonReportsAClosedEntryWhenARegisteredComparisonMatches(t *testing.T) {
	key := oneConformanceKey("JA4L-S")
	value := "6252_58"

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: value, Theirs: value, Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: value},
		map[conformanceKey]string{key: value},
		register,
	)

	if len(result.Closed) != 1 {
		t.Fatalf("the comparison reports %d closed entries, and the register names one comparison that now matches", len(result.Closed))
	}

	if result.Closed[0] != key {
		t.Errorf("the comparison reports the closed entry %q, and the register names %q", result.Closed[0], key)
	}

	// A closed entry is a failure, so it must never count as a match that the summary
	// reports as healthy.
	if result.Matches != 0 {
		t.Errorf("the comparison counts %d matches, and a closed register entry is a failure", result.Matches)
	}
}

// #307 states that a register entry records a value the run no longer produces. The entry
// then accepts a comparison it does not describe, and FR-reference-26 never fires, because
// the two values still differ.
func TestTheComparisonReportsAStaleEntryWhenTheRunNoLongerProducesTheRecordedValue(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_57"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 1 {
		t.Fatalf("the comparison reports %d stale entries, and the run produces `6252_57` where the register records `6252_58`",
			len(result.Stale))
	}

	stale := result.Stale[0]

	if stale.Key != key {
		t.Errorf("the comparison reports the stale entry %q, and the register names %q", stale.Key, key)
	}

	if stale.Recorded != "6252_58" || stale.Produced != "6252_57" {
		t.Errorf("the stale entry records %q and produces %q, and the fixture holds `6252_58` and `6252_57`",
			stale.Recorded, stale.Produced)
	}

	// The entry still accepts the deviation. A stale record is a defect of the register,
	// and it never turns a ruling into an unaccepted deviation.
	if len(result.Deviations) != 1 || !result.Deviations[0].Accepted {
		t.Errorf("the comparison reports %d deviations, and the register names the comparison %q",
			len(result.Deviations), key)
	}
}

// An entry the run still reaches is not stale. A check that reported one on every entry
// would fail every run and gate nothing.
func TestTheComparisonReportsNoStaleEntryWhenTheRunProducesTheRecordedValue(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_58"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 0 {
		t.Errorf("the comparison reports %d stale entries, and the run produces the recorded value `6252_58`",
			len(result.Stale))
	}
}

// A capability decline records the empty string, because the library produces no value.
// The library that starts to produce one makes that record wrong.
func TestTheComparisonReportsAStaleEntryWhenTheLibraryProducesAValueACapabilityDeclineDenies(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Capability: true, Ours: "", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_58"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 1 {
		t.Fatalf("the comparison reports %d stale entries, and the entry records no value where the run produces `6252_58`",
			len(result.Stale))
	}

	if result.Stale[0].Recorded != "" || result.Stale[0].Produced != "6252_58" {
		t.Errorf("the stale entry records %q and produces %q, and the fixture holds the empty string and `6252_58`",
			result.Stale[0].Recorded, result.Stale[0].Produced)
	}
}

// A capability decline that still holds produces no value, and the empty record matches it.
func TestTheComparisonReportsNoStaleEntryWhenACapabilityDeclineStillProducesNoValue(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Capability: true, Ours: "", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Stale) != 0 {
		t.Errorf("the comparison reports %d stale entries, and the library produces no value for the key %q",
			len(result.Stale), key)
	}
}

// One entry carries two defects when the run reaches the vector value and the entry records
// a third value. The suite then prints one message for each, and neither one replaces the
// other.
func TestTheComparisonReportsAClosedEntryAndAStaleEntryForOneRegisterKey(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: "6252_58", Theirs: "6252_59", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "6252_59"},
		map[conformanceKey]string{key: "6252_59"},
		register,
	)

	if len(result.Closed) != 1 {
		t.Fatalf("the comparison reports %d closed entries, and the run produces the vector value `6252_59`",
			len(result.Closed))
	}

	if len(result.Stale) != 1 {
		t.Fatalf("the comparison reports %d stale entries, and the entry records `6252_58` where the run produces `6252_59`",
			len(result.Stale))
	}

	if result.Matches != 0 {
		t.Errorf("the comparison counts %d matches, and the register names the comparison %q", result.Matches, key)
	}
}

// The register names no comparison the run makes, so no stale entry can stand. A nil
// register accepts nothing, and it must report nothing.
func TestTheComparisonReportsNoStaleEntryWhenTheRegisterNamesNoComparison(t *testing.T) {
	key := oneConformanceKey("JA4")

	result := compareConformance(
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f58"},
		map[conformanceKey]string{key: "t13d1715h2_5b57614c22b0_3d5424432f57"},
		nil,
	)

	if len(result.Stale) != 0 {
		t.Errorf("the comparison reports %d stale entries, and the register names no comparison", len(result.Stale))
	}
}

// The engine sorts its deviations, so a report and a failure message read the same on
// every run. A range over a map orders nothing.
func TestTheComparisonSortsTheDeviationsByKey(t *testing.T) {
	produced := map[conformanceKey]string{
		{Capture: "b.pcap", Stream: "1", Method: "JA4"}:  "b1",
		{Capture: "a.pcap", Stream: "2", Method: "JA4"}:  "a2",
		{Capture: "a.pcap", Stream: "1", Method: "JA4S"}: "a1s",
		{Capture: "a.pcap", Stream: "1", Method: "JA4"}:  "a1",
	}

	result := compareConformance(produced, map[conformanceKey]string{}, nil)

	wanted := []string{
		"a.pcap/1/JA4",
		"a.pcap/1/JA4S",
		"a.pcap/2/JA4",
		"b.pcap/1/JA4",
	}

	if len(result.Deviations) != len(wanted) {
		t.Fatalf("the comparison reports %d deviations, and the fixture holds %d", len(result.Deviations), len(wanted))
	}

	for index, key := range wanted {
		if got := result.Deviations[index].Key.String(); got != key {
			t.Errorf("deviation %d holds the key %q, and the sorted order names %q", index, got, key)
		}
	}
}

func TestTheConformanceKeyWritesTheRegisterKeyForm(t *testing.T) {
	// `testdata/README.md` states the form `<capture>/<stream>/<method>`, and
	// `deviations.CheckKey` holds it. A key the register cannot name is a key that
	// FR-reference-25 cannot reach.
	key := conformanceKey{Capture: "ssh2.pcapng", Stream: "15", Method: "JA4L-S"}

	if key.String() != "ssh2.pcapng/15/JA4L-S" {
		t.Fatalf("the key writes %q, and the register form is `ssh2.pcapng/15/JA4L-S`", key.String())
	}

	if err := deviations.CheckKey(key.String()); err != nil {
		t.Errorf("the register reader rejects the key %q: %v", key.String(), err)
	}
}

// #328 states that the stale check of #307 reaches the keys of the two value maps alone. A
// register entry whose key neither map holds reaches no comparison, so the comparison names
// the keys it reaches and the run subtracts them from the register.
func TestTheComparisonNamesEveryRegisterKeyItReaches(t *testing.T) {
	reached := oneConformanceKey("JA4")
	absent := oneConformanceKey("JA4S")

	register := map[conformanceKey]deviations.Entry{
		reached: {Key: reached.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
		absent:  {Key: absent.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{reached: "ours"},
		map[conformanceKey]string{reached: "theirs"},
		register,
	)

	if len(result.Reached) != 1 {
		t.Fatalf("the comparison names %d reached register keys, and it compares the one key %q",
			len(result.Reached), reached)
	}

	if result.Reached[0] != reached {
		t.Errorf("the comparison names the reached key %q, and it compares %q", result.Reached[0], reached)
	}
}

// A key that the register does not name measures nothing about the register, so the
// comparison names it nowhere.
func TestTheComparisonNamesNoReachedKeyThatTheRegisterDoesNotHold(t *testing.T) {
	key := oneConformanceKey("JA4")

	result := compareConformance(
		map[conformanceKey]string{key: "value"},
		map[conformanceKey]string{key: "value"},
		nil,
	)

	if len(result.Reached) != 0 {
		t.Errorf("the comparison names %d reached register keys, and the register holds none", len(result.Reached))
	}
}

// A closed entry names a key the run reaches. An orphan check that counted it as unreached
// would report an orphan the register does not hold.
func TestTheComparisonNamesAReachedKeyForAClosedEntry(t *testing.T) {
	key := oneConformanceKey("JA4")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: "value", Theirs: "value", Ruling: "#19"},
	}

	result := compareConformance(
		map[conformanceKey]string{key: "value"},
		map[conformanceKey]string{key: "value"},
		register,
	)

	if len(result.Closed) != 1 {
		t.Fatalf("the comparison reports %d closed entries, and the two values are equal", len(result.Closed))
	}

	if len(result.Reached) != 1 || result.Reached[0] != key {
		t.Errorf("the comparison names %d reached register keys, and it compares the closed key %q",
			len(result.Reached), key)
	}
}

// #328 states the orphan entry. The run reaches the key of one entry and no key of the
// other, so the second entry is an orphan entry.
func TestTheOrphanEntriesNameEveryRegisterKeyTheRunNeverReaches(t *testing.T) {
	reached := oneConformanceKey("JA4")
	orphan := oneConformanceKey("JA4S")

	register := map[conformanceKey]deviations.Entry{
		reached: {Key: reached.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
		orphan:  {Key: orphan.String(), Ours: "recorded", Theirs: "theirs", Ruling: "#20"},
	}

	entries := conformanceOrphanEntries(register, map[conformanceKey]bool{reached: true})

	if len(entries) != 1 {
		t.Fatalf("the run reports %d orphan entries, and it reaches the key of one of the two entries", len(entries))
	}

	if entries[0].Key != orphan {
		t.Errorf("the run reports the orphan entry %q, and it reaches no key of %q", entries[0].Key, orphan)
	}

	if entries[0].Recorded != "recorded" {
		t.Errorf("the orphan entry records %q, and the register entry holds `recorded`", entries[0].Recorded)
	}
}

// An orphan check that fired on a reached key would fail every run and gate nothing.
func TestTheOrphanEntriesNameNoRegisterKeyTheRunReaches(t *testing.T) {
	key := oneConformanceKey("JA4")

	register := map[conformanceKey]deviations.Entry{
		key: {Key: key.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
	}

	entries := conformanceOrphanEntries(register, map[conformanceKey]bool{key: true})

	if len(entries) != 0 {
		t.Errorf("the run reports %d orphan entries, and it reaches the key of the one entry", len(entries))
	}
}

// A range over the register orders nothing, and an unordered report changes on every run.
func TestTheOrphanEntriesSortTheEntriesByKey(t *testing.T) {
	first := conformanceKey{Capture: "dhcp.pcapng", Stream: "1", Method: "JA4D"}
	second := conformanceKey{Capture: "tls12.pcap", Stream: "1", Method: "JA4"}

	register := map[conformanceKey]deviations.Entry{
		second: {Key: second.String(), Ours: "ours", Theirs: "theirs", Ruling: "#19"},
		first:  {Key: first.String(), Ours: "ours", Theirs: "theirs", Ruling: "#20"},
	}

	entries := conformanceOrphanEntries(register, nil)

	if len(entries) != 2 {
		t.Fatalf("the run reports %d orphan entries, and it reaches no key of the two entries", len(entries))
	}

	if entries[0].Key != first || entries[1].Key != second {
		t.Errorf("the run reports the orphan entries %q and %q, and the sorted order names `dhcp.pcapng` first",
			entries[0].Key, entries[1].Key)
	}
}

// The maintainer ruled on 2026-08-13 in #361. The run reports a value whose vector file
// publishes no key for its method as an uncovered value. Such a value reaches a third
// category, which is neither a match nor a deviation.
func TestTheRunReportsAnUncoveredValueWhenTheVectorFileNamesNoKeyForItsMethod(t *testing.T) {
	key := oneConformanceKey("JA4L-C")

	comparison := conformanceSplitUncovered(
		compareConformance(
			map[conformanceKey]string{key: "45_64"},
			map[conformanceKey]string{},
			nil,
		),
		map[string]bool{"JA4": true},
	)

	if len(comparison.Deviations) != 0 {
		t.Errorf("the run reports %d deviations, and the vector file names no key for the method",
			len(comparison.Deviations))
	}

	if len(comparison.Uncovered) != 1 {
		t.Fatalf("the run reports %d uncovered values, and the library produces one", len(comparison.Uncovered))
	}

	if comparison.Uncovered[0].Key != key {
		t.Errorf("the run names the key %q, and the library produces the value for %q", comparison.Uncovered[0].Key, key)
	}

	if comparison.Uncovered[0].Produced != "45_64" {
		t.Errorf("the run records the produced value %q, and the library produces `45_64`",
			comparison.Uncovered[0].Produced)
	}

	if comparison.Uncovered[0].Accepted {
		t.Error("the run accepts the uncovered value, and the register names no entry for it")
	}
}

// A vector file that names the method states an expected value for it. A surplus value of
// that method therefore stays the deviation kind of FR-conformance-17. The key carries an
// occurrence number, and the split reads the method without it.
func TestTheRunReportsADeviationWhenTheVectorFileNamesTheMethodAndHoldsNoValueForTheKey(t *testing.T) {
	key := oneConformanceKey("JA4T.1")

	comparison := conformanceSplitUncovered(
		compareConformance(
			map[conformanceKey]string{key: "8192_2-1-3-1-1-4_1460_8"},
			map[conformanceKey]string{},
			nil,
		),
		map[string]bool{"JA4T": true},
	)

	if len(comparison.Uncovered) != 0 {
		t.Errorf("the run reports %d uncovered values, and the vector file names the method",
			len(comparison.Uncovered))
	}

	if len(comparison.Deviations) != 1 {
		t.Fatalf("the run reports %d deviations, and FR-conformance-17 names one", len(comparison.Deviations))
	}

	if comparison.Deviations[0].Kind != conformanceExtraValue {
		t.Errorf("the run reports the kind %q, and FR-conformance-17 names %q",
			comparison.Deviations[0].Kind, conformanceExtraValue)
	}
}

// #361 admits a register entry for an uncovered value. The orphan gate of #328 reads the
// reached keys, so the entry must reach that set.
func TestTheRunAcceptsAnUncoveredValueTheRegisterNames(t *testing.T) {
	key := oneConformanceKey("JA4L-S")

	comparison := conformanceSplitUncovered(
		compareConformance(
			map[conformanceKey]string{key: "13532_57"},
			map[conformanceKey]string{},
			map[conformanceKey]deviations.Entry{key: {Key: key.String(), Ours: "13532_57", Ruling: "#361"}},
		),
		map[string]bool{},
	)

	if len(comparison.Uncovered) != 1 {
		t.Fatalf("the run reports %d uncovered values, and the library produces one", len(comparison.Uncovered))
	}

	if !comparison.Uncovered[0].Accepted {
		t.Error("the run reports the uncovered value as unaccepted, and the register names the comparison")
	}

	if len(comparison.Reached) != 1 || comparison.Reached[0] != key {
		t.Errorf("the run reaches %d register keys, and the entry names one comparison the run makes",
			len(comparison.Reached))
	}

	if len(comparison.Stale) != 0 {
		t.Errorf("the run reports %d stale entries, and the entry records the value the run produces",
			len(comparison.Stale))
	}
}

// An absent value and a changed value each hold an expected value, so neither one can name a
// method that the vector file never publishes. The split reads the deviation kind for that
// reason, and it never reads the covered set alone.
func TestTheRunReportsNoUncoveredValueForAnAbsentValueOrAChangedValue(t *testing.T) {
	absent := oneConformanceKey("JA4X.1")
	changed := oneConformanceKey("JA4X.2")

	comparison := conformanceSplitUncovered(
		compareConformance(
			map[conformanceKey]string{changed: "2e9214a636bc_2e9214a636bc_795797892f9c"},
			map[conformanceKey]string{
				absent:  "795797892f9c_2e9214a636bc_2e9214a636bc",
				changed: "795797892f9c_2e9214a636bc_2e9214a636bc",
			},
			nil,
		),
		map[string]bool{},
	)

	if len(comparison.Uncovered) != 0 {
		t.Errorf("the run reports %d uncovered values, and the vector holds a value for each key",
			len(comparison.Uncovered))
	}

	if len(comparison.Deviations) != 2 {
		t.Fatalf("the run reports %d deviations, and the fixture holds an absent value and a changed value",
			len(comparison.Deviations))
	}
}

// The split moves a deviation, and it moves nothing else. A match of a covered method stands
// beside an uncovered value of another method on one capture.
func TestTheRunKeepsEveryMatchWhenItSplitsTheUncoveredValues(t *testing.T) {
	matched := oneConformanceKey("JA4")
	uncovered := oneConformanceKey("JA4LS")
	value := "t13d1715h2_5b57614c22b0_3d5424432f57"

	comparison := conformanceSplitUncovered(
		compareConformance(
			map[conformanceKey]string{matched: value, uncovered: "781_238"},
			map[conformanceKey]string{matched: value},
			nil,
		),
		map[string]bool{"JA4": true},
	)

	if comparison.Matches != 1 {
		t.Errorf("the run reports %d matches, and the two values of the covered method are equal", comparison.Matches)
	}

	if len(comparison.Matched) != 1 {
		t.Errorf("the run names %d matched keys, and it reports one match", len(comparison.Matched))
	}

	if len(comparison.Deviations) != 0 {
		t.Errorf("the run reports %d deviations, and the fixture holds a match and an uncovered value",
			len(comparison.Deviations))
	}

	if len(comparison.Uncovered) != 1 {
		t.Fatalf("the run reports %d uncovered values, and the library produces one", len(comparison.Uncovered))
	}
}

// The comparison engine of the conformance suite. It holds FR-conformance-16 through
// FR-conformance-19, and it holds FR-reference-25 and FR-reference-26.
//
// The engine compares two maps of values. It reads no file and it decodes no packet, so a
// test proves every case with a fixture. `conformance_test.go` fills the two maps from the
// corpus.
//
// The engine stays in the test build. It reads `deviations.Entry`, which `deviations_test.go`
// defines, and `v1.0.0` freezes the exported API of the library.

// conformanceKey names one comparison. It writes the register key form of
// `testdata/README.md`, so that an entry of `testdata/deviations.json` names a comparison
// the suite makes.
type conformanceKey struct {
	// Capture is the file name of the capture, such as `tls12.pcap`.
	Capture string
	// Stream names the stream or the frame that carries the value.
	Stream string
	// Method names the JA4+ method, such as `JA4S`.
	Method string
}

// String returns the key in the register form `<capture>/<stream>/<method>`.
func (k conformanceKey) String() string {
	return k.Capture + "/" + k.Stream + "/" + k.Method
}

// conformanceDeviationKind names which of the three differences a comparison found.
// The report prints the value, so each one reads as a sentence.
type conformanceDeviationKind string

const (
	// conformanceExtraValue holds FR-conformance-17.
	conformanceExtraValue conformanceDeviationKind = "the library produces a value the vector does not hold"
	// conformanceAbsentValue holds FR-conformance-18.
	conformanceAbsentValue conformanceDeviationKind = "the vector holds a value the library does not produce"
	// conformanceChangedValue holds FR-conformance-19.
	conformanceChangedValue conformanceDeviationKind = "the two values differ"
)

// conformanceDeviation is one difference between the library and a FoxIO vector.
type conformanceDeviation struct {
	// Key names the capture, the stream and the method.
	Key conformanceKey
	// Kind names which of the three differences the comparison found.
	Kind conformanceDeviationKind
	// Expected is the value the vector holds. An extra value holds the empty string here.
	Expected string
	// Produced is the value the library produces. An absent value holds the empty string
	// here.
	Produced string
	// Accepted is true when the register names this comparison. FR-reference-25 expects
	// such a comparison to differ, so an accepted deviation is a recorded ruling.
	Accepted bool
}

// conformanceStaleEntry is one register entry whose recorded `ours` value differs from the
// value the run produces. #307 states the defect it reports.
//
// A register entry records the two values that the maintainer ruled on. A later change
// moves the value this library produces, and the entry then accepts a comparison it does
// not describe. FR-reference-26 never reaches such an entry, because the two values still
// differ.
type conformanceStaleEntry struct {
	// Key names the comparison the register entry accepts.
	Key conformanceKey
	// Recorded is the `ours` value of the register entry.
	Recorded string
	// Produced is the value the run produces. It is the empty string when the library
	// produces no value for the key.
	Produced string
}

// conformanceOrphanEntry is one register entry whose key no comparison of the run reaches.
// #328 states the defect it reports.
//
// A register entry names a comparison. A renamed method key, a dropped capture or a moved
// stream name each stop the run from making that comparison. The entry then accepts a
// difference that no comparison of the run reports. FR-reference-26 never reaches such an
// entry, and #307 never reaches it either, because both checks read the compared keys
// alone.
type conformanceOrphanEntry struct {
	// Key names the comparison the register entry accepts.
	Key conformanceKey
	// Recorded is the `ours` value of the register entry.
	Recorded string
}

// conformanceUncoveredValue is one value that the library produces where the vector file
// publishes no key for its method. The maintainer ruled it on 2026-08-13 in #361.
//
// A vector file that publishes no key for a method states nothing about that method, so the
// comparison holds no expected value. The difference measures the coverage of the reference
// file, and it measures nothing about the library. The run therefore counts such a value in a
// third category, which is neither a match nor a deviation.
//
// The register may hold a decline for an uncovered value. The comparison reaches the key, so
// `conformanceCheckOrphans` reaches the entry.
type conformanceUncoveredValue struct {
	// Key names the comparison.
	Key conformanceKey
	// Produced is the value the library produces.
	Produced string
	// Accepted is true when the register names this comparison.
	Accepted bool
}

// conformanceComparison holds the outcome of one comparison run.
type conformanceComparison struct {
	// Matches counts the comparisons where the two values are equal and the register
	// names neither.
	Matches int
	// Matched names every comparison that Matches counts, sorted by key. The report reads
	// it, because a count alone cannot say which method of which capture matched.
	Matched []conformanceKey
	// Deviations holds every difference, sorted by key.
	Deviations []conformanceDeviation
	// Uncovered holds every value whose method the vector file never names, sorted by key. It
	// holds FR-conformance-33p, and `conformanceSplitUncovered` fills it.
	Uncovered []conformanceUncoveredValue
	// Closed names every comparison that the register names and that now matches.
	// FR-reference-26 fails the suite for each one.
	Closed []conformanceKey
	// Stale holds every register entry whose recorded value the run no longer produces,
	// sorted by key. #307 fails the suite for each one.
	Stale []conformanceStaleEntry
	// Reached names every register key that this comparison reaches, sorted by key. It holds
	// FR-conformance-33h. The run subtracts the reached keys from the register, and each key
	// that remains names an orphan entry.
	Reached []conformanceKey
}

// compareConformance returns the comparison of the produced values with the vector values.
//
// The comparison is an exact string match, so a case change and a whitespace change are
// both deviations. It never trims, lowercases or sorts a value.
//
// The register maps a key to the entry that accepts the difference. A key the register
// names produces an accepted deviation when the two values differ, and a closed entry when
// the two values are equal. A nil register accepts nothing.
//
// A key the register names produces a stale entry when the recorded `ours` value differs
// from the produced value. A stale entry stands beside a match, a deviation and a closed
// entry, and it replaces none of them.
//
// A key the register names also reaches `Reached`. The comparison reads one capture and one
// vector set, so it sees one part of the register. `conformanceOrphanEntries` reads the
// reached keys of the whole run.
func compareConformance(
	produced map[conformanceKey]string,
	expected map[conformanceKey]string,
	register map[conformanceKey]deviations.Entry,
) conformanceComparison {
	var result conformanceComparison

	for _, key := range conformanceComparedKeys(produced, expected) {
		producedValue, libraryHolds := produced[key]
		expectedValue, vectorHolds := expected[key]
		entry, registered := register[key]

		// #328 records the key before the branches below. A closed entry and a stale entry
		// each name a key the run reaches, so the record stands outside every branch.
		if registered {
			result.Reached = append(result.Reached, key)
		}

		// #307 reads the recorded value of the entry, and never its presence alone. The
		// check stands outside the two branches below, because a stale record is a defect of
		// the register and it says nothing about the comparison.
		//
		// The check reads `producedValue` and never `libraryHolds`. A key the library
		// produces no value for reads the empty string, and a capability decline records the
		// empty string, so the two agree. This holds because no fingerprinter of this project
		// returns an empty value without an error.
		if registered && entry.Ours != producedValue {
			result.Stale = append(result.Stale, conformanceStaleEntry{
				Key:      key,
				Recorded: entry.Ours,
				Produced: producedValue,
			})
		}

		if libraryHolds && vectorHolds && producedValue == expectedValue {
			if registered {
				result.Closed = append(result.Closed, key)

				continue
			}

			result.Matches++
			result.Matched = append(result.Matched, key)

			continue
		}

		deviation := conformanceDeviation{
			Key:      key,
			Kind:     conformanceChangedValue,
			Expected: expectedValue,
			Produced: producedValue,
			Accepted: registered,
		}

		switch {
		case !vectorHolds:
			deviation.Kind = conformanceExtraValue
		case !libraryHolds:
			deviation.Kind = conformanceAbsentValue
		}

		result.Deviations = append(result.Deviations, deviation)
	}

	return result
}

// conformanceMethodOfComparisonKey returns the method that the comparison key names, without
// the occurrence number.
//
// `conformanceCoveredMethods` builds the covered set from the same form, so the two agree on
// the key `JA4X.1` and on the bare key `JA4S`.
func conformanceMethodOfComparisonKey(key conformanceKey) string {
	method, _, held := strings.Cut(key.Method, ".")
	if !held {
		return key.Method
	}

	return method
}

// conformanceSplitUncovered returns the comparison with every uncovered value under
// `Uncovered` and out of `Deviations`. It holds FR-conformance-33p.
//
// The covered set names every method that the vector file publishes a key for.
// `conformanceCoveredMethods` builds it for the per-packet set, and
// `conformanceStreamShape.Covered` holds it for the per-stream set.
//
// The split reads the deviation kind first, and never the covered set alone. An absent value
// and a changed value each carry an expected value, so the vector file names the method of
// each one. An extra value is the one kind that a method with no key can reach.
//
// The maintainer ruled the third category on 2026-08-13 in #361. The register entries that
// ruling admits each name #361, so one reader reverses the whole set.
func conformanceSplitUncovered(
	comparison conformanceComparison,
	covered map[string]bool,
) conformanceComparison {
	kept := make([]conformanceDeviation, 0, len(comparison.Deviations))

	for _, deviation := range comparison.Deviations {
		if deviation.Kind != conformanceExtraValue || covered[conformanceMethodOfComparisonKey(deviation.Key)] {
			kept = append(kept, deviation)

			continue
		}

		comparison.Uncovered = append(comparison.Uncovered, conformanceUncoveredValue{
			Key:      deviation.Key,
			Produced: deviation.Produced,
			Accepted: deviation.Accepted,
		})
	}

	// A comparison that reports no uncovered value keeps the slice the engine built, so the
	// split allocates nothing that the caller reads.
	if len(comparison.Uncovered) > 0 {
		comparison.Deviations = kept
	}

	return comparison
}

// conformanceOrphanEntries returns one entry for each register key that the reached set does
// not hold, sorted by key. It holds FR-conformance-33i.
//
// The caller passes the reached keys of the whole run, and never of one comparison. One
// comparison reads one capture and one vector set, so a key it does not reach is a key
// another comparison of the run reaches.
func conformanceOrphanEntries(
	register map[conformanceKey]deviations.Entry,
	reached map[conformanceKey]bool,
) []conformanceOrphanEntry {
	var entries []conformanceOrphanEntry

	for key, entry := range register {
		if reached[key] {
			continue
		}

		entries = append(entries, conformanceOrphanEntry{Key: key, Recorded: entry.Ours})
	}

	// A range over a map orders nothing, and an unordered report changes on every run.
	slices.SortFunc(entries, func(first, second conformanceOrphanEntry) int {
		return strings.Compare(first.Key.String(), second.Key.String())
	})

	return entries
}

// conformanceComparedKeys returns every key of the two maps, sorted.
// A range over a map orders nothing, and an unordered report changes on every run.
func conformanceComparedKeys(produced, expected map[conformanceKey]string) []conformanceKey {
	seen := make(map[conformanceKey]struct{}, len(produced)+len(expected))

	for key := range produced {
		seen[key] = struct{}{}
	}

	for key := range expected {
		seen[key] = struct{}{}
	}

	keys := make([]conformanceKey, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}

	slices.SortFunc(keys, func(first, second conformanceKey) int {
		return strings.Compare(first.String(), second.String())
	})

	return keys
}

// These tests hold FR-ja4ls-21. The conformance harness compares every published JA4LS
// value.
//
// The two vector sets name JA4LS by two different keys, and neither key is the string
// `JA4LS`. The per-stream set writes the key `JA4L-S`, and the per-packet set writes the
// field `ja4.ja4ls`. `conformanceStreamMethodKeys` holds the first, and
// `conformancePacketMethods` maps the second to the method name `JA4LS`.
//
// A published value is a value the vector file holds. The harness compares such a value
// when it reaches the expected map of the set, because `compareConformance` reads that map.
// A published value that reaches no expected map reaches no comparison, and the run then
// reports neither a match nor a deviation for it.
//
// Each test below counts the published values from the raw vector, and it counts the
// compared values from the expected map. The two counts come from two different readings of
// one file, so a test failure names a value the harness drops.

// conformancePerStreamJA4LSKey names the per-stream vector key for JA4LS.
const conformancePerStreamJA4LSKey = "JA4L-S"

// conformancePerPacketJA4LSMethod names the method that the per-packet adapter writes for
// JA4LS. `conformancePacketMethods` maps the field `ja4.ja4ls` to it.
const conformancePerPacketJA4LSMethod = "JA4LS"

// conformancePerPacketJA4LSField names the per-packet vector field for JA4LS.
const conformancePerPacketJA4LSField = "ja4.ja4ls"

// conformancePublishedJA4LSStreamValues counts the JA4LS values that the corpus publishes in
// the per-stream set at the pin of `testdata/foxio.pin`.
//
// A pin move changes this count. Re-measure the corpus. Write the new count here.
const conformancePublishedJA4LSStreamValues = 59

// conformancePublishedJA4LSPacketValues counts the JA4LS values that the corpus publishes in
// the per-packet set at the pin of `testdata/foxio.pin`.
//
// A pin move changes this count. Re-measure the corpus. Write the new count here.
const conformancePublishedJA4LSPacketValues = 45

// conformanceKeyNamesMethod reports whether the comparison key names the method.
// The key of a method carries an occurrence number, so the test reads the stem.
func conformanceKeyNamesMethod(key conformanceKey, method string) bool {
	return conformanceMethodOfComparisonKey(key) == method
}

// conformanceCountComparedJA4LS returns the number of keys of the expected map that name the
// method.
func conformanceCountComparedJA4LS(expected map[conformanceKey]string, method string) int {
	count := 0

	for key := range expected {
		if conformanceKeyNamesMethod(key, method) {
			count++
		}
	}

	return count
}

// conformanceCountPublishedStreamJA4LS returns the number of JA4LS values that the per-stream
// vector holds.
//
// The count reads the raw entry, and it calls no adapter. A count that read the adapter would
// pass whatever the adapter did, so it would prove nothing.
func conformanceCountPublishedStreamJA4LS(entries []conformanceStreamEntry) int {
	count := 0

	for _, entry := range entries {
		for key := range entry {
			stem, _, held := strings.Cut(key, ".")
			if !held {
				stem = key
			}

			if stem == conformancePerStreamJA4LSKey {
				count++
			}
		}
	}

	return count
}

// conformanceCountPublishedPacketJA4LS returns the number of JA4LS values that the per-packet
// vector holds.
//
// One frame holds a list of values for one field, so the count reads the length of the list.
func conformanceCountPublishedPacketJA4LS(records []conformancePacketRecord) int {
	count := 0

	for _, record := range records {
		count += len(record.Source.Layers[conformancePerPacketJA4LSField])
	}

	return count
}

// The per-stream expected map holds every JA4LS value that the per-stream vector publishes.
//
// The adapter collects the values of one stream and one method, and it numbers them when one
// stream holds more than one. A single map write would keep the last value alone, and the
// other values would then reach no comparison. Issue #209 measured that loss on JA4H.
func TestTheHarnessComparesEveryPublishedPerStreamJA4LSValue(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	published, compared := 0, 0

	for _, capture := range conformanceCaptureNames(t) {
		path := conformanceVectorPath(conformanceStreamVectorDir, capture)
		if path == "" {
			continue
		}

		entries := conformanceReadStreamVector(t, path)

		shape, err := conformanceExpectedFromStreamVector(capture, entries)
		if err != nil {
			t.Fatalf("the per-stream vector for %s does not read: %v", capture, err)
		}

		capturePublished := conformanceCountPublishedStreamJA4LS(entries)
		captureCompared := conformanceCountComparedJA4LS(shape.Expected, conformancePerStreamJA4LSKey)

		if capturePublished != captureCompared {
			t.Errorf("the per-stream vector for %s publishes %d JA4LS values, and the harness compares %d",
				capture, capturePublished, captureCompared)
		}

		published += capturePublished
		compared += captureCompared
	}

	if published != conformancePublishedJA4LSStreamValues {
		t.Errorf("the per-stream set publishes %d JA4LS values, and the corpus at the pin holds %d",
			published, conformancePublishedJA4LSStreamValues)
	}

	if compared != published {
		t.Errorf("the harness compares %d per-stream JA4LS values, and the set publishes %d", compared, published)
	}
}

// The per-packet expected map holds every JA4LS value that the per-packet vector publishes.
//
// The adapter numbers the values of one frame, so a frame that holds two values reaches two
// comparisons.
func TestTheHarnessComparesEveryPublishedPerPacketJA4LSValue(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	published, compared := 0, 0

	for _, capture := range conformanceCaptureNames(t) {
		path := conformanceVectorPath(conformancePacketVectorDir, capture)
		if path == "" {
			continue
		}

		records := conformanceReadPacketVector(t, path)
		expected := conformanceExpectedFromPacketVector(t, capture, records)

		capturePublished := conformanceCountPublishedPacketJA4LS(records)
		captureCompared := conformanceCountComparedJA4LS(expected, conformancePerPacketJA4LSMethod)

		if capturePublished != captureCompared {
			t.Errorf("the per-packet vector for %s publishes %d JA4LS values, and the harness compares %d",
				capture, capturePublished, captureCompared)
		}

		published += capturePublished
		compared += captureCompared
	}

	if published != conformancePublishedJA4LSPacketValues {
		t.Errorf("the per-packet set publishes %d JA4LS values, and the corpus at the pin holds %d",
			published, conformancePublishedJA4LSPacketValues)
	}

	if compared != published {
		t.Errorf("the harness compares %d per-packet JA4LS values, and the set publishes %d", compared, published)
	}
}

// The two adapters name JA4LS, so neither vector set drops the method.
//
// A removal of either name stops the harness from comparing a whole set of JA4LS values.
// `conformanceRecognizeStreamKey` and `conformanceRecognizePacketField` each fail the suite
// for an unrecognized key, so a removal reports as a harness defect and never as a deviation.
func TestBothConformanceAdaptersNameJA4LS(t *testing.T) {
	if !conformanceStreamMethodKeys[conformancePerStreamJA4LSKey] {
		t.Errorf("the per-stream key set does not hold %q, and the per-stream vector writes that key",
			conformancePerStreamJA4LSKey)
	}

	method, mapped := conformancePacketMethods[conformancePerPacketJA4LSField]
	if !mapped {
		t.Fatalf("the per-packet field map does not hold %q, and the per-packet vector writes that field",
			conformancePerPacketJA4LSField)
	}

	if method != conformancePerPacketJA4LSMethod {
		t.Errorf("the per-packet field map writes %q for %q, and the method name is %q",
			method, conformancePerPacketJA4LSField, conformancePerPacketJA4LSMethod)
	}
}

// The library reports a JA4LS value under the label `JA4L-S`, and each adapter reads that
// label.
//
// `JA4LFingerprinter` writes both JA4L and JA4LS, and it reports the type `ja4l` for the two.
// The label names which of the two the value holds. An adapter that misread the label would
// compare a JA4LS value against a JA4L key. The run would then report two deviations for one
// correct value.
func TestBothConformanceAdaptersReadTheJA4LSLabelOfTheLibrary(t *testing.T) {
	result := FingerprintResult{Type: "ja4l", Fingerprint: "JA4L-S=12517_53"}

	streamMethod, streamValue, streamHeld := conformanceStreamMethodOfResult(result)
	if !streamHeld || streamMethod != conformancePerStreamJA4LSKey || streamValue != "12517_53" {
		t.Errorf("the per-stream adapter reads %q and %q for the label `JA4L-S`, and the key is %q with the value `12517_53`",
			streamMethod, streamValue, conformancePerStreamJA4LSKey)
	}

	packetMethod, packetValue, packetHeld := conformanceMethodOfResultType(result)
	if !packetHeld || packetMethod != conformancePerPacketJA4LSMethod || packetValue != "12517_53" {
		t.Errorf("the per-packet adapter reads %q and %q for the label `JA4L-S`, and the method is %q with the value `12517_53`",
			packetMethod, packetValue, conformancePerPacketJA4LSMethod)
	}
}

// The guard on the register key namespace. It holds FR-reference-29 and FR-reference-30.
//
// The middle part of a register key holds a stream number in the per-stream set and a frame
// number in the per-packet set. Both are small integers, so a reader cannot tell the two
// apart. #217 records the consequence: a per-stream entry and a per-packet entry could hold
// one identical key and name two different comparisons. `compareConformance` reads one
// register map for both sets, so such a pair would accept a comparison the maintainer never
// ruled on.
//
// The guard proves the collision is unreachable. It compares the key space of the two sets
// on every capture the suite compares, and it fails on a key that both sets hold.

// conformanceSharedKeys returns every key that both key sets hold, sorted.
// It returns nil when the two sets share no key.
func conformanceSharedKeys(stream, packet []conformanceKey) []conformanceKey {
	held := make(map[conformanceKey]struct{}, len(stream))
	for _, key := range stream {
		held[key] = struct{}{}
	}

	var shared []conformanceKey

	// The check removes the key from the set after it reports it. A caller that passed one
	// key twice in the second set would otherwise report one collision twice.
	for _, key := range packet {
		if _, both := held[key]; both {
			shared = append(shared, key)

			delete(held, key)
		}
	}

	slices.SortFunc(shared, func(first, second conformanceKey) int {
		return strings.Compare(first.String(), second.String())
	})

	return shared
}

func TestTheSharedKeyCheckFindsAKeyThatBothSetsHold(t *testing.T) {
	stream := []conformanceKey{
		{Capture: "tls3.pcapng", Stream: "21", Method: "JA4L-C"},
		{Capture: "tls3.pcapng", Stream: "22", Method: "JA4X.1"},
	}
	packet := []conformanceKey{
		{Capture: "tls3.pcapng", Stream: "22", Method: "JA4X.1"},
		{Capture: "tls3.pcapng", Stream: "63", Method: "JA4L.1"},
	}

	shared := conformanceSharedKeys(stream, packet)
	if len(shared) != 1 {
		t.Fatalf("the check reports %d shared keys, and the two sets share `tls3.pcapng/22/JA4X.1`", len(shared))
	}

	if got := shared[0].String(); got != "tls3.pcapng/22/JA4X.1" {
		t.Errorf("the check reports the shared key %q, and the two sets share `tls3.pcapng/22/JA4X.1`", got)
	}
}

func TestTheSharedKeyCheckReportsNothingForTwoDisjointSets(t *testing.T) {
	stream := []conformanceKey{{Capture: "tls3.pcapng", Stream: "21", Method: "JA4L-C"}}
	packet := []conformanceKey{{Capture: "tls3.pcapng", Stream: "21", Method: "JA4L.1"}}

	if shared := conformanceSharedKeys(stream, packet); len(shared) != 0 {
		t.Errorf("the check reports the shared key %q, and the two sets share none", shared[0])
	}
}

// TestNoKeyNamesBothAPerStreamAndAPerPacketComparison holds FR-reference-30.
//
// A key that both sets hold makes one register entry accept two comparisons. The register
// grows on every session, so the guard reads the whole corpus and never a sample.
func TestNoKeyNamesBothAPerStreamAndAPerPacketComparison(t *testing.T) {
	conformanceSkipWithoutCorpus(t)

	shared := 0
	near := 0
	streamKeys := 0
	packetKeys := 0

	for _, capture := range conformanceCaptureNames(t) {
		// FoxIO marks such a capture `notest`, so the suite makes no comparison for it and
		// the register can hold no key for it.
		if strings.Contains(capture, conformanceNotestMarker) {
			continue
		}

		outcome := conformanceCheckOneCaptureKeySpace(t, capture)

		shared += outcome.shared
		near += outcome.near
		streamKeys += outcome.streamKeys
		packetKeys += outcome.packetKeys
	}

	// A guard that compares two empty key spaces passes and proves nothing. A broken vector
	// path would reach that state, so the test reads the size of each space.
	if streamKeys == 0 || packetKeys == 0 {
		t.Errorf("the corpus reports %d per-stream keys and %d per-packet keys, and the suite compares a value in each set",
			streamKeys, packetKeys)
	}

	// The near count is the measurement #217 asks for, and it fails nothing. It counts the
	// pairs that the method name alone keeps apart, so it states how much of the key space
	// the middle part already shares.
	t.Logf("the corpus holds %d per-stream keys and %d per-packet keys, %d keys that both sets name, and %d pairs that the method name alone separates",
		streamKeys, packetKeys, shared, near)
}

// conformanceKeySpaceOutcome holds the counts of one capture.
type conformanceKeySpaceOutcome struct {
	// streamKeys counts the keys the per-stream comparison reads.
	streamKeys int
	// packetKeys counts the keys the per-packet comparison reads.
	packetKeys int
	// shared counts the keys that both sets hold.
	shared int
	// near counts the pairs that hold one capture and one middle part, and two method
	// names.
	near int
}

// conformanceCheckOneCaptureKeySpace compares the key space of the two sets on one capture.
// It returns the counts, and it fails the test for each key that both sets hold.
func conformanceCheckOneCaptureKeySpace(t *testing.T, capture string) conformanceKeySpaceOutcome {
	t.Helper()

	packets := loadPCAP(t, conformanceCaptureDir+"/"+capture)

	stream := conformanceStreamKeySpace(t, capture, packets)
	packet := conformancePacketKeySpace(t, capture, packets)

	shared := conformanceSharedKeys(stream, packet)
	for _, key := range shared {
		t.Errorf("the key %s names a comparison in the per-stream set and in the per-packet set, and FR-reference-29 gives one meaning to the middle part of one key",
			key)
	}

	return conformanceKeySpaceOutcome{
		streamKeys: len(stream),
		packetKeys: len(packet),
		shared:     len(shared),
		near:       conformanceCountNearKeys(stream, packet),
	}
}

// conformanceCountNearKeys returns the count of key pairs that hold one capture and one
// middle part, and that two method names keep apart.
func conformanceCountNearKeys(stream, packet []conformanceKey) int {
	middle := make(map[string]int, len(stream))
	for _, key := range stream {
		middle[key.Stream]++
	}

	near := 0

	for _, key := range packet {
		near += middle[key.Stream]
	}

	return near
}

// conformanceStreamKeySpace returns every key the per-stream comparison of the capture
// reads. It returns nil when the corpus holds no per-stream vector for the capture.
//
// The comparison reads the register at the key of every value that either side holds, so
// the key space holds the produced keys and the expected keys together.
func conformanceStreamKeySpace(t *testing.T, capture string, packets []gopacket.Packet) []conformanceKey {
	t.Helper()

	path := conformanceVectorPath(conformanceStreamVectorDir, capture)
	if path == "" {
		return nil
	}

	shape, err := conformanceExpectedFromStreamVector(capture, conformanceReadStreamVector(t, path))
	if err != nil {
		t.Fatalf("the per-stream adapter fails for %s: %v", capture, err)
	}

	if len(shape.Expected) == 0 {
		return nil
	}

	return conformanceComparedKeys(conformanceProducedByStream(t, capture, packets, shape), shape.Expected)
}

// conformancePacketKeySpace returns every key the per-packet comparison of the capture
// reads. It returns nil when the corpus holds no per-packet vector for the capture.
func conformancePacketKeySpace(t *testing.T, capture string, packets []gopacket.Packet) []conformanceKey {
	t.Helper()

	path := conformanceVectorPath(conformancePacketVectorDir, capture)
	if path == "" {
		return nil
	}

	expected := conformanceExpectedFromPacketVector(t, capture, conformanceReadPacketVector(t, path))
	if len(expected) == 0 {
		return nil
	}

	return conformanceComparedKeys(conformanceProducedByFrame(t, capture, packets), expected)
}

// The report of the conformance suite. It holds FR-conformance-27 through
// FR-conformance-33.
//
// The renderer reads the comparisons that `compareConformance` returns and writes
// `docs/audit/conformance.md`. It reads no file and it decodes no packet, so a fixture
// proves every case without the corpus. `conformance_test.go` fills it from the corpus,
// and `conformance_check_test.go` holds the tests.
//
// # Why the report samples the deviations
//
// The report is tracked in git, so every row of it lands in each future diff. The corpus
// at the pinned commit reports 3431 deviations. The three SSH captures carry 1808 of them.
// A table of 3431 rows costs about 420 KB. It also hides the 159 deviations where the two
// values differ. 2025 rows where the library produces a value the vector does not hold
// stand in front of them.
//
// The report therefore holds the count of every group and at most
// `conformanceReportSampleLimit` rows of it. `conformance.log` holds every deviation. The
// `Run the conformance suite` step of `.github/workflows/ci.yml` writes that log. The
// `Upload the conformance log` step of that file uploads it. No measurement is lost.
//
// The renderer stays in the test build. `v1.0.0` freezes the exported API of the library,
// and a measurement of the library is no part of that API.

// conformanceReportPath names the report that FR-conformance-27 writes on every run.
const conformanceReportPath = "docs/audit/conformance.md"

// conformanceReportSampleLimit bounds the deviation rows that the report holds for one
// capture, one method and one vector set.
const conformanceReportSampleLimit = 3

// conformanceReportStreamSet and conformanceReportPacketSet name the two vector sets.
const (
	conformanceReportStreamSet = "per-stream"
	conformanceReportPacketSet = "per-packet"
)

// conformanceReportNotestReason states why the suite compares no value on a capture that
// FoxIO marks `notest`.
const conformanceReportNotestReason = "FoxIO marks the capture `notest`, so the suite compares no value on it."

// conformanceReportNoVectorReason states why the suite compares no value on a capture that
// no vector reaches.
const conformanceReportNoVectorReason = "No vector of the corpus holds a value for the capture."

// conformanceReportNoValueReason states why one method of one capture reaches no
// comparison.
const conformanceReportNoValueReason = "No vector of the corpus holds a value for the method on the capture."

// conformanceReportSharedFieldReason states why JA4D6 reaches no row of its own name.
//
// FoxIO writes both JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25
// makes the per-packet adapter authoritative for the two. The corpus therefore holds no
// value under a JA4D6 name, and `conformance_test.go` compares a JA4D6 value under the
// method JA4D.
const conformanceReportSharedFieldReason = "FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, " +
	"and FR-conformance-25 compares the two under JA4D."

// conformanceReportMethods names the eleven passive methods, in the order the report
// prints them. `docs/specs/spec.md` `## Terms` defines the word `method`. The twelfth
// method is JA4TScan, and the FoxIO corpus holds no vector for it, because it sends
// packets and reads no capture.
var conformanceReportMethods = []string{
	"JA4", "JA4S", "JA4H", "JA4X", "JA4SSH",
	"JA4L", "JA4LS", "JA4T", "JA4TS", "JA4D", "JA4D6",
}

// conformanceReportResult names one of the three results that FR-conformance-29 states.
type conformanceReportResult string

const (
	conformanceReportMatch         conformanceReportResult = "match"
	conformanceReportDeviation     conformanceReportResult = "deviation"
	conformanceReportNotApplicable conformanceReportResult = "not applicable"
)

// conformanceReportRow is one row of the result table. FR-conformance-28 holds one row for
// each capture and each method.
type conformanceReportRow struct {
	// Capture is the file name of the capture.
	Capture string
	// Method is one of the eleven passive methods this project implements. JA4TScan reaches
	// no vector of the FoxIO corpus, so no row names it.
	Method string
	// Set names the vector sets that hold a value for the row.
	Set string
	// Result is `match`, `deviation` or `not applicable`.
	Result conformanceReportResult
	// Matches counts the comparisons of the row that match.
	Matches int
	// Deviations counts the comparisons of the row that differ, accepted and unaccepted.
	Deviations int
	// Reason states why the row records `not applicable`. It is empty on every other row.
	Reason string
}

// conformanceReportGroup holds the deviations of one capture, one method and one vector
// set.
type conformanceReportGroup struct {
	// Capture, Method and Set name the group.
	Capture string
	Method  string
	Set     string
	// Count is the number of deviations of the group.
	Count int
	// Samples holds at most `conformanceReportSampleLimit` of them, sorted by key.
	Samples []conformanceDeviation
}

// conformanceReportCell names one capture and one method.
type conformanceReportCell struct {
	Capture string
	Method  string
}

// conformanceReportGroupKey names one capture, one method and one vector set.
type conformanceReportGroupKey struct {
	Capture string
	Method  string
	Set     string
}

// conformanceReportCount counts the comparisons of one capture and one method.
type conformanceReportCount struct {
	Matches    int
	Deviations int
	Accepted   int
	Sets       map[string]bool
}

// conformanceReportSetTotals counts the outcome of one vector set.
type conformanceReportSetTotals struct {
	Matches    int
	Deviations int
	Accepted   int
	Stale      int
	// Uncovered counts the uncovered values that the register does not name, and
	// AcceptedUncovered counts the uncovered values that the register names. #361 makes an
	// uncovered value a third category.
	Uncovered         int
	AcceptedUncovered int
}

// conformanceReportUncoveredGroup holds the uncovered values of one capture, one method and
// one vector set. It holds FR-conformance-33s.
type conformanceReportUncoveredGroup struct {
	// Capture, Method and Set name the group.
	Capture string
	Method  string
	Set     string
	// Count is the number of uncovered values of the group.
	Count int
	// Samples holds at most `conformanceReportSampleLimit` of them, in the key order the
	// engine writes.
	Samples []conformanceUncoveredValue
}

// conformanceReport collects the outcome of one conformance run and renders it.
//
// The suite calls `readCapture` for each capture it reads, `recordComparison` for each
// comparison it makes, and `declineCapture` for each capture it compares nothing on.
type conformanceReport struct {
	// commit is the FoxIO commit that `make corpus` fetched.
	commit string
	// captures names every capture the suite read.
	captures []string
	// declined maps a capture to why the suite compares no value on it.
	declined map[string]string
	// counts maps a capture and a method to its comparison counts.
	counts map[conformanceReportCell]conformanceReportCount
	// groups maps a capture, a method and a vector set to its deviations.
	groups map[conformanceReportGroupKey]*conformanceReportGroup
	// uncovered maps a capture, a method and a vector set to its uncovered values. #361 keeps
	// them apart from the deviations, because an uncovered value is neither a match nor a
	// deviation.
	uncovered map[conformanceReportGroupKey]*conformanceReportUncoveredGroup
	// sets counts the outcome of each vector set.
	sets map[string]conformanceReportSetTotals
	// stale holds every register entry the run no longer reaches, in the key order the
	// engine writes.
	stale []conformanceStaleEntry
	// reached names every register key that a comparison of the run reaches. #328 subtracts
	// it from the register.
	reached map[conformanceKey]bool
	// orphan holds every register entry that no comparison of the run reaches, sorted by
	// key. `recordOrphans` fills it.
	orphan []conformanceOrphanEntry
	// err holds the first method key the report could not place.
	err error
}

// newConformanceReport returns an empty report for the corpus at the commit.
func newConformanceReport(commit string) *conformanceReport {
	return &conformanceReport{
		commit:   commit,
		declined: make(map[string]string),
		counts:   make(map[conformanceReportCell]conformanceReportCount),
		groups:   make(map[conformanceReportGroupKey]*conformanceReportGroup),
		sets:     make(map[string]conformanceReportSetTotals),
		reached:  make(map[conformanceKey]bool),

		uncovered: make(map[conformanceReportGroupKey]*conformanceReportUncoveredGroup),
	}
}

// readCapture records that the suite read the capture.
// FR-conformance-28 holds one row for each capture, so a capture the suite compares
// nothing on still reaches the table.
func (r *conformanceReport) readCapture(capture string) {
	if !slices.Contains(r.captures, capture) {
		r.captures = append(r.captures, capture)
	}
}

// declineCapture records that the suite compares no value on the capture, and why.
func (r *conformanceReport) declineCapture(capture, reason string) {
	r.readCapture(capture)
	r.declined[capture] = reason
}

// recordComparison adds one comparison of one capture and one vector set to the report.
//
// A method key that the report cannot place is a defect of the harness. It is never a
// deviation of the library. The report holds the first such key, and `Err` returns it. A
// caller then fails the run, rather than write a table that drops a comparison.
func (r *conformanceReport) recordComparison(capture, set string, comparison conformanceComparison) {
	r.readCapture(capture)

	setTotals := r.sets[set]

	for _, key := range comparison.Matched {
		method, err := conformanceReportMethodOf(key.Method)
		if err != nil {
			r.hold(err)

			continue
		}

		count := r.count(capture, method, set)
		count.Matches++
		r.counts[conformanceReportCell{Capture: capture, Method: method}] = count
		setTotals.Matches++
	}

	for _, deviation := range comparison.Deviations {
		method, err := conformanceReportMethodOf(deviation.Key.Method)
		if err != nil {
			r.hold(err)

			continue
		}

		count := r.count(capture, method, set)
		count.Deviations++

		if deviation.Accepted {
			count.Accepted++
			setTotals.Accepted++
		} else {
			setTotals.Deviations++
		}

		r.counts[conformanceReportCell{Capture: capture, Method: method}] = count
		r.addDeviation(capture, method, set, deviation)
	}

	// An uncovered value reaches no row of the result table. The vector file holds no value
	// for the method, and FR-conformance-33 records `not applicable` for that cell. #361
	// gives the value a section of its own.
	//
	// The loop therefore calls no `r.count`, and `totals` reads `r.counts` to count the
	// captures the suite compared. **A capture whose every value is uncovered would reach no
	// cell, and the report would then count it as a capture the suite compared nothing on
	// while `conformance_test.go` counts it as compared.** `conformanceCheckReportTotals`
	// would fail on that pair.
	//
	// **That capture is unreachable.** `conformanceRunStreamSet` at `conformance_test.go:815`
	// and `conformanceRunPacketSet` at `conformance_test.go:853` each report that the suite
	// compared nothing when the expected map is empty. A set that reports a comparison
	// therefore holds one expected key or more, and an expected key produces a match, an
	// absent value or a changed value. An uncovered value needs `!vectorHolds`, so no
	// expected key reaches this loop.
	//
	// A change that lets a comparison run over an empty expected map breaks that reasoning.
	for _, value := range comparison.Uncovered {
		method, err := conformanceReportMethodOf(value.Key.Method)
		if err != nil {
			r.hold(err)

			continue
		}

		if value.Accepted {
			setTotals.AcceptedUncovered++
		} else {
			setTotals.Uncovered++
		}

		r.addUncovered(capture, method, set, value)
	}

	// A stale entry names a register entry rather than a comparison, so it reaches no row
	// of the result table. #307 gives it a section of its own.
	r.stale = append(r.stale, comparison.Stale...)
	setTotals.Stale += len(comparison.Stale)

	// #328 collects the reached keys of every comparison. The report counts the orphan
	// entries on its own, and `conformance_test.go` compares the result with its own count.
	for _, key := range comparison.Reached {
		r.reached[key] = true
	}

	r.sets[set] = setTotals
}

// recordOrphans records every register entry that no comparison of the run reaches.
// It holds FR-conformance-33i.
//
// The caller calls it once, after the last comparison. A caller that calls it earlier
// reports an orphan entry for each comparison the run has not yet made.
func (r *conformanceReport) recordOrphans(register map[conformanceKey]deviations.Entry) {
	r.orphan = conformanceOrphanEntries(register, r.reached)
}

// hold records the first error the report met.
func (r *conformanceReport) hold(err error) {
	if r.err == nil {
		r.err = err
	}
}

// Err returns the first method key the report could not place, and nil when it placed
// every key.
func (r *conformanceReport) Err() error {
	return r.err
}

// count returns the counts of one capture and one method, with the vector set recorded.
func (r *conformanceReport) count(capture, method, set string) conformanceReportCount {
	cell := conformanceReportCell{Capture: capture, Method: method}

	count, held := r.counts[cell]
	if !held {
		count.Sets = make(map[string]bool)
	}

	count.Sets[set] = true

	return count
}

// addDeviation adds one deviation to its group, and keeps at most the sample limit.
func (r *conformanceReport) addDeviation(capture, method, set string, deviation conformanceDeviation) {
	key := conformanceReportGroupKey{Capture: capture, Method: method, Set: set}

	group, held := r.groups[key]
	if !held {
		group = &conformanceReportGroup{Capture: capture, Method: method, Set: set}
		r.groups[key] = group
	}

	group.Count++

	if len(group.Samples) < conformanceReportSampleLimit {
		group.Samples = append(group.Samples, deviation)
	}
}

// addUncovered adds one uncovered value to its group, and keeps at most the sample limit.
func (r *conformanceReport) addUncovered(capture, method, set string, value conformanceUncoveredValue) {
	key := conformanceReportGroupKey{Capture: capture, Method: method, Set: set}

	group, held := r.uncovered[key]
	if !held {
		group = &conformanceReportUncoveredGroup{Capture: capture, Method: method, Set: set}
		r.uncovered[key] = group
	}

	group.Count++

	if len(group.Samples) < conformanceReportSampleLimit {
		group.Samples = append(group.Samples, value)
	}
}

// conformanceReportMethodOf returns the method that one comparison key names.
//
// The key carries the vector key form, so it holds an occurrence number, a raw-form suffix,
// or the JA4L label the per-stream vector writes. A raw form is a form of its method, and
// never a method of its own, so `JA4H_ro.3` names the method JA4H.
//
// It returns an error for a key that names none of the eleven passive methods.
func conformanceReportMethodOf(key string) (string, error) {
	method, _, held := strings.Cut(key, ".")
	if !held {
		method = key
	}

	// The per-stream vector names the two JA4L methods `JA4L-C` and `JA4L-S`.
	// `conformance_test.go` reads the label from the library output form.
	switch method {
	case "JA4L-C":
		return "JA4L", nil
	case "JA4L-S":
		return "JA4LS", nil
	}

	// `_ro` ends with `_o`, so the longer suffix comes first.
	for _, suffix := range []string{"_ro", "_r", "_o"} {
		if base, cut := strings.CutSuffix(method, suffix); cut {
			method = base

			break
		}
	}

	if !slices.Contains(conformanceReportMethods, method) {
		return "", fmt.Errorf(
			"the comparison key %q names the method %q, and this project implements none of that name", key, method)
	}

	return method, nil
}

// rows returns one row for each capture and each method, sorted by capture and then by the
// order of `conformanceReportMethods`. It holds FR-conformance-28, FR-conformance-29 and
// FR-conformance-33.
func (r *conformanceReport) rows() []conformanceReportRow {
	captures := slices.Clone(r.captures)
	slices.Sort(captures)

	rows := make([]conformanceReportRow, 0, len(captures)*len(conformanceReportMethods))

	for _, capture := range captures {
		for _, method := range conformanceReportMethods {
			rows = append(rows, r.row(capture, method))
		}
	}

	return rows
}

// row returns the row of one capture and one method.
//
// A deviation outranks a match, because a row that reads `match` while a deviation stands
// hides the deviation. FR-conformance-33 records `not applicable` only where no vector
// holds a value, so a row reaches that result only where the suite compared nothing.
func (r *conformanceReport) row(capture, method string) conformanceReportRow {
	count := r.counts[conformanceReportCell{Capture: capture, Method: method}]

	row := conformanceReportRow{
		Capture:    capture,
		Method:     method,
		Set:        "—",
		Result:     conformanceReportNotApplicable,
		Matches:    count.Matches,
		Deviations: count.Deviations,
	}

	switch {
	case count.Deviations > 0:
		row.Result = conformanceReportDeviation
	case count.Matches > 0:
		row.Result = conformanceReportMatch
	case r.declined[capture] != "":
		row.Reason = r.declined[capture]
	case method == "JA4D6":
		row.Reason = conformanceReportSharedFieldReason
	default:
		row.Reason = conformanceReportNoValueReason
	}

	if len(count.Sets) > 0 {
		sets := make([]string, 0, len(count.Sets))
		for set := range count.Sets {
			sets = append(sets, set)
		}

		slices.Sort(sets)
		row.Set = strings.Join(sets, " and ")
	}

	return row
}

// deviationGroups returns every deviation group, sorted by capture, then vector set, then
// method.
func (r *conformanceReport) deviationGroups() []conformanceReportGroup {
	groups := make([]conformanceReportGroup, 0, len(r.groups))
	for _, group := range r.groups {
		groups = append(groups, *group)
	}

	slices.SortFunc(groups, func(first, second conformanceReportGroup) int {
		return strings.Compare(
			first.Capture+"\x00"+first.Set+"\x00"+first.Method,
			second.Capture+"\x00"+second.Set+"\x00"+second.Method,
		)
	})

	return groups
}

// uncoveredGroups returns every uncovered group, sorted by capture, then vector set, then
// method.
func (r *conformanceReport) uncoveredGroups() []conformanceReportUncoveredGroup {
	groups := make([]conformanceReportUncoveredGroup, 0, len(r.uncovered))
	for _, group := range r.uncovered {
		groups = append(groups, *group)
	}

	slices.SortFunc(groups, func(first, second conformanceReportUncoveredGroup) int {
		return strings.Compare(
			first.Capture+"\x00"+first.Set+"\x00"+first.Method,
			second.Capture+"\x00"+second.Set+"\x00"+second.Method,
		)
	})

	return groups
}

// conformanceReportCounts counts the whole run.
type conformanceReportCounts struct {
	Captures      int
	Compared      int
	NotApplicable int
	Matches       int
	Deviations    int
	Accepted      int
	Stale         int
	Orphan        int
	// Uncovered counts the uncovered values that the register does not name, and
	// AcceptedUncovered counts the uncovered values that the register names. #361.
	Uncovered         int
	AcceptedUncovered int
}

// totals counts the whole run from the comparisons the report holds.
//
// The report counts the run on its own, and `conformance_test.go` compares the result with
// `conformanceRunTotals`. Two counts that must agree catch a renderer that drops a
// comparison, which one count cannot.
func (r *conformanceReport) totals() conformanceReportCounts {
	totals := conformanceReportCounts{Captures: len(r.captures), Orphan: len(r.orphan)}

	for _, set := range r.sets {
		totals.Matches += set.Matches
		totals.Deviations += set.Deviations
		totals.Accepted += set.Accepted
		totals.Stale += set.Stale
		totals.Uncovered += set.Uncovered
		totals.AcceptedUncovered += set.AcceptedUncovered
	}

	compared := make(map[string]bool, len(r.captures))
	for cell := range r.counts {
		compared[cell.Capture] = true
	}

	totals.Compared = len(compared)
	totals.NotApplicable = totals.Captures - totals.Compared

	return totals
}

// render returns the whole report as Markdown.
//
// Every table is sorted, so two runs over one corpus render one text. An unsorted table
// changes on every run and fills each future diff with noise.
func (r *conformanceReport) render() string {
	var out strings.Builder

	r.renderHead(&out)
	r.renderSummary(&out)
	r.renderDeviations(&out)
	r.renderUncovered(&out)
	r.renderStale(&out)
	r.renderOrphans(&out)
	r.renderResults(&out)

	return out.String()
}

// renderHead writes the title and the commit. It holds FR-conformance-30.
func (r *conformanceReport) renderHead(out *strings.Builder) {
	out.WriteString("# FoxIO conformance report\n\n")
	out.WriteString("`make conformance` writes this file on every run. Never edit it by hand.\n\n")
	fmt.Fprintf(out, "The corpus holds the FoxIO commit `%s`.\n\n", r.commit)
	out.WriteString("`docs/specs/features/04-conformance-harness.md` states the requirements this report holds.\n\n")
}

// renderSummary writes the counts. It holds FR-conformance-31.
func (r *conformanceReport) renderSummary(out *strings.Builder) {
	totals := r.totals()

	out.WriteString("## Summary\n\n")
	out.WriteString("| Measure | Count |\n|---|---|\n")
	fmt.Fprintf(out, "| Captures | %d |\n", totals.Captures)
	fmt.Fprintf(out, "| Matches | %d |\n", totals.Matches)
	fmt.Fprintf(out, "| Deviations | %d |\n", totals.Deviations)
	fmt.Fprintf(out, "| Accepted deviations | %d |\n", totals.Accepted)
	// The row names the unaccepted count in full, because `Uncovered values` alone would
	// name the unaccepted count here and the whole count in the section below. One phrase
	// carries one meaning. The two numbers differ on every tree that holds an accepted
	// uncovered value, and the section states the whole count with the accepted part of it.
	fmt.Fprintf(out, "| Unaccepted uncovered values | %d |\n", totals.Uncovered)
	fmt.Fprintf(out, "| Accepted uncovered values | %d |\n", totals.AcceptedUncovered)
	fmt.Fprintf(out, "| Accepted comparisons | %d |\n", totals.Accepted+totals.AcceptedUncovered)
	fmt.Fprintf(out, "| Stale register entries | %d |\n", totals.Stale)
	fmt.Fprintf(out, "| Orphan register entries | %d |\n", totals.Orphan)
	fmt.Fprintf(out, "| Captures the suite compared | %d |\n", totals.Compared)
	fmt.Fprintf(out, "| Captures the suite compared nothing on | %d |\n\n", totals.NotApplicable)

	out.WriteString("The two vector sets cover different methods, so the report counts each one on its own.\n\n")
	out.WriteString("| Vector set | Matches | Deviations | Accepted deviations | Unaccepted uncovered values | " +
		"Accepted uncovered values |\n|---|---|---|---|---|---|\n")

	for _, set := range []string{conformanceReportStreamSet, conformanceReportPacketSet} {
		counts := r.sets[set]
		fmt.Fprintf(out, "| %s | %d | %d | %d | %d | %d |\n",
			set, counts.Matches, counts.Deviations, counts.Accepted, counts.Uncovered, counts.AcceptedUncovered)
	}

	out.WriteString("\nAn accepted deviation is an entry of `testdata/deviations.json`, which records a ruling.\n")
	out.WriteString("An accepted uncovered value is an entry of that file too, and `## Uncovered values` below " +
		"states what an uncovered value is.\n")
	out.WriteString("The register holds one entry for each accepted comparison, so the accepted comparison count " +
		"equals the register key count.\n\n")
}

// renderDeviations writes the deviation table. It holds FR-conformance-32.
func (r *conformanceReport) renderDeviations(out *strings.Builder) {
	groups := r.deviationGroups()

	out.WriteString("## Deviations\n\n")

	if len(groups) == 0 {
		out.WriteString("The run reports no deviation.\n\n")

		return
	}

	fmt.Fprintf(out, "The run reports %d deviations in %d groups. One group is one capture, one method and one "+
		"vector set.\n\n", r.totals().Deviations+r.totals().Accepted, len(groups))
	fmt.Fprintf(out, "This file is tracked in git, so the table holds at most %d deviations of each group. "+
		"The `Deviations` column counts the whole group.\n", conformanceReportSampleLimit)
	out.WriteString("`conformance.log` holds every deviation, `make conformance` writes it in CI, and the " +
		"conformance job uploads it as an artifact.\n\n")

	out.WriteString("| Capture | Vector set | Method | Deviations | Comparison | Difference | Expected | Produced |\n")
	out.WriteString("|---|---|---|---|---|---|---|---|\n")

	for _, group := range groups {
		for _, deviation := range group.Samples {
			accepted := ""
			if deviation.Accepted {
				accepted = " (accepted)"
			}

			fmt.Fprintf(out, "| `%s` | %s | %s | %d | `%s` | %s%s | %s | %s |\n",
				group.Capture, group.Set, group.Method, group.Count, deviation.Key,
				deviation.Kind, accepted,
				conformanceReportValue(deviation.Expected), conformanceReportValue(deviation.Produced))
		}
	}

	out.WriteString("\n")
}

// renderUncovered writes the uncovered values. It holds FR-conformance-33s and
// FR-conformance-33t, and #361 states the rule it reports. FR-conformance-33r names the
// summary rather than this section, and `renderSummary` above holds it.
//
// The section states the result of every run, and never of a run with an uncovered value
// alone. A reader who finds no section cannot tell full coverage from a renderer that dropped
// the count.
//
// The row holds no expected value. The vector file names no key for the method, so the
// comparison reads no value to print.
func (r *conformanceReport) renderUncovered(out *strings.Builder) {
	groups := r.uncoveredGroups()

	out.WriteString("## Uncovered values\n\n")
	out.WriteString("The library produces a value, and the vector file of the capture publishes no key for its " +
		"method. Such a file states nothing about the method. The run therefore counts the value apart from a " +
		"match, and apart from a deviation. The maintainer ruled the third category on 2026-08-13 in #361.\n\n")
	out.WriteString("The count below holds the accepted values and the unaccepted ones. The summary above counts " +
		"the two apart.\n\n")

	if len(groups) == 0 {
		out.WriteString("The run reports no uncovered value.\n\n")

		return
	}

	totals := r.totals()

	// The sentence states the whole count and the accepted count. The summary row
	// `Uncovered values` counts the unaccepted ones alone, as the row `Deviations` does, so a
	// reader who meets one number without the other reads two counts as one.
	fmt.Fprintf(out, "The run reports %d uncovered values in %d groups, and the register accepts %d of them. "+
		"One group is one capture, one method and one vector set.\n\n",
		totals.Uncovered+totals.AcceptedUncovered, len(groups), totals.AcceptedUncovered)
	fmt.Fprintf(out, "This file is tracked in git, so the table holds at most %d uncovered values of each group. "+
		"The `Uncovered` column counts the whole group.\n\n", conformanceReportSampleLimit)

	out.WriteString("| Capture | Vector set | Method | Uncovered | Comparison | Produced | Accepted |\n")
	out.WriteString("|---|---|---|---|---|---|---|\n")

	for _, group := range groups {
		for _, value := range group.Samples {
			accepted := "no"
			if value.Accepted {
				accepted = "yes"
			}

			fmt.Fprintf(out, "| `%s` | %s | %s | %d | `%s` | %s | %s |\n",
				group.Capture, group.Set, group.Method, group.Count, value.Key,
				conformanceReportValue(value.Produced), accepted)
		}
	}

	out.WriteString("\n")
}

// renderStale writes the stale register entries. It holds #307.
//
// The section states the result of every run, and never of a failed run alone. A reader who
// finds no section cannot tell a healthy register from a renderer that dropped one.
func (r *conformanceReport) renderStale(out *strings.Builder) {
	out.WriteString("## Stale register entries\n\n")
	out.WriteString("An entry of `testdata/deviations.json` records the value this library produced when the " +
		"maintainer ruled. A later change moves that value, and the entry then accepts a comparison it does not " +
		"describe.\n\n")

	if len(r.stale) == 0 {
		out.WriteString("The run reports no stale register entry.\n\n")

		return
	}

	entries := slices.Clone(r.stale)
	slices.SortStableFunc(entries, func(first, second conformanceStaleEntry) int {
		return strings.Compare(first.Key.String(), second.Key.String())
	})

	out.WriteString("| Comparison | Recorded | Produced |\n|---|---|---|\n")

	for _, entry := range entries {
		fmt.Fprintf(out, "| `%s` | %s | %s |\n",
			entry.Key, conformanceReportValue(entry.Recorded), conformanceReportValue(entry.Produced))
	}

	out.WriteString("\n")
}

// renderOrphans writes the orphan register entries. It holds FR-conformance-33m,
// FR-conformance-33n and FR-conformance-33o, and #328 states the defect it reports.
//
// The section states the result of every run, and never of a failed run alone. A reader who
// finds no section cannot tell a healthy register from a renderer that dropped one.
//
// The row holds no produced value. No comparison of the run reaches the key, so the run
// produces nothing to print.
func (r *conformanceReport) renderOrphans(out *strings.Builder) {
	out.WriteString("## Orphan register entries\n\n")
	out.WriteString("An entry of `testdata/deviations.json` names one comparison. No comparison of the run reaches " +
		"the key of an entry below, so the entry accepts a difference the run never measures.\n\n")

	if len(r.orphan) == 0 {
		out.WriteString("The run reports no orphan register entry.\n\n")

		return
	}

	out.WriteString("| Comparison | Recorded |\n|---|---|\n")

	for _, entry := range r.orphan {
		fmt.Fprintf(out, "| `%s` | %s |\n", entry.Key, conformanceReportValue(entry.Recorded))
	}

	out.WriteString("\n")
}

// renderResults writes the result table. It holds FR-conformance-28, FR-conformance-29 and
// FR-conformance-33.
func (r *conformanceReport) renderResults(out *strings.Builder) {
	out.WriteString("## Results\n\n")
	out.WriteString("The table holds one row for each capture and each method. A row records `not applicable` " +
		"only where no vector of the corpus holds a value for that method on that capture.\n\n")
	out.WriteString("| Capture | Method | Vector set | Result | Matches | Deviations | Reason |\n")
	out.WriteString("|---|---|---|---|---|---|---|\n")

	for _, row := range r.rows() {
		reason := row.Reason
		if reason == "" {
			reason = "—"
		}

		fmt.Fprintf(out, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
			row.Capture, row.Method, row.Set, row.Result,
			strconv.Itoa(row.Matches), strconv.Itoa(row.Deviations), reason)
	}
}

// conformanceReportValue returns one fingerprint value as a table cell.
//
// An extra value holds no expected value, and an absent value holds no produced value.
// FR-conformance-16 compares as an exact string match, so the cell reproduces the value
// without a change. A code span holds it, so a reader never reads it as Markdown.
func conformanceReportValue(value string) string {
	if value == "" {
		return "(none)"
	}

	return "`" + value + "`"
}

// conformanceWriteReport writes the report to `docs/audit/conformance.md`.
// It holds FR-conformance-27.
func conformanceWriteReport(report *conformanceReport) error {
	if err := report.Err(); err != nil {
		return err
	}

	// The report is tracked in git and a reader opens it, so it carries the file mode of a
	// tracked document.
	if err := os.WriteFile(conformanceReportPath, []byte(report.render()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", conformanceReportPath, err)
	}

	return nil
}
