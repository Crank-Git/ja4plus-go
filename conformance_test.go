//go:build conformance

package ja4plus

import (
	"encoding/json"
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
// # What this suite compares
//
// The suite compares the two vector sets, and it compares each one on its own. A
// per-packet record names its frame, so a per-packet key holds the frame number. A
// per-stream entry names a connection by the `src`, `dst`, `srcport` and `dstport` fields,
// so a per-stream key holds the stream name of that connection.
// `conformanceStreamNames` of `conformance_adapters_test.go` states the two forms of the
// stream name, and issue #250 states why a stream number alone names no connection.
//
// `conformance_adapters_test.go` holds the two adapters and FR-conformance-20 through
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
// `conformancePacketNonMethodFields` of `conformance_adapters_test.go` names every field
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
	processor := NewProcessor()

	record := func(results []FingerprintResult) {
		for _, result := range results {
			endpoint := conformanceEndpointKey(result.SrcIP, result.SrcPort, result.DstIP, result.DstPort)

			stream, named := shape.StreamOfEndpoint[endpoint]
			if !named {
				stream = endpoint
			}

			for _, value := range conformanceStreamValuesOfResult(result) {
				if !shape.Covered[value.Method] {
					continue
				}

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

// conformanceSetTotals counts the outcome of one vector set.
type conformanceSetTotals struct {
	Matches          int
	Deviations       int
	AcceptedDeviants int
	Closed           int
	Stale            int
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
	}
}

// conformanceRunOneCapture compares one capture against the two vector sets and adds its
// outcome to the totals.
func conformanceRunOneCapture(
	t *testing.T,
	capture string,
	register map[conformanceKey]deviationEntry,
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

		conformanceProducedByFrame(t, capture, packets, map[string]bool{})

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
	register map[conformanceKey]deviationEntry,
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
	comparison := compareConformance(produced, shape.Expected, register)

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
	register map[conformanceKey]deviationEntry,
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

	produced := conformanceProducedByFrame(t, capture, packets, conformanceCoveredMethods(expected))
	comparison := compareConformance(produced, expected, register)

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
