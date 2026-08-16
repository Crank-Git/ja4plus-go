package ja4plus

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The register is the tracked file `testdata/deviations.json`. It holds one entry for
// each accepted difference from a FoxIO value. These tests hold FR-reference-19 through
// FR-reference-24, FR-reference-27 and FR-reference-28.
//
// The register is empty today, because no conformance run has measured a deviation. An
// empty register passes every content test without exercising the reader, so the reader
// tests below run over fixture entries that this file holds. #33 builds the conformance
// suite, and FR-reference-25 and FR-reference-26 move there with it.
//
// The reader stays in the test build. `v1.0.0` freezes the exported API, and the register
// serves the test suite alone.

// deviationRegisterFile is the path of the register, relative to the package directory.
const deviationRegisterFile = "testdata/deviations.json"

// deviationFieldNames names every field that FR-reference-20 requires.
var deviationFieldNames = []string{"key", "capability", "ours", "theirs", "ruling", "reason"}

// deviationRulingPattern is the form of a `ruling` value. FR-reference-23 requires the
// value to name the issue that holds the ruling, and this project names an issue as `#`
// and a number.
var deviationRulingPattern = regexp.MustCompile(`^#[1-9][0-9]*$`)

// deviationCaptureSuffixes names the two capture formats the Terms table defines.
var deviationCaptureSuffixes = []string{".pcap", ".pcapng"}

// deviationEntry is one accepted difference from a FoxIO value.
type deviationEntry struct {
	// Key names the capture, the stream and the method.
	Key string
	// Capability is true for a capability decline and false for a value decline.
	Capability bool
	// Ours is the value this library produces.
	Ours string
	// Theirs is the value the reference produces.
	Theirs string
	// Ruling names the issue that holds the ruling.
	Ruling string
	// Reason holds one sentence.
	Reason string
}

// parseDeviationRegister returns one entry for each element of the register content.
// It returns an error in five cases.
//
//   - The content is not a JSON array of objects.
//   - An entry omits a field.
//   - An entry holds a field this project does not define.
//   - A field value has the wrong form.
//   - Two entries hold one key.
func parseDeviationRegister(content []byte) ([]deviationEntry, error) {
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("the register is not a JSON array of objects: %w", err)
	}

	entries := make([]deviationEntry, 0, len(raw))

	// FR-reference-31 gives one entry to one comparison. The conformance suite reads the
	// register as a map, so a second entry for one key replaces the first in silence. The
	// ruling of the first entry then accepts nothing.
	first := make(map[string]int, len(raw))

	for index, fields := range raw {
		entry, err := readDeviationEntry(fields)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index, err)
		}

		if held, twice := first[entry.Key]; twice {
			return nil, fmt.Errorf("entry %d holds the key %q, and entry %d holds it too, so one comparison carries two entries",
				index, entry.Key, held)
		}

		first[entry.Key] = index

		entries = append(entries, entry)
	}

	return entries, nil
}

// readDeviationEntry returns the entry that the fields describe.
// It returns an error in three cases.
//
//   - A field is absent.
//   - The entry holds a field this project does not define.
//   - A field value has the wrong form.
func readDeviationEntry(fields map[string]json.RawMessage) (deviationEntry, error) {
	var entry deviationEntry

	// A JSON null decodes into the Go zero value and reports no error, so `"capability":
	// null` would read as a value decline. The reader declines a null for that reason.
	for _, name := range deviationFieldNames {
		raw, held := fields[name]
		if !held {
			return entry, fmt.Errorf("the field %q is absent", name)
		}

		if string(raw) == "null" {
			return entry, fmt.Errorf("the field %q holds null, and every register field holds a value", name)
		}
	}

	// An entry that holds an undefined field is a defect the reader must report. A JSON
	// decoder drops such a field in silence, so a misspelled `capability` would read as a
	// value decline.
	undefined := make([]string, 0, len(fields))

	for name := range fields {
		if !containsDeviationField(name) {
			undefined = append(undefined, name)
		}
	}

	if len(undefined) > 0 {
		slices.Sort(undefined)

		return entry, fmt.Errorf("the entry holds the field %q, and this project defines no such register field", undefined[0])
	}

	if err := json.Unmarshal(fields["capability"], &entry.Capability); err != nil {
		return entry, fmt.Errorf("the field %q is not a boolean: %w", "capability", err)
	}

	// The `ours` value and the `theirs` value carry no form rule. A capability decline
	// produces no value on one side, so an empty string is a true record of the state.
	//
	// The list keeps the order fixed. A range over a map reports a different field first
	// on each run, and an entry with two defects would then produce two error messages.
	for _, field := range []struct {
		name   string
		target *string
	}{
		{"key", &entry.Key},
		{"ours", &entry.Ours},
		{"theirs", &entry.Theirs},
		{"ruling", &entry.Ruling},
		{"reason", &entry.Reason},
	} {
		if err := json.Unmarshal(fields[field.name], field.target); err != nil {
			return entry, fmt.Errorf("the field %q is not a string: %w", field.name, err)
		}
	}

	if err := checkDeviationKey(entry.Key); err != nil {
		return entry, err
	}

	if !deviationRulingPattern.MatchString(entry.Ruling) {
		return entry, fmt.Errorf("the field %q holds %q, and it must name an issue as #<number>", "ruling", entry.Ruling)
	}

	return entry, checkDeviationReason(entry.Reason)
}

// containsDeviationField reports whether the name is a register field.
func containsDeviationField(name string) bool {
	return slices.Contains(deviationFieldNames, name)
}

// checkDeviationKey returns an error when the key does not name the capture, the stream
// and the method. FR-reference-21 states the three parts, and the port writes them in
// that order, for example `gre-erspan-vxlan.pcap/0:65174/JA4T.1`.
func checkDeviationKey(key string) error {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return fmt.Errorf("the field %q holds %q, and it must name the capture, the stream and the method as <capture>/<stream>/<method>", "key", key)
	}

	for _, part := range parts {
		if part == "" {
			return fmt.Errorf("the field %q holds %q, and no part of it may be empty", "key", key)
		}
	}

	for _, suffix := range deviationCaptureSuffixes {
		if strings.HasSuffix(parts[0], suffix) {
			return nil
		}
	}

	return fmt.Errorf("the field %q holds %q, and its first part must name a capture file", "key", key)
}

// checkDeviationReason returns an error when the reason is not one sentence.
// FR-reference-24 allows one sentence, so the value ends with a full stop and holds no
// full stop that a space follows.
//
// The check reads a full stop and a space as a sentence break, so it also declines an
// abbreviation such as `e.g. `. A register reason states one fact about one comparison,
// and `.claude/rules/ste.md` rule 10 keeps an undefined abbreviation out of it.
func checkDeviationReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("the field %q is empty, and it must hold one sentence", "reason")
	}

	if !strings.HasSuffix(reason, ".") {
		return fmt.Errorf("the field %q holds %q, and one sentence ends with a full stop", "reason", reason)
	}

	if strings.Contains(reason, ". ") {
		return fmt.Errorf("the field %q holds %q, and a full stop that a space follows breaks the one sentence FR-reference-24 allows", "reason", reason)
	}

	return nil
}

// readDeviationRegister returns the parsed register.
// It fails the test when the file is absent or when it does not parse.
func readDeviationRegister(t *testing.T) []deviationEntry {
	t.Helper()

	content, err := os.ReadFile(deviationRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", deviationRegisterFile, err)
	}

	entries, err := parseDeviationRegister(content)
	if err != nil {
		t.Fatalf("parse %s: %v", deviationRegisterFile, err)
	}

	return entries
}

// oneValidDeviationEntry returns the fields of one well-formed entry.
// A test changes one field of the result to build a malformed case.
func oneValidDeviationEntry() map[string]any {
	return map[string]any{
		"key":        "ssh2.pcapng/15/JA4L-S",
		"capability": false,
		"ours":       "6252_58",
		"theirs":     "6252_58",
		"ruling":     "#19",
		"reason":     "This entry is a fixture of the test, and no conformance run produced it.",
	}
}

// oneDeviationRegister returns the JSON form of a register that holds the entries.
func oneDeviationRegister(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()

	content, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal the fixture register: %v", err)
	}

	return content
}

func TestTheRegisterFileExists(t *testing.T) {
	if _, err := os.Stat(deviationRegisterFile); err != nil {
		t.Fatalf("FR-reference-19 requires %s: %v", deviationRegisterFile, err)
	}
}

func TestGitTracksTheRegisterFile(t *testing.T) {
	// A build environment that holds no git cannot answer the question, and a failure
	// there would report a defect the repository does not hold.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on the path, so this test cannot read the index")
	}

	command := exec.Command("git", "ls-files", "--error-unmatch", deviationRegisterFile)

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FR-reference-19 requires git to track %s: %v\n%s", deviationRegisterFile, err, output)
	}
}

func TestTheRegisterParsesAndEveryEntryHoldsEveryField(t *testing.T) {
	entries := readDeviationRegister(t)

	t.Logf("the register holds %d entries", len(entries))
}

func TestEveryRulingOfTheRegisterNamesAnIssue(t *testing.T) {
	// The check reads the form of the value and reaches no network. A call to the
	// GitHub API fails offline and fails in CI without a token, so a unit test that
	// made one would report a defect that the register does not hold.
	//
	// The reader already declines a malformed ruling, so this loop repeats that check
	// over the tracked file. The repeat is deliberate: FR-reference-27 names a test of
	// its own, and a reader who moves the form check out of the reader still has one.
	// `TestTheReaderRejectsAMalformedRegister` holds the cases that prove the check.
	for _, entry := range readDeviationRegister(t) {
		if !deviationRulingPattern.MatchString(entry.Ruling) {
			t.Errorf("entry %q names the ruling %q, and FR-reference-23 requires an issue", entry.Key, entry.Ruling)
		}
	}
}

func TestTheReaderAcceptsAWellFormedEntry(t *testing.T) {
	valueDecline := oneValidDeviationEntry()

	// FR-reference-31 gives one entry to one key, so the second entry carries its own key.
	capabilityDecline := oneValidDeviationEntry()
	capabilityDecline["key"] = "ssh2.pcapng/15/JA4L-C"
	capabilityDecline["capability"] = true
	capabilityDecline["ours"] = ""

	entries, err := parseDeviationRegister(oneDeviationRegister(t, valueDecline, capabilityDecline))
	if err != nil {
		t.Fatalf("the reader rejects a well-formed register: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("the reader returns %d entries, and the register holds 2", len(entries))
	}

	if entries[0].Capability {
		t.Errorf("entry 0 reports a capability decline, and FR-reference-22 makes `false` a value decline")
	}

	if !entries[1].Capability {
		t.Errorf("entry 1 reports a value decline, and FR-reference-22 makes `true` a capability decline")
	}

	if entries[0].Key != "ssh2.pcapng/15/JA4L-S" {
		t.Errorf("entry 0 holds the key %q, and the fixture holds `ssh2.pcapng/15/JA4L-S`", entries[0].Key)
	}
}

func TestTheReaderAcceptsAnEmptyRegister(t *testing.T) {
	entries, err := parseDeviationRegister([]byte("[]\n"))
	if err != nil {
		t.Fatalf("the reader rejects an empty register: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("the reader returns %d entries for an empty register", len(entries))
	}
}

func TestTheReaderRejectsAMalformedRegister(t *testing.T) {
	withField := func(name string, value any) []byte {
		entry := oneValidDeviationEntry()
		entry[name] = value

		content, err := json.Marshal([]map[string]any{entry})
		if err != nil {
			t.Fatalf("marshal the fixture register: %v", err)
		}

		return content
	}

	withoutField := func(name string) []byte {
		entry := oneValidDeviationEntry()
		delete(entry, name)

		content, err := json.Marshal([]map[string]any{entry})
		if err != nil {
			t.Fatalf("marshal the fixture register: %v", err)
		}

		return content
	}

	// Two entries that hold one key need two entries, and `withField` builds one. The
	// second entry carries a different ruling, so the register reads as two rulings on one
	// comparison.
	twiceFirst := oneValidDeviationEntry()
	twiceSecond := oneValidDeviationEntry()
	twiceSecond["ruling"] = "#217"

	cases := []struct {
		name    string
		content []byte
	}{
		{"two entries hold one key", oneDeviationRegister(t, twiceFirst, twiceSecond)},
		{"the content is not an array", []byte(`{"key": "a.pcap/1/JA4"}`)},
		{"the content is not JSON", []byte(`not json`)},
		{"the entry omits the key", withoutField("key")},
		{"the entry omits the capability", withoutField("capability")},
		{"the entry omits the ours value", withoutField("ours")},
		{"the entry omits the theirs value", withoutField("theirs")},
		{"the entry omits the ruling", withoutField("ruling")},
		{"the entry omits the reason", withoutField("reason")},
		{"the entry holds a field this project does not define", withField("note", "a note")},
		{"the capability is a string", withField("capability", "false")},
		{"the capability is null", withField("capability", nil)},
		{"the key is null", withField("key", nil)},
		{"the ours value is null", withField("ours", nil)},
		{"the theirs value is null", withField("theirs", nil)},
		{"the ruling is null", withField("ruling", nil)},
		{"the reason is null", withField("reason", nil)},
		{"the key names no stream", withField("key", "ssh2.pcapng/JA4L-S")},
		{"the key names no method", withField("key", "ssh2.pcapng/15/")},
		{"the key names no capture file", withField("key", "ssh2/15/JA4L-S")},
		{"the ruling names no issue", withField("ruling", "the maintainer")},
		{"the ruling omits the number sign", withField("ruling", "19")},
		{"the reason holds two sentences", withField("reason", "The reference splits. A person ruled.")},
		{"the reason ends with no full stop", withField("reason", "The reference splits")},
		{"the reason is empty", withField("reason", "")},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := parseDeviationRegister(testCase.content); err == nil {
				t.Errorf("the reader accepts a register where %s", testCase.name)
			}
		})
	}
}

func TestTheRegisterHoldsEachKeyOnce(t *testing.T) {
	// This test reads the keys of the tracked file and never `readDeviationRegister`. The
	// reader declines a second entry for one key, so a test that read the register through
	// it could never reach this loop and could never fail. FR-reference-31 names a test of
	// its own, and a reader who moves the check out of the reader still has one.
	content, err := os.ReadFile(deviationRegisterFile)
	if err != nil {
		t.Fatalf("read %s: %v", deviationRegisterFile, err)
	}

	var raw []struct {
		Key string `json:"key"`
	}

	if err := json.Unmarshal(content, &raw); err != nil {
		t.Fatalf("decode %s: %v", deviationRegisterFile, err)
	}

	first := make(map[string]int, len(raw))

	for index, entry := range raw {
		if held, twice := first[entry.Key]; twice {
			t.Errorf("entry %d and entry %d hold the key %q, and FR-reference-31 gives one entry to one comparison",
				held, index, entry.Key)

			continue
		}

		first[entry.Key] = index
	}

	t.Logf("the register holds %d entries and %d keys", len(raw), len(first))
}

func TestTheSchemaDocumentStatesTheMeaningOfTheMiddleKeyPart(t *testing.T) {
	document := readRepoFile(t, "testdata/README.md")

	// FR-reference-29 gives the middle part two meanings, one for each vector set. A reader
	// cannot tell a frame number from a stream number, because both are small integers, so
	// the schema document must name both.
	for _, wanted := range []string{"stream number", "frame number"} {
		if !strings.Contains(document, wanted) {
			t.Errorf("testdata/README.md does not name the %s, and FR-reference-29 states both meanings of the middle key part", wanted)
		}
	}
}

func TestTheSchemaDocumentNamesEveryRegisterField(t *testing.T) {
	// A JSON file carries no comment, so the schema lives beside the register.
	document := readRepoFile(t, "testdata/README.md")

	for _, field := range deviationFieldNames {
		if !strings.Contains(document, "`"+field+"`") {
			t.Errorf("testdata/README.md does not name the field %q", field)
		}
	}
}

// #758 removed the mirrored copy of the port's register on 2026-08-16 UTC, and this test
// holds the removal.
//
// A whole-page copy of the port's material restates every value that page holds.
// `.claude/rules/ste.md` `### A value of another repository is cited, and never mirrored`
// states the rule that bars it. A later change that restores the copy restores the drift
// check, the local bare-number namespace and the maintenance cost with it, so the guard
// reports the return of the path rather than the return of the text.
//
// Issue #758 is the reversal path. A reversal removes this test and it states the reason.
func TestTheTreeHoldsNoMirroredCopyOfThePortRegister(t *testing.T) {
	const removedPage = "docs/specs/foxio/port-register.md"

	if _, err := os.Stat(removedPage); err == nil {
		t.Errorf("%s exists, and #758 removed it on 2026-08-16 UTC. Cite the port at the tag %s instead, under `.claude/rules/rulings.md` `## A citation names its repository`",
			removedPage, portReadVersion)
	}
}
