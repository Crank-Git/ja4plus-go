package ja4plus

import (
	"crypto/sha256"
	"encoding/hex"
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

// portRegisterFile is the path of the port's register copy.
const portRegisterFile = "docs/specs/foxio/port-register.md"

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
// It returns an error when the content is not a JSON array of objects, when an entry
// omits a field, when an entry holds a field this project does not define, or when a
// field value has the wrong form.
func parseDeviationRegister(content []byte) ([]deviationEntry, error) {
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("the register is not a JSON array of objects: %w", err)
	}

	entries := make([]deviationEntry, 0, len(raw))

	for index, fields := range raw {
		entry, err := readDeviationEntry(fields)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index, err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// readDeviationEntry returns the entry that the fields describe.
// It returns an error when a field is absent, undefined or of the wrong form.
func readDeviationEntry(fields map[string]json.RawMessage) (deviationEntry, error) {
	var entry deviationEntry

	for _, name := range deviationFieldNames {
		if _, held := fields[name]; !held {
			return entry, fmt.Errorf("the field %q is absent", name)
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
func checkDeviationReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("the field %q is empty, and it must hold one sentence", "reason")
	}

	if !strings.HasSuffix(reason, ".") {
		return fmt.Errorf("the field %q holds %q, and one sentence ends with a full stop", "reason", reason)
	}

	if strings.Contains(reason, ". ") {
		return fmt.Errorf("the field %q holds %q, and FR-reference-24 allows one sentence", "reason", reason)
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
	for _, entry := range readDeviationRegister(t) {
		if !deviationRulingPattern.MatchString(entry.Ruling) {
			t.Errorf("entry %q names the ruling %q, and FR-reference-23 requires an issue", entry.Key, entry.Ruling)
		}
	}
}

func TestTheReaderAcceptsAWellFormedEntry(t *testing.T) {
	valueDecline := oneValidDeviationEntry()

	capabilityDecline := oneValidDeviationEntry()
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

	cases := []struct {
		name    string
		content []byte
	}{
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

func TestTheSchemaDocumentNamesEveryRegisterField(t *testing.T) {
	// A JSON file carries no comment, so the schema lives beside the register.
	document := readRepoFile(t, "testdata/README.md")

	for _, field := range deviationFieldNames {
		if !strings.Contains(document, "`"+field+"`") {
			t.Errorf("testdata/README.md does not name the field %q", field)
		}
	}
}

func TestThePortRegisterPageNamesThePortCommitAndTheRetrievalDate(t *testing.T) {
	page := readRepoFile(t, portRegisterFile)

	// FR-reference-17 requires the port commit and the retrieval date. The commit is the
	// one that `v1.1.0` points at in `Crank-Git/ja4plus`.
	for _, wanted := range []string{
		"21299645366591331eb93155355b65a76a3729f3",
		"v1.1.0",
		"2026-08-11",
	} {
		if !strings.Contains(page, wanted) {
			t.Errorf("%s does not name %q", portRegisterFile, wanted)
		}
	}
}

func TestThePortRegisterPageHoldsThePortSection(t *testing.T) {
	page := readRepoFile(t, portRegisterFile)

	const beginMarker = "<!-- port-register:begin -->"
	const endMarker = "<!-- port-register:end -->"

	begin := strings.Index(page, beginMarker)
	end := strings.Index(page, endMarker)

	if begin < 0 || end < begin {
		t.Fatalf("%s holds no marked copy between %s and %s", portRegisterFile, beginMarker, endMarker)
	}

	copied := page[begin+len(beginMarker) : end]

	// FR-reference-18 requires a verbatim copy. These anchors are the section heading and
	// the last line of the port's own section, so a reworded copy fails the test.
	for _, wanted := range []string{
		"## Parity with ja4plus-go",
		"### Divergence register",
		"| Item | This project today | The port today | Rule | Action |",
		"Verified against: https://github.com/Crank-Git/ja4plus-go",
	} {
		if !strings.Contains(copied, wanted) {
			t.Errorf("the copy in %s does not hold %q", portRegisterFile, wanted)
		}
	}

	// The hash is the whole gate on FR-reference-18. An anchor test passes over an edit
	// between the anchors, and this test does not. The page states the command that
	// reproduces the value.
	const wantedDigest = "f5ec7502b46cea632ac8d291f32acf3b97fcf3471a5ee8a4a8ea0ac6aba45f4b"

	digest := sha256.Sum256([]byte(strings.Trim(copied, "\n") + "\n"))
	if hex.EncodeToString(digest[:]) != wantedDigest {
		t.Errorf("the copy in %s hashes to %s, and the port section at commit 21299645366591331eb93155355b65a76a3729f3 hashes to %s",
			portRegisterFile, hex.EncodeToString(digest[:]), wantedDigest)
	}
}
