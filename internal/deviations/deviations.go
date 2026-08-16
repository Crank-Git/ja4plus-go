// Package deviations reads `testdata/deviations.json`, the register of accepted
// differences from a FoxIO value.
//
// The register is data of this repository rather than of this library, and two test
// packages read it: `ja4plus` runs the conformance comparison, and `internal/repocheck`
// holds the register schema and the changelog counts. A test helper lives in a `_test.go`
// file, and no package imports another package's test files, so the reader lives here.
//
// The reader stays out of the exported surface of the library. `v1.0.0` freezes that
// surface, and the register serves the test suite alone.
//
// FR-reference-19 through FR-reference-24, FR-reference-27, FR-reference-28 and
// FR-reference-31 state the rules this package holds.
package deviations

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// RegisterFile is the path of the register, relative to the repository root.
const RegisterFile = "testdata/deviations.json"

// FieldNames names every field that FR-reference-20 requires.
var FieldNames = []string{"key", "capability", "ours", "theirs", "ruling", "reason"}

// CaptureSuffixes names the two capture formats the Terms table defines.
var CaptureSuffixes = []string{".pcap", ".pcapng"}

// Entry is one accepted difference from a FoxIO value.
type Entry struct {
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

// Load returns the parsed register. It returns an error when the file is absent or when
// it does not parse. The caller runs from the repository root.
func Load() ([]Entry, error) {
	content, err := os.ReadFile(RegisterFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RegisterFile, err)
	}

	entries, err := Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", RegisterFile, err)
	}

	return entries, nil
}

// Parse returns one entry for each element of the register content.
// It returns an error in five cases.
//
//   - The content is not a JSON array of objects.
//   - An entry omits a field.
//   - An entry holds a field this project does not define.
//   - A field value has the wrong form.
//   - Two entries hold one key.
func Parse(content []byte) ([]Entry, error) {
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("the register is not a JSON array of objects: %w", err)
	}

	entries := make([]Entry, 0, len(raw))

	// FR-reference-31 gives one entry to one comparison. The conformance suite reads the
	// register as a map, so a second entry for one key replaces the first in silence. The
	// ruling of the first entry then accepts nothing.
	first := make(map[string]int, len(raw))

	for index, fields := range raw {
		entry, err := readEntry(fields)
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

// ContainsField reports whether the name is a register field.
func ContainsField(name string) bool {
	return slices.Contains(FieldNames, name)
}

// CheckKey returns an error when the key does not name the capture, the stream
// and the method. FR-reference-21 states the three parts, and the port writes them in
// that order, for example `gre-erspan-vxlan.pcap/0:65174/JA4T.1`.
func CheckKey(key string) error {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return fmt.Errorf("the field %q holds %q, and it must name the capture, the stream and the method as <capture>/<stream>/<method>", "key", key)
	}

	for _, part := range parts {
		if part == "" {
			return fmt.Errorf("the field %q holds %q, and no part of it may be empty", "key", key)
		}
	}

	for _, suffix := range CaptureSuffixes {
		if strings.HasSuffix(parts[0], suffix) {
			return nil
		}
	}

	return fmt.Errorf("the field %q holds %q, and its first part must name a capture file", "key", key)
}

// CheckReason returns an error when the reason is not one sentence.
// FR-reference-24 allows one sentence, so the value ends with a full stop and holds no
// full stop that a space follows.
//
// The check reads a full stop and a space as a sentence break, so it also declines an
// abbreviation such as `e.g. `. A register reason states one fact about one comparison,
// and `.claude/rules/ste.md` rule 10 keeps an undefined abbreviation out of it.
func CheckReason(reason string) error {
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

// RulingPattern is the form of a `ruling` value. FR-reference-23 requires the value to
// name the issue that holds the ruling, and this project names an issue as `#` and a
// number.
var RulingPattern = regexp.MustCompile(`^#[1-9][0-9]*$`)

// readEntry returns the entry that the fields describe.
// It returns an error in three cases.
//
//   - A field is absent.
//   - The entry holds a field this project does not define.
//   - A field value has the wrong form.
func readEntry(fields map[string]json.RawMessage) (Entry, error) {
	var entry Entry

	// A JSON null decodes into the Go zero value and reports no error, so `"capability":
	// null` would read as a value decline. The reader declines a null for that reason.
	for _, name := range FieldNames {
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
		if !ContainsField(name) {
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

	if err := CheckKey(entry.Key); err != nil {
		return entry, err
	}

	if !RulingPattern.MatchString(entry.Ruling) {
		return entry, fmt.Errorf("the field %q holds %q, and it must name an issue as #<number>", "ruling", entry.Ruling)
	}

	return entry, CheckReason(entry.Reason)
}
