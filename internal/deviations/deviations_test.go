package deviations

import (
	"encoding/json"
	"testing"
)

// These tests exercise the reader over fixture entries. The tracked register is empty
// today, because no conformance run has measured a deviation, so a content test of the
// tracked file exercises no branch of the reader. `internal/repocheck/deviations_test.go`
// holds the tests that read the tracked file itself.

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
func TestTheReaderAcceptsAWellFormedEntry(t *testing.T) {
	valueDecline := oneValidDeviationEntry()

	// FR-reference-31 gives one entry to one key, so the second entry carries its own key.
	capabilityDecline := oneValidDeviationEntry()
	capabilityDecline["key"] = "ssh2.pcapng/15/JA4L-C"
	capabilityDecline["capability"] = true
	capabilityDecline["ours"] = ""

	entries, err := Parse(oneDeviationRegister(t, valueDecline, capabilityDecline))
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
	entries, err := Parse([]byte("[]\n"))
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
			if _, err := Parse(testCase.content); err == nil {
				t.Errorf("the reader accepts a register where %s", testCase.name)
			}
		})
	}
}
