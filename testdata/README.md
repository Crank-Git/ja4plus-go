# The test data of this repository

This directory holds the register, the corpus pin and the fixtures the tests read.

| Path | Holds | Tracked |
|---|---|---|
| `deviations.json` | The register. One entry for each accepted difference from a FoxIO value. | Yes |
| `foxio.pin` | The FoxIO commit that `make corpus` fetches. | Yes |
| `foxio-license-1.1.txt` | The FoxIO License 1.1 text that the license tests read. | Yes |
| `http1-with-cookies.expected.json` | One expected-output fixture. | Yes |
| `foxio/` | The fetched FoxIO corpus. It is FoxIO-licensed material. | No |

## The register

`deviations.json` holds a JSON array. **The array is empty today**, because no conformance
run has measured a deviation. `docs/specs/features/11-foxio-reference.md` FR-reference-19
through FR-reference-24 state the file and the schema, and `deviations_test.go` holds them.

**An entry records a ruling, and only the maintainer makes one.** Read
`.claude/rules/rulings.md` before you add an entry. Never write an entry for a difference
that no conformance run measured, and never write a placeholder.

**An entry is an accepted difference, not a hidden failure.** The conformance suite fails
when an entry names a comparison that now matches. #33 builds that suite, and
FR-reference-25 and FR-reference-26 land with it.

### The schema

Each entry is a JSON object that holds six fields, and no other field.

| Field | Type | Meaning |
|---|---|---|
| `key` | string | The capture, the stream and the method, written `<capture>/<stream>/<method>`. |
| `capability` | boolean | `true` for a capability decline. `false` for a value decline. |
| `ours` | string | The value this library produces. A capability decline holds the empty string here. |
| `theirs` | string | The value the FoxIO reference produces. |
| `ruling` | string | The issue that holds the ruling, written `#<number>`. |
| `reason` | string | One sentence that states why this project declines the value. |

`docs/specs/spec.md` `## Terms` defines the words `value decline` and `capability
decline`.

### One entry

```json
[
  {
    "key": "ssh2.pcapng/15/JA4L-S",
    "capability": false,
    "ours": "6252_58",
    "theirs": "6252_58",
    "ruling": "#19",
    "reason": "The FoxIO implementations disagree, and the maintainer ruled on the value."
  }
]
```

**That example is not a register entry.** It shows the form, and the register holds no
entry.
