# The test data of this repository

This directory holds the register, the corpus pin and the fixtures the tests read.

| Path | Holds | Tracked |
|---|---|---|
| `deviations.json` | The register. One entry for each accepted difference from a FoxIO value. | Yes |
| `foxio.pin` | The FoxIO commit that `make corpus` fetches. | Yes |
| `foxio-license-1.1.txt` | The FoxIO License 1.1 text that the license tests read. | Yes |
| `foxio/` | The fetched FoxIO corpus. It is FoxIO-licensed material. | No |

**This directory holds no expected-output fixture.**
`docs/specs/features/04-conformance-harness.md` passes that role to the corpus, and the
conformance suite compares every value against the FoxIO vector. Never add a second source
for an expected value.

## The register

`deviations.json` holds a JSON array. **Each entry records one ruling that a conformance
run measured.** `docs/specs/features/11-foxio-reference.md` FR-reference-19 through
FR-reference-24 state the file and the schema, and `internal/repocheck/deviations_test.go` holds them.

**An entry records a ruling, and only the maintainer makes one.** Read
`.claude/rules/rulings.md` before you add an entry. Never write an entry for a difference
that no conformance run measured. Never write a placeholder.

**An entry is an accepted difference, not a hidden failure.** The conformance suite fails
when an entry names a comparison that now matches. #33 builds that suite, and
FR-reference-25 and FR-reference-26 land with it.

### The schema

Each entry is a JSON object that holds six fields, and no other field.

| Field | Type | Meaning |
|---|---|---|
| `key` | string | The capture, the stream and the method, written `<capture>/<stream>/<method>`. **The middle part holds a stream name, an endpoint key or a frame number.** The section below states which. |
| `capability` | boolean | `true` for a capability decline. `false` for a value decline. |
| `ours` | string | The value this library produces. A capability decline holds the empty string here. |
| `theirs` | string | The value the FoxIO reference produces. |
| `ruling` | string | The issue that holds the ruling, written `#<number>`. |
| `reason` | string | One sentence that states why this project declines the value. |

`docs/specs/spec.md` `## Terms` defines the words `value decline` and `capability
decline`.

### The middle part of the key

**The middle part names whichever thing the comparison names.** The conformance suite
compares two vector sets, and each set names a value differently. The middle part therefore
holds one of four things.

| Set | The middle part holds | One key |
|---|---|---|
| The per-stream set, under `foxio/python/` | The stream number of the vector entry. | `ssh2.pcapng/33/JA4L-S` |
| The per-stream set, where one stream number names more than one connection | The stream number and the source port, written `<stream>:<srcport>`. | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-C` |
| The per-stream set, where no vector entry names the connection | The endpoint key, written `<src>:<srcport>-<dst>:<dstport>` with the two endpoints sorted. | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4` |
| The per-packet set, under `foxio/wireshark/` | The frame number of the vector record, counted from 1. | `badcurveball.pcap/4/JA4L.1` |

**A stream number and a frame number read alike, because both are small integers.** Before
you read the middle part of an entry, read the vector set that holds the value. An endpoint
key holds no `/`, so a key of any of the four forms still reads in three parts.

**A stream number names no connection on its own.** `tcp.stream` and `udp.stream` are two
counters, and both start at 0, so one capture names a TCP connection and a UDP connection
with the stream number `0`. The second form above keeps such a pair apart, and it reaches
the colliding stream number alone. `conformanceStreamNames` of
`conformance_adapters_test.go` writes the name, and issue #250 holds the reading.

**One key names one comparison.** The suite reads one register for both sets, so a key that
named a comparison in each set would accept a difference the maintainer never ruled on.
FR-reference-30 fails the suite for such a key, and
`conformance_key_kind_test.go` holds that test. FR-reference-31 gives one entry to one key,
and `internal/repocheck/deviations_test.go` holds it.

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

**That example is not a register entry.** It shows the form, and the register holds no entry
for that key.
