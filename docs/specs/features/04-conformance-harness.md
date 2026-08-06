---
id: conformance-harness
feature: Conformance harness
epic: "Epic 4: Conformance harness"
status: planned
issues: []
mockups: [mockups/01-conformance-report.html]
---

## Purpose

The library claims to implement the FoxIO specification. Nothing tests that claim. The
repository holds one expected-output file, `testdata/http1-with-cookies.expected.json`,
covering two methods on one capture.

FoxIO publishes a corpus. It holds 38 captures, 37 per-stream vectors under
`python/test/testdata/`, and 37 per-packet vectors under `wireshark/test/testdata/`. The
two vector sets cover different methods, so the harness needs both.

This feature set fetches the corpus and tests every method against it. It produces the
deviation list that Epic 5 closes.

## User stories

- As a maintainer, I want a single command that tells me whether the library matches
  FoxIO, so that I know before I release.
- As a maintainer, I want a report that names each deviation, so that I can turn it into
  work.
- As a library author, I want CI to fail when a change breaks conformance, so that a
  regression cannot reach a release.
- As a contributor, I want the corpus to fetch with one command, so that I can run the
  suite locally.

## Functional requirements

### The fetch

- **FR-conformance-1** — The repository holds `testdata/foxio.pin`, which names one
  FoxIO commit.
- **FR-conformance-2** — `scripts/fetch-corpus.sh` fetches the FoxIO repository at the
  commit in `testdata/foxio.pin`.
- **FR-conformance-3** — The script writes the captures to `testdata/foxio/pcap/`.
- **FR-conformance-4** — The script writes the per-stream vectors to
  `testdata/foxio/python/`.
- **FR-conformance-5** — The script writes the per-packet vectors to
  `testdata/foxio/wireshark/`.
- **FR-conformance-6** — The script downloads nothing when the corpus is present and the
  pin has not changed.
- **FR-conformance-7** — The script records the fetched commit in
  `testdata/foxio/.fetched`.
- **FR-conformance-8** — `.gitignore` ignores `testdata/foxio/`.
- **FR-conformance-9** — The script fails with a message that names the network when it
  cannot reach the reference.

### The harness

- **FR-conformance-10** — The conformance suite builds only with the `conformance` build
  tag.
- **FR-conformance-11** — The suite skips with a message that names `make corpus` when
  `testdata/foxio/` is absent.
- **FR-conformance-12** — The suite reads every capture in `testdata/foxio/pcap/`.
- **FR-conformance-13** — The suite reads the per-stream vector for a capture when one
  exists.
- **FR-conformance-14** — The suite reads the per-packet vector for a capture when one
  exists.
- **FR-conformance-15** — The suite runs one `Processor` over every packet in a capture,
  in capture order.
- **FR-conformance-16** — The suite compares the library output with the vector as an
  exact string match.
- **FR-conformance-17** — The suite reports a deviation when the library produces a
  fingerprint that the vector does not hold.
- **FR-conformance-18** — The suite reports a deviation when the vector holds a
  fingerprint that the library does not produce.
- **FR-conformance-19** — The suite reports a deviation when the two fingerprints differ
  by any character.

### The vector adapters

- **FR-conformance-20** — The per-stream adapter reads the keys `JA4.1`, `JA4_r.1`,
  `JA4_o.1` and `JA4_ro.1` and maps each to the matching `FingerprintResult` field.
- **FR-conformance-21** — The per-stream adapter reads the keys for JA4S, JA4H, JA4X and
  JA4SSH in the same way.
- **FR-conformance-22** — The per-stream adapter matches a stream by the `src`, `dst`,
  `srcport` and `dstport` fields.
- **FR-conformance-23** — The per-packet adapter reads the `ja4.*` fields under
  `_source.layers` and maps each to a method.
- **FR-conformance-24** — The per-packet adapter matches a packet by the
  `frame.number` field.
- **FR-conformance-25** — The per-packet adapter is authoritative for JA4D and JA4D6,
  because the per-stream vector for `dhcpv6.pcap` is an empty list.
- **FR-conformance-26** — An adapter fails the test when it meets a vector key that it
  does not recognize. It does not skip the key.

### The report

- **FR-conformance-27** — The suite writes `docs/audit/conformance.md` on every run.
- **FR-conformance-28** — The report holds one row for each capture and each method.
- **FR-conformance-29** — Each row records `match`, `deviation` or `not applicable`.
- **FR-conformance-30** — The report names the fetched FoxIO commit.
- **FR-conformance-31** — The report names the count of captures, the count of matches
  and the count of deviations.
- **FR-conformance-32** — Each deviation row records the expected value and the produced
  value.
- **FR-conformance-33** — A row records `not applicable` only when the vector holds no
  value for that method on that capture.

### The gate

- **FR-conformance-34** — `.github/workflows/ci.yml` runs the conformance suite on every
  pull request.
- **FR-conformance-35** — The CI job fails when the suite reports any deviation.
- **FR-conformance-36** — The CI job fails when the suite skips.
- **FR-conformance-37** — The CI job caches the corpus by the pinned commit.

## User flows

### A contributor runs conformance locally

1. Run `make corpus`. The script fetches the corpus at the pinned commit.
2. Run `make conformance`. The suite runs every capture.
3. The suite writes `docs/audit/conformance.md`.
4. The contributor reads the deviation rows.

### CI gates a pull request

1. The workflow restores the corpus from the cache, keyed by the pinned commit.
2. The workflow runs `make corpus` when the cache misses.
3. The workflow runs `make conformance`.
4. The job fails when the suite reports a deviation.
5. The job attaches `docs/audit/conformance.md` as an artifact.

### The maintainer moves the pin

1. The maintainer changes `testdata/foxio.pin` to a newer FoxIO commit.
2. The maintainer runs `make corpus`. The script fetches the new corpus.
3. The maintainer runs `make conformance`.
4. A new deviation means that FoxIO changed a definition. The maintainer opens an issue.

## Screens & states

The conformance report is the only reader-facing output. `mockups/01-conformance-report.html`
shows its intended shape as a rendered page.

| State | What it shows |
|---|---|
| All match | A summary line, and one table with every row marked `match`. |
| Deviations present | A summary line with the deviation count, a deviation table first, then the full table. |
| Corpus absent | A single message that names `make corpus`. |

## Behaviour rules

- The comparison is an exact string match. A case difference is a deviation. A whitespace
  difference is a deviation.
- The suite compares only the methods that a vector holds. A capture with no JA4H vector
  produces no JA4H row.
- The suite does not sort the library output before it compares. Order is part of the
  result for the per-packet vectors.
- The suite runs one `Processor` per capture, and calls `Reset` between captures.
- The report is regenerated on every run and is committed. A stale report is worse than
  none.
- The pin moves only in a commit that does nothing else.

## Data touched

No entity changes. The following files change.

| File | Change |
|---|---|
| `testdata/foxio.pin` | New. Holds one commit. |
| `scripts/fetch-corpus.sh` | New. |
| `conformance_test.go` | New. Carries the `conformance` build tag. |
| `conformance_adapters.go` | New. Holds the two vector adapters. |
| `docs/audit/conformance.md` | New. Regenerated on every run. |
| `.gitignore` | Keeps `testdata/foxio/`. |
| `.github/workflows/ci.yml` | Gains the conformance job. |
| `scripts/gen_expected.py` | Removed. Its role passes to the corpus. |
| `testdata/http1-with-cookies.expected.json` | Removed. The corpus replaces it. |
| `integration_test.go` | Changed to read the corpus, or removed. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| FoxIO reference repository | Pinned in `testdata/foxio.pin` | <https://github.com/FoxIO-LLC/ja4> |
| FoxIO per-stream vectors | At the pinned commit | <https://github.com/FoxIO-LLC/ja4/tree/main/python/test/testdata> |
| FoxIO per-packet vectors | At the pinned commit | <https://github.com/FoxIO-LLC/ja4/tree/main/wireshark/test/testdata> |
| `actions/cache` | v4 | <https://github.com/actions/cache> |

### The per-stream vector shape

Read from `python/test/testdata/tls12.pcap.json` at commit `27f0cbf`:

```json
[
    {
        "stream": 0,
        "src": "192.168.133.129",
        "dst": "34.117.237.239",
        "srcport": "36372",
        "dstport": "443",
        "domain": "contile.services.mozilla.com",
        "JA4.1": "t13d1715h2_5b57614c22b0_3d5424432f57",
        "JA4_r.1": "t13d1715h2_002f,0035,...",
        "JA4_o.1": "t13d1715h2_5b234860e130_014157ec0da2",
        "JA4_ro.1": "t13d1715h2_1301,1303,..."
    }
]
```

The `.1` suffix counts the occurrence within the stream. A stream with two client hellos
carries `JA4.1` and `JA4.2`.

### The per-packet vector shape

Read from `wireshark/test/testdata/dhcp.pcapng.json` at commit `27f0cbf`:

```json
[
  {
    "_source": {
      "layers": {
        "frame.number": ["1"],
        "ja4.ja4d": ["disco0000in_61-55_1-3-6-42"]
      }
    }
  }
]
```

## Edge cases & failures

| Case | What happens |
|---|---|
| A capture has no vector in either set. | The suite records every method as `not applicable` and does not fail. |
| A per-stream vector holds an empty list. | The suite records `not applicable` for that capture in the per-stream set, and reads the per-packet set. |
| The library produces a fingerprint for a stream that the vector does not name. | The suite reports a deviation. An extra fingerprint is as wrong as a missing one. |
| A capture is larger than 1 MB. | The suite still runs it. `http2-with-cookies.pcapng` is 1.9 MB and `ssh-scp-1050.pcap` is 1.1 MB. |
| The capture is `dtls-udp.notest.cap`. | FoxIO marks it `notest`. The suite records it as `not applicable` and names the marker as the reason. |
| The FoxIO commit in the pin no longer exists. | `make corpus` fails and names the commit. The maintainer moves the pin. |
| Two vector sets disagree for one method on one capture. | The suite reports a deviation against both and names the disagreement. The FoxIO Wireshark plugin decides. |

## Acceptance criteria

- [ ] `make corpus` fetches 38 captures into `testdata/foxio/pcap/`.
- [ ] `make corpus` fetches 37 per-stream vectors and 37 per-packet vectors.
- [ ] A second `make corpus` downloads nothing.
- [ ] `testdata/foxio/.fetched` holds the commit from `testdata/foxio.pin`.
- [ ] `go test ./...` without the `conformance` tag does not build the suite.
- [ ] `make conformance` without a corpus prints a message that names `make corpus`.
- [ ] `make conformance` with a corpus writes `docs/audit/conformance.md`.
- [ ] The report holds a row for every capture and every method.
- [ ] The report names the fetched FoxIO commit.
- [ ] The report summary names the count of captures, matches and deviations.
- [ ] Every deviation row holds the expected value and the produced value.
- [ ] The suite reports a deviation when a fingerprint is deliberately changed by one
      character in a test.
- [ ] The CI conformance job fails when the suite reports a deviation.
- [ ] The CI conformance job fails when the corpus is absent.
- [ ] `scripts/gen_expected.py` is removed.

## Out of scope

- This feature set does not close a deviation. Epic 5 does that.
- This feature set does not implement tunnel decapsulation. Epic 5 does that.
- This feature set does not read pcapng Decryption Secrets Blocks. Epic 5 does that.
- This feature set does not commit the corpus. Risk R1 in `../spec.md` records why.
- This feature set does not test the Python port. Epic 8 does that.

## Open questions

None. Risk R3 in `../spec.md` records that Epic 5 cannot be sized until this feature set
produces the deviation list.
