---
id: ja4ls
feature: JA4LS
epic: "Epic 12: JA4LS"
status: issued
issues: [59, 60, 61, 62, 63]
mockups: []
---

## Purpose

JA4LS is the server form of the JA4L latency method. **This project emits the value, and
it emits no second type.** `ja4l.go:183` and `ja4l.go:381` each write a `JA4L-S=` label, and
`ja4l.go:493` writes `Type: "ja4l"` for every result of the fingerprinter.

**This section read `This project does not implement it` and cited `ja4l.go:198` until
2026-08-13, and both statements were wrong.** `ja4l.go:198` holds `return nil, nil`. The
maintainer ruled on 2026-08-13, in issue #60, that the result keeps `Type: "ja4l"`, and
`## Behaviour rules` below states the label rule the reader uses to tell the two apart.

Round 2 of this spec listed JA4LS as a non-goal, under a bullet that grouped it with JA4E,
JA4SScan and JA4TScan. **That grouping was wrong.** JA4LS is a defined method with
published reference values. The other three are names in a license list. The maintainer
ruled on 2026-08-11 that a capability Go can achieve is in scope, and this is one.

The port implements it. `JA4LFingerprinter` there writes both JA4L and JA4LS, so ten
fingerprinter classes carry eleven methods. This feature set builds the same shape here.

## The source problem this feature set must solve first

**No FoxIO image specifies JA4LS.** The port's issue #200 established this. `JA4L.png`
titles itself `JA4L: Light Distance/Location Fingerprint`, it labels its one example
`JA4L=`, and it states no server rule. `technical_details/` holds no `JA4LS.png` and no
`JA4LS.md`.

**The rules therefore come from the reference implementations alone**, and the
implementations disagree with each other on two points that `features/08-python-parity.md`
already settles for JA4L: the part count and the protocol marker. JA4LS follows the same
rulings, because one fingerprinter writes both values and a reader compares them side by
side.

This is why Epic 12 depends on Epic 8. The JA4L rows decide the form before JA4LS writes
it.

## User stories

- As a user who runs both libraries, I want `ja4plus-go` to report a JA4LS value where
  `ja4plus` reports one, so that the two outputs match.
- As an analyst, I want the server latency of a connection as well as the client latency,
  so that I can tell which side is distant.
- As a library author, I want `JA4LFingerprinter` to return both values from one call, so
  that I do not construct a second fingerprinter.
- As a maintainer, I want every document that states a method count to state the same
  count, so that a reader is not told two numbers.

## Functional requirements

### The method

**The maintainer ruled FR-ja4ls-1 on 2026-08-13**, and the ruling is recorded at
https://github.com/Crank-Git/ja4plus-go/issues/60#issuecomment-5275948279. The requirement was
wrong, and the code
was right. It read `JA4LFingerprinter` emits a result whose `Type` is `ja4ls` before that
ruling. `ja4l.go:183` and `ja4l.go:381` each emit the server value today, and `ja4l.go:493`
writes `Type: "ja4l"` for every result. `## Behaviour rules` below states that JA4LS reaches
no type of its own, so the file contradicted itself. `ja4plus/processor.py:106` at `v1.1.0`
registers `("ja4l", JA4LFingerprinter)`, so the port writes one type for both methods. The
`Type` field is part of the surface that `v1.0.0` freezes. #60 records the measurement.

**FR-ja4ls-7 and FR-ja4ls-8 carry a PROVISIONAL ruling of #60, made on 2026-08-13.**
`.claude/rules/rulings.md` `## What a delegated session may rule` governs it. Each
requirement asked for a value that no FoxIO implementation writes, and the code already
agrees with the reference. `docs/specs/foxio/JA4L.md` R13 at :90-92 states that part b holds
the value the packet carries. R18 at :114-116 states that no implementation writes an
estimated hop count. R6 at :57-61 states that four implementations divide by 2, and R22 at
:137-139 states that no implementation computes a distance. The propagation factor belongs
to the distance formula of R19, which `CalculateDistance` holds and no fingerprint reads.
**The maintainer confirms both rulings or reverses them, and #60 is the reversal path.**
Neither amendment changes code, and `ja4ls_emission_test.go` holds each one as a test.

- **FR-ja4ls-1** — `JA4LFingerprinter` emits the JA4LS value in a result whose `Type` is
  `ja4l`. The `JA4L-S=` label of the fingerprint names the method.
- **FR-ja4ls-2** — The JA4LS value measures the server side of the connection.
- **FR-ja4ls-3** — The value holds two timing parts on a TCP connection, under
  FR-parity-19.
- **FR-ja4ls-4** — The value holds `quic` as a third part on a QUIC connection, under
  FR-parity-20.
- **FR-ja4ls-5** — The fingerprinter reports one JA4LS value for one connection.
- **FR-ja4ls-6** — A retransmitted SYN-ACK produces no second JA4LS value, under
  FR-parity-18.
- **FR-ja4ls-7** — The second part of the value holds the time-to-live that the server
  SYN-ACK carries. The value writes that number unchanged.
- **FR-ja4ls-8** — The first part is half of the interval between the two measurement
  points. No propagation factor reaches the value.
- **FR-ja4ls-9** — A connection that reaches no server measurement point produces no JA4LS
  value.

### The interface

- **FR-ja4ls-10** — `ComputeJA4LS` computes the JA4LS value for one connection. It matches
  the shape of `ComputeJA4T`, which is a one-shot function. **This library exports no
  `ComputeJA4L`.** The maintainer ruled #356 on 2026-08-13, and
  `parity_one_shot_not_applicable_test.go:32-35` holds that ruling as a test. **Open
  question 2 below asks whether this requirement is worth building, and the maintainer
  answers it.** **This requirement is unbuildable today, and that is deliberate.**
  `terms_one_shot_function_test.go` makes `ComputeJA4LS` a red build, so the tree holds a
  requirement that its own guard blocks. **The cross-member review of batch #391 reported
  that pair, and the project manager resolved neither half**, because #356 named JA4L and
  JA4SSH and it named no JA4LS. **The maintainer answers open question 2, and the two places
  to change are the `multi-packet method` row of the `## Terms` table and that test.**
- **FR-ja4ls-11** — **Provisional, and the reversal path is issue #61.** #61 measured that
  `Processor` holds no type filter at all, so the requirement as written named a surface that
  does not exist. `Processor` returns the result of every method, and the caller selects
  the methods it reads.
- **FR-ja4ls-12** — `cmd/ja4plus` accepts `ja4ls` in `--types`, and that token selects the
  JA4LS value alone.
- **FR-ja4ls-12a** — `cmd/ja4plus` accepts `ja4l` in `--types`, and that token selects the
  JA4L value and the JA4LS value.
- **FR-ja4ls-12b** — `cmd/ja4plus` returns an error for a `--types` token that names no
  method, and the error names every token the command accepts.
- **FR-ja4ls-13** — `JA4LFingerprinter.CleanupConnection` clears the state that both
  methods read.
- **FR-ja4ls-14** — `JA4LFingerprinter.Reset` clears the results of both methods.

**FR-ja4ls-11 read that `Processor` accepts `ja4ls` in its type filter, and #61 measured
that `Processor` holds no type filter.** `processor.go` runs every fingerprinter and returns
every result, and `cmd/ja4plus/main.go` holds the one filter of this repository. A filter on
`Processor` would add an exported method, which `v1.0.0` then freezes, and
`sync_processor_test.go:59` holds the signature set that such a method changes. **The
requirement therefore states what the library does**, and FR-ja4ls-12 states the filter.

### The count

- **FR-ja4ls-15** — Every document that states a method count states eleven methods.
- **FR-ja4ls-16** — Every document that states a fingerprinter count states ten
  fingerprinters.
- **FR-ja4ls-17** — No document applies the count of ten to methods.
- **FR-ja4ls-18** — A test reads every tracked Markdown file, every tracked HTML file and
  every Go comment. It fails when one applies the count of ten to methods, or the count of
  eleven to fingerprinters.
- **FR-ja4ls-19** — The test names the file and the line of each violation.
- **FR-ja4ls-20** — `CLAUDE.md` states eleven methods and ten fingerprinters.

### Conformance

- **FR-ja4ls-21** — The conformance harness compares every published JA4LS value.
- **FR-ja4ls-22** — A per-stream JA4LS value that the harness cannot compare, because the
  reference file holds no key, carries a register entry under FR-parity-22.
- **FR-ja4ls-23** — `docs/specs/foxio/JA4L.md` states that no image specifies JA4LS, and
  names the sources that do.

**FR-ja4ls-22 carries a PROVISIONAL scope decision of #63, made on 2026-08-13.** The
requirement named both vector sets before that decision. **The decision is a scope decision
and never a ruling.** It writes no register entry, and it states no rule about a fingerprint
value, so it reaches nothing that `.claude/rules/rulings.md` reserves to the maintainer.

**A reading explains the per-stream set, and no reading explains the per-packet set.**
`python/ja4.py:340` at the pin holds `delete_keys(['JA4L-S', 'JA4L-C'], final)`, under the
guard `if 'ja4l' not in output_types:` at :339. That pair states why a per-stream reference
file publishes no JA4L key. Ruling #361 registered 24 such uncovered values on 2026-08-13,
and each entry names #361. **No reading covers the Wireshark generator.**

**#376 owns the uncovered per-packet JA4LS values, and #376 is open at `status:ready`.** Its
body states `Write no register entry until the cause is read.` A later issue writes those
entries once #376 reads why the Wireshark generator publishes no JA4L key. **#376 records
that an uncovered value fails no gate.** The run of #63 counts 33 uncovered per-packet JA4LS
values, and the register accepts none of them. **Read that sentence with the two spellings in
mind.** The register spells the method `JA4L-S`, and it holds 24 such per-stream keys under
ruling #361. **It holds no per-packet key for the method under either spelling**, and those 33
values are the ones #376 owns.

**This slice adds no entry to `testdata/deviations.json`.** The register holds 449 entries
before this slice, and 449 after it.

**The reversal path is issue comment 5276074116 of #63.** The maintainer reverses this scope
by a ruling, and that ruling restores the per-packet set to FR-ja4ls-22.

## User flows

### An analyst reads both latency values

1. The analyst runs `ja4plus --types ja4l,ja4ls capture.pcap`.
2. The program prints one JA4L value and one JA4LS value per connection.
3. The analyst compares the two time-to-live values to tell which endpoint is distant.

### An engineer implements the method

1. The engineer reads `docs/specs/foxio/JA4L.md` and the two sources it names.
2. The engineer confirms that Epic 8 closed FR-parity-16 through FR-parity-21.
3. The engineer writes the conformance comparison first. It fails.
4. The engineer adds the emission. It passes.
5. The engineer runs the count test of FR-ja4ls-18 and repairs every document it names.

## Screens & states

The command-line output gains one line per connection. **`mockups/02-cli-output.html` holds a
`JA4L-S=` row from 2026-08-13.** It shows
the shape, and Epic 12 updates that mockup to hold a `ja4ls` row.

## Behaviour rules

- **One fingerprinter writes two methods.** JA4LS gets no type of its own. A second type
  would double the state table and split one connection across two owners.
- **Ten is a count of fingerprinters and never a count of methods.** A document that
  writes "ten methods" is wrong after this epic, and FR-ja4ls-18 makes that a red build.
- **JA4LS follows every JA4L ruling.** A ruling that moves one value moves the other. A
  reader compares them side by side, so a divergence between them would read as a defect.
- **No image specifies JA4LS**, so every rule cites a reference implementation.

## Data touched

| File | Change |
|---|---|
| `ja4l.go` | Emits a second result. **`ComputeJA4LS` is not built**, because open question 2 below asks whether to add it and `terms_one_shot_function_test.go` makes the name a red build until the maintainer answers. |
| `ja4l_test.go` | New cases for the server value. |
| `processor.go` | No change. It holds no type filter. |
| `cmd/ja4plus/types.go` | New. The token list, the parse and the selection. |
| `cmd/ja4plus/main.go` | `--types` reads the token list, and it refuses an unknown token. |
| `conformance_test.go` | The JA4LS comparison. |
| `docs/specs/foxio/JA4L.md` | Records that no image specifies JA4LS. |
| `README.md`, `CLAUDE.md`, `docs/` | The method count. |
| `method_count_test.go` | New. FR-ja4ls-18. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| FoxIO Wireshark dissector | The commit in `testdata/foxio.pin` | <https://github.com/FoxIO-LLC/ja4/tree/main/wireshark> |
| FoxIO Zeek package | The same commit | <https://github.com/FoxIO-LLC/ja4/tree/main/zeek> |
| FoxIO per-packet vectors | The same commit | <https://github.com/FoxIO-LLC/ja4/tree/main/wireshark/test/testdata> |

**The Wireshark test data is the primary reference for this method.** It publishes 44
`ja4.ja4ls` values. `docs/specs/foxio/zeek.md` declines the Zeek JA4LS values as reference
values, under the rule that the port's `.claude/rules/external-apis.md` states.

## Edge cases & failures

| Case | Expected behaviour |
|---|---|
| The connection carries no SYN-ACK. | No JA4LS value. FR-ja4ls-9 covers it. |
| The observed time-to-live carries any value the packet holds. | The value writes that number unchanged. **No branch computes a hop count**, which amended FR-ja4ls-7 states and which `docs/specs/foxio/JA4L.md` R13 and R18 record. |
| The server measurement point is set and the client one is not. | The JA4LS value is emitted and the JA4L value is not. The two are independent. |
| A QUIC connection reaches a server measurement point. | The value carries `quic` as a third part. |
| A document states "ten JA4+ methods". | FR-ja4ls-18 fails and names the file and the line. |
| The reference file for a capture holds `ja4.ja4ls` and this project emits nothing. | A conformance deviation. It is a defect, not a register entry, unless a ruling says otherwise. |

## Acceptance criteria

1. `ja4plus --types ja4ls` prints a JA4LS value for a capture that holds a TCP handshake.
2. The conformance suite compares every published JA4LS value and reports no deviation
   that the register does not hold.
3. A capture with two SYN-ACK packets produces one JA4LS value.
4. A QUIC capture produces a JA4LS value whose third part is `quic`.
5. `go test -run TestMethodCount ./...` passes, and no tracked document applies the count
   of ten to methods.
6. `CLAUDE.md` states eleven methods and ten fingerprinters.
7. `docs/specs/foxio/JA4L.md` states that no FoxIO image specifies JA4LS.

## Out of scope

- A separate `JA4LSFingerprinter` type. One fingerprinter writes both methods.
- Changing the JA4L form. `features/08-python-parity.md` owns every JA4L ruling, and this
  feature set follows them.
- A twelfth method. `docs/specs/spec.md` `Non-goals` holds the reason for each name.

## Open questions

1. ~~**Does `--types ja4l` alone print the JA4LS value?**~~ **Closed. The maintainer ruled
   it on 2026-08-13, and #61 records the ruling.** `--types ja4l` prints the JA4L value and
   the JA4LS value. `--types ja4ls` prints the JA4LS value alone. **The ruling is a superset
   over the port, and no fingerprint value moves.** `Crank-Git/ja4plus#605` proposes the
   same token for the port. R9 question 3 of `docs/specs/spec.md` records the closure.
2. **Does the freeze make FR-ja4ls-10 worth adding?** `ComputeJA4LS` matches the shape of
   the one-shot functions this library exports, and every exported name added now is frozen
   at `v1.0.0`. **The ruling of #356 bears on the answer.** #356 declined a one-shot
   function for JA4L, because JA4L reads the SYN and the SYN-ACK. JA4LS reads the same
   connection state. **The maintainer rules this question, and #373 records the connection
   alone.**
