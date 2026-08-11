---
id: ja4ls
feature: JA4LS
epic: "Epic 12: JA4LS"
status: planned
issues: []
mockups: []
---

## Purpose

JA4LS is the server form of the JA4L latency method. **This project does not implement
it.** `ja4l.go:198` sets `Type: "ja4l"` and the fingerprinter writes no second method
name.

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

- **FR-ja4ls-1** — `JA4LFingerprinter` emits a result whose `Type` is `ja4ls`.
- **FR-ja4ls-2** — The JA4LS value measures the server side of the connection.
- **FR-ja4ls-3** — The value holds two timing parts on a TCP connection, under
  FR-parity-19.
- **FR-ja4ls-4** — The value holds `quic` as a third part on a QUIC connection, under
  FR-parity-20.
- **FR-ja4ls-5** — The fingerprinter reports one JA4LS value for one connection.
- **FR-ja4ls-6** — A retransmitted SYN-ACK produces no second JA4LS value, under
  FR-parity-18.
- **FR-ja4ls-7** — The second part of the value is the hop count, read as the initial
  time-to-live minus the observed time-to-live.
- **FR-ja4ls-8** — The first part is the measured time divided by the propagation factor
  that the FoxIO hop-count table gives.
- **FR-ja4ls-9** — A connection that reaches no server measurement point produces no JA4LS
  value.

### The interface

- **FR-ja4ls-10** — `ComputeJA4LS` computes the JA4LS value for one connection, matching
  the shape of the existing `ComputeJA4L`.
- **FR-ja4ls-11** — `Processor` accepts `ja4ls` as a method name in its type filter.
- **FR-ja4ls-12** — `cmd/ja4plus` accepts `ja4ls` in `--types`.
- **FR-ja4ls-13** — `JA4LFingerprinter.CleanupConnection` clears the state that both
  methods read.
- **FR-ja4ls-14** — `JA4LFingerprinter.Reset` clears the results of both methods.

### The count

- **FR-ja4ls-15** — Every document that states a method count states eleven methods.
- **FR-ja4ls-16** — Every document that states a fingerprinter count states ten
  fingerprinters.
- **FR-ja4ls-17** — No document states a count of ten methods.
- **FR-ja4ls-18** — A test reads every tracked Markdown file and every Go doc comment, and
  fails when one states a count that FR-ja4ls-15 through FR-ja4ls-17 forbid.
- **FR-ja4ls-19** — The test names the file and the line of each violation.
- **FR-ja4ls-20** — `CLAUDE.md` states eleven methods and ten fingerprinters.

### Conformance

- **FR-ja4ls-21** — The conformance harness compares every published JA4LS value.
- **FR-ja4ls-22** — A JA4LS value that the harness cannot compare, because the reference
  file holds no key, carries a register entry under FR-parity-22.
- **FR-ja4ls-23** — `docs/specs/foxio/JA4L.md` states that no image specifies JA4LS, and
  names the sources that do.

## User flows

### An analyst reads both latency values

1. The analyst runs `ja4plus --types ja4l,ja4ls capture.pcap`.
2. The program prints one JA4L value and one JA4LS value per connection.
3. The analyst compares the two hop counts to tell which endpoint is distant.

### An engineer implements the method

1. The engineer reads `docs/specs/foxio/JA4L.md` and the two sources it names.
2. The engineer confirms that Epic 8 closed FR-parity-16 through FR-parity-21.
3. The engineer writes the conformance comparison first. It fails.
4. The engineer adds the emission. It passes.
5. The engineer runs the count test of FR-ja4ls-18 and repairs every document it names.

## Screens & states

The command-line output gains one line per connection. `mockups/02-cli-output.html` shows
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
| `ja4l.go` | Emits a second result. New `ComputeJA4LS`. |
| `ja4l_test.go` | New cases for the server value. |
| `processor.go` | `ja4ls` joins the type filter. |
| `cmd/ja4plus/main.go` | `ja4ls` joins `--types`. |
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
| The observed time-to-live exceeds the initial time-to-live. | The hop count is zero. The packet crossed no router the reader can count. |
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
5. `go test -run TestMethodCount ./...` passes, and no tracked document states ten
   methods.
6. `CLAUDE.md` states eleven methods and ten fingerprinters.
7. `docs/specs/foxio/JA4L.md` states that no FoxIO image specifies JA4LS.

## Out of scope

- A separate `JA4LSFingerprinter` type. One fingerprinter writes both methods.
- Changing the JA4L form. `features/08-python-parity.md` owns every JA4L ruling, and this
  feature set follows them.
- A twelfth method. `docs/specs/spec.md` `Non-goals` holds the reason for each name.

## Open questions

1. **Does `--types ja4l` alone print the JA4LS value?** The port emits both from one
   fingerprinter, and its type filter names ten fingerprinters rather than eleven methods.
   FR-ja4ls-11 and FR-ja4ls-12 make `ja4ls` its own filter token here, which is the more
   useful behaviour and the one that differs from the port. **The maintainer rules, and
   the ruling lands in both repositories.**
2. **Does the freeze make FR-ja4ls-10 worth adding?** `ComputeJA4LS` matches the existing
   convenience functions, and every exported name added now is frozen at `v1.0.0`.
