---
id: python-parity
feature: Parity with the port
epic: "Epic 8: Parity with the port"
status: issued
issues: [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58]
mockups: []
---

## Purpose

The maintainer owns a second implementation, `Crank-Git/ja4plus`, written in Python. It is
at version `v1.1.0`. A user who runs both must get one answer.

**The port shipped first and it ruled first.** Between 2026-08-07 and 2026-08-11 it
settled about thirty questions that FoxIO leaves open, and it recorded each one with a
measurement in a closed issue. Its own spec holds the register that carries them, and
about twenty rows end with a sentence of the form "The port must X, or the two
implementations disagree on Y". In that sentence "the port" names this repository.

**This feature set closes those rows.** It re-litigates none of them. Each ruling carries
a measurement the port already took, and this project re-measures one only when a Go fact
contradicts it.

The `Parity with ja4plus` section of `docs/specs/spec.md` holds the register. This file
turns each row into a numbered requirement.

## What round 3 deleted, and why

Round 2 of this file held FR-parity-8 through FR-parity-14. Those seven requirements
specified a test that runs the Python library over the corpus and compares the two outputs
as strings.

**The port rejected that design in its own parity rule 3**, and this project adopts the
rejection. The rule reads: "No test in this repository builds, runs, or imports the port.
A cross-language test rig couples two repositories that move at different speeds, and it
fails for reasons that have nothing to do with the change under test."

The shared FoxIO vector set is the gate instead. Both repositories read the same vectors
at the same pinned commit. Two implementations that each match the reference match each
other, and neither one needs the other installed to prove it.

## User stories

- As a user who runs both libraries, I want the same packet to produce the same
  fingerprint, so that I can compare results across the two.
- As a user who moves from Python to Go, I want a familiar interface, so that I do not
  relearn the library.
- As a maintainer, I want each ruling to carry a test, so that a later change cannot
  reverse one without a red build.
- As an engineer, I want a written reason beside each accepted difference, so that I do
  not re-open a question the maintainer already settled.

## Functional requirements

### The general rule

- **FR-parity-1** — Each requirement below names the port issue that holds its ruling.
- **FR-parity-2** — A requirement that no FoxIO vector separates carries a test that
  builds the separating packet.
- **FR-parity-3** — A test that holds a ruling fails when the ruling is reversed.
- **FR-parity-4** — No test in this repository builds, runs or imports the port.
- **FR-parity-5** — The project records a table at `docs/parity.md` that names the port
  version each row was read from.
- **FR-parity-6** — `docs/parity.md` holds one row for each exported name of the port.
- **FR-parity-7** — Each row of `docs/parity.md` records the Go equivalent, or records
  `none` with `applicable` or `not applicable` and one sentence of reason.

### JA4 and JA4S: the ALPN form

The port's issues #127, #141, #162 and #522 hold these rulings. The FoxIO references
disagree with each other, and each one reads its own tooling rather than the packet.

**The maintainer ruled the condition of FR-parity-8 and FR-parity-9 on 2026-08-12.** Each
one read `not alphanumeric` before that ruling, and the FoxIO measurement contradicts that
test. **Both FoxIO implementations pass a printable ASCII byte through**, whether or not
that byte is alphanumeric, so `\x20\x61` reads ` a` in each one. Parity rule 1 gives the
behavior to FoxIO, so the requirement was wrong and the code was right. #50 records the
measurement, and `Crank-Git/ja4plus#601` closes the same wording on the port side.

- **FR-parity-8** — When the first byte of the first ALPN value falls outside the printable
  ASCII range `0x20-0x7E`, the ALPN field writes `99`.
- **FR-parity-9** — When the last byte of the first ALPN value falls outside the printable
  ASCII range `0x20-0x7E`, the ALPN field writes `99`. **The last byte is the one position
  other than the first that the field reads.** A byte outside the range in a middle position
  writes no character. The first ALPN value `\x30\xab\xcd\x31` writes `01`.
- **FR-parity-10** — When the first ALPN value holds one alphanumeric byte, the ALPN field
  repeats the byte and writes `hh`. **This requirement keeps the alphanumeric test**, because
  the two FoxIO implementations dispute every one-byte value. When a one-byte value falls
  outside the alphanumeric ranges, the field writes `99`.
- **FR-parity-11** — A test builds one packet for each of FR-parity-8, FR-parity-9 and
  FR-parity-10, and asserts the value.
- **FR-parity-12** — `docs/specs/foxio/JA4.md` records that FoxIO Python writes `U+FFFD`
  and FoxIO Rust writes the `tshark` escape text, and that neither value reads a byte the
  packet holds.

### JA4 and JA4S: the plausibility guard

- **FR-parity-13** — The library holds no plausibility guard. A structurally valid
  ClientHello produces a fingerprint whatever its body holds.
- **FR-parity-14** — A test asserts that a ClientHello with no cipher suite and no
  extension produces a well-formed fingerprint.
- **FR-parity-15** — A test asserts that a ClientHello with the version token `00`
  produces a well-formed fingerprint.

### JA4L and JA4LS

The port's issues #156, #200, #225 and #272 hold these rulings. `features/12-ja4ls.md`
builds the method itself.

- **FR-parity-16** — `JA4LFingerprinter` reports one client value for one connection.
- **FR-parity-17** — `JA4LFingerprinter` reports one server value for one connection.
- **FR-parity-18** — A retransmitted SYN-ACK produces no second server value.
- **FR-parity-19** — A JA4L value on a TCP connection holds two timing parts.
- **FR-parity-20** — A JA4L value and a JA4LS value on a QUIC connection hold `quic` as a
  third part.
- **FR-parity-21** — No JA4L value and no JA4LS value holds the literal `tcp`.
- **FR-parity-22** — The register holds one value decline for each JA4L comparison of the
  three reference files that publish no JA4L key. The port writes five keys, because a port
  key names a capture and a method. A key of this repository names a capture, a stream and a
  method, so the five port keys cover 28 entries here. #361 makes each comparison reachable.
- **FR-parity-23** — A test builds a connection with two SYN-ACK packets and asserts one
  server value.
- **FR-parity-24** — A test builds a QUIC connection and asserts the protocol marker.

### JA4SSH

The port's issues #28, #96, #97, #105, #199 and #214 hold these rulings.

- **FR-parity-25** — `JA4SSHFingerprinter` emits at `packetCount` packets. The default is
  200.
- **FR-parity-26** — The threshold holds no upper cap. `ja4ssh.go:176-180` caps it at 10
  today, and that cap goes.
- **FR-parity-27** — The mode field reads the packet lengths of the window alone.
- **FR-parity-28** — A window that holds no SSH packet produces no fingerprint.
- **FR-parity-29** — `JA4SSHFingerprinter` exports `CloseOpenWindows`, which emits the
  window each connection holds open and returns the results.
- **FR-parity-30** — `WindowCloser` declares `CloseOpenWindows` alone, and
  `ConnectionWindowCloser` declares `CloseConnectionWindow` alone. A stateless fingerprinter
  implements neither interface, and `Processor` skips it. Each `Processor` call site asserts
  the interface that declares the one method it calls. Issue #53 records the placement, and
  issue #268 records the split.
- **FR-parity-31** — `Processor` exports `CloseOpenWindows`, which calls each
  fingerprinter and returns the joined results.
- **FR-parity-32** — `cmd/ja4plus` calls `Processor.CloseOpenWindows` when the capture
  ends.
- **FR-parity-33** — A test asserts that a connection with 15 SSH packets and a window of
  200 produces no fingerprint before `CloseOpenWindows` and one after it.
- **FR-parity-33a** — `JA4SSHFingerprinter` exports `CloseConnectionWindow`, which emits
  the window one connection holds open and returns the results. The maintainer ruled the
  method on 2026-08-12, and issue #216 records the ruling. This project named the
  behavior first, and `Crank-Git/ja4plus` issue #598 holds the port half.
- **FR-parity-33b** — `CloseConnectionWindow` reads the two endpoints of the connection in
  either order, as `CleanupConnection` does.
- **FR-parity-33c** — `CloseConnectionWindow` removes the connection from the state table,
  so a second call returns an empty slice.
- **FR-parity-33d** — `CloseConnectionWindow` returns an empty slice for a connection the
  state table does not hold.
- **FR-parity-33e** — `CleanupConnection` emits no fingerprint. A caller that wants the
  open window of one connection calls `CloseConnectionWindow` instead.
- **FR-parity-33f** — `Processor` and `SyncProcessor` each export
  `CloseConnectionWindow`, which calls each fingerprinter that implements
  `ConnectionWindowCloser` and returns the joined results.
- **FR-parity-33g** — `CloseConnectionWindow` removes a connection whose window holds no
  SSH packet. FR-parity-28 states that such a window produces no fingerprint.
- **FR-parity-33h** — A test asserts that a connection with an open window produces one
  fingerprint on the first `CloseConnectionWindow` call and none on the second.

### JA4T and JA4TS

The port's issues #215, #226 and #246 hold these rulings.

**FR-parity-43 carries an amendment that the maintainer made on 2026-08-14, and #484 is the
reversal path.** The requirement read
`A RST on a connection that holds no delay produces no value.` The maintainer ruled split T2
on that date, and the ruling contradicts that sentence. A connection that holds one SYN-ACK
holds no delay, and the library now publishes the stored four-part value for a reset of it.
`wireshark/source/packet-ja4.c:1599-1608` writes the four-part value above the delay guard
of `wireshark/source/packet-ja4.c:684`. `docs/audit/ja4t-ja4ssh-ja4s-deviation-cluster.md`
`## Cause 2 — the library returns no JA4TS value on a reset of a connection that holds one SYN-ACK`
holds the reading, #495 built the change, and
`TestJA4TS_PublishesTheStoredFourPartValueOnAResetOfAOneSynAckConnection` of
`ja4ts_part_e_test.go` holds the rule. **`Crank-Git/ja4plus#609` holds the port half.**

- **FR-parity-34** — An empty TCP option list writes `00` in part b.
- **FR-parity-35** — Part c writes two digits. An absent maximum segment size writes `00`.
- **FR-parity-36** — Part d writes two digits. A window scale of zero writes `00`.
- **FR-parity-37** — A JA4TS value carries part e when the server sent two SYN-ACK packets
  or more.
- **FR-parity-38** — Part e holds the delay of each SYN-ACK after the first, in whole
  seconds, joined by `-`.
- **FR-parity-39** — A connection the server answered once omits part e.
- **FR-parity-40** — A RST on a connection that already holds a delay appends `-R` and the
  delay of the RST to part e.
- **FR-parity-41** — The RST value reads part a through part d from the first SYN-ACK of
  the connection.
- **FR-parity-42** — The RST test reads the RST bit of the flag byte, so a RST that also
  carries ACK reaches the rule.
- **FR-parity-43** — A RST on a connection that holds one SYN-ACK produces the stored
  four-part value. **The maintainer amended this requirement on 2026-08-14, and #484 is the
  reversal path.**
- **FR-parity-43a** — A RST that reaches no stored connection produces no value.
- **FR-parity-44** — A RST that the client sent produces no value.
- **FR-parity-45** — `JA4TSFingerprinter` holds a state table keyed by the five-tuple, and
  `CleanupConnection` clears one entry of it.
- **FR-parity-46** — A test builds the capture that the deleted `technical_details/
  JA4T.md` describes, and asserts the value `65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6`.

### JA4H, JA4X, JA4D and JA4D6

The port's issues #138, #219, #231 and #271 hold these rulings.

- **FR-parity-47** — The JA4H method code reads the first two characters of any method
  token, in lower case.
- **FR-parity-48** — A test asserts that `PROPFIND` writes `pr` and `MKCOL` writes `mk`.
- **FR-parity-49** — JA4X reads the TLS record layer without regard to the tunnel protocol
  that carries it.
- **FR-parity-50** — A test asserts three JA4X values on the SOCKS4 tunnel of
  `socks4-https.pcap` on port 9901. The register holds each comparison of the three as a
  value decline. **This requirement is closed.** `ja4x_tunnel_test.go` holds the test half,
  and #57 built it. `testdata/deviations.json` holds twelve entries under the ruling #375,
  and #375 wrote them. **The three values reach twelve comparisons**, because the run
  compares `JA4X` and `JA4X_r` in the per-stream set and in the per-packet set. A key of
  this repository names a capture, a stream and a method, and a key of the port names a
  capture and a method.
- **FR-parity-51** — Subfield 2 of JA4D writes the first Maximum DHCP Message Size when a
  message repeats option 57.
- **FR-parity-52** — Part a of a JA4D value holds eleven characters.
- **FR-parity-53** — A BOOTP message that carries no option 53 produces no JA4D value.
- **FR-parity-54** — Subfield 1 of JA4D6 writes the outer DHCPv6 message type alone, in
  five characters.
- **FR-parity-55** — Part a of a JA4D6 value holds eleven characters.
- **FR-parity-56** — A test builds a DHCPv6 relay message and asserts FR-parity-54.

### The register drift check — withdrawn

**#758 withdrew FR-parity-57, FR-parity-58, FR-parity-59 and FR-parity-60 on 2026-08-16
UTC**, and it removed `docs/specs/foxio/port-register.md` and `port_register_drift_test.go`
with them.

| Withdrawn | What it specified |
|---|---|
| FR-parity-57 | The committed copy of the port's register, with the port commit. |
| FR-parity-58 | The row count of that copy, against a recorded number. |
| FR-parity-59 | That the check performs no network call. |
| FR-parity-60 | The failure message that asks for a re-read. |

**The check caught no defect, and the copy it read carried the cost.** No change of this
repository could edit the copy, and `.claude/rules/ste.md`
`### A value of another repository is cited, and never mirrored` bars a whole-page copy of
the port's material.

**Rule 3 of `.claude/rules/parity.md` is what holds the two implementations together**, and
it reads the shared FoxIO vector set rather than a row count. A reader re-reads the port at
the tag, under `.claude/rules/rulings.md`
`### How a reader finds the port's ruling on a shared question`.

**No number of the four is reused**, so a reader who meets one in an older document finds it
here.

## User flows

### An engineer closes a register row

1. The engineer reads the row in `docs/specs/spec.md` and the port issue it names.
2. The engineer reads the transcription in `docs/specs/foxio/` that the row cites.
3. The engineer writes the test first. The test fails.
4. The engineer changes the fingerprinter. The test passes.
5. The engineer runs `make conformance` and records the count of moved values in the pull
   request.
6. The engineer updates `docs/parity.md`.

### An engineer finds that a Go fact contradicts a ruling

1. The engineer records the fact, with a file and a line.
2. The engineer opens an issue in this repository that names the port issue.
3. The engineer opens an issue in `Crank-Git/ja4plus` that names the same fact.
4. The engineer stops. **A ruling moves in both repositories or in neither.**

## Screens & states

This feature set changes no screen. `mockups/02-cli-output.html` holds the output shape
that FR-parity-32 adds a line to.

## Behaviour rules

- **A ruling is reversible, and a reversal is a two-repository change.** A test that holds
  a ruling names the port issue in a comment, so a reader who reverses it knows where the
  other half lives.
- **A measurement belongs in the pull request.** A row that moves a fingerprint states how
  many values moved, on which captures, and what the conformance count was before and
  after.
- **A row that moves no fingerprint says so.** Several rows record a property rather than
  a change, and a reader must be able to tell the two apart.
- **The register decides an accepted difference. The conformance suite decides the rest.**
  A deviation that the register does not hold is a failure.

## Data touched

| File | Change |
|---|---|
| `ja4.go`, `ja4s.go` | The ALPN form. |
| `ja4l.go` | One value per connection, the part count, the protocol marker, the retransmission guard. |
| `ja4ssh.go` | The window threshold, the mode field, the empty-window rule, `CloseOpenWindows`, `CloseConnectionWindow`. |
| `ja4t.go`, `ja4ts.go` | The two-digit form, part e, the RST value, the JA4TS state table. |
| `ja4x.go` | The stream reader. The tunnel rule already matched, and two defects gave the SOCKS4 tunnel no value: the reader concatenated the segments in arrival order, and it read the first handshake message of a TLS record alone. |
| `ja4d.go`, `ja4d6.go` | The repeated option 57, the BOOTP rule, the relay message. |
| `ja4h.go` | A test only. `ja4h.go:201-205` already reads the first two characters of the method token. |
| `internal/parser/http.go` | The request-line pattern reads any method token, and `IsHTTPRequest` admits any method that a whole request line names. The nine-method list gave `PROPFIND` no JA4H value, so FR-parity-47 needs this file. |
| `types.go` | `WindowCloser` declares `CloseOpenWindows`, `ConnectionWindowCloser` declares `CloseConnectionWindow`, and `Fingerprinter` does not change. |
| `processor.go` | `Processor.CloseOpenWindows`, `Processor.CloseConnectionWindow`. |
| `sync_processor.go` | `SyncProcessor.CloseOpenWindows`, `SyncProcessor.CloseConnectionWindow`. `features/03-concurrency.md` states the `SyncProcessor` contract. |
| `cmd/ja4plus/main.go` | The end-of-capture call. |
| `testdata/deviations.json` | The value declines that FR-parity-22 and FR-parity-50 add. |
| `docs/parity.md` | New. |
| `docs/specs/foxio/port-register.md` | New. **#758 removed it on 2026-08-16 UTC**, with FR-parity-57 through FR-parity-60. |

## Interfaces

| Interface | Version | Documentation |
|---|---|---|
| The port's register | `v1.1.0`, read 2026-08-11 | <https://github.com/Crank-Git/ja4plus/blob/dev/docs/specs/spec.md> |
| FoxIO reference | The commit in `testdata/foxio.pin` | <https://github.com/FoxIO-LLC/ja4> |
| `github.com/google/gopacket` | v1.1.19 | <https://pkg.go.dev/github.com/google/gopacket> |

**`CloseOpenWindows` breaks no exported interface.** The maintainer ruled on 2026-08-11 that
the method sits on the second optional interface `WindowCloser`, and #53 records the ruling.
`Fingerprinter` does not change, so no third-party implementation of it breaks. A caller
discovers the capability with a type assertion. `features/10-release.md` FR-release-51 states
what the CHANGELOG records.

## Edge cases & failures

| Case | Expected behavior |
|---|---|
| A connection holds an open window and the caller never calls `CloseOpenWindows`. | The window is lost. The method is opt-in, and the library forces no flush. |
| `CloseOpenWindows` is called twice. | The second call returns an empty slice. A window is emitted once. |
| One connection ends before the packet source ends. | `CloseConnectionWindow` emits the window that connection holds open, and it removes the connection. `CleanupConnection` removes the connection and emits nothing. FR-parity-33a and FR-parity-33e cover the two. |
| A RST arrives before any SYN-ACK. | No JA4TS value. FR-parity-43a covers it. |
| A RST arrives on a connection that holds one SYN-ACK. | The stored four-part value. FR-parity-43 covers it, and the maintainer amended that requirement on 2026-08-14. |
| The server sends three SYN-ACK packets. | Part e holds two delays, joined by `-`. |
| A DHCPv6 message nests a relay inside a relay. | Subfield 1 writes the outermost type. FR-parity-54 says "the outer", and the test builds the two-level case. |
| The first ALPN value is empty. | The ALPN field writes the zero form the method already writes. This row settles a one-byte value, and an empty value is a separate case that no ruling covers. Record it in `Open questions`. |

## Acceptance criteria

1. Every requirement above is closed, and each one names its port issue in a test comment.
2. `go test -race ./...` passes.
3. `make conformance` reports no deviation that `testdata/deviations.json` does not hold.
4. `testdata/deviations.json` holds no entry whose comparison now matches.
5. `docs/parity.md` exists, names port version `v1.1.0`, and holds one row per exported
   port name.
6. `grep -r "python" --include="*_test.go" .` finds no test that runs the port.
7. `ja4ssh.go` holds no upper cap on the window threshold.
8. `JA4TSFingerprinter` produces `65535_2-1-3-1-1-4_65495_8_1-2-4-8-R6` for the capture
   that FR-parity-46 builds.
9. The drift check passes against the recorded row count.

**Criterion 9 no longer holds, and this record corrects it rather than rewrites it.** #758
withdrew FR-parity-57 through FR-parity-60 on 2026-08-16 UTC, and it removed
`port_register_drift_test.go` with them. **A criterion of a feature file is a dated record**
under `.claude/rules/ste.md` `### Two permitted restatements, and one date rule`, so the
line above stays and this paragraph states the later fact.
`### The register drift check — withdrawn` above states the reason.

## Out of scope

- Changing the port. This project files an issue there and writes no code there.
- JA4LS. `features/12-ja4ls.md` owns it, and it depends on this feature set.
- The remote lookup split. `features/09-database-lookup.md` owns it.
- Any ruling the port has not made. A question this file does not answer goes to the
  maintainer, and it is answered in both repositories at once.

## Open questions

1. ~~**What does the ALPN field write when the first ALPN value is empty?**~~ **Closed on
   2026-08-12. The answer is `00`.** The port ruled on a one-byte value and on a byte
   outside the printable ASCII range `0x20-0x7E`, and no ruling covered a zero-byte value.
   **The question needed a reading and not a ruling.** `technical_details/JA4.md:93` states
   the rule, and `Reading 17` of `docs/specs/foxio/JA4.md` records it. The `R9` section of
   `docs/specs/spec.md` holds the closure and the evidence, and the question blocks nothing
   because #50 built FR-parity-8, FR-parity-9 and FR-parity-10.
2. ~~**Does the drift check belong in this repository at all?**~~ **Closed on 2026-08-16
   UTC. The answer is no, and #758 removed the check.** The question named the cost
   correctly: FR-parity-57 committed a copy of another repository's document, and the copy
   went stale. **The measurement that closed it is that the check caught no defect**, and
   `.claude/rules/ste.md`
   `### A value of another repository is cited, and never mirrored` bars the copy it read.
   **The scheduled workflow that the question offered as the alternative was declined too**,
   because a reader re-reads the port at the tag and no check of this repository reports the
   drift. `### The register drift check — withdrawn` above states the closure.

**One question closed, and the list drops it.** It asked where `CloseOpenWindows` sits. The
maintainer ruled on 2026-08-11 that the method sits on a second optional interface, and on
2026-08-12 that each capability holds an interface of its own. FR-parity-30 above states the
answer. Issue #53 records the first ruling, and issue #268 records the second one.
