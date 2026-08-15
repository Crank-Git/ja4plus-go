# How key material reaches a fingerprinter

**This page is a reading, and it is not a ruling.** It states three candidate shapes, and
it answers five questions for each one. **The maintainer picks the shape.**
`.claude/rules/rulings.md` `## The two words` reserves an exported-name decision to the
maintainer, and this page invents no answer.

This page recommends one candidate in `## The recommendation`. **A recommendation is not a
decision, and this branch applies none of the three shapes.** No line of the library
changes under this page.

**Issue #649 owns this page**, under Epic 5b. Measured on 2026-08-15.

## Why the project reads this before the API freeze

**A route into a fingerprinter is an exported name.** Epic 10 freezes the exported surface
at `v1.0.0`. A freeze that precedes this decision locks a surface that cannot express the
three issues below, and each of those issues then needs an additive `v1.1` interface.

**The maintainer moved Epic 5b ahead of Epic 10 on 2026-08-15 for this reason.**

Three issues wait on the answer.

- **#492** reads the certificate of a protected TLS 1.3 handshake record. It needs a key
  log, a TLS record decryptor for TCP, and a reader for the compressed certificate of
  RFC 8879.
- **#529** reads an HTTP/2 request. It needs the same TLS record decryptor, and an HPACK
  decoder above it.
- **#164** reads an HTTP/3 request. It needs the QUIC 1-RTT keys, and a QPACK decoder
  above them.

**The conformance run of this branch reports 267 deviations that the register does not
hold**, measured on 2026-08-15. **Epic 5b estimates that the three issues above hold about
91 of those 267.** That estimate is the project manager's, and this page re-measured no part
of it. **#529 states that the 80-deviation figure of `docs/audit/ja4h-deviation-cluster.md`
predates the 89 comparisons that closed on 2026-08-14**, so a reader who needs the count
re-measures it.

## The word `library` in this page

`docs/specs/spec.md` `## Terms` states the meaning of `library`. #613 wrote that row, and
batch #644 carries it. **This page uses that meaning, and it restates no extent of its
own.** Rule 6 of `.claude/rules/ste.md` gives one word one meaning.

## What the tree holds today

**The key material is exported. The route into a fingerprinter is not.** #171 recorded that
gap on 2026-08-11, and the gap is open today.

`types.go` exports eight names for key material.

| Name | Signature |
|---|---|
| `ErrNoSecret` | `var ErrNoSecret error` |
| `KeyLog` | `type KeyLog struct{ ... }` |
| `ParseKeyLog` | `func ParseKeyLog(r io.Reader) (*KeyLog, error)` |
| `ReadKeyLogFromCapture` | `func ReadKeyLogFromCapture(r io.Reader) (*KeyLog, error)` |
| `KeyLog.Secret` | `func (k *KeyLog) Secret(clientRandom []byte, label string) ([]byte, error)` |
| `KeyLog.ClientRandoms` | `func (k *KeyLog) ClientRandoms() [][]byte` |
| `KeyLog.Len` | `func (k *KeyLog) Len() int` |
| `DecryptQUICPacket` | `func DecryptQUICPacket(payload, secret []byte, connectionIDLength int) ([]byte, error)` |

**The maintainer accepted those eight names on 2026-08-11.** Round 11 of the `## Changelog`
of `docs/specs/spec.md` records the acceptance.

**No constructor of the library accepts a `KeyLog`.** `NewProcessor` in `processor.go` takes
no parameter. `NewSyncProcessor` in `sync_processor.go` takes no parameter. `NewJA4X` and
`NewJA4H` each take no parameter.

**`Processor` holds each fingerprinter in an unexported field, and it exports no accessor.**
`Processor` in `processor.go` declares ten unexported fields. Its exported methods are
`ProcessPacket`, `Reset`, `CleanupConnection`, `CloseOpenWindows`, `CloseConnectionWindow`
and `GetShardKey`. **So a caller that holds a `Processor` reaches no fingerprinter of it.**

**One fingerprinter already carries a construction option, and a `Processor` cannot reach
it.** `NewJA4SSH(packetCount int)` in `ja4ssh.go` accepts a window size, and `NewProcessor`
calls `NewJA4SSH(0)`. A caller that holds a `Processor` therefore runs JA4SSH at the default
window, and it changes that window through no exported name. **This is the measured
precedent for a per-fingerprinter option**, and `## Candidate 2` reads it.

## What the two consumers need

**JA4X and JA4H need different amounts of state, and that difference decides this page.**

### JA4X needs one decrypted record, and it holds no state above the record

`findCertificatesInStream` in `ja4x.go` walks the TLS records of a reassembled TCP stream.
`internal/parser/tls.go` holds `TLSRecordTypeHandshake  = 0x16`, and a TLS 1.3 server writes
the Certificate message inside a record whose type byte is `0x17`. **#492 states that
cause.**

**A certificate is self-contained.** `ComputeJA4XFromDER(certDER []byte) string` in `ja4x.go`
already produces the value from the certificate bytes alone. So a caller that reaches the
decrypted certificate reaches the JA4X value through a name the library exports today.

### JA4H needs a decoder whose state spans the connection

**An HTTP/2 request carries no request line.** `ja4h.go` requires a TCP layer, and
`internal/parser/http.go` matches a line of the form `<method> <path> HTTP/<digit>.<digit>`.
An HTTP/2 request carries an HPACK header block instead. #529 states that cause.

**HPACK holds a dynamic table, and a decoder needs that table to decode a header block.**
RFC 7541 Section 2.2 states it:

> To decompress header blocks, a decoder only needs to maintain a dynamic table (see
> Section 2.3.2) as a decoding context. No other dynamic state is needed.

Section 2.3.2 states that the dynamic table is a list of header fields in first-in,
first-out order, so a header block that references the table depends on the blocks that
filled it. **QPACK holds the same kind of table**, and #164 states that a QPACK dynamic
table is state that spans packets.

**So a decoder that reads one header block in isolation produces a wrong header list.** JA4H
hashes the header names in order, so a wrong list produces a wrong fingerprint rather than
no fingerprint. #164 states that risk.

### The two consumers hold separate stream state today

`ja4x.go` builds its own `parser.TCPStreamReassembler`, and `ja4h.go` builds a second one.
**The two carry different bounds.** `ja4x.go` sets `ja4xMaxStreams = 50`, and `ja4h.go` sets
`ja4hMaxStreams = 100`. **A capture with 60 concurrent streams therefore reaches JA4H on
streams that JA4X has already evicted.**

**A TLS record decryptor counts records**, because RFC 8446 Section 5.3 derives the AEAD
nonce from a per-record sequence number. **A decryptor that misses one record loses the
count, and every later record of that stream then fails the tag.** So two decryptors under
two different stream bounds do not produce one answer on one capture.

## The five questions

The issue body states five questions, and each candidate below answers all five.

1. Which exported names does the shape add, in full, with signatures?
2. How does the shape interact with the rule that one `Processor` serves one goroutine?
3. Can the port carry the same shape?
4. Does the shape serve JA4X alone, or JA4X and JA4H together?
5. Does the shape reach `ja4db/`?

## Candidate 1 — a `Processor` option at construction

The caller supplies a `KeyLog` when it constructs the `Processor`, and every fingerprinter
of that `Processor` reads it.

### Question 1 — the exported names

**Two forms carry this candidate, and they differ at the freeze.** This page states both,
and it picks neither.

**Form 1a — a named constructor.** It adds two names, and it moves no existing signature.

```go
// NewProcessorWithKeyLog returns a Processor that reads the key log while it fingerprints.
// A fingerprinter that needs no secret ignores the key log.
// The Processor holds the key log and never writes to it.
func NewProcessorWithKeyLog(keyLog *KeyLog) *Processor

// NewSyncProcessorWithKeyLog returns a SyncProcessor that reads the key log.
func NewSyncProcessorWithKeyLog(keyLog *KeyLog) *SyncProcessor
```

**Form 1b — a functional option.** It adds two names, and it moves two existing signatures.

```go
// ProcessorOption sets one option of a Processor at construction.
type ProcessorOption func(*Processor)

// WithKeyLog returns the option that gives a Processor the key log.
func WithKeyLog(keyLog *KeyLog) ProcessorOption

func NewProcessor(options ...ProcessorOption) *Processor
func NewSyncProcessor(options ...ProcessorOption) *SyncProcessor
```

**Form 1b is available before the freeze, and never after it.** A variadic parameter changes
the type of the function. A caller that assigns `NewProcessor` to a variable of type
`func() *Processor` stops compiling under form 1b, and a plain call keeps compiling.

**Form 1b costs two names for every later option, and form 1a costs two constructors.** The
maintainer decides which cost this project takes.

### Question 2 — the concurrency contract

**Candidate 1 keeps the contract, and it needs no lock.** The doc comment of `KeyLog` in
`types.go` states that the value does not change after construction, and that any number of
goroutines read one `KeyLog`.

**So a sharded caller builds one `KeyLog` and gives the same pointer to every `Processor`.**
Each goroutine then reads one immutable value, and the packet path acquires no lock.
`.claude/rules/concurrency.md` `## The contract` names that pattern.

**The decryption state is the part that needs care, and it is per-connection state.**
`.claude/rules/concurrency.md` `## Rules` requires a removal path in `CleanupConnection` and
in `Reset` for each new state map. **A record sequence number and an HPACK dynamic table are
both such state.** That cost is the same under all three candidates that put the state in
the library.

**Candidate 1 adds a constructor and no method**, so `SyncProcessor` needs a matching
constructor rather than a matching method.

### Question 3 — the port

**The port expresses this shape.** `ja4plus/processor.py:113` at tag `v1.1.0` declares
`def __init__(self, thread_safe: bool = True) -> None:`, so the port already carries a
keyword argument at construction. A `key_log` keyword argument reads the same way.

**The port holds no value to pass.** `## The port` below states that fact once, and it
holds for all three candidates.

### Question 4 — JA4X and JA4H

**Candidate 1 serves both.** The `Processor` owns the key log, so every fingerprinter it
drives reaches the same secrets on the same packets. **The library holds the HPACK dynamic
table and the QPACK dynamic table**, which is where the state that spans a connection has to
live.

**Candidate 1 leaves one gap.** A caller that builds `NewJA4X()` alone reaches no key log,
because this candidate adds a name to `Processor` and to `SyncProcessor` alone.
`## The candidates are not exclusive` below states the repair.

### Question 5 — `ja4db/`

**No.** `## The network boundary` below states the reading once, and it holds for all three
candidates.

## Candidate 2 — a `Fingerprinter` setter

Each fingerprinter that needs key material accepts one, and the rest are untouched.

### Question 1 — the exported names

**Two forms carry this candidate too.**

**Form 2a — a setter.** It adds one name for each fingerprinter that needs key material.

```go
// SetKeyLog gives the fingerprinter the key log it reads.
// The caller calls this method before the first packet.
func (f *JA4XFingerprinter) SetKeyLog(keyLog *KeyLog)
func (f *JA4HFingerprinter) SetKeyLog(keyLog *KeyLog)
```

**Form 2b — a constructor for each fingerprinter.** It adds one name for each one.

```go
// NewJA4XWithKeyLog returns a JA4X fingerprinter that reads the key log.
func NewJA4XWithKeyLog(keyLog *KeyLog) *JA4XFingerprinter

// NewJA4HWithKeyLog returns a JA4H fingerprinter that reads the key log.
func NewJA4HWithKeyLog(keyLog *KeyLog) *JA4HFingerprinter
```

**A third name follows either form**, because a caller that wants both fingerprinters and a
`Processor` needs a `Processor` that carries them. This candidate names no such route today.

### Question 2 — the concurrency contract

**Form 2a breaks the contract, and form 2b keeps it.**

**A setter admits a write after the first packet.** Two goroutines that share one
fingerprinter then write and read one field with no lock. `.claude/rules/concurrency.md`
`## Rules` bars a mutex on the packet path, so the library detects that write in no way. The
doc comment can bar the late call, and **a doc comment is not a guard**.

**Form 2b writes the field once, at construction**, so it holds the same property as
candidate 1.

### Question 3 — the port

**The port expresses this shape.** `ja4plus/processor.py:133` at tag `v1.1.0` declares
`def __getattr__(self, name: str) -> Any:`, and the comment above it states that
`processor.ja4` returns the underlying fingerprinter. **So a port caller reaches a
fingerprinter of a processor, and a Go caller does not.**

**That asymmetry is a defect of this candidate in Go, and not a parity difference.** The two
languages express the shape differently, and the Go form reaches no `Processor`.

### Question 4 — JA4X and JA4H

**Candidate 2 serves each fingerprinter alone, and it serves no `Processor`.**

**`Processor` constructs its fingerprinters internally and exports no accessor**, so a caller
that holds a `Processor` calls no setter of a fingerprinter. **`NewJA4SSH(packetCount int)`
is the measured precedent**, and `NewProcessor` calls `NewJA4SSH(0)`. A `Processor` therefore
runs JA4SSH at a window the caller cannot change.

**The JA4SSH case produces a different value, and this case produces no value at all.** A
`Processor` under candidate 2 alone leaves #492, #529 and #164 unreachable, which is the
result the three issues exist to prevent.

**Candidate 2 also duplicates the decryptor.** JA4X and JA4H each hold their own key log and
their own decryption state, over their own stream reassembler. `## The two consumers hold
separate stream state today` above measures the divergent bounds: 50 streams against 100.
**Two decryptors under two bounds decrypt two different stream sets on one capture.**

### Question 5 — `ja4db/`

**No.** `## The network boundary` below states the reading.

## Candidate 3 — a decrypt-then-feed helper

The caller decrypts outside the library and feeds the plain text in. This candidate adds key
material to no fingerprinter.

### Question 1 — the exported names

**The library exports no TLS record decryptor**, so this candidate adds one.

```go
// DecryptTLSRecord returns the plain text of one TLS 1.3 record, which the secret protects.
// sequenceNumber states the record sequence number of the record, which RFC 8446 Section 5.3
// combines with the initialization vector.
// It returns ErrNoSecret when the caller supplies no secret.
func DecryptTLSRecord(record, secret []byte, sequenceNumber uint64) ([]byte, error)
```

**JA4X needs no second name.** `ComputeJA4XFromDER(certDER []byte) string` in `ja4x.go`
already accepts certificate bytes.

**JA4H needs a second name, and the library holds none.** `ComputeJA4H(packet
gopacket.Packet) string` in `ja4h.go` accepts a packet, so a caller that holds a decoded
header list reaches no entry point. A new one reads about like this.

```go
// ComputeJA4HFromHeaders returns the JA4H value of one request, from the decoded headers.
func ComputeJA4HFromHeaders(method, version string, headers [][2]string, cookies [][2]string) string
```

**That name moves the HPACK dynamic table to the caller**, and the caller then builds the
state that spans the connection.

### Question 2 — the concurrency contract

**Candidate 3 adds no state to the library, so it breaks nothing.** This is the one question
where candidate 3 scores best. `DecryptTLSRecord` is a pure function, and a caller calls it
from any goroutine.

**The state does not disappear. It moves to the caller.** Every caller that wants HTTP/2 then
builds one HPACK dynamic table for each connection, under its own concurrency rules.

### Question 3 — the port

**The port expresses this shape.** The port already publishes free functions of this kind:
`compute_ja4x_from_der` and `compute_ja4x_from_pem` sit in `ja4plus/__init__.py:116` at tag
`v1.1.0`, inside `__all__`.

### Question 4 — JA4X and JA4H

**Candidate 3 serves JA4X, and it does not serve JA4H. This is the failure that #649 exists
to prevent.**

**JA4X is stateless above the record.** A certificate is self-contained, so a caller that
decrypts one record reaches the value through `ComputeJA4XFromDER`.

**JA4H is not stateless above the record.** HPACK holds a dynamic table for each connection,
and QPACK holds one too. **A caller that decodes one header block without the table of the
connection produces a wrong header list**, and JA4H then produces a wrong fingerprint rather
than no fingerprint.

**So candidate 3 pushes the hardest part of #529 and of #164 onto every caller**, and each
caller then reimplements RFC 7541 and RFC 9204. **Two callers that implement the table
differently produce two different fingerprints for one capture**, and comparison is the only
thing a fingerprint is for.

### Question 5 — `ja4db/`

**No.** `## The network boundary` below states the reading.

## The deciding question — does one shape serve JA4X and JA4H together?

**Yes for candidate 1. No for candidate 2. No for candidate 3.**

| Candidate | JA4X | JA4H over HTTP/2 and HTTP/3 | Why |
|---|---|---|---|
| 1 — a `Processor` option | Yes | Yes | The `Processor` owns the key log, and the library holds the table that spans the connection. |
| 2 — a `Fingerprinter` setter | Yes, standalone | Yes, standalone | **A `Processor` reaches neither**, because it exports no accessor for a fingerprinter. |
| 3 — decrypt then feed | Yes | **No** | HPACK and QPACK hold a table for each connection, and a caller that feeds one record holds no table. |

**The one sentence that decides it: an HPACK dynamic table and a QPACK dynamic table span a
connection, so the state has to live where the packets arrive, and the packets arrive at a
`Processor`.**

## The port

**The port at tag `v1.1.0` expresses each of the three shapes in Python, and it holds no
value to pass to any of them.**

**The port exports no key-material name.** `ja4plus/__init__.py:116` at tag `v1.1.0` opens
`__all__`, and that list names 25 entries. **No entry of it names a key log, a secret or a
decryptor.**

**The port declines decryption as a non-goal.** `docs/specs/spec.md:199` at tag `v1.1.0`
states it:

> - Decryption is out of scope. `ja4plus` reads no key material and reads no Decryption
>   Secrets Block. It decrypts no TLS record and no QUIC 1-RTT packet. Traffic that a
>   capture carries only in encrypted form therefore produces no fingerprint, even when
>   the same capture file carries the key material that decrypts it. #129 holds the
>   ruling, and the ruling is reversible.

**The bare `#129` of that quotation names the port's issue #129**, because the quotation
comes from the port. `.claude/rules/rulings.md` `## A citation names its repository` states
the rule, and this sentence resolves the number for a reader of this repository.

**This project shipped the key-log interface first.** The `The key-log interface` row of the
register in `docs/specs/spec.md` records it, and it states that rule 2 of
`.claude/rules/parity.md` runs the other way. `Crank-Git/ja4plus#593` asks the port to adopt
or decline the eight names, and it is open on 2026-08-15.

**So the shape does not decide the parity difference. The decision to decrypt at all decides
it.** Any of the three candidates opens a parity difference on the interface until the port
reverses the port's issue #129. **A ruling lands in this repository and in the port together,
or in neither**, and `.claude/rules/parity.md` states that rule.

**#492 already records the same direction for the value.** The port breaks the same
certificate scan on a byte that is not the handshake content type, so a change here that the
port does not make opens a parity difference on 11 values.

## The network boundary

**No candidate reaches `ja4db/`, and none of the three is a network reach.**

**#613 applied the maintainer ruling of 2026-08-15: the boundary names an HTTP call and a
remote lookup, and never a raw socket.** `docs/audit/network-boundary.md` holds the record,
and `network_boundary_test.go` fails on an import that breaks the rule.

**A key log reaches the library through an `io.Reader` that the caller opens.**
`ParseKeyLog(r io.Reader)` and `ReadKeyLogFromCapture(r io.Reader)` in `types.go` each accept
a reader. **The library opens no file of its own**, so it performs no file input either.

**This page reopens no part of that boundary.**

## The candidates are not exclusive

**Candidate 1 and form 2b of candidate 2 compose, and the composition repairs the one gap of
candidate 1.**

- Candidate 1 gives a `Processor` the key log, which serves every caller that drives a
  `Processor`.
- Form 2b gives a standalone fingerprinter the key log at construction, which serves a caller
  that builds `NewJA4X()` alone.
- **Neither one admits a write after the first packet**, so the composition keeps the
  concurrency contract.

**This page records that the composition exists. It picks nothing.** The maintainer decides
whether the standalone path needs the second half.

## The recommendation

**This page recommends candidate 1, and it applies nothing.**

**The sentence that decides it: HPACK and QPACK each hold a dynamic table for each
connection, so the decoded state must live in the library where the packets arrive, and only
a shape that gives the `Processor` the key material at construction puts it there.**

Three findings support the recommendation.

1. **Candidate 3 is the trap the issue names.** It serves JA4X through
   `ComputeJA4XFromDER`, which exists today, and it cannot serve JA4H without every caller
   reimplementing RFC 7541 and RFC 9204.
2. **Candidate 2 alone reaches no `Processor`.** `Processor` exports no accessor for a
   fingerprinter, and `NewJA4SSH(packetCount int)` is the measured precedent for an option a
   `Processor` cannot reach.
3. **Candidate 1 keeps the concurrency contract without a lock**, because a `KeyLog` does not
   change after construction and any number of goroutines read one.

**#492 already assumes this answer**, and it wrote that assumption before this reading. Its
first acceptance criterion states that a `Processor` accepts a `KeyLog`. **That criterion is
an assumption of #492 and not a decision**, and the maintainer still picks.

**The reading takes no position between form 1a and form 1b.** It records one fact that the
maintainer needs: **form 1b changes the signature of `NewProcessor` and of `NewSyncProcessor`,
and the freeze of Epic 10 closes that option permanently.**

## What this page does not do

- **It picks no answer.** The maintainer picks.
- **It writes no decoder.** No HPACK decoder, no QPACK decoder and no TLS record decryptor
  reaches this branch.
- **It closes no deviation, and it moves no fingerprint value.**
- **It changes no exported name.**

## The external specifications this page reads

`.claude/rules/external-apis.md` bars a description of an external interface from memory.
This page reads three specifications, and it confirmed each reading against the published
text on 2026-08-15.

| Specification | What this page reads | Source |
|---|---|---|
| RFC 7541 | Section 2.2 states that a decoder needs the dynamic table as a decoding context. Section 2.3.2 states the first-in, first-out order. | <https://www.rfc-editor.org/rfc/rfc7541> |
| RFC 8446 | Section 5.3 constructs the AEAD nonce from a 64-bit record sequence number and the write initialization vector. | <https://www.rfc-editor.org/rfc/rfc8446> |
| RFC 9204 | The specification of QPACK. #164 reads it, and this page names it without a section claim. | <https://www.rfc-editor.org/rfc/rfc9204> |

**This page quotes RFC 7541 Section 2.2 verbatim, and it paraphrases RFC 8446 Section 5.3.**

## The reversal path

**Issue #649 is the reversal path of every reading of this page.** A later fact that
contradicts a reading above lands on that issue, and the page then records the new
measurement.
