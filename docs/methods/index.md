# Methods

JA4+ is a set of network fingerprint methods that FoxIO publishes. **This library
implements twelve of them.** This section holds one page for each one.

**The twelve methods of this library are not the twelve that FoxIO names.** `License
FAQ.md:5` of FoxIO at commit `16b96d95` lists JA4Scan and omits JA4. This library implements
JA4, and it implements no JA4Scan.

## The two counts, and what each one counts

**A method is one named JA4+ algorithm. A fingerprinter is the Go type that implements one
method or two.** The two words count different things, and a reader who applies one count
to the other reads the wrong number.

| What is counted | The count | Why |
|---|---|---|
| The methods this library implements | Twelve | The two tables below name each one. |
| The Go fingerprinter types that carry the passive methods | Ten | `JA4LFingerprinter` writes both JA4L and JA4LS. |
| The packages that carry the active method | One | Package `scan` carries JA4TScan, and no fingerprinter does. |

**`JA4LFingerprinter` is the one type that writes two methods.** It measures the client
side and the server side of one connection, so one state table serves both. Every other
method reaches one type of its own.

## The eleven passive methods

| Method | Page | What it fingerprints | Go type | `Type` token |
|---|---|---|---|---|
| JA4 | [JA4](ja4.md) | One TLS client hello. | `JA4Fingerprinter` | `ja4` |
| JA4S | [JA4S](ja4s.md) | One TLS server hello. | `JA4SFingerprinter` | `ja4s` |
| JA4H | [JA4H](ja4h.md) | One HTTP request. | `JA4HFingerprinter` | `ja4h` |
| JA4X | [JA4X](ja4x.md) | One X.509 certificate. | `JA4XFingerprinter` | `ja4x` |
| JA4SSH | [JA4SSH](ja4ssh.md) | One window of SSH packets. | `JA4SSHFingerprinter` | `ja4ssh` |
| JA4L | [JA4L](ja4l.md) | The client latency of one connection. | `JA4LFingerprinter` | `ja4l` |
| JA4LS | [JA4LS](ja4ls.md) | The server latency of one connection. | `JA4LFingerprinter` | `ja4l` |
| JA4T | [JA4T](ja4t.md) | One TCP SYN packet. | `JA4TFingerprinter` | `ja4t` |
| JA4TS | [JA4TS](ja4ts.md) | One TCP SYN-ACK packet. | `JA4TSFingerprinter` | `ja4ts` |
| JA4D | [JA4D](ja4d.md) | One DHCPv4 message. | `JA4DFingerprinter` | `ja4d` |
| JA4D6 | [JA4D6](ja4d6.md) | One DHCPv6 message. | `JA4D6Fingerprinter` | `ja4d6` |

**JA4L and JA4LS share the `Type` token `ja4l`.** One fingerprinter writes both, and the
value itself carries the label. The [JA4L](ja4l.md) page states how a caller separates the
two.

## The active method

| Method | Page | What it fingerprints | Go package | `Type` token |
|---|---|---|---|---|
| JA4TScan | [JA4TScan](ja4tscan.md) | The SYN-ACK and the retransmissions that one crafted SYN draws from a host. | `scan` | `ja4tscan` |

**JA4TScan is the one method that sends packets, so it is opt-in and separate.** No
fingerprinter and no `Processor` imports package `scan`. The maintainer reversed the decline
of JA4TScan on 2026-09-30, because FoxIO publishes the scanner at
`https://github.com/FoxIO-LLC/ja4tscan`. #796 built it.

## What this library does not implement

**FoxIO also names a scanner method, and this project decided nothing about it.** The name
carries two spellings across the FoxIO records, and FoxIO publishes no format and no
implementation for either spelling. This project states no reason, because a stated reason
would assert a ruling that no round holds.

## Read the FoxIO records before you compare this list to theirs

**Never read this list as equal to the list that FoxIO names.** Three records of the FoxIO
reference name three different sets, at commit
`16b96d95c220762cf658f67d678cda2aac95c81e`.

| FoxIO record | How many methods it names |
|---|---|
| `License FAQ.md:5` | Twelve. |
| `LICENSE:3` | Thirteen, and it spells the scanner `JA4SScan`. |
| `README.md:299` | Fifteen. |

**So the sentence "the methods FoxIO names" resolves to three different lists.** Every page
of this section therefore names what this library implements, and it cites the pinned
commit above.

## Where the evidence for each page comes from

Each method page below states what this library emits today, and it cites two kinds of
source.

- **The FoxIO transcription.** `docs/specs/foxio/` holds one file for each FoxIO image, and
  each file numbers the rules it transcribes. A page that states a part count or a field
  width cites a rule number of that file.
- **The Go implementation.** A page that states what the library emits names the Go
  identifier that produces it.

**Where a question reaches no answer, the page says so and it names the issue.** The
maintainer decides a question that the FoxIO implementations split on, and no page of this
site decides one.

## The license of these methods

The site footer states the license of this repository and the license that FoxIO applies.
The licensing page holds the full FoxIO terms.
