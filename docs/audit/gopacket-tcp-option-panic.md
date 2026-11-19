# The gopacket TCP option panic

**This file records a defect of a pinned dependency, and it rules nothing.** Issue #510
holds the record, and issue #494 met the defect in its own first commit.

`CLAUDE.md` states that every packet is untrusted input, and that a fingerprinter returns a
non-fatal error and never a panic. **An ICMP payload is exactly the input that rule exists
for**, so the defect belongs in the record rather than in a comment alone.

**This file states no ruling.** `.claude/rules/rulings.md` reserves a ruling for the
maintainer.

## What panics at v1.6.1

**`go.mod` pinned `github.com/gopacket/gopacket v1.6.1` when #510 wrote this record, and it
pins `v1.7.7` today.** #721 moved the pin to `v1.7.1` on 2026-08-15, and
`## The repair at v1.7.1` below holds the second reading. #791 moved it to `v1.7.2` on
2026-09-30 UTC, and `## The re-read at v1.7.2` below holds the third. The move to `v1.7.7`
landed on 2026-11-15 UTC, and `## The re-read at v1.7.7` below holds the fourth. **This section reads v1.6.1, and it reads no later version.**

At v1.6.1, `layers.TCP.DecodeFromBytes` reads two bytes of a Multipath TCP option without a
length guard, at `layers/tcp.go:347-353`:

```go
		case TCPOptionKindMultipathTCP:
			tcp.Multipath = true
			opt.OptionLength = data[1]
			if opt.OptionLength <= 0 {
				return fmt.Errorf("MPTCP bad option length %d", opt.OptionLength)
			}
			opt.OptionMultipath = MPTCPSubtype(data[2] >> 4)
```

**The `default` branch of the same loop guards that read**, at `layers/tcp.go:534-538`:

```go
		default:
			if len(data) < 2 {
				df.SetTruncated()
				return fmt.Errorf("Invalid TCP option length. Length %d less than 2", len(data))
			}
```

So the option kind `30` as the last byte of the option region panics. `data` holds one byte
at that point, and `data[1]` reads past the end.

## The input that reaches it

A 24-byte TCP header whose byte 12 states the data offset `6` carries a four-byte option
region. The region `01 01 01 1E` holds three NOPs and the option kind `30`, and the kind
byte is the last byte of the region.

## The measurement

**Issue #510 records the measurement of #494, and #510 measured it again on 2026-08-14.**
The second measurement ran in a throwaway module outside this repository, at
`github.com/gopacket/gopacket v1.6.1`. It printed:

```
direct call panicked: runtime error: index out of range [1] with length 1
outer tcp layer held: false
error layer: runtime error: index out of range [1] with length 1
```

**The direct call panics, and the outer decode path survives the same bytes.**
`gopacket.NewPacket` recovers a panic of a decoder, and it writes a decode failure layer in
place of the TCP layer. So the packet holds no TCP layer, and `GetTCPLayer` of
`internal/parser/packet.go` returns `nil` for it.

**The two measurements agree, and one printer separates their text.** #510 read
`ErrorLayer().Error()`, which returns the error. #494 read the layer as a string, and
`decode.go:139-141` states that `DecodeFailure.String()` prepends `Packet decoding error: `.
Both readings report the same runtime error.

## The repair at v1.7.1

**`github.com/gopacket/gopacket v1.7.1` repairs the defect**, and #721 read the source on
2026-08-15. `TestTheGopacketPanicRecordCitesThePinnedVersion` demanded this reading, because
a bump moves the source that the section above cites.

**The MPTCP branch now bounds the read before it takes `data[1]`**, at
`layers/tcp.go:347-367`:

```go
		case TCPOptionKindMultipathTCP:
			tcp.Multipath = true
			// The subtype nibble lives in data[2], so three bytes are the
			// minimum any MPTCP option can occupy.
			if len(data) < 3 {
				df.SetTruncated()
				return fmt.Errorf("Invalid MPTCP option. Length %d less than 3", len(data))
			}
			opt.OptionLength = data[1]
			if opt.OptionLength < 3 {
				return fmt.Errorf("MPTCP bad option length %d", opt.OptionLength)
			} else if int(opt.OptionLength) > len(data) {
```

**The `default` branch keeps its guard, and it gains a second bound**, at
`layers/tcp.go:554-565`. The added branch reads
`return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.OptionLength, len(data))`.

### The measurement of the repair

**#721 ran one program against both versions on 2026-08-15**, in a throwaway module outside
this repository. It built the input that `## The input that reaches it` above names. At
`v1.6.1` it printed:

```
direct call panicked: runtime error: index out of range [1] with length 1
outer tcp layer held: false
error layer: runtime error: index out of range [1] with length 1
```

**That text reproduces the #510 measurement without a change**, so the program reads the
defect the record names. At `v1.7.1` the same program printed:

```
direct call returned: Invalid MPTCP option. Length 1 less than 3
outer tcp layer held: true
error layer: Invalid MPTCP option. Length 1 less than 3
```

**So the direct call returns an error at `v1.7.1`, and it panics at `v1.6.1`.** The outer
decode path also moves: `v1.6.1` writes a decode failure in place of the TCP layer, and
`v1.7.1` keeps the TCP layer and reports the error beside it.

**The bump moves no fingerprint value.** The conformance suite reports 1754 matches before
the bump and 1754 after it, measured on 2026-08-15.

### The record page keeps the guard

**The vendor states that every version through `v1.7.0` carries the defect.** The `v1.7.1`
release notes state
`All versions up to and including v1.7.0 are affected — upgrade is recommended for anyone decoding untrusted packets or capture files.`
The MPTCP repair carries the advisory `GHSA-6h9g-cjv3-pg2c`.

Verified against: <https://github.com/gopacket/gopacket/releases/tag/v1.7.1>, retrieved
2026-08-15.

**The guard stays, and the repaired version is not a reason to remove it.**
`TestNoProductionFileCallsDecodeFromBytesDirectly` holds a property of this repository, and
it asserts no behavior of the dependency. A later bump can reintroduce a panic in another
decoder, and the guard holds without a re-read.

## The re-read at v1.7.2

**`layers/tcp.go` is byte-identical at `v1.7.1` and at `v1.7.2`**, read from the module
cache with `diff` on 2026-09-30 UTC. So the reading of `## The repair at v1.7.1` holds at
`v1.7.2` without a change, and every line range it cites names the same source.

**The `v1.7.2` release changes three files of the module**: `decode.go`, `layers/sctp.go`
and `layers/decode_oob_test.go`. `layers/sctp.go` carries the repair of
`GHSA-358w-w75h-x6rx`, a set of out-of-bounds panics in SCTP chunk decoding. No
fingerprinter of this library reads SCTP. `decode.go` exports the error of `decodeUnknown`
as `ErrUnsupportedLayer`, and the message is unchanged.

Verified against: <https://github.com/gopacket/gopacket/releases/tag/v1.7.2>, retrieved
2026-09-30.

**The bump moves no fingerprint value.** The conformance suite reports 1826 matches before
the bump and 1826 after it, measured on 2026-09-30 UTC.

## The re-read at v1.7.7

**`layers/tcp.go` differs between `v1.7.2` and `v1.7.7`**, read with `diff` on 2026-11-15
UTC. Pull request #854 proposed the move. **So the reading of `## The repair at v1.7.1`
holds through `v1.7.2`, and it holds at no later version.**

**A bad option length now stops the option loop, and it returns no error.** The MPTCP
branch reads at `layers/tcp.go:378-381`:

```go
			if len(data) < 3 || data[1] < 3 || int(data[1]) > len(data) {
				tcp.stopOptions(data)
				break OPTIONS
			}
```

The `default` branch reads the same way at `layers/tcp.go:586-589`. **`stopOptions`
removes the last option from `tcp.Options`, and it assigns the rest of the option region to
`tcp.Padding`**, at `layers/tcp.go:604`. The per-subtype length checks of the MPTCP branch
now call it too, in place of a `return fmt.Errorf`.

The `v1.7.7` release notes state the change:

> - A TCP segment with a bad option length no longer carries a decode failure or the truncated flag.

Verified against: <https://github.com/gopacket/gopacket/releases/tag/v1.7.7>, retrieved
2026-11-15.

### The measurement of the re-read

**One program ran against both versions on 2026-11-15 UTC**, in a throwaway module outside
this repository. It built the input that `## The input that reaches it` above names. At
`v1.7.2` it printed:

```
direct call returned: Invalid MPTCP option. Length 1 less than 3
options: 4, padding: 
outer tcp layer held: true
error layer: Invalid MPTCP option. Length 1 less than 3
```

**That text reproduces the `v1.7.1` measurement of #721**, so the program reads the same
path. At `v1.7.7` the same program printed:

```
direct call returned: <nil>
options: 3, padding: 1e
outer tcp layer held: true
error layer: none
```

**So the direct call returns no error at `v1.7.7`, and the outer decode path writes no
error layer.** The option kind `30` leaves `tcp.Options`, and `tcp.Padding` holds it.

### What reaches this library

**No production file reads `tcp.Options`, `tcp.Padding` or `ErrorLayer`**, measured with
`git grep` on 2026-11-15 UTC. `tcpOptionEntries` in `ja4t.go` reads the raw option bytes
from `tcp.Contents`, so JA4T and JA4TS read the same bytes at both versions.
`layers/tcp.go:355` assigns `tcp.Payload` before the option loop at `v1.7.7`, as `v1.7.2`
does, so every fingerprinter that reads the payload reads the same bytes.

**The release notes of `v1.7.7` name two more changes of behavior, and neither one reaches
this library.** One reassembles a TLS ClientHello in the `layers.TLS` decoder. The other
removes the length prefix of DNS over TCP. No production file reads `layers.TLS`,
`layers.DNS` or `ApplicationLayer`, measured with `git grep` on 2026-11-15 UTC.

**The bump moves no fingerprint value.** The conformance suite reports 1838 matches before
the bump and 1838 after it, measured on 2026-11-15 UTC.

## The library crashes on no packet today

**No production line of this repository calls `DecodeFromBytes`**, measured on 2026-08-14.
Every fingerprinter takes a `gopacket.Packet` that the caller supplies, and
`cmd/ja4plus/main.go` holds the one call of `gopacket.NewPacket` in this repository.

**The recovery of `gopacket.NewPacket` covers no direct call.** So a later production line
that calls the method on untrusted bytes adds a crash path that no recovery reaches.

## The guard

`internal/repocheck/gopacket_direct_decode_test.go` holds the guard, and
`TestNoProductionFileCallsDecodeFromBytesDirectly` is its name.

**The guard holds a property of this repository: no line outside a test calls
`DecodeFromBytes`.** It reads the abstract syntax tree of each production Go file, so a
comment that names the method reaches no result.

- **The guard triggers no panic.** A test that triggered the panic would assert third-party
  behavior, and a dependency bump can change that behavior. Such a test would also leave the
  repository free to add the call the guard exists to prevent.
- **An exception carries a reason.** One entry of `directDecodeException` states one file, the
  count of call sites on it, and why the call is safe. The table is empty on 2026-08-14.
- **A stale exception fails.**
  `TestTheDirectDecodeExceptionTableHoldsNoStaleEntry` fails on an entry that excuses a call
  the tree no longer holds.
- **The guard reads a call whose function is a selector.** It reads no call that reaches the
  method through a function value.

`TestTheGopacketPanicRecordCitesThePinnedVersion` holds this page against `go.mod`. A
version bump fails that test, and the reader then reads `layers/tcp.go` again at the new
version. `.claude/rules/external-apis.md` bars a description of an external interface from
memory.

## What this record does not do

- **#510 moved no pin, and #721 moved it on 2026-08-15.** Issue #510 stated a third candidate
  answer: report the defect upstream and move the pin when a release repairs it. **The
  Dependabot pull request #721 took that answer**, and `## The repair at v1.7.1` above holds
  the reading. **The bump changes `go.mod` and `go.sum` alone, and it moves the Go language
  version of this module from 1.24 to 1.25.** `github.com/gopacket/gopacket@v1.7.1` declares
  `go 1.25.0` in its own `go.mod`, and Go requires the main module to declare a language
  version at or above every dependency. **That move is a maintainer question, and this page
  rules nothing.** Pull request #730 states the question, and #721 changed no requirement and
  no guard that names 1.24.
- **It vendors nothing, and it patches nothing.**
- **It moves no fingerprint value.** The deviation count and the match count of the
  conformance suite are equal before this record and after it.
