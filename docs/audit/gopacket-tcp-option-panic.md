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
pins `v1.7.1` today.** #721 moved the pin on 2026-08-15, and `## The repair at v1.7.1` below
holds the second reading. **This section reads v1.6.1, and it reads no later version.**

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
