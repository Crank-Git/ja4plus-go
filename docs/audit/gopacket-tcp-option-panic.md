# The gopacket TCP option panic

**This file records a defect of a pinned dependency, and it makes no decision.** Issue #510
holds the record, and issue #494 met the defect in its own first commit.

`CLAUDE.md` states that every packet is untrusted input, and that a fingerprinter returns a
non-fatal error and never a panic. **An ICMP payload is exactly the input that rule exists
for**, so the defect belongs in the record rather than in a comment alone.

**This file states no ruling.** `.claude/rules/rulings.md` reserves a ruling for the
maintainer.

## What panics

`go.mod` pins `github.com/gopacket/gopacket v1.6.1`. At that version,
`layers.TCP.DecodeFromBytes` reads two bytes of a Multipath TCP option without a length
guard, at `layers/tcp.go:347-353`:

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

## The library crashes on no packet today

**No production line of this repository calls `DecodeFromBytes`**, measured on 2026-08-14.
Every fingerprinter reads a packet that `gopacket.NewPacket` decoded, and `cmd/ja4plus`
builds each packet through that call.

**The recovery of `gopacket.NewPacket` covers no direct call.** So a later production line
that calls the method on untrusted bytes adds a crash path that no recovery reaches.

## The guard

`gopacket_direct_decode_test.go` holds the guard, and
`TestNoProductionFileCallsDecodeFromBytesDirectly` is its name.

**The guard holds a property of this repository: no line outside a test calls
`DecodeFromBytes`.** It reads the abstract syntax tree of each production Go file, so a
comment that names the method reaches no result.

- **The guard triggers no panic.** A test that triggered the panic would assert third-party
  behavior that a dependency bump can change, and it would leave the repository free to add
  the call the guard exists to prevent.
- **An exception carries a reason.** `directDecodeException` records one production file, the
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

- **It moves no pin.** Issue #510 states a third candidate answer: report the defect upstream
  and move the pin when a release repairs it. **That answer stays open**, and this record
  neither adopts it nor declines it.
- **It vendors nothing, and it patches nothing.**
- **It moves no fingerprint value.** The deviation count and the match count of the
  conformance suite are equal before this record and after it.
