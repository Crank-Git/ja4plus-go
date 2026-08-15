# Processors

**A processor runs every fingerprinter on each packet and joins the results.** It is the
entry point most callers use, and the [Usage](../usage.md) page holds the runnable code.

## The two processors

| Type | Constructor | What it is for |
|---|---|---|
| [`Processor`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor) | [`NewProcessor`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewProcessor) | One goroutine. The per-packet path acquires no lock. |
| [`SyncProcessor`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor) | [`NewSyncProcessor`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewSyncProcessor) | Any number of goroutines. One mutex serializes every call. |

**`SyncProcessor` exposes no way to reach the inner `Processor`.** A caller who reaches it
can break the contract, so the type holds it unexported.

**The [Concurrency](../concurrency.md) page states which pattern to pick and why.** It
holds the whole contract, and this page repeats none of it.

## The methods

**Both types declare the same six methods, and the signatures are identical.** So a caller
changes one constructor call to move between them.

| Method | What it returns | `Processor` | `SyncProcessor` |
|---|---|---|---|
| `ProcessPacket` | The results of one packet, and the non-fatal errors. | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.ProcessPacket) | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor.ProcessPacket) |
| `GetShardKey` | One routing key for both directions of one connection. | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.GetShardKey) | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor.GetShardKey) |
| `CloseOpenWindows` | The value of the window each fingerprinter holds open. | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.CloseOpenWindows) | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor.CloseOpenWindows) |
| `CloseConnectionWindow` | The value of the window one named connection holds open. | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.CloseConnectionWindow) | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor.CloseConnectionWindow) |
| `CleanupConnection` | Nothing. It removes the state of one named connection. | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.CleanupConnection) | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor.CleanupConnection) |
| `Reset` | Nothing. It clears the state of every fingerprinter. | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.Reset) | [link](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SyncProcessor.Reset) |

**`ProcessPacket` returns a slice of errors and not one error.** A packet can reach every
fingerprinter, so more than one of them can report a non-fatal failure on one packet.

**`GetShardKey` returns an empty string for a packet that carries neither TCP nor UDP**, and
the caller decides what to do with it.

**Three of the six close or drop state, and a reader that skips them loses a value or leaks
memory.** The [Usage](../usage.md#close-the-open-windows-at-the-end-of-the-input) page
states when to call each one. Two properties that a caller reads here rather than there:

- **`CloseConnectionWindow` removes the connection**, so a second call returns an empty
  slice.
- **`CloseOpenWindows` starts a new window on each connection**, so a second call with no
  packet between the two returns an empty slice.

## The one-shot functions

**A one-shot function reads one packet through a fingerprinter it builds and discards.** It
serves a caller that holds no connection state, and it returns the bare value as a string.

| Function | Method | Argument |
|---|---|---|
| [`ComputeJA4`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4) | [JA4](../methods/ja4.md) | One packet. |
| [`ComputeJA4S`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4S) | [JA4S](../methods/ja4s.md) | One packet. |
| [`ComputeJA4H`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4H) | [JA4H](../methods/ja4h.md) | One packet. |
| [`ComputeJA4T`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4T) | [JA4T](../methods/ja4t.md) | One packet. |
| [`ComputeJA4TS`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4TS) | [JA4TS](../methods/ja4ts.md) | One packet. |
| [`ComputeJA4D`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4D) | [JA4D](../methods/ja4d.md) | One packet. |
| [`ComputeJA4D6`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4D6) | [JA4D6](../methods/ja4d6.md) | One packet. |
| [`ComputeJA4XFromPacket`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4XFromPacket) | [JA4X](../methods/ja4x.md) | One packet. |
| [`ComputeJA4XFromDER`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4XFromDER) | [JA4X](../methods/ja4x.md) | The DER bytes of one certificate. |
| [`ComputeJA4XFromPEM`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ComputeJA4XFromPEM) | [JA4X](../methods/ja4x.md) | The PEM bytes of one certificate. |

**Each one returns an empty string for a packet that carries no input it reads.** It returns
no error, so a caller that needs the reason keeps a fingerprinter instead.

**Two limits follow from the discarded fingerprinter, and each one changes the value.**

- **`ComputeJA4TS` carries no part e.** The packet it reads is always the first SYN-ACK of
  its connection, and part e measures the delays between later ones. A caller that needs
  part e keeps one `JA4TSFingerprinter` across the packets of the connection.
- **`ComputeJA4XFromPacket` reassembles no stream.** A certificate that spans more than one
  packet needs `JA4XFingerprinter`.

**JA4L, JA4LS and JA4SSH reach no one-shot function.** Each one measures a run of packets,
so one packet states nothing.
