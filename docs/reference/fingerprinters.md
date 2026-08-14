# Fingerprinters

**A fingerprinter is the Go type that reads packets and produces the value of one JA4+
method or two.** This page indexes each one and the three interfaces a caller asserts
against. The [Methods](../methods/index.md) section states what each value holds, and it
states which type carries which method.

**A caller who wants every method at once builds one [`Processor`](processors.md) rather
than one fingerprinter at a time.**

## The types

Each row names the constructor and the type. Read the method page for the value, and read
the linked signature for the arguments.

| Type | Constructor | Method page |
|---|---|---|
| [`JA4Fingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4Fingerprinter) | [`NewJA4`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4) | [JA4](../methods/ja4.md) |
| [`JA4SFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4SFingerprinter) | [`NewJA4S`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4S) | [JA4S](../methods/ja4s.md) |
| [`JA4HFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4HFingerprinter) | [`NewJA4H`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4H) | [JA4H](../methods/ja4h.md) |
| [`JA4XFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4XFingerprinter) | [`NewJA4X`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4X) | [JA4X](../methods/ja4x.md) |
| [`JA4SSHFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4SSHFingerprinter) | [`NewJA4SSH`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4SSH) | [JA4SSH](../methods/ja4ssh.md) |
| [`JA4LFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4LFingerprinter) | [`NewJA4L`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4L) | [JA4L](../methods/ja4l.md) and [JA4LS](../methods/ja4ls.md) |
| [`JA4TFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4TFingerprinter) | [`NewJA4T`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4T) | [JA4T](../methods/ja4t.md) |
| [`JA4TSFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4TSFingerprinter) | [`NewJA4TS`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4TS) | [JA4TS](../methods/ja4ts.md) |
| [`JA4DFingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4DFingerprinter) | [`NewJA4D`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4D) | [JA4D](../methods/ja4d.md) |
| [`JA4D6Fingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4D6Fingerprinter) | [`NewJA4D6`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewJA4D6) | [JA4D6](../methods/ja4d6.md) |

**One row of that table names two method pages.** The [Methods overview](../methods/index.md)
states the reading, and it states the two counts that a reader must not exchange.

**`NewJA4SSH` takes an argument, and no other constructor does.** The
[Usage](../usage.md#processor-and-the-individual-fingerprinters) page states the argument
and the default, and the [JA4SSH](../methods/ja4ssh.md) page states what a window is.

## The three methods every fingerprinter carries

Every type above implements
[`Fingerprinter`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Fingerprinter), which
declares `ProcessPacket`, `Reset` and `CleanupConnection`. The
[Usage](../usage.md#processor-and-the-individual-fingerprinters) page states what each one
does and when a caller calls it.

**A fingerprinter returns a non-fatal error, and it never panics.** A packet it cannot read
produces no result and one error, so a reader of a malformed capture keeps running.

## The two window interfaces

**A window is a run of packets that produces one value at its end.** JA4SSH holds one, and
no other method of this library does. So a caller reaches the value through a type
assertion rather than through a method of `Fingerprinter`.

| Interface | Its one method | When the caller calls it |
|---|---|---|
| [`WindowCloser`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#WindowCloser) | [`CloseOpenWindows`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#WindowCloser.CloseOpenWindows) | The packet source ended. |
| [`ConnectionWindowCloser`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ConnectionWindowCloser) | [`CloseConnectionWindow`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ConnectionWindowCloser.CloseConnectionWindow) | The monitor evicted one connection. |

**Each interface declares one capability, as `http.Flusher` and `http.Hijacker` each do.**
A type that implements one keeps the dispatch of that one. `Processor` skips a
fingerprinter that implements neither, because such a fingerprinter holds no window open.

**`Fingerprinter` gains no method here, and the reason is the freeze.** A new method on an
exported interface breaks every third-party implementation, which `v1.0.0` forbids for the
whole `v1` series.

## One fingerprinter serves one goroutine

**Every type on this page holds state that no lock guards.** Two goroutines that share one
fingerprinter write a data race, and the race detector reports it. The library does not
detect it at run time.

The [Concurrency](../concurrency.md) page states the two patterns that reach more than one
goroutine, and it holds the runnable code for each one.

## The JA4SSH extra method

[`GetHASSHFingerprints`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#JA4SSHFingerprinter.GetHASSHFingerprints)
returns the HASSH values that the SSH handshakes produced. HASSH is not a JA4+ method, and
[Types and helpers](types.md) indexes the result type.
