# API reference

**This section indexes the exported surface of the library, and it links each name to the
generated documentation.** It answers one question: which name do I call, and where do I
read its signature.

## The reference is hand-written, and it adds no generator

**Go already publishes a canonical API surface at `pkg.go.dev`**, and the module proxy
builds it from the doc comments of this library. A second generated copy would drift from
that surface, and a check for the drift would cost more than these pages are worth. **This
section is therefore hand-written, and it adds no generator.**

**So no page of this section repeats a signature.** A copied signature goes stale at the
first change, and a reader who trusts it reaches a compiler error. Each page states what a
name is for, and the link states what it takes and what it returns.

## The pages

| Page | What it indexes |
|---|---|
| [Fingerprinters](fingerprinters.md) | One type for each JA4+ method, and the three interfaces a caller asserts against. |
| [Processors](processors.md) | `Processor`, `SyncProcessor` and the one-shot functions. |
| [Types and helpers](types.md) | The result types, the key log, the database lookup and the interpretation helpers. |
| [Examples](examples.md) | The runnable programs of `examples/`. |

## What this section leaves to another page

- **What a method means, and what its value holds.** The [Methods](../methods/index.md)
  section holds one page for each one. This section names the Go type and links there.
- **How to run the program and the library.** The [Usage](../usage.md) page holds it.
- **Which goroutine may call which method.** The [Concurrency](../concurrency.md) page
  holds the contract, and every page of this section defers to it.

## The import path

The module is `github.com/Crank-Git/ja4plus-go`, and the package name is `ja4plus`. **The
two differ, so an import that does not name the package reads a name the compiler does not
hold.** Every sample of this site therefore writes the alias:

    ja4plus "github.com/Crank-Git/ja4plus-go"

**The module exports two packages, and each one answers a different question.**

| Import path | Package | What it holds |
|---|---|---|
| `github.com/Crank-Git/ja4plus-go` | `ja4plus` | Every fingerprinter, `Processor`, and the local database lookup. |
| `github.com/Crank-Git/ja4plus-go/ja4db` | `ja4db` | The remote lookup at `ja4db.com`. |

**`ja4db` is the one package of the library that reaches the network.** The maintainer
ruled that boundary on 2026-08-14, and `internal/repocheck/network_boundary_test.go` fails on an import that
breaks it. So a caller who imports `ja4plus` alone links no HTTP client.

**`internal/parser`, `internal/keylog`, `internal/dbcache` and every other `internal`
package reach no caller outside this module**, and no page of this section indexes one. The
Go toolchain enforces that boundary.

## How a link to the generated documentation is written

**Each name below links to `https://pkg.go.dev/github.com/Crank-Git/ja4plus-go`, followed
by an anchor.** The anchor is the identifier for a top-level name, and it is
`Type.Member` for a method and for a struct field.

| What is linked | The anchor | Example |
|---|---|---|
| A function, a type, a variable | `#Name` | [`NewProcessor`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#NewProcessor) |
| A method or a field | `#Type.Member` | [`Processor.ProcessPacket`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#Processor.ProcessPacket) |

**The anchor form was confirmed against a live page and never from memory**, which
`.claude/rules/external-apis.md` requires.
`https://pkg.go.dev/github.com/gopacket/gopacket@v1.6.1` was read on 2026-08-14. Its markup
holds each of these.

- `id="NewPacket"`, for a function.
- `id="CaptureInfo"`, for a type.
- `id="PacketSource.NextPacket"`, for a method.
- `id="CaptureInfo.Timestamp"`, for a struct field.
- `id="DecodingLayer.CanDecode"`, for an interface method.

## The generated page renders the documentation, and this states what changed

**`https://pkg.go.dev/github.com/Crank-Git/ja4plus-go` answers 200 and it renders the
documentation.** The served markup was read on 2026-08-16 UTC, and it holds each of these.

- The version `v1.0.0`, with `Published: Aug 15, 2026`.
- The license `BSD-3-Clause`.
- `id="NewProcessor"` and `id="Processor.ProcessPacket"`, which are two anchors of the
  table above.
- No `None detected`, and no `Documentation not displayed due to license restrictions`.

**That license label is the one the generator detects from `LICENSE`, and it is not the
license of every method.** `NOTICE` holds the FoxIO License 1.1 terms, and
`docs/specs/features/01-licensing.md` states the split.

**The page served no documentation until the `v1.0.0` tag, and the cause was measurable.**
Read on 2026-08-14, it stated `License: None detected` and:

> Documentation not displayed due to license restrictions.

**The latest tag was `v0.3.0` on that date, and that tag carries no `LICENSE` file.**
`git show v0.3.0:LICENSE` reports
`fatal: path 'LICENSE' exists on disk, but not in 'v0.3.0'`. **The `v1.0.0` tag carries
`LICENSE` and `NOTICE`**, measured on 2026-08-16 UTC, so it gives the generator a license
to detect.

**Every link of this section resolves to the right page and to the right anchor.** The
links name no version, so each one follows the latest version the generator holds, which is
`v1.0.0`. Issue [#593](https://github.com/Crank-Git/ja4plus-go/issues/593) recorded the
question that the old measurement raised, and it is closed.

Verified against: <https://pkg.go.dev/github.com/Crank-Git/ja4plus-go>, retrieved
2026-08-16.

**`go doc` reads the same doc comments from the module itself, and it needs no network.**
Run `go doc github.com/Crank-Git/ja4plus-go` for the index, and
`go doc github.com/Crank-Git/ja4plus-go.Processor` for one name.

## The exported surface freezes at `v1.0.0`

`v1.0.0` freezes every name this section indexes. **A name that is absent here is a name
the library does not export**, and `internal` holds the rest.
