# API reference

**This section indexes the exported surface of the library, and it links each name to the
generated documentation.** It answers one question: which name do I call, and where do I
read its signature.

## The reference is hand-written, and it adds no generator

`docs/specs/features/14-documentation.md` states the design:

> The API reference is hand-written and links to `pkg.go.dev`. Do not add a generator; Go already publishes a canonical generated surface from the same doc comments.

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

**`internal/parser`, `internal/keylog` and every other `internal` package reach no caller
outside this module**, and no page of this section indexes one. The Go toolchain enforces
that boundary.

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

## The generated page serves no documentation today, and this states why

**`https://pkg.go.dev/github.com/Crank-Git/ja4plus-go` answers 200 and it renders no
documentation.** Read on 2026-08-14, the page states `License: None detected` and:

> Documentation not displayed due to license restrictions.

**The cause is measurable. The latest tag is `v0.3.0`, and that tag carries no `LICENSE`
file.** `git show v0.3.0:LICENSE` reports
`fatal: path 'LICENSE' exists on disk, but not in 'v0.3.0'`. The working tree holds
`LICENSE` and `NOTICE`, so a later tag that carries both gives the generator a license to
detect.

**Every link of this section resolves to the right page and to the right anchor.** The
target renders the documentation when a tagged version carries the license. The links name
no version, so each one follows the latest version the generator holds. Issue
[#593](https://github.com/Crank-Git/ja4plus-go/issues/593) records the question for the
maintainer.

**`go doc` reads the same doc comments from the module itself, and it needs no network.**
Run `go doc github.com/Crank-Git/ja4plus-go` for the index, and
`go doc github.com/Crank-Git/ja4plus-go.Processor` for one name.

## The exported surface freezes at `v1.0.0`

`v1.0.0` freezes every name this section indexes. **A name that is absent here is a name
the library does not export**, and `internal` holds the rest.
