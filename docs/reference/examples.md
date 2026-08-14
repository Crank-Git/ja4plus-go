# Examples

**`examples/` holds one runnable Go program for each Go code sample of this site.** A
reader who wants to run a sample builds the program rather than copying the page.

## The programs

| Program | What it shows | The page it mirrors |
|---|---|---|
| `examples/readcapture` | Reads a capture file through one `Processor` and prints each result. | [Usage](../usage.md#read-a-capture-file) |
| `examples/shardedprocessors` | Routes each packet to one of four `Processor` goroutines. | [Concurrency](../concurrency.md) |
| `examples/syncprocessor` | Shares one `SyncProcessor` across four worker goroutines. | [Concurrency](../concurrency.md) |

Read the source at
[`examples/`](https://github.com/Crank-Git/ja4plus-go/tree/master/examples).

## Run one

Each program reads `capture.pcap` from the working directory, and none of them reaches the
network.

    go run ./examples/readcapture

**No program needs the FoxIO corpus.** `make corpus` fetches that corpus for the
conformance suite, and no example reads it.

## The page and the program are held equal

**A code sample that nothing compiles rots at the first rename.** So every fenced Go block
of this site is mirrored twice, and a test holds each mirror equal to the page.

| The mirror | What compiles it |
|---|---|
| `examples/<name>/main.go` | `go build ./examples/...`, which runs on every pull request. |
| An example function of `example_test.go` | `go test`, which type-checks it on every run. |

`docs_go_samples_test.go` holds the three equal. **It compares the Go token sequence, after
the comments and the semicolons are removed.**

- A reindent, an added blank line and an edited comment each pass.
- A renamed variable, a changed literal and a dropped call each fail.

That file states the rule, the two rules it rejected, and the measurement of each case.

**Edit a page and its two mirrors in one commit.** A page edited alone reddens the build,
and the message names the page and the line.
