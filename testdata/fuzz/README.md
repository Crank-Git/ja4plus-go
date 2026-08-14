# The fuzz seed corpus

This directory holds the seed inputs of the fuzz targets of the root package. The seed
inputs of `internal/parser` live at `internal/parser/testdata/fuzz/`, because Go reads
`testdata/fuzz/<TargetName>/` under the directory of the package that holds the target.

`docs/specs/features/06-fuzz-testing.md` states FR-fuzz-19 through FR-fuzz-24. Issue #46
built this corpus.

## What each file is

One file holds one seed input, in the `go test fuzz v1` format. The first line names the
format, and each later line holds one argument of the fuzz function.

`go test ./...` replays every file of every target. A replay that panics fails the ordinary
test run, so a seed is a permanent regression guard and not a fuzzer hint alone.

The name of a file states the behavior it holds.

| Prefix | What it holds |
|---|---|
| `accepts-` | An input the code accepts. FR-fuzz-20 states the requirement. |
| `rejects-` | An input the code rejects. FR-fuzz-21 states the requirement. |
| `issue-<n>-` | A crash the fuzzer found. FR-fuzz-24 states the requirement. |

`internal/parser/testdata/fuzz/FuzzParseServerHelloReadsAnyPayload/issue-556-supported-versions-declares-data-the-record-holds-not`
is the worked example of FR-fuzz-24. `FuzzParseServerHelloReadsAnyPayload` found that
crash in 1.14 seconds on its first 30-second run, #556 repaired the parser, and the input
now replays green. **Never remove a file with an `issue-` prefix.**

## Two tests guard this corpus

`fuzz_seed_corpus_test.go` of each package builds every seed of that package, and it
asserts the verdict of the code for each one. It then compares the tracked file against the
value it built. So a seed cannot drift from the statement above it, and a target cannot
lose its accepted input or its rejected input without a failure.

Run `JA4PLUS_SEEDGEN=1 go test ./...` to write the files after a deliberate change.

**Never set `JA4PLUS_SEEDGEN` in a CI job.** The variable switches the two tests above from
compare to write. A job that sets it rewrites every seed to match whatever the code now does,
and it then reports success whatever the code does. **The guard can never fail after that.**
An engineer sets the variable by hand, and a workflow file never sets it.

Two checks hold this rule, and #47 built both.

- The fuzz job of `.github/workflows/ci.yml` and the fuzz job of `.github/workflows/fuzz.yml`
  each refuse a run that carries the variable.
- `TestNoWorkflowSetsTheSeedGenerationVariable` in `fuzz_job_test.go` reads both workflow
  files for an assignment and for an environment key.
  `TestEachFuzzJobRefusesASeedCorpusWrite` reads both jobs for the refusal.

**Read the seed diff before you commit a write.** The variable makes the tracked file agree
with the code, so a write hides a defect exactly as well as it records a deliberate change.

## The license reading of FR-fuzz-23

**FR-fuzz-23 tracks this corpus in git, and `.gitignore` excludes the FoxIO corpus at
`testdata/foxio/`.** The two rules agree, because no file of this directory holds a byte of
a FoxIO capture.

**Every seed is built, and no seed is copied.** A seed comes from one of two sources.

1. **A synthesized value.** The test builds the record from the helpers of this repository.
   `accepts-a-synthesized-version-1-initial-packet-that-carries-a-client-hello` is the
   strongest case: it is a QUIC version 1 Initial packet that the parser decrypts, and RFC
   9001 Section 5.2 states the public derivation that makes such a packet buildable from a
   connection identifier of our own choice.
2. **A reduction of a FoxIO record.** `scripts/seed-fuzz.sh` reads the corpus and writes
   the three files that carry the `-reduced-` mark in the name.

**The reduction reads these numbers of a captured record, and it reads nothing else.**

- The protocol version.
- The cipher suite identifiers, in order.
- The TLS extension identifiers, in order.
- The HTTP method, and the HTTP header names, in order.

**The script then builds a new record from those numbers.** Every other field holds a fixed
filler that the script states.

- The random field holds 32 zero bytes.
- The session identifier is empty.
- The server name is `example.invalid`.
- The application protocol is `h2`.
- Every header value is `x`.

**So the output holds no value of the capture from any of these fields.**

- The random field.
- The session identifier.
- The key share.
- The host name.
- The header value.
- The certificate.
- The payload.

**Each number the reduction keeps is an identifier of an IANA registry.** A cipher suite
number, a TLS extension number and an HTTP field name are the words of a public protocol.
A record that lists them states a fact about a client. The reduction therefore carries the
fact and it drops the expression, and the result carries no FoxIO license obligation.

**A seed that fails this test is not committed.** One case reached that decline, and the
verdict of #46 names it: a QUIC Initial packet of the corpus authenticates its own bytes
with an AEAD tag, so no reduction of it survives. The corpus therefore holds a synthesized
Initial packet in place of a captured one, and the synthesized packet decrypts.

## The formats this script reads

`scripts/seed-fuzz.sh` reads a classic pcap file, and it reads no pcapng file. A classic
pcap file states one link type in its header and one length before each packet. **24 of the
38 captures of the corpus carry a classic pcap magic number**, measured on 2026-08-14 at
the commit that `testdata/foxio.pin` holds. A pcapng file carries block types, options and
an interface table, and the reduction needs none of that.

Two limits follow, and neither one loses a seed.

- The script reads a file whose name ends `.pcap`, and 21 files of the corpus carry that
  name.
- `scripts/seed-fuzz-reduce.awk` reads the little-endian byte order alone. It declines
  every other file, and the script then reads the next capture.

The script reports the capture that each seed came from, and it names the target.

The script writes nothing when `testdata/foxio/pcap` is absent. A fresh clone holds no
corpus, and the tracked seeds of this corpus need no fetch.
