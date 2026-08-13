# The dependency decision

**This file records a reading. It records no decision, and it makes none.** The maintainer
decides whether this project moves from `github.com/google/gopacket` to another candidate.
`.claude/rules/rulings.md` states that rule.

Risk R5 of `docs/specs/spec.md` holds the open question. FR-supply-25 through FR-supply-29
of `docs/specs/features/07-supply-chain.md` state what this file must hold. Issue #70
produced it.

**Every measurement below carries the date 2026-08-13. Two branches produced them.** Issue
#70 measured on `issue/70-gopacket-dependency-decision`, and issue #434 measured on
`issue/434-gopacket-fork-measurement`. Each section of #434 names its branch, and every
other section carries the branch of #70. A reader who repeats a measurement runs the
command that the same section names.

## The question the maintainer answers

**Does this project keep `github.com/google/gopacket` v1.1.19, or does it move to
`github.com/gopacket/gopacket`?**

Three facts make the question urgent, and `## When the answer must land` states them
together.

1. A move changes the type that every exported signature of this library names.
2. Epic 10 freezes the exported API, so a move after Epic 10 needs a `v2` path.
3. Epic 13 builds the monitor on `pcapgo.NewEthernetHandle`, so a move after Epic 13
   carries the monitor as well as the parser.

## The last release date of each candidate

FR-supply-26 asks for this table. Each row cites the Go checksum database proxy, which
publishes the version and the time of each release. The command is
`curl -s https://proxy.golang.org/<path>/@latest`.

| Candidate | Latest release | Release date | Source |
|---|---|---|---|
| `github.com/google/gopacket` | `v1.1.19` | 2020-10-19 | `{"Version":"v1.1.19","Time":"2020-10-19T16:12:32Z"}` |
| `github.com/gopacket/gopacket` | `v1.7.1` | 2026-08-09 | `{"Version":"v1.7.1","Time":"2026-08-09T04:45:16Z"}` |

**Risk R5 of `docs/specs/spec.md` states the wrong year, and this measurement refutes it.**
R5 at :935 states:

> `github.com/google/gopacket` has had no release since v1.1.19 in 2022.

The proxy reports 2020-10-19 for that release. **The gap is five years and ten months, and
not three years.** Issue #70 reports the correction, and the writer of `docs/specs/spec.md`
repairs the sentence.

### What each repository looks like today

The command is `curl -s https://api.github.com/repos/<owner>/<name>`.

| Field | `google/gopacket` | `gopacket/gopacket` |
|---|---|---|
| `archived` | `false` | `false` |
| `pushed_at` | `2025-03-19T23:47:36Z` | `2026-08-09T05:04:59Z` |
| `open_issues_count` | `370` | `17` |
| `stargazers_count` | `6792` | `310` |

**`google/gopacket` publishes no GitHub release record.** The command
`curl -s https://api.github.com/repos/google/gopacket/releases?per_page=3` returns an empty
list, and the tag list ends at `v1.1.19`.

### The release history of the candidate fork

| Version | Release date | The Go version its `go.mod` states |
|---|---|---|
| `v1.1.1` | 2023-06-27 | Not read. |
| `v1.6.1` | 2026-06-04 | `go 1.24.0` |
| `v1.7.0` | 2026-07-03 | `go 1.25.0` |
| `v1.7.1` | 2026-08-09 | `go 1.25.0` |

**`v1.7.1` states two different Go versions, and the two contradict each other.** Its
`go.mod` states `go 1.25.0`. Its `README.md` states:

> Minimum Go supported is 1.24.0

**`docs/specs/spec.md` Assumption 1 accepts a Go 1.24 floor**, and `CLAUDE.md` states
`Go 1.24 or later`. So `v1.7.0` and `v1.7.1` raise the floor of this project, and `v1.6.1`
does not.

### What the candidate fork claims

`README.md` of `v1.7.1` states the reason the fork exists:

> Forked from the popular gopacket [repo](https://github.com/google/gopacket) by Google, this fork was created to ensure the project doesn't become stale and bugfixes, new protocols and performance improvements can be merged into it. submit your PRs here :)

**The README claims no compatibility with the original, and it names no migration path.**
`## What a move costs` below measures the compatibility that this project needs.

## The import surface this library reaches

A migration costs the surface, and never the dependency count. The command is
`grep -rl 'github.com/google/gopacket' --include='*.go' .`

- **54 files hold an import path of `gopacket`.** 39 of them are a test file, and 15 are
  not. **The tree has moved since, and #434 counts 55.**
  `### The count of files a migration changes` below holds the later count.
- **The tree names three import paths.** `github.com/google/gopacket`,
  `github.com/google/gopacket/layers` and `github.com/google/gopacket/pcapgo`.
- **Two files reach `pcapgo`**: `cmd/ja4plus/main.go:20` and `integration_test.go:12`. Each
  one calls `pcapgo.NewReader` and `pcapgo.NewNgReader` alone.

The code outside a test file names six identifiers of `gopacket` and 37 identifiers of
`layers`. The six are `CaptureInfo`, `Default`, `Layer`, `LayerType`, `NewPacket` and
`Packet`.

**The measurement unpacked the published archive of `v1.7.1`, and it searched for the
declaration site of each of those 43 names. It found all 43.** This file reproduces four
of the 43 sites, and a reader who wants the other 39 repeats the search:

- `layers/layertypes.go:24` declares `LayerTypeIPv4`.
- `layers/tcp.go:45` declares `TCPOptionKindMSS`.
- `layers/dhcpv6_options.go:23` declares `DHCPv6OptClientID`.
- `packet.go:725` declares `func NewPacket(data []byte, firstLayerDecoder Decoder, options DecodeOptions) (p Packet)`.

## What a move costs

### Every exported signature of this library names a type of the dependency

**FR-supply-29 asks whether a migration keeps every exported signature unchanged. The text
of each signature stays the same, and the type it names changes.** `types.go:18` states the
interface that every fingerprinter implements:

```go
	ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error)
```

`Processor.ProcessPacket` at `processor.go:123`, `Processor.GetShardKey` at
`processor.go:261`, `SyncProcessor.ProcessPacket` at `sync_processor.go:37`,
`SyncProcessor.GetShardKey` at `sync_processor.go:99` and each `Compute*` one-shot function
name the same type.

**`gopacket.Packet` is an interface, and its methods return types of its own package.**
`packet.go:56` of `v1.1.19` opens the declaration, and `packet.go:70` states
`Layers() []Layer`. The Go specification states the rule for a defined type:

> A named type is always different from any other type.

So the `Layer` of one candidate is not the `Layer` of the other. The two `Packet`
interfaces then hold different method sets. A caller cannot pass one where the other is
expected. **A move is therefore a breaking change for every caller of this library, and the
text of no signature moves.** FR-supply-29 offers two answers, and its second answer covers
this case: Epic 10 records the change.

### The work a move needs

1. `go.mod` and `go.sum` name the new dependency.
2. 54 files change an import path.
3. `make corpus` runs, then `make conformance` runs, and a reader compares the deviation
   set against the set this branch produces.
4. `docs/specs/spec.md` Assumption 1 and `CLAUDE.md` state the Go floor, and `v1.7.0` or
   later raises it.
5. Epic 10 records the change of the exported surface, because the change is breaking.

## `pcapgo.NewEthernetHandle`, which Epic 13 builds on

FR-capture-11 of `docs/specs/features/13-live-capture.md:70` states that the pure-Go
backend uses `pcapgo.NewEthernetHandle`.

**Both candidates declare it, and the two signatures are the same text.**

| Candidate | Where it is declared | The build constraint of the file |
|---|---|---|
| `google/gopacket` v1.1.19 | `pcapgo/capture.go:237` | `// +build linux,go1.9` |
| `gopacket/gopacket` v1.7.1 | `pcapgo/capture.go:291` | `//go:build linux` |

Each one declares:

```go
func NewEthernetHandle(ifname string) (*EthernetHandle, error) {
```

**Neither candidate reaches macOS.** The constraint of each file names Linux alone, so the
`libpcap` build tag stays necessary for the macOS monitor. `docs/specs/features/13-live-capture.md:186`
holds the same reading for the original, and this measurement extends it to the fork.

**`internal/capture/` does not exist on this branch.** The command `ls internal/` reports
`keylog/` and `parser/` alone. So a move today changes no capture code, and a move after
Epic 13 changes `internal/capture/pcapgo_linux.go`.

## The `CGO_ENABLED=0` constraint

`CLAUDE.md` states that the default build holds no cgo, and that it cross-compiles to five
platforms. One build path uses cgo, and the `libpcap` build tag selects it.

**Both candidates keep the same package split, and the split is the mechanism that holds
the constraint.** `pcapgo/doc.go` of the fork at `v1.7.1` states:

> Package pcapgo provides some native PCAP support, not requiring C libpcap to be installed.

Each candidate holds a separate `pcap` package that links libpcap, and this project imports
no `pcap` package.

**A build measurement of `CGO_ENABLED=0 go build ./...` against the fork needs a migration
branch. Issue #434 built one on 2026-08-13, and the command succeeds.**
`### The migration builds, and one test of this tree fails` holds that result.

## The security record of each candidate

The command is
`curl -s -X POST -d '{"package":{"name":"<path>","ecosystem":"Go"}}' https://api.osv.dev/v1/query`.

| Candidate | What OSV reports |
|---|---|
| `github.com/google/gopacket` | `{}`. No advisory. |
| `github.com/gopacket/gopacket` | Two advisories. Each one is `MODERATE`, and each one states `"fixed":"1.6.1"`. |

The two advisories are `GHSA-6r28-9ppf-4hj5` (`CVE-2026-54345`), against the Diameter
option decoder, and `GHSA-g6v3-7xmc-w563` (`CVE-2026-54332`), against the sFlow record
decoder.

**This library reaches neither decoder.** The command
`grep -rn "Diameter\|SFlow\|sflow" --include='*.go' .` returns nothing. The first advisory
states that the Diameter layer belongs to the fork alone:

> The Diameter layer is specific to this gopacket fork (the original google/gopacket has no Diameter layer), so there is no upstream sibling fix.

**Read the empty result for the original carefully.** An unmaintained dependency receives
no advisory and no fix, so an empty result reports no audit. It reports that nobody has
published one.

## What FR-supply-27 asks for, and what a source comparison reveals

**FR-supply-27 asks for every behaviour difference that the conformance suite reveals
between the candidates. That measurement needs a migration branch, and issue #70 changes no
dependency. So issue #70 left the conformance comparison unmeasured.**

**Issue #434 built that branch on 2026-08-13, and
`## The conformance measurement against the fork at v1.6.1` below holds the result.** This
section states what a source comparison reveals, and it states the cost that the
measurement carried.

### The cost of the conformance measurement

1. One branch changes `go.mod`, `go.sum` and the import path of 54 files.
2. `make corpus` fetches the corpus at the pin, then `make conformance` runs.
3. A reader compares the deviation set of that branch against the set of the base.
4. **The base is red today, so the comparison reads two red runs.** On
   `issue/70-gopacket-dependency-decision`, `make conformance` exits 2, `TestConformance`
   fails, and the output holds 1054 lines that name a per-stream deviation or a per-packet
   deviation. **That count reads lines and never distinct deviations.** Epic 5 owns the
   exit code of the base.

### The source comparison, which is measured

The measurement compared each file this library reaches, between `v1.1.19` in the local
build cache and the published archive of `v1.7.1`. It counted the lines that a unified
comparison marks as added or removed.

| File | Changed lines |
|---|---|
| `layers/tcp.go` | 324 |
| `packet.go` | 272 |
| `pcapgo/ngread.go` | 224 |
| `pcapgo/capture.go` | 127 |
| `layers/ip4.go` | 101 |
| `layers/geneve.go` | 93 |
| `layers/gre.go` | 56 |
| `layers/ip6.go` | 37 |
| `pcapgo/read.go` | 32 |
| `layers/dhcpv4.go` | 28 |
| `layers/udp.go` | 25 |
| `decode.go` | 21 |
| `layers/enums.go` | 16 |
| `layers/layertypes.go` | 13 |
| `layers/dhcpv6.go` | 8 |
| `base.go` | 6 |
| `layers/ethernet.go` | 2 |
| `layers/vxlan.go` | 2 |
| `layers/dhcpv6_options.go` | 2 |
| `layertype.go` | 0 |
| **Total** | **1389** |

Each count holds the one line that changes the import path.

### Four differences that touch a fingerprint value

**1. The Geneve option decoder reads different bits.** `layers/geneve.go` of `v1.1.19`
states:

```go
	opt.Flags = data[3] >> 4
	opt.Length = (data[3]&0xf)*4 + 4
```

`layers/geneve.go` of `v1.7.1` states:

```go
	opt.Flags = data[3] >> 5
	opt.Length = (data[3]&0x1f)*4 + 4
```

`internal/parser/packet.go:33` names `LayerTypeGeneve` inside `isTunnelLayerType`, and the
corpus holds `tcpdump-geneve.pcap`. **A different option length moves the inner layer that
`TunnelDepth` and `CheckTunnel` read.**

**2. The TCP option decoder gains option kind 30, and it returns an error for a malformed
one.** `v1.1.19` names no case for kind 30, so it records the option and it continues.
`v1.7.1` adds `case TCPOptionKindMultipathTCP:` and it returns an error from
`DecodeFromBytes` for several malformed forms, for example:

```go
				return fmt.Errorf("MP_CAPABLE bad option length %d", opt.OptionLength)
```

**JA4T and JA4TS read the TCP option list.** A decode error produces no TCP layer, so a
capture that holds a malformed option of kind 30 produces no JA4T value under the fork.

**3. `TCP` and `TCPOption` gain fields.** `TCP` gains `Multipath bool`, and `TCPOption`
gains ten fields. **No file of this tree builds a `layers.TCPOption` with unkeyed fields**,
so the added fields break no build here. The command
`grep -rln 'layers.TCPOption{' --include='*.go' .` names six files, and each site names its
fields. The six are `ja4t_two_digit_test.go`, `ja4t_test.go`,
`ja4t_option_byte_count_test.go`, `ja4ts_part_e_test.go`, `ja4ts_test.go` and
`benchmark_test.go`.

**4. The checksum computation changes.** `v1.7.1` wraps the result of
`computeChecksum` in `gopacket.FoldChecksum`. The tests of this tree build packets with
`ComputeChecksums: true`, and no test of this tree asserts a checksum value.

### One capability the fork adds, and this project holds its own copy of it

`pcapgo` of the fork holds `ngread_dsb.go`, which reads a decryption secrets block.
`internal/keylog/pcapng.go:46` states why this project holds its own reader:

> `gopacket` v1.1.19 discards a Decryption Secrets Block, so this reader reads the block.

**A move therefore offers a later issue the option to delete a file of this project.** That
option is not part of the question this file records, and no requirement asks for it.

## The conformance measurement against the fork at v1.6.1

**The maintainer authorized a throwaway migration branch on 2026-08-13, and issue #434 ran
it.** Every measurement of this section carries that date and the branch
`issue/434-gopacket-fork-measurement`. **Nothing of the migration merges. The branch holds
this file and no other change.**

**The measurement reads `github.com/gopacket/gopacket` v1.6.1, and it reads no later
version.** v1.6.1 states `go 1.24.0` in its own `go.mod`, so it holds the Go floor that
Assumption 1 of `docs/specs/spec.md` accepts. The command is
`curl -s https://proxy.golang.org/github.com/gopacket/gopacket/@v/v1.6.1.mod`, and it
returns:

```
module github.com/gopacket/gopacket

go 1.24.0
```

### The count of files a migration changes

The command is `grep -rl 'github.com/google/gopacket' --include='*.go' .`

- **55 Go files hold an import path of `gopacket`.** 40 of them are a test file, and 15 are
  not. **Issue #70 counted 54 on its own branch, and the tree has gained one test file
  since.**
- **`go.mod` and `go.sum` change too, so a build migration changes 57 files.**
- **11 more tracked files name the import path in prose.** The command is
  `git grep -l 'github.com/google/gopacket'`, which reports 68 files in total.
- **The tree names three import paths**, and the count of each name is 54, 41 and 2. The
  command is `grep -rhoE 'github\.com/google/gopacket(/[a-z0-9]+)?' --include='*.go' .`

**`rtk` filters the output of a `git` command, and a count taken through it is wrong.**
`git diff --name-only | wc -l` reported 58 for a diff of 55 files, and
`git status --porcelain | wc -l` reported 54 for the same diff. `rtk proxy git ...` reports
55 for each one. **Read a file count through `rtk proxy`, or from `git diff --numstat`.**

### The migration builds, and one test of this tree fails

**`go build ./...` succeeds, and `CGO_ENABLED=0 go build ./...` succeeds.** So the fork
holds the cgo constraint that `CLAUDE.md` states. **Issue #70 named that build an open
question, and this measurement answers it**, so `## What this file does not answer` no
longer carries it.

**`go test -race ./...` fails one test, and that test reads `go.mod`.**
`foundation_test.go:27` declares `TestGoModDeclaresGo124`, and `foundation_test.go:30`
holds the pattern:

```go
	if !regexp.MustCompile(`(?m)^go 1\.24$`).MatchString(goMod) {
```

**The migration writes `go 1.24.0` in `go.mod`, and the pattern accepts `go 1.24` alone.**
The toolchain writes the longer form, and it refuses the shorter one. `go mod tidy -diff`
reports:

```
-go 1.24
+go 1.24.0
```

**`go build ./...` then refuses the shorter form**, and it prints
``go: updates to go.mod needed; to update it:``. **`github.com/gopacket/gopacket@v1.6.1`
states `go@1.24.0` in the module graph**, and no other module of the graph states a higher
one. So the fork causes the longer form.

**The Go floor does not move.** `go 1.24.0` and `go 1.24` name one language version, and
`CLAUDE.md` states `Go 1.24 or later`. **The guard reads the literal text, and the literal
text moves.** A migration therefore changes `foundation_test.go` as well, and no fingerprint
value is involved.

**No other test fails.** The command `go test -race ./...` reports one failing test in the
root package, and it reports `ok` for `cmd/ja4plus`, for `internal/keylog` and for
`internal/parser`.

### The migration moves three more modules, so it is not a one-variable change

**`go get github.com/gopacket/gopacket@v1.6.1` upgraded three `golang.org/x` modules**, and
it reported:

```
go: upgraded golang.org/x/crypto v0.28.0 => v0.37.0
go: upgraded golang.org/x/net v0.30.0 => v0.39.0
go: upgraded golang.org/x/sys v0.26.0 => v0.32.0
```

**The fork requires `golang.org/x/net@v0.39.0`, and that module requires
`golang.org/x/crypto@v0.37.0`.** The command is `go mod graph`, and it reports
`golang.org/x/net@v0.39.0 golang.org/x/crypto@v0.37.0`. **`golang.org/x/crypto` decodes the
SSH handshake that JA4SSH reads**, so the upgrade is a second variable and it is not
optional.

**No fingerprint value moved under both changes together, so this measurement needs no
attribution run.** A later measurement that finds a moved value must separate the two
modules first.

### The four counts, before and after

The command is `make conformance`, which runs `go test -tags conformance -count=1 -v ./...`
with the corpus present.

| Count | Before | After |
|---|---|---|
| Matches | 1658 | 1658 |
| Deviations | 635 | 635 |
| Accepted deviations | 419 | 419 |
| Register keys | 459 | 459 |
| Stale register entries | 0 | 0 |
| Unaccepted uncovered values | 202 | 202 |
| Accepted uncovered values | 40 | 40 |

The per-set counts hold as well. Each run reports:

```
the per-stream set reports 1103 matches, 82 deviations and 276 accepted deviations
the per-packet set reports 555 matches, 553 deviations and 143 accepted deviations
the run reports 1658 matches, 635 deviations and 419 accepted deviations
```

**The register key count reads `testdata/deviations.json`, which the migration does not
edit.** The file holds 459 entries and 459 distinct keys before and after.

### No comparison moved, and this is how the measurement proves it

**A count that holds can still hide two values that swap, so the measurement compares the
two logs line by line.** It removes each run duration, and it compares the rest.

- **The two logs hold 1054 deviation lines each**, 635 unaccepted and 419 accepted, and the
  two key sets are equal.
- **The one substantive difference between the two logs is `TestGoModDeclaresGo124`.** Every
  other difference is the order of a subtest name, which Go map iteration decides.
- **The run reports 0 stale register entries under the fork.** `conformance_test.go:925`
  calls `t.Errorf` for each entry of the loop that `conformance_test.go:924` opens, so a
  register entry that records a value the run no longer produces fails the suite. A moved
  value inside an accepted deviation would reach that call, and none did.

**So no comparison moved, and the list of moved comparisons is empty.**

### The Geneve difference, which the corpus does not reach

**`layers/geneve.go:68` of the fork at v1.6.1 states:**

```go
	opt.Flags = data[3] >> 5
	opt.Length = (data[3]&0x1f)*4 + 4
```

**`layers/geneve.go:62` of `google/gopacket` v1.1.19 states:**

```go
	opt.Flags = data[3] >> 4
	opt.Length = (data[3]&0xf)*4 + 4
```

**The corpus reaches that decoder.** A probe read every capture under `testdata/foxio/` and
counted each Geneve layer and each Geneve option. It reports:

```
HIT testdata/foxio/pcap/tcpdump-geneve.pcap geneveLayers=39 geneveOptions=19 tcpKind30=0
TOTAL geneveLayers=39 geneveOptions=19 tcpKind30=0 tcpLayers=7163 decodeErrors=0
```

**The two candidates decode those 19 options to one value.** The probe ran once under each
candidate, and each run printed the same line 19 times:

```
GENEVEOPT testdata/foxio/pcap/tcpdump-geneve.pcap class=0 type=128 flags=0 length=8 data=0000000c
```

**One option byte explains the agreement.** A length of 8 needs `data[3]&0x1f` to be 1 under
the fork, and it needs `data[3]&0xf` to be 1 under v1.1.19. A flags value of 0 needs the top
three bits to be 0. So `data[3]` is `0x01`, and the two readings agree on that byte.

**A capture whose option byte sets bit 4 separates the two candidates, and the corpus holds
none.** So the corpus reaches the decoder, and it does not reach the difference.

### The TCP option difference: the corpus reaches neither

**`layers/tcp.go:59` of the fork at v1.6.1 declares
`TCPOptionKindMultipathTCP                    = 30`, and `layers/tcp.go:347` opens a case
for it.** The case returns an error for a malformed option, for example at
`layers/tcp.go:357`:

```go
					return fmt.Errorf("MP_CAPABLE bad option length %d", opt.OptionLength)
```

**`layers/tcp.go` of `google/gopacket` v1.1.19 names no case for kind 30.** The option
reaches the `default:` branch at `layers/tcp.go:285`, which records `opt.OptionData` and
continues.

**The corpus holds no TCP option of kind 30.** The probe above read 7163 TCP layers and it
counted 0 options of kind 30. **It also counted 0 packets with an error layer**, so no
capture produced a decode error under either candidate.

**So the corpus reaches neither half of this difference.** A capture that holds a malformed
option of kind 30 separates the two candidates, and a later measurement needs one.

### How to repeat the measurement

1. Copy the corpus into the worktree with
   `cp -R <checkout>/testdata/foxio testdata/foxio`. **Never symlink it**, because
   `method_count_test.go` reads that path as a file.
2. Run `make conformance` and keep the log.
3. Rewrite the import path with
   `grep -rl 'github.com/google/gopacket' --include='*.go' . | xargs sed -i '' 's|github.com/google/gopacket|github.com/gopacket/gopacket|g'`.
4. Run `go mod edit -droprequire=github.com/google/gopacket`, then
   `go get github.com/gopacket/gopacket@v1.6.1`, then `go mod tidy`.
5. Run `make conformance` again, and compare the two logs.
6. Revert with `git checkout -- .`. **Never run `git stash`**, because
   `.claude/rules/worktrees.md` bars it and the permission layer refuses it.

### What FR-supply-27 asks for, and the answer

**FR-supply-27 asks the record to name every behaviour difference that the conformance
suite reveals between the candidates. The suite reveals none.** Every count holds, every
deviation key holds, and no register entry goes stale.

**That answer reads the corpus, and it reads no other input.** The two source differences
above are real, and the corpus separates neither one. **A behaviour difference that no
capture reaches stays a behaviour difference**, and this measurement bounds the risk rather
than removes it.

### What this measurement does not change

**`## The recommendation, which decides nothing` below keeps every sentence that issue #70
wrote.** That section states that the conformance result is unmeasured, and issue #70 wrote
the sentence before this branch existed. **Issue #434 changes no sentence of that section,
because the maintainer has chosen no candidate.** A reader reads the two sections together,
and the maintainer decides what the measurement means.

## The candidates, and the cost of each

| Candidate | What it costs | What it risks |
|---|---|---|
| **A. Keep `google/gopacket` v1.1.19.** | No work. | The dependency reaches six years without a release. No defect of it is ever repaired. The library keeps its own decryption secrets block reader. |
| **B. Move to `gopacket/gopacket` v1.6.1.** | 57 files, plus `foundation_test.go`. Both published advisories are fixed at this version. The Go floor stays 1.24.0, so Assumption 1 holds. | Every caller breaks. The corpus separates neither the `layers/tcp.go` difference nor the `layers/geneve.go` difference, so each one stays an unbounded risk on a capture the corpus does not hold. The move also upgrades three `golang.org/x` modules. |
| **C. Move to `gopacket/gopacket` v1.7.1.** | The cost of B, plus a Go floor of 1.25.0. | The cost of B, plus a contradiction with Assumption 1 of `docs/specs/spec.md` and with `CLAUDE.md`. |
| **D. Answer after Epic 13.** | The cost of B or C, plus the capture backend that Epic 13 builds. | Epic 10 freezes the API, so a move after Epic 10 needs a `v2` path. |

## The recommendation, which decides nothing

**A recommendation is a reading. The maintainer rules.**

**The reading recommends candidate B, under one condition.** The condition is a measurement:
one branch migrates, `make conformance` runs, and no fingerprint value moves without a
FoxIO reason. **If a value moves, the reading recommends candidate A.** `.claude/rules/parity.md` rule 1
states that FoxIO decides behaviour. A dependency decides none of it.

Three facts support B over A.

1. **A move is breaking, and Epic 10 freezes the API.** So the project moves before the
   freeze, or it stays on `v1.1.19` for the life of `v1`.
2. **The original publishes no release in five years and ten months, and it publishes no
   advisory.** A user of a security tool reads that pair as an unaudited dependency.
3. **The fork shipped the repair for both of its own advisories before GitHub published
   them.** `v1.6.1` carries commit `76119086f5936aacd7088bdf97d565501bb6c4cc` and it
   released on 2026-06-04. `GHSA-g6v3-7xmc-w563` names that same commit as the fix, and
   GitHub published the advisory on 2026-07-28. The fork therefore answers a report.

Two facts support A over B.

1. **The conformance result is unmeasured**, and `layers/tcp.go` and `layers/geneve.go`
   each hold a difference that a fingerprint value can read.
2. **The fork carries two published advisories, and the original carries none.** Each fork
   advisory names a decoder that the fork added.

**B names `v1.6.1` and not `v1.7.1`, because `v1.7.0` raises the Go floor to 1.25.0.** A
maintainer who accepts a Go 1.25 floor reads candidate C instead, and that acceptance is a
separate decision.

## When the answer must land

**Epic 10 freezes the exported API, and every candidate that moves the dependency is a
breaking change. So the answer lands before Epic 10.** FR-supply-28 states the same
requirement.

`docs/specs/spec.md:848` states the dependency of Epic 10:

> **Depends on.** Every other epic.

**Eight epics are open today.** The command
`gh issue list --repo Crank-Git/ja4plus-go --state all` reports that #43, #64, #71, #76,
#83, #89, #94 and #100 are `OPEN`, and that every other epic issue is `CLOSED`. Those eight
are Epic 6, Epic 7, Epic 9, Epic 13, Epic 14, Epic 15, Epic 16 and Epic 10.

**`docs/specs/spec.md` states the order of the open epics as a document order, and it
states no schedule.** The section of each open epic sits at one of these lines.

| Epic | Line |
|---|---|
| Epic 6 | :714 |
| Epic 7 | :726 |
| Epic 9 | :779 |
| Epic 13 | :792 |
| Epic 14 | :806 |
| Epic 15 | :818 |
| Epic 16 | :830 |
| Epic 10 | :842 |

- **One open epic stands between the epic that runs today and Epic 13, and it is Epic 9.**
  Epic 7 runs now, and the document order puts Epic 9 alone between Epic 7 and Epic 13.
- **Epic 6 is open, and the document order puts it before Epic 7.** So Epic 6 runs at a
  time the maintainer chooses, and the document order states nothing about that time.
- **Three epics stand between Epic 13 and Epic 10.** They are Epic 14, Epic 15 and Epic 16.
- **A count of batches is not measurable, because one epic runs as one or more batches.**

**No dependency forces Epic 13 to wait.** `docs/specs/spec.md:798` states that Epic 13
depends on Epic 2 and on Epic 3, and both of those epics are closed. **So the order of Epic
6, Epic 9 and Epic 13 is a schedule choice, and the maintainer holds it.**

## What this file does not answer

- **Whether a capture that the corpus does not hold moves a fingerprint value.**
  `### The Geneve difference, which the corpus does not reach` and
  `### The TCP option difference: the corpus reaches neither` each name the capture that
  separates the two candidates, and the corpus holds neither one.
- **Which of the four upgraded modules a later moved value comes from.** The measurement
  moved `github.com/gopacket/gopacket`, `golang.org/x/crypto`, `golang.org/x/net` and
  `golang.org/x/sys` together, and it found no moved value, so it ran no attribution.
- **Whether a third candidate exists.** The measurement read `github.com/tsg/gopacket`,
  which publishes `v0.0.0-20200626092518-2ab8e397a786` at 2020-06-26, and it read no other
  candidate.
- **How far the two candidates diverge in whole.** `github.com/google/gopacket` and
  `github.com/gopacket/gopacket` are separate GitHub repositories rather than one fork
  network, so the GitHub comparison endpoint returns `"status": "404"`. The source
  comparison above reads the 20 files this library reaches, and it reads no other file.
