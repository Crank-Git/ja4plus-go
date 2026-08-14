# Changelog

This file records every notable change to this project.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Every measurement in this section names the base of the run that produced it. **The
enumeration below states the count that the register holds today under each ruling.** It
never states the count that the issue first wrote, so the enumeration is a statement of the
present and never a history. Issue #42 put 248
entries into `testdata/deviations.json`, and the register held no entry before that. Issue #196
put 35 more entries into it, issue #197 put 13 more, issue #223 put 4 more, issue #285 put
140 more, issue #361 put 8 more, issue #375 put 12 more, issue #387 put 10 more, and issue
#441 put 108 more.
Issue #455 wrote the last 32 entries of the ruling #285 count, because the body gate moved
16 frames of `http1.pcapng` to a match and left the raw forms of those frames in deviation.
Issue #409 extended the ruling of #387 to the hashed JA4S value, and it wrote the last 5
of those 10 entries. Issue #447 removed 21 entries, because the library no longer produces
the value each one records. **The enumeration above already subtracts that removal, so a
reader adds nothing to it.** The removal lowered #197 from 14 entries to 13, and it lowered
#361 from 28 entries to 8. A run on
the current tree
reports 1716 matches, 331
deviations, 558 accepted deviations and 578 register keys. The run also reports 183 unaccepted
uncovered values and 20 accepted uncovered values, and #361 states what an uncovered value is.
An accepted deviation and an accepted uncovered value each name one register entry, so 558 and
20 add up to the 578 register keys. A count that an entry below states therefore differs from
a fresh run.

**A guard holds this paragraph true, and `changelog_counts_freshness_test.go` is that guard.**
It reads the four counts and the enumeration above, and it compares each one against
`docs/audit/conformance.md` and against `testdata/deviations.json`. A member that moves a
count and leaves this paragraph fails `go test ./...`. Issue #306 built the guard, after the
paragraph was false at the end of three consecutive batches.

**Batch Epic 8b closed the parity rows of the TCP, HTTP, certificate and DHCP methods, and
this paragraph records the measurement of the whole batch.** Issue #58 wrote the drift check
for the port register copy. Issue #56 wrote JA4TS part e and the JA4TS value that a RST
produces, under three bounds on the state it added. Issue #57 widened the request-line pattern
so that a method outside a closed list of nine reaches a JA4H value, and it made JA4X read a
reassembled stream, and it kept the first Maximum DHCP Message Size on a repeated option 57.
Issue #361 built the uncovered value, and it put 28 entries into the register. Issue #126 held
the JA4T SYN selection in a test, and it changed no behaviour. Issue #356 recorded the two
one-shot names as `not applicable`. Issue #375 put 12 entries into the register and closed
FR-parity-50. The batch ran from `5010de7` to the merge of `epic/54-parity-tcp-http-cert-dhcp`.
The run reports 1627 matches, 676 deviations and 409 accepted deviations before, and 1658
matches, 645 deviations and 409 accepted deviations after. The register holds 409 keys before
and 449 after. **Thirty-one values moved, and every one moved from a deviation to a match.**
**The run reported no uncovered value before this batch, because the suite compared no value
whose reference file publishes no key for its method.** It reports 202 unaccepted and 40
accepted after. Round 38 of the `## Changelog` of `docs/specs/spec.md` records the seven
rulings of 2026-08-13 and the six findings of the cross-member review.

**Batch #293 repaired four fingerprint paths, and this paragraph records the measurement of
the whole batch.** Issue #55 wrote the two-digit form for a zero JA4T value and a zero JA4TS
value. Issue #286 repaired three defects in the JA4H path. Issue #295 stepped
`ParseClientHello` over a leading non-handshake record. Issue #287 wrote the `JA4_o` zero
sentinel that the maintainer ruled on 2026-08-12. Issue #299 put 98 entries into the register
under the ruling of issue #42. The batch ran from `34b6715` to `db53765`. The run reports 1545
matches, 940 deviations and 203 accepted deviations before, and 1602 matches, 783 deviations
and 301 accepted deviations after. The register holds 203 keys before and 301 after. Issue
#306 records this measurement.

**Batch #281 filled four raw fields, and this paragraph records the measurement of the whole
batch.** Issue #274 filled `JA4H_ro`, issue #275 filled `JA4S_r`, issue #276 filled `JA4X_r`
and issue #277 added `OriginalOrder` for `JA4_o`. Only #277 disclosed counts, and its
"before" figures already held the three other members, so no entry below states the batch
total. The batch ran from `388b6c8` to `5282cb9`. The run reports 1091 matches, 1274
deviations and 203 accepted deviations before, and 1545 matches, 940 deviations and 203
accepted deviations after. The per-stream set reports 742 matches and 458 deviations before,
and 1043 matches and 250 deviations after. The per-packet set reports 349 matches and 816
deviations before, and 502 matches and 690 deviations after. The register holds 203 keys
before and after, so the batch moves 454 comparisons to a match and accepts no new deviation.
Issue #290 records this measurement.

### Added

An entry counts an interface as one exported name. It counts no second name for the method
that the interface declares.

- No exported name, and one test that holds the method count. `TestMethodCount` reads every
  tracked Markdown file, every tracked HTML file and every Go comment. It fails when one
  applies the count of ten to methods, or the count of eleven to fingerprinters, and it
  names the file and the line. It reported nine violations on the tree that Epic 12 started
  from, and `method_count_test.go` holds it. `NOTICE`, `README.md` and `doc.go` now name
  JA4LS, so FoxIO License 1.1 covers ten of the eleven methods this project implements.
  Issue #62 holds the measurement, and no fingerprint value moved.
- No exported name, and twelve register entries that close FR-parity-50. The SOCKS4 tunnel
  of `socks4-https.pcap` produces three JA4X values, and no vector file of the corpus
  publishes a JA4X key for that capture. `testdata/foxio/python/socks4-https.pcap.json` and
  `testdata/foxio/wireshark/socks4-https.pcap.json` each publish none, so the run reports
  each value as an uncovered value. **The port ruled at `Crank-Git/ja4plus#138` on
  2026-08-07 that the three values stay.** The maintainer ruled on 2026-08-13 that a ruling
  the port's register records lands here as a reading. **The three values reach
  twelve comparisons**, because the run compares `JA4X` and `JA4X_r` in the per-stream set
  and in the per-packet set. **The change moves no fingerprint value.** The run reports 1658
  matches, 645 deviations and 409 accepted deviations before and after. **The register key
  count moves from 437 to 449.** The unaccepted uncovered values fall from 214 to 202, and
  the accepted uncovered values rise from 28 to 40. The run reports 0 stale register entries
  and 0 orphan register entries. Issue #57 carries the test half, and `ja4x_tunnel_test.go`
  holds it.
- No exported name, and one conformance category that records a value the reference file
  does not cover. The harness dropped a value whose vector file publishes no key for its
  method. The run reported nothing for it, and the report read as full coverage of every
  value the library emits. **The maintainer ruled on 2026-08-13 in #361.** The run compares
  such a value and reports it as an **uncovered value**, which is neither a match nor a
  deviation. `conformance_engine_test.go` gains `conformanceUncoveredValue` and
  `conformanceSplitUncovered`. The two producers of `conformance_test.go` now build the whole
  produced map. `docs/audit/conformance.md` gains the section `## Uncovered values`, and the
  summary rows `Unaccepted uncovered values`, `Accepted uncovered values` and
  `Accepted comparisons`. **The change moves no fingerprint value.** The run reports 1627
  matches, 676 deviations and 409 accepted deviations before and after. It reports 220
  uncovered values, and the register accepts 28 of them. **The register key count moves from
  409 to 437, and the port holds the same ruling in five rows.** The port names a capture and
  a method in one key. This repository names a capture, a stream and a method, so five port
  rows cover 28 entries here. `python/ja4.py:340` at the pinned commit runs
  `delete_keys(['JA4L-S', 'JA4L-C'], final)` when the run names another method. That filter
  is why `CVE-2018-6794.pcap`, `https-connect.pcap` and `tls-handshake.pcapng` publish no
  JA4L key. `ja4l_test.go` reverses the guard of #52, which named #361 as its reversal path.
  `docs/specs/features/04-conformance-harness.md` numbers the category as FR-conformance-33p
  through FR-conformance-33v. Issues #52 and #57 carry the parity half.
- No exported name, and one guard that holds every citation of `docs/specs/foxio/`.
  `foxio_citation_base_test.go` holds 849 lines and seven tests. It reads every
  path-shaped code span of the directory against the seven bases of the table at
  `docs/specs/foxio/README.md:41-49`, and
  `docs/specs/features/11-foxio-reference.md:106-120` numbers the check as
  FR-reference-18a through FR-reference-18l. **The shape check of FR-reference-18b needs
  no corpus.** `foxio_citation_base_test.go:530` declares `foxioCorpusAbsentMessage`, and
  every skip of the file writes that sentence, so no skip of the file is silent. **The
  line-bound check of FR-reference-18h opens the file a citation names**, and it fails a
  citation that names a line past the end of it. **A counted exception table holds two
  entries and three spans**, and each entry names one page, one span, one count and one
  reason. `docs/specs/foxio/README.md` carries 2 spans of `ja4l.py`, and
  `docs/specs/foxio/port-register.md` carries 1. An exception that now resolves fails
  `TestTheCitationExceptionTableHoldsNoSpanThatNowResolves`. **The
  member watched four failure modes**: a citation under no base, that same citation with
  the corpus moved aside, a citation that names a line past the end of its file, and a
  stale exception count. **The line-bound check found a defect that no reader had seen.**
  `docs/specs/foxio/port-register.md:81` cites `.claude/rules/external-apis.md:95` and
  `.claude/rules/external-apis.md:101`, and this repository holds a file at that path with
  62 lines. A resolver that reads base 5 before base 7 therefore answers from the wrong
  repository and reports nothing. `docs/specs/foxio/README.md:90-91` states that the
  citations of the verbatim copy name paths of the port, so base 7 outranks base 5 on that
  page. **No page changed, and the resolver reads the recorded order.** **One comment of
  the new file named a guard that guarded nothing, and `c5e2aad` repairs that inside the
  batch.** `foxio_citation_base_test.go:527-529` names
  `TestTheCISkipDetectorMatchesNoUntaggedSkipMessage`, and the extractor of
  `conformance_skip_marker_test.go` read a string literal alone. `foxioCorpusAbsentMessage`
  concatenates a package constant and two literals, so that guard read no skip of the file
  that names it. **The repair makes the claim true rather than correct the comment.** The
  extractor now reads the skip argument through `go/ast`, and it resolves a literal, a
  constant of the package and a concatenation of the two. **A skip argument it cannot read
  now fails the test**, so the silent gap cannot return. The repair was watched failing on
  a temporary file that skips with a constant carrying the marker, and on a skip that
  passes a variable. **The member moves no fingerprint value.** The four counts read 1623,
  680, 409 and 409 before and after. Issue #335 holds the guard, and issue #351 records
  that the guard reaches no citation outside `docs/specs/foxio/`.
- No exported name, and one rule that names the repository of an issue citation.
  `.claude/rules/rulings.md:35-49` holds `## A citation names its repository`, and
  `.claude/rules/rulings.md:37` states that a bare `#N` names an issue of this repository.
  A citation of the port names the port, as `the port's issue #N` in a sentence or as
  `Crank-Git/ja4plus#N` in a table cell. **The member ships one rule, and not eighteen
  edits.** **The form is one the tree already uses.** Measured at `c5e2aad` over `*.go`,
  `*.md`, `*.html`, `*.json` and `*.yml`, outside the untracked `testdata/foxio/`, the tree
  writes `Crank-Git/ja4plus#N` 5 times, `port issue #N` 5 times, `` `Crank-Git/ja4plus`
  issue #N `` 3 times and `the port's issue #N` once. **Two pages carry a
  local rule, and the section names both.** The `Ruling` column of the register names the
  port, and `docs/specs/spec.md:380` now states that. `docs/specs/foxio/port-register.md`
  is a verbatim copy of the port's specification, so a bare number in it names the port.
  **The member changed three citations.** `docs/specs/spec.md:446` now reads `This
  repository's #216`, and `ja4l_test.go:1272-1273` now names both halves of one question.
  **The JA4L part count is issue #127 here and issue #225 in the port**, and the member
  confirmed the port title `Decide the JA4L form: the part count, the protocol part and
  the duplicate server value` on 2026-08-12. **The member changes no Go file outside one
  test comment, and it moves no fingerprint value.** Issue #255 holds the rule.
- No exported name, and four rows of the `## Terms` table of `docs/specs/spec.md`, at
  `docs/specs/spec.md:122-125`. The rows are `maintainer`, `project manager`, `schema
  violation` and `delegated ruling`. **The member writes four rows, and #261 names
  three.** The boundary sentence of the `delegated ruling` meaning uses `schema
  violation`, and `.claude/rules/ste.md` bars a domain word the table does not hold. The
  project manager accepted the fourth row for that reason. **Every row records a meaning
  a rule file already fixed, and the member invents none.** `maintainer` and `project
  manager` come from `.claude/rules/rulings.md` `## The two words` and `## What a
  delegated session may rule`. `schema violation` comes from `.claude/rules/parity.md`
  `## Where a difference comes from`, which names `a value the published schema forbids`.
  The `delegated ruling` meaning carries the two sentences that decide the boundary. A
  schema violation has one right answer, and a reference split has none. A delegated
  ruling stays provisional until the maintainer confirms it. **The member
  writes no `## Changelog` row**, because a member that writes its own round produces the
  defect #278 records. Issue #331 holds that row. **The member changes no Go file, and it
  moves no fingerprint value.** Issue #261 holds the change.
- No exported name, and one conformance check that reports a register entry the run never
  reaches. The stale check of #307 visits the keys of one comparison alone, so a register
  key that no capture produces falls outside every branch of it.
  `conformanceComparison.Reached` now names every register key that one comparison visits.
  `conformanceOrphanEntries` subtracts the reached keys of the whole run from the
  register, and it runs after the last capture. An orphan entry fails the suite, as a
  stale entry does. `docs/audit/conformance.md` gains the summary row `Orphan register
  entries` and the section `## Orphan register entries`, and that section states the
  result of every run. The `## Terms` table of `docs/specs/spec.md:130` gains the row
  `orphan entry`, beside the `stale entry` row that #307 added.
  **`docs/specs/features/04-conformance-harness.md:126-138` numbers the check as
  FR-conformance-33h through FR-conformance-33o**, and the member carries them from its
  first commit. **The check was watched failing.** The worker added the temporary entry
  `tls12.pcap/1/JA4ORPHANWATCH`, ran the suite, and removed the entry. The run reported
  `the run reaches 409 register keys and reports 1 orphan register entries`, and the
  report named the entry in both new places. `conformance_test.go:931` writes that line,
  and `conformanceReportTotals` calls `t.Helper()` at `conformance_test.go:910`, so the
  run attributes the line to the caller at `conformance_test.go:680`.
  **The run on the merged tree reaches all 409 register keys and reports 0 orphan
  register entries**, so the check reports no finding against the register today.
  **`Accepted == 409 == |register|` was the whole proof that no register entry had
  drifted, and two named checks now replace it.** That identity fails the moment one
  batch adds an entry and removes another in one commit, and
  `changelog_counts_freshness_test.go:135-137` already concedes the asymmetry. **The
  member moves no fingerprint value.** The four counts read 1623, 680, 409 and 409 before
  and after. Issue #328 holds the measurement.
- No exported name, and one statement of the bases that a FoxIO citation joins to, at
  `docs/specs/foxio/README.md:31-49`. **The member changes no citation, and that is the
  result.** #254 asks for a `reference/` prefix on every citation of
  `docs/specs/foxio/`, and the measurement proves that prefix wrong. **`make corpus`
  writes two corpus roots.** `scripts/fetch-corpus.sh:149` moves `pcap`,
  `python/test/testdata` and `wireshark/test/testdata` out of the staged tree, and
  `scripts/fetch-corpus.sh:167` then writes the rest to `testdata/foxio/reference/`. Four
  citations of the nine method pages name
  `python/test/testdata/browsers-x509.pcapng.json`, which `make corpus` writes under
  `testdata/foxio/python/`, so a blanket prefix breaks each one. **The short citation
  form is also a repository-wide convention, and a Go change alone moves it.**
  `.claude/rules/rulings.md` states the form, and `ja4l.go:141`, `ja4t.go:132`,
  `ja4ssh.go:158` and `ja4x_raw_test.go:101` carry it. Five assertions of
  `foxio_transcription_tcp_test.go` anchor on it, at `:230-232` and `:251-252`. A first
  draft repointed the four vector citations, and
  `TestTLSTranscriptionRulesThatNameAnImplementationCarryAFileAndALine` then failed.
  **The member repairs two false statements as well.** `zeek.md` stated that a path is
  relative to the `zeek/` directory of the FoxIO repository, while every citation on the
  page already carries that prefix. `README.md` stated that the script fetches no part of
  `technical_details/`, and `testdata/foxio/reference/technical_details/` holds each file
  of the inventory table at `docs/specs/foxio/README.md:166`. **#254 stated its rule on a
  page whose own citations break it, and the cross-member review of this batch found
  that.** The rule named two bases, and the tree holds seven, so it sent a reader of
  `docs/specs/foxio/zeek.md:76` to a path that no tree holds. **That is the silent
  failure #254 exists to stop, on the page that states the rule.** **`db52e4a` repairs it
  inside the batch.** `docs/specs/foxio/README.md:41-49` now holds one table of seven
  bases, and the page states no count of pages. A count of pages goes stale at the next
  edit, and that is how the defect arose. **Base 2 is evidence that no member named.** A
  page cites a bare image name such as `JA4D.png`, and that file sits at
  `testdata/foxio/reference/technical_details/JA4D.png`. The FoxIO repository root holds
  no file of that name, so base 1 reaches it at no path.
  `docs/specs/foxio/README.md:110` counts 27 spans at base 2. **`docs/specs/foxio/README.md:96-131` records the measurement of
  the repaired rule.** A resolver read the thirteen pages of the directory and 822
  path-shaped code spans. 621 resolve at base 1, 15 at the short form of base 1, 27 at
  base 2, 26 at base 3, 19 at base 4, 83 at base 5, 10 at base 6, 18 at base 7, and 3
  under no base. **No citation names a line past the end of the file it names.** **One
  citation resolves under no base, and the page reports it rather than repointing it**:
  `ja4l.py`, at `docs/specs/foxio/port-register.md:80`. The FoxIO `python/` directory at
  the pin holds `common.py`, `ja4.py`, `ja4h.py`, `ja4ssh.py` and `ja4x.py`, and no
  `ja4l.py`. **The repair changes `README.md` alone, so #254 still changes no citation.**
  **No test holds the repair**, because the acceptance criteria of #254 bar a Go file
  change. Issue #335 records the guard, and it names a shape check that needs no corpus.
  **The member changes no Go file, and it moves no fingerprint value.** Issue #254 holds
  the measurement of the member, and #339 holds the measurement of the repair.
- No exported name, and `.claude/rules/cross-member-review.md`. The file states why the
  project runs a cross-member review, how to spawn one that reports, the five categories
  and the return contract. `CLAUDE.md:119` gains one bullet of `## Conventions` that
  points at it, as #305 did for `.claude/rules/worktrees.md`. The `## Terms` table of
  `docs/specs/spec.md:192-197` gains six rows: `batch`, `member`, `cross-member review`,
  `mailbox`, `idle signal` and `spawn path`. **The member appends the six rows at the end
  of the table**, so they touch no row that #261 wrote. **A cross-member review returned
  an idle signal and no text in eight consecutive attempts, across session 5 and session
  6.** **The worker of #260 spawned three agents on 2026-08-12 to separate the cause.**
  Arm A carried no `name` and the review brief, and it reached the in-process path. Arm B
  carried a `name` and the review brief, and it reached the cross-session path. Arm C
  carried a `name`, `isolation` set to `"worktree"` and a one-command brief, and it
  reached the in-process path. Arm A and arm C each reported to the spawner without a
  request. Arm B reported to the project manager, and never to the spawner. **Arm A
  against arm B is the one contrast of the measurement that varies a single parameter**,
  because arm C moves `isolation` and the brief together. **Arm B and arm C both carry a
  name and reach different paths, so the name alone does not decide the path.** That
  conclusion reads the path of each arm, and it reads no duration. The session-6 record
  names the `name` parameter as the cause, and that names the wrong variable. **The
  cross-member review of this batch found that the first draft read as a one-parameter
  measurement, and `db52e4a` repairs it inside the batch.**
  `.claude/rules/cross-member-review.md:47-51` gains a `Brief` column, and `:53-55` states
  that the two durations measure the two briefs and nothing about the spawn path. **The
  file records three open questions at `:103-116`, and the third is a fourth arm that
  nobody has run.** That arm sets `isolation` and carries the review brief, and it
  separates the two variables that arm C holds together. **The rule states the
  discriminator that survives a harness change.** Read the spawn response: the in-process
  path names an output file, and the cross-session path names a mailbox. A response that
  names a mailbox gets one more spawn on the in-process path, and no session waits on a
  cross-session spawn. **The review also repaired two of the six rows.** The
  `cross-member review` row stated that the rule file names the term in full at the head
  of each section, and the file names it in full at one heading of eleven. The `mailbox`
  row and the `spawn path` row each declined `channel`, so a reader could not tell
  whether the word is permitted. The `mailbox` row now keeps the decline, and the
  `spawn path` row points at it. **The member changes no Go file, and it moves no
  fingerprint value.** Issue #260 holds the measurement, and #339 holds the repair.
- No exported name, and two tests that hold the JA4H value of one request across every
  run: `TestJA4H_ComputesOneValueForOneRequestOnEveryRun` and
  `TestJA4H_SortsTheCookiePairListByTheCookieName`, in `ja4h_determinism_test.go`. Issue
  #303 reports two JA4H values for `http-empty-useragent.pcap`, and **the defect does not
  reproduce on this tree**. 10 consecutive runs of `make conformance` on `d7b01d0`
  produced one deviation key set and one report, and 3 more runs after this change agreed.
  The 10 report copies share the SHA-256 prefix `47f414a1bf67f069`. `ja4h.go:315` is the
  one map range that the JA4H value reads, and `ja4h.go:318` sorts that result by the
  cookie name. A map key is unique, so the comparator meets no tie. **Issue #286 is the
  probable closer**, because `internal/parser/http.go:90` now returns nil for a header
  block that has not ended. The worker removed the sort at `ja4h.go:318`, and each test
  then failed. **The member changes no library file, and it moves no fingerprint value.**
  The run reports 1623 matches, 680 deviations, 409 accepted deviations and 409 register
  keys before and after. Issue #303 holds the measurement.
- No exported name, and one conformance check that compares the recorded `ours` value of a
  register entry against the run. `compareConformance`
  read the presence of the key alone before this change, at
  `conformance_engine_test.go:99`. An entry therefore stayed accepted after a later change
  moved the value it records. The suite now fails with one line for each stale entry.
  `docs/audit/conformance.md` gains the summary row `Stale register entries` and the
  section `## Stale register entries`. That section states the result of every run, so a
  reader tells a healthy register from a renderer that dropped a row. The `## Terms` table
  of `docs/specs/spec.md` gains the row `stale entry`. **The run reports 0 stale entries
  against the 409 register keys**, so the check blocks nothing today. **The check covers
  the value half alone, and never the orphan half.** A register key that the run never
  reaches falls outside the key loop of the engine. Issue #307 asks for no second pass over
  the register. **`docs/specs/features/04-conformance-harness.md:115-125` numbers the
  check as FR-conformance-33a through FR-conformance-33g.** The behaviour reached no
  requirement when `6a03362` merged, and `4a30c33` numbered it inside this batch. The
  ordinal carries a letter, because `.github/workflows/ci.yml`, `corpus_fetch_test.go`,
  `conformance_skip_marker_test.go` and `docs/specs/spec.md` cite FR-conformance-34
  through FR-conformance-39. Nine tests hold the check, and `go vet -tags conformance ./...`
  reported `result.Stale undefined` before the engine held the field. The worker changed
  one character of the first register entry, and the run then reported `the run reports 1
  stale register entries`. **The member moves no fingerprint value.** The four counts read
  1623, 680, 409 and 409 before and after. Issue #307 holds the measurement.
- No exported name, and one rule that forbids `git stash` in a worktree of this
  repository. `CLAUDE.md` `## Conventions` holds the rule as the first bullet.
  `.claude/rules/worktrees.md` holds the reason, the three alternatives and two readings.
  Batch #293 lost the work of issue #295 to a stash push and a stash pop, and neither
  worker saw an error. **A worktree cannot hold a stash of its own.** `git-worktree(1)` at
  git 2.53.0 shares every ref under `refs/`, except `refs/bisect`, `refs/worktree` and
  `refs/rewritten`. `git-stash(1)` writes `refs/stash`. Copy the file with `cp`, or
  restore it with `git checkout -- <file>`. **`.githooks/reference-transaction` refuses a
  hand-written stash from a linked worktree, and it lets an autostash store through.** It
  repairs no `git stash pop`. **The first hook refused the autostash store too, and that
  refusal destroyed the work git had just saved.** `git merge --autostash`,
  `merge.autostash`, `rebase.autostash` and `git pull --rebase --autostash` each fall back
  to `git stash store` when the entry cannot re-apply. git removes the autostash file
  after the store, whether the store succeeded or failed. **The cross-member review of
  batch #321 measured that loss, and `4a30c33` repaired the hook inside the batch.** The
  ref name, the old value and the new value separate nothing, and `GIT_REFLOG_ACTION` is
  unset. The hook therefore reads the state file that git writes.
  `.githooks/reference-transaction:27-31` tests `MERGE_AUTOSTASH`,
  `rebase-merge/autostash` and `rebase-apply/autostash` under the git directory of the
  worktree. **`.claude/rules/worktrees.md` records two limits of the repaired hook.**
  `:262` holds the one case that misses a refusal: a hand-written stash while a rebase
  autostash is pending exits 0. That case destroys nothing. `:245` holds one over-refusal:
  the hook refuses `git stash drop` on the entry it allowed, and the `Dropped` line prints
  the object id first, so the entry stays reachable. The rule at `CLAUDE.md:115` binds
  every agent whether or not the hook runs. `docs/specs/spec.md` `## Terms` gains the row
  `autostash`. **The hook is inert until the maintainer runs
  `git config core.hooksPath .githooks`.** The
  second reading records that a `PostToolUse` hook of `.claude/settings.json` did not run
  for a worktree-isolated worker. A `PreToolUse` hook therefore stops no worker. **The member
  changes no Go file, and it moves no fingerprint value.** Issue #305 holds the readings.
- No exported name, and eight numbered requirements that hold `CloseConnectionWindow`:
  FR-parity-33a through FR-parity-33h, at
  `docs/specs/features/08-python-parity.md:136-154`. They number the fingerprinter method,
  the two processor methods, the endpoint order, the eviction, the empty window, the miss
  case and the test. Epic 10 freezes the exported surface, and the freeze reads the spec,
  so an unnumbered method escapes it. **The ordinal carries a letter, because
  FR-parity-34 through FR-parity-60 already exist.** A renumber would break the references
  that ten test files and four documents hold.
  `docs/specs/features/08-python-parity.md:287` gains the eviction row, which separates
  `CloseConnectionWindow` from `CleanupConnection`. `docs/specs/spec.md:433` gains the
  register row, and that row states that this project named the behaviour first. Rule 2 of
  `.claude/rules/parity.md` therefore runs toward the port, and the row cites
  `Crank-Git/ja4plus#598`. `docs/specs/spec.md:474` names the method in the `Cleared by`
  cell of `JA4SSHFingerprinter`. **The member changes no Go file, and it moves no
  fingerprint value.** Issue #264 holds the change.
- One exported name, which carries the FoxIO `JA4_o` value: the `OriginalOrder` field of
  `FingerprintResult`. `JA4_o` hashes each list of the wire-order raw form, and
  `RawOriginalOrder` holds the same two lists unhashed, so one function builds the two.
  `testdata/foxio/reference/python/ja4.py:291` states the form. The FoxIO key suffix names
  each of the four value fields, so `Raw` carries `_r`, `OriginalOrder` carries `_o` and
  `RawOriginalOrder` carries `_ro`. This project rejects the names
  `FingerprintOriginalOrder`, `HashedOriginalOrder` and `JA4O`. Epic 10 freezes the exported surface
  for the whole `v1` series, so the name lands before that freeze.
  `docs/specs/features/05-conformance-gaps.md` FR-gaps-24 through FR-gaps-26 number the
  field. `JA4Fingerprinter` fills the field, and every other fingerprinter leaves it empty.
  The measurement ran on `origin/batch/281-raw-forms` at `d8ac53f`. The run reports 1400
  matches, 1036 deviations and 203 accepted deviations before, and 1545 matches, 940
  deviations and 203 accepted deviations after. The register holds 203 keys before and
  after. 145 `JA4_o` comparisons close, and 49 new deviations appear. Each new deviation is
  a `JA4_o` value that the vector does not hold. The change moves no `JA4` value, no
  `JA4_r` value and no `JA4_ro` value. Issue #277 records the field, and issue #287 records
  one reference split that four comparisons reach. **The port needs no change**, because
  `Crank-Git/ja4plus` emits `JA4_o` already.
- Four exported names, which emit the JA4SSH window that one connection holds open and then
  remove that connection: the `ConnectionWindowCloser` interface,
  `JA4SSHFingerprinter.CloseConnectionWindow`, `Processor.CloseConnectionWindow` and
  `SyncProcessor.CloseConnectionWindow`. The maintainer ruled the name on 2026-08-12, and
  issue #216 records the ruling. `CloseOpenWindows` reaches every connection at the end of
  the packet source, and this method reaches one connection before that moment. The method
  takes the connection key that `CleanupConnection` accepts, and `CleanupConnection` keeps
  its signature. Epic 10 freezes the exported surface for the whole `v1` series, so the name
  lands before that freeze. No conformance vector separates the two answers, so ten tests
  build the separating sequence. The change moves no fingerprint. Issue #264 records that no
  spec file numbers the method as a requirement, and the maintainer ruled on issue #268 that
  the method sits on its own interface. `WindowCloser` keeps `CloseOpenWindows` alone, and
  each dispatch asserts one capability, so a type that implements one method alone is never
  skipped.
- Four exported names, which emit the JA4SSH window that a connection holds open at the end
  of the packet source: the `WindowCloser` interface, `JA4SSHFingerprinter.CloseOpenWindows`,
  `Processor.CloseOpenWindows` and `SyncProcessor.CloseOpenWindows`. The maintainer ruled on
  2026-08-11 that the method sits on a second optional interface, so the exported
  `Fingerprinter` interface does not change and no third-party implementation breaks. A
  caller discovers the interface with a type assertion, and a stateless fingerprinter
  implements nothing. `cmd/ja4plus analyze` calls the method when the capture ends.
  `docs/specs/features/08-python-parity.md` FR-parity-29 through FR-parity-33 state the
  requirements, and the port's issues #105, #199 and #214 hold the ruling.
- Eight exported names, which read a pcapng Decryption Secrets Block and decrypt one QUIC
  packet with a TLS secret: `ErrNoSecret`, `KeyLog`, `ParseKeyLog`,
  `ReadKeyLogFromCapture`, `KeyLog.Secret`, `KeyLog.ClientRandoms`, `KeyLog.Len` and
  `DecryptQUICPacket`. The maintainer accepted the eight names on 2026-08-11, before the
  `v1.0.0` freeze. `docs/specs/features/05-conformance-gaps.md` FR-gaps-15 through
  FR-gaps-18 state the requirements, and the `Interface` register row of
  `docs/specs/spec.md` records that the port adopts these names under parity rule 2. The
  change moves no fingerprint.
- The `corpus`, `conformance`, `cover` and `fuzz` make targets.
- The FoxIO corpus pin in `testdata/foxio.pin`, and `scripts/fetch-corpus.sh`, which
  fetches the corpus at that commit. The corpus is FoxIO-licensed material, so the
  repository holds no fetched file.
- A benchmark for the processor, and one benchmark for each method.
- `data/README.md`, which names FoxIO as the source of `data/ja4plus-mapping.csv` and
  states that FoxIO License 1.1 covers that file.
- `docs/audit/license-decision.md`, which transcribes the maintainer's license decision
  and the date of each part of it.

### Fixed

- **The library now produces the JA4H value at the packet that completes the request, and it
  produced the value at the packet that ends the header block before.** The maintainer ruled
  the body gate on 2026-08-13, at #455. The library holds the value until the payload after
  the header block reaches the byte count that `Content-Length` names.
  **A caller of `v0.3.0` who upgrades reads two changes.** A request that carries a body now
  reaches a value at a later packet, and that result carries the timestamp of that packet. **A
  request whose body never completes now reaches no value, and it produced one before.**
  `zeek/ja4h/main.zeek:186` computes the value in
  `event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)`.
  That file holds no handler that flushes a partial request. The ruling follows that shape.
  `parser.HTTPMessageIsComplete` holds the gate, and every path that produces a JA4H value
  reads it. **The change closes 64 deviations**, and the deviations that the register does not
  hold fall from 571 to 507 with the register unchanged. **16 values moved, all of them on
  `http1.pcapng`**, and each one moved from a deviation to a match. The 32 raw-form
  comparisons of those 16 frames still differ by one trailing underscore, so the register
  gains 32 entries under ruling #285 and the deviations then fall to 475. **No capture of the
  corpus separates the candidate answers**, so `ja4h_body_gate_test.go` records the ruling and
  the register records none of it. **The port does not hold this rule**, at
  `ja4plus/fingerprinters/ja4h.py:149-151`, so the change opens a parity difference that the
  port's issue Crank-Git/ja4plus#607 carries.
- **A repeated TCP segment now produces one JA4H value, and it produced two before.** Frame 6
  and frame 15 of `CVE-2018-6794.pcap` carry the same bytes on the same four-tuple, and the
  library fingerprinted both. No FoxIO implementation publishes a second value for the repeat.
  **A caller of `v0.3.0` who upgrades reads one JA4H value where two arrived.** A consumer
  that counts JA4H results therefore reads a lower count on the same capture.
  `JA4HFingerprinter` now
  holds `ranges`, which records the sequence range of each stream that the fingerprinter
  already read. The table holds an entry bound and an age bound, and `CleanupConnection` and
  `Reset` each remove from it. **The change closes 50 deviations**, and the deviations that the
  register does not hold fall from 635 to 585. The register gains no entry, because
  `.claude/rules/parity.md` `## Where a difference comes from` row 1 governs a unanimous
  reference. **The port already holds this rule**, at the `consumed_seq` table of
  `ja4plus/fingerprinters/ja4h.py`, so the change closes a parity difference and opens none.
  Issue #446 built it, and no exported name moved.
- **`JA4L-S` now reaches the frame that fills point D, and it reached the point B frame
  before.** The value is identical on the two frames, and the per-packet vector holds it at
  the point D frame. **A caller of `v0.3.0` who upgrades reads the same `JA4L-S` value on a
  later frame.** A consumer that pairs the value with a frame number therefore reads a
  different pairing. The per-stream set does not move, because it names a stream rather than a
  frame.
  `processUDP` of `ja4l.go` holds the emission. **The change closes 14 deviations**, and the
  deviations that the register does not hold fall from 585 to 571. **The whole-corpus match
  count rises from 1658 to 1664**, which is the first rise of this session. **The register
  falls from 459 keys to 438**, because 20 entries became orphan entries and 1 became a stale
  entry, and the change removed all 21. Issue #447 built it, and no exported name moved.
- The `Maintainer` row of the `## Users & personas` table of `docs/specs/spec.md` now cites
  the `## Terms` row instead of restating it. `docs/specs/spec.md:262` reads `The person
  that row maintainer of ## Terms names.`, and the cell stated a second meaning before.
  `.claude/rules/ste.md` rule 6 gives one word one meaning, and the `maintainer` row at
  `docs/specs/spec.md:122` bars the word `owner` that the old cell used. **The member
  checked all 4 rows of the users table against the 100 rows of the `## Terms` table at
  `docs/specs/spec.md:98-197`.** **It found a second collision on the word `monitor`, and
  it repaired nothing there.** The `monitor` row at `docs/specs/spec.md:171` names the
  `ja4plus watch` command, and four sites name a program the caller writes:
  `docs/specs/spec.md:76`, `docs/specs/spec.md:253`, `docs/specs/spec.md:259` and
  `docs/specs/features/06-fuzz-testing.md:12`. The collision reaches three sections and a
  second file, so it sits outside the table this member owns, and issue #344 holds it.
  **The member changes one line of one document.** It changes no Go file and no register
  entry, and it moves no fingerprint value. Issue #334 holds the repair.
- Two mockup fingerprint values, two missing port citations and one wrong field citation.
  `docs/specs/mockups/02-cli-output.html:59-60` now write
  `65535_2-1-3-1-1-8-4-0-0_16344_6` on the JA4T line and on the JA4TS line, which is the
  form ruling #297 delivers. **The sweep found a second dead value, and no ruling moved
  that one.** `docs/specs/mockups/03-watch-output.html:88` held
  `ge20cn10enus_9da5c4e0ba8f_e3b0c44298fc_e3b0c44298fc`. `e3b0c44298fc` is the truncated
  SHA-256 of the empty string, and `internal/parser/hash.go:8` writes `000000000000` for
  an empty list, **so the library reaches neither value**. The value also contradicts
  itself, because part a carries the cookie flag `c` and a cookie list that is not empty
  hashes to no empty value. `testdata/foxio/python/http1-with-cookies.pcapng.json`
  supplied the repair, and the line now writes
  `ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442`. **A mockup value that a person
  composed by hand never matched the library**, so a later member checks a mockup value
  against a corpus vector and never against a ruling alone. **The port half of #297 is
  `Crank-Git/ja4plus#215`, and the port needs no change**, because
  `ja4plus/utils/tcp_options.py:51-56` already writes one entry for each option byte.
  **The port holds no issue for #285**, and `ja4h_raw_test.go:81-82` records that reading
  with the port lines that carry the three-field shape. **The field citation at
  `ja4t_option_byte_count_test.go:76-79` named the wrong field.** Frame 31 of
  `browsers-x509.pcapng` is a SYN-ACK, so the per-packet vector holds `ja4.ja4ts` and not
  `ja4.ja4t`, and the comment now names frame 30 as the SYN of the same connection. **The
  member found one more defect and repaired nothing.**
  `docs/specs/mockups/02-cli-output.html:56` shows `$ ja4plus
  testdata/foxio/pcap/tls12.pcap` and six fingerprint lines. `cmd/ja4plus/main.go:74` and
  `cmd/ja4plus/main.go:100` show that the program takes `ja4plus analyze <pcap-file>`, and
  `tls12.pcap` reaches one JA4 value alone, so no capture reproduces the example, and issue
  #350 holds it. **The body of #350 names that line as `:57`, and `:57` is blank**, so a
  worker of #350 reads `:56`. **The member wrote a bare `#215` that
  names the port, and `c5e2aad` repairs that inside the batch.** The breach broke the rule
  that issue #255 added in the same batch. **#215 of this repository is `The JA4L-C
  occurrences of one QUIC stream are shifted by one against the vector`**, which no part
  of the JA4T question reaches. `ja4t_option_byte_count_test.go:28-32` now quotes the port
  docstring as a code span, and it names the port's issue. **The member moves no
  fingerprint value.** The four counts read 1623, 680, 409 and 409 before and after.
  Issue #319 holds the repairs.
- `JA4HFingerprinter` now fills the `Raw` field of `FingerprintResult`, which carries the FoxIO
  `JA4H_r` value. It filled the field on no path before. The FoxIO per-packet vector set
  publishes `ja4.ja4h_r` on 126 records, and the FoxIO per-stream vector set publishes none.
  Issue #274 read the per-stream set and left the field empty, and issue #290 recorded that the
  two sets differ. The form is
  `<part a>_<header names>_<sorted cookie names>_<sorted cookie pairs>`.
  `testdata/foxio/reference/wireshark/source/packet-ja4.c:603` writes the four fields, and
  `testdata/foxio/reference/python/ja4h.py:82` writes the same four. Both references sort the
  cookie by the cookie name alone:
  `testdata/foxio/reference/wireshark/source/packet-ja4.c:525` writes the pair list in the name
  order, and `testdata/foxio/reference/python/ja4h.py:68` sorts the pair list by the name. The
  base value hashes the same two strings, so `ja4hSortedCookieStrings` builds them once for both
  forms and the base value cannot drift from the raw form. The two references disagree on the
  request that holds no cookie, where Wireshark writes four fields and the FoxIO Python
  reference writes three. Issue #285 holds that reference split, and this change rules nothing:
  `Raw` follows `RawOriginalOrder`, which issue #274 built in the Python shape, so one ruling
  moves both fields together. The measurement ran on `origin/batch/311-ja4h-and-harness` at
  `27e82a5`. The run reports 1602 matches, 783 deviations and 301 accepted deviations before,
  and 1608 matches, 803 deviations and 301 accepted deviations after. The register holds 301
  keys before and after, and it gains no entry. 6 `JA4H_r` comparisons close, and each one is a
  request that holds a cookie. 51 comparisons report `the two values differ`, and every one of
  the 51 differs by one trailing underscore, which is the split of issue #285. 26 comparisons
  report a surplus key, on 16 frames of `http1.pcapng` and 10 frames of `CVE-2018-6794.pcap`,
  and issue #289 already reads that cause. The change moves no `JA4H` value and no `JA4H_ro`
  value, and the per-stream set reports 1089 matches, 106 deviations and 266 accepted deviations
  before and after. **The port needs a change**, because
  `ja4plus/fingerprinters/ja4h.py:70` states that FoxIO publishes no `JA4H_r` key and the port
  fills only `raw_original_order`. `Crank-Git/ja4plus#600` holds the port half. Issue #310
  records the change.
- Part b of JA4T and JA4TS now holds one entry for each option byte the packet carries,
  including every End-of-Option-List byte. `generateTCPFingerprint` read `tcp.Options`, and
  `github.com/google/gopacket@v1.1.19` reports option kind 0 exactly once.
  `layers/tcp.go:279-282` appends one option for the first kind 0 byte, assigns the rest of
  the header to `tcp.Padding`, and breaks the option loop. The library therefore wrote one
  entry where the wire holds two, and no reference produces that count.
  `wireshark/source/packet-ja4.c:1456` appends one entry for each `tcp.option_kind` field
  occurrence. `rust/ja4/src/tcp.rs:70` reads that same field list. The port reads the raw
  option bytes in `ja4plus/utils/tcp_options.py`. Each of the three writes two entries for
  `badcurveball.pcap` frame 1, and the per-packet vector holds
  `65535_2-1-3-1-1-8-4-0-0_1386_6`. `zeek/ja4t/main.zeek:96-98` breaks before the append and
  writes no entry, so Zeek is the single outlier. The maintainer ruled the split on
  2026-08-12, and issue #297 records the ruling. `docs/specs/foxio/JA4T.md` R10 now carries
  the reference split mark. The library reads `tcp.Contents`, which `layers/tcp.go:270`
  assigns the whole header, and it parses the option list under each option length field. A
  zero byte inside the data of a timestamps option or a segment size option reaches no entry.
  The read stops at the first length the region does not hold, so a crafted option list
  reaches no panic and no unbounded loop. The read is also bounded by the data offset. A
  crafted segment states a header length the segment does not hold, and
  `layers/tcp.go:264-268` then assigns `tcp.Contents` the payload as well as the header.
  `layers/tcp.go:319` adds that layer before it reads the error, so the fingerprinter reaches
  it, and an unbounded read would build part b out of payload bytes. Ruling #125 stays
  closed, because it keys the part width on the value and this ruling decides the entry
  count. The measurement reads `batch/311-ja4h-and-harness` at `27e82a5`, with the corpus
  present. 15 comparisons reach a match, 10 of them JA4T and 5 of them JA4TS, and no
  comparison opens. The run reports 1602 matches before and 1617 after. It reports 783
  deviations before and 768 after. It reports 301 accepted deviations and 301 register keys
  before and after. No register entry reads as closed.
- `ProcessPacket` now emits the open JA4SSH window on a packet that carries the FIN flag and
  the ACK flag. Such a packet closes the connection, and the reference writes the value on it.
  `wireshark/source/packet-ja4.c:1400` tests the flags and
  `wireshark/source/packet-ja4.c:1402` writes the value. `python/ja4.py:555` tests the two
  flags, `python/ja4.py:556` calls `finalize_ja4ssh`, and `python/ja4.py:370` defines it. The
  port emits the window at `ja4plus/fingerprinters/ja4ssh.py:268`. Before the change
  `CloseOpenWindows` was the one emission path, so a value the vector anchors to a FIN+ACK
  packet reached no per-packet comparison. The emission clears the four counters of the window.
  `python/ja4.py:377` deletes the stream from the cache, and the port clears the counters at
  `ja4plus/fingerprinters/ja4ssh.py:439`. `wireshark/source/packet-ja4.c:1485` clears the
  counters of a filled window alone, so Wireshark writes one value twice, at `ssh-r.pcap`
  frame 1850 and at frame 1851. The library follows the port, and the maintainer's rule of
  2026-08-12 states that order. An empty window still emits nothing, so the second FIN+ACK
  packet of a close emits nothing. Issue #222 records the readings, and issue #221 recorded the
  `ssh-r.pcap` bare ACK reading that this change completes. The measurement reads
  `batch/236-ja4ssh-remainder` at `53e8678`, with the corpus present. 5 comparisons reach a
  match, over `gre-sample.pcap` frame 30, `ssh-r.pcap` frames 335, 1826 and 1850, and
  `ssh-r.pcap` stream 2 `JA4SSH.5`. 4 values move from `CloseOpenWindows` to `ProcessPacket`,
  and part c of `ssh-r.pcap` stream 1 falls from `c5s5` to `c4s5`. `sshv1.pcap` frame 72 and
  `v6.pcap` frame 72 now hold a value that differs, and the SSH version 1 packet boundary
  causes that difference. The run reports 1086 matches before and 1091 after, 1284 deviations
  before and 1279 after, and 198 register keys before and after. No register entry reads as
  closed.
- JA4SSH part c now counts the bare ACK of the TCP handshake. The third packet of the handshake
  carries the ACK flag alone and no payload. It arrives before the first SSH packet of the
  connection. `ProcessPacket` opened its state table on SSH data alone, so it dropped that
  packet. Part c reported one client ACK too few in the first window of a connection. The
  reference reads no SSH state before it counts:
  `wireshark/source/packet-ja4.c:1302` tests the flags and the payload length, and
  `python/ja4ssh.py:112` tests the same two fields. Both read the TCP port to pick the side, at
  `wireshark/source/packet-ja4.c:1303` and at `python/ja4ssh.py:113`. A bare ACK therefore opens
  a connection where TCP port 22 is the source port or the destination port. The port holds the
  same test at `ja4plus/fingerprinters/ja4ssh.py:176`. A bare ACK of a connection the library
  already reads counts on every TCP port, as `ja4plus/fingerprinters/ja4ssh.py:250` does. Issue
  #221 records the readings. Issue #200 decomposed the cause. The measurement reads
  `batch/236-ja4ssh-remainder` at `a3b2bf9`, with the corpus present. Part c moves on 8
  comparisons, over `ssh-r.pcap` streams 0 and 2, `ssh-scp-1050.pcap` stream 0 and
  `ssh2.pcapng` stream 14. 7 comparisons reach a match. `ssh-r.pcap/2/JA4SSH.1` still differs in
  part a, which issue #223 owns. No value appears and no value disappears. The run reports 1078
  matches before and 1085 after, 1293 deviations before and 1286 after, and 198 register keys
  before and after. The JA4SSH deviation count falls from 32 to 25.
- The conformance harness now compares the last JA4L value of each connection, and no longer
  the last JA4L value of each stream number. FoxIO writes one per-stream entry for one
  connection, and it numbers two entries of `chrome-cloudflare-quic-with-secrets.pcapng` with
  the stream number `0`: the TCP connection of the source port `57098` and the QUIC connection
  of the source port `50280`. The vector group therefore held two values, the adapter wrote an
  occurrence number for them, and the last-emission rule of issue #196 reached no value. The
  client measurement point of the TCP connection moves, so the library reports `30_64` at frame
  3 and `149_64` at frame 4, and the surplus first value shifted every later occurrence by one.
  The three JA4L-C occurrences of that stream held `30_64`, `149_64` and `113_64_quic` against
  the two values `149_64` and `113_64` that the vector holds. `conformance_test.go` collapses the
  values of one connection, and it keeps the bare key on the last value of the stream. This
  change moves no fingerprint, and it writes no register entry. Issue #215 holds the reading.
  Measured against `batch/236-ja4ssh-remainder` at `a3b2bf9` with the corpus present: 1 JA4L-C
  comparison moved to a match, 1 surplus JA4L-C comparison went away, and 1 JA4L-C comparison
  still reports the QUIC marker that issue #197 adds. The run reports 1078 matches before and
  1079 after, 1293 deviations before and 1291 after, and 198 register keys before and after.
- JA4SSH now counts the SSH packets that FoxIO counts, so the window fills and
  `ProcessPacket` emits a value again. `internal/parser/ssh.go:17` reads the four-byte length
  field of an SSH record, and a cipher hides that field after the key exchange, so the library
  counted almost no SSH packet after the key exchange. On `ssh.pcapng` stream 0 the reference
  counted 200 SSH packets and the library counted 7, so no window of 200 ever filled and
  `CloseOpenWindows` was the only emission path. Two changes carry the repair. A payload on a
  connection the library already reads now counts, because the version line of either
  direction identifies the connection. `internal/parser/ssh_tracker.go` adds
  `parser.SSHMessageTracker`, which follows the SSH message boundary and reads the TCP
  sequence number, so the count reads the SSH message and not the TCP segment. Two FoxIO
  implementations state the rule and the two agree:
  `wireshark/source/packet-ja4.c:1469` counts one packet for each `ssh.direction` field, and
  `python/ja4ssh.py:94` counts the packet whose protocol list holds `ssh`. The port holds the
  same rule at `ja4plus/fingerprinters/ja4ssh.py:247`. Issue #200 records the readings.
  Measured against `batch/210-session5-followups` at `c4978ab` with the corpus present: 12
  JA4SSH comparisons moved to a match and 2 spurious values appeared, on `gre-sample.pcap`,
  `ssh-r.pcap`, `ssh-scp-1050.pcap`, `ssh.pcapng`, `ssh2.pcapng`, `sshv1.pcap` and `v6.pcap`.
  The run reports 1065 matches before and 1077 after, 1288 deviations before and 1278 after,
  and 198 register keys before and after. The JA4SSH deviation count falls from 42 to 32.
  The base moved twice while this branch was open, and the four counts read the same on
  `5f05554` and on `c4978ab`, because #211 moves no fingerprint of the corpus.
- JA4L now times a second connection on one grouping key from the measurement points of that
  connection. `ja4l.go:150` wrote the initial sequence number of the endpoint before the guard
  that holds point A. A second connection therefore kept the points of the first one. It
  reported no server value. Its client value measured the first SYN-ACK, so the value grew with
  the age of the state. A SYN that carries an initial sequence number the connection does not
  hold now restarts the connection. The restart drops the timestamps, the time-to-live values
  and the initial sequence numbers. It keeps the endpoints that every result reports.
  `ja4plus/fingerprinters/ja4l.py:433-437` holds the same test.
  `ja4plus/fingerprinters/ja4l.py:406-417` clears the same three maps. This is a reading, and
  not a ruling. The corpus holds no capture that reaches one grouping key twice, so
  `TestJA4LTimesASecondConnectionOnOneGroupingKeyFromItsOwnPoints` builds the separating packet
  sequence. The measurement reads `batch/210-session5-followups` at `5f05554`, with the corpus
  present. The run reports 1065 matches, 1288 deviations and 198 accepted deviations before and
  after. The register holds 198 keys before and after. The change moves no fingerprint of the
  corpus. Issue #211 holds the reading.
- The JA4SSH window now emits at the packet count the caller names, and the threshold holds
  no upper cap. `ja4ssh.go:196-199` capped it at 10, so the library over-emitted by hundreds
  of values on one capture. The window also counts the SSH packets of the two directions
  alone, so a bare ACK no longer advances it and a window of bare ACKs produces no value.
  The HASSH trigger goes too: `ja4ssh.go:201` emitted when the two HASSH values were present
  and the window held one packet, and the port holds no such rule. `docs/specs/spec.md`
  `## Parity with ja4plus` holds the four JA4SSH rows, FR-parity-25 through FR-parity-28
  state the requirements, and the port's issues #28, #96 and #97 hold the rulings. Measured
  against `epic/48-parity-tls-latency` at `ec0f63e` with the corpus present: 1807 JA4SSH
  comparisons moved, on `gre-sample.pcap`, `ssh-r.pcap`, `ssh-scp-1050.pcap`, `ssh.pcapng`,
  `ssh2.pcapng`, `sshv1.pcap` and `v6.pcap`. The run reports 1035 matches before and after,
  3155 deviations before and 1348 after, and 150 register keys before and after. Every moved
  comparison was an extra value that the vector does not hold.
- `CleanupConnection` on JA4L now removes a tunneled connection. The method normalized the
  address pair the caller gave, and it deleted that one key. `normalizeKey` builds the
  grouping key from the inner address pair, and a `FingerprintResult` reports the outer
  pair, so the two keys never met. A caller that named the reported pair removed no
  tunneled connection, and `connections` grew without a bound. `JA4LFingerprinter` now
  holds `groupingKeys`, which reads the grouping key from the reported key. The method
  removes the connection and every index entry of it, so a caller that names either key
  leaves no state behind. `ja4plus/fingerprinters/ja4l.py:100-104` holds the same map, and
  `ja4plus/fingerprinters/ja4l.py:216` holds the same cleanup rule. Every FoxIO reference
  and the port agree, so this is a reading and not a ruling.
  `docs/specs/features/05-conformance-gaps.md` FR-gaps-14c states the rule, and issue #169
  holds the reading. JA4 and JA4S read no such index, so they remove no tunneled
  connection, and issue #193 owns that repair. The change moves no fingerprint.
- The QUIC CRYPTO stream reassembly. `ParseCryptoFrames` stepped over a PADDING frame
  alone, so a PING frame in front of the CRYPTO frames hid the whole client hello. RFC 9000
  Section 19.2 gives the PING frame no field. The library now produces a JA4 value on every
  QUIC capture of the corpus that carries a client hello. Issue #42 holds the measurement.

### Changed

- **`--types` returns an error for a token that names no method, and the command exits 1.** It
  exited 0 and printed an empty table before, so a caller that misspelled a token read the
  absence of output as the absence of fingerprints. `cmd/ja4plus/types.go` holds the eleven
  tokens, and the error names every one of them. **The shape follows the port**, at
  `ja4plus/cli.py:82-92` of tag `v1.1.0`. **A script that passes an unknown token changes
  behaviour**, and `--types` with an empty list still selects nothing and exits 0, which the
  port also does. Issue #61 built it.
- **`--types ja4ls` selects the JA4LS values alone, and `--types ja4l` still selects both.**
  The token is a superset over the port, which rejects `ja4ls` today, and
  `Crank-Git/ja4plus#605` proposes it there so the two converge. The filter reads the
  `JA4L-S=` label of the value, because a JA4LS result carries `Type: "ja4l"`. Issue #61 built
  it, and it closes R9 question 3.
- **The register declines 108 per-packet JA4H raw values, and the library keeps the per-stream
  shape.** The keys name 57 `JA4H_ro` comparisons and 51 `JA4H_r` comparisons, on 9 captures.
  **The maintainer ruled on 2026-08-12 in issue #285.** The two FoxIO vector sets disagree, and
  no single value satisfies both. On a request that carries no cookie the per-stream set holds
  `co10nn010000_User-Agent_` and the per-packet set holds `co10nn010000_User-Agent__`. On the
  last cookie pair the per-packet set writes a trailing comma, and the per-stream set writes
  none. `.claude/rules/parity.md` rule 3 names the shared vector set as the gate, and the
  Python port writes the per-stream shape. The library therefore follows the per-stream set.
  `wireshark/source/packet-ja4.c:615` writes the format string with no condition, and `:1181`
  and `:1183` append the commas. `:1637-1638` truncate `unsorted_cookie_fields` alone, so the
  trailing comma of `unsorted_cookie_values` survives. `zeek/ja4h/main.zeek:210` writes four
  fields always. **Every one of the 108 comparisons differs by that shape alone**, and issue
  #314 measured each one. The 26 surplus `JA4H_r` keys reach no entry, because issue #289 holds
  their cause. The 69 comparisons on frames that produce no JA4H value reach no entry either.
  **This change moves no fingerprint value.** Measured on `595ed13` with the corpus present:
  the run reports 1608 matches before and after. It reports 803 deviations before and 695
  after, and 301 accepted deviations before and 409 after. The register holds 301 keys before
  and 409 after, and no entry reads as closed. Issue #314 holds the measurement.

- **The register declines four FoxIO JA4SSH values, and the library keeps its own value.** The
  four keys are `ssh-r.pcap/1/JA4SSH.1`, `ssh-r.pcap/2/JA4SSH.1`,
  `ssh-scp-1050.pcap/0/JA4SSH.3` and `ssh-scp-1050.pcap/0/JA4SSH.4`. Each one differs in part a
  alone, which holds the two mode fields. **The project manager ruled on 2026-08-12 in issue
  #223, and the ruling is provisional.** `.claude/rules/rulings.md` reserves a ruling to the
  maintainer. The maintainer delegated the session and slept, and the project manager ruled
  under that delegation. This is the one provisional ruling of the register, so a later reader
  confirms it. **The four vectors contradict a rule that the reference implements.**
  `docs/specs/foxio/JA4SSH.md` R13 states that the mode is `0` when the side sent no SSH packet.
  Four implementations enforce R13: `zeek/ja4ssh/main.zeek:63`,
  `wireshark/source/packet-ja4.c:400`, `rust/ja4/src/ssh.rs:284` and `python/ja4ssh.py:51`.
  `testdata/foxio/python/ssh-scp-1050.pcap.json` holds `c112s1460_c0s200_c36s0` and
  `c112s1460_c0s200_c23s0`, and each value pairs a client mode of `112` with a client packet
  count of `0`. **A shallow copy causes the defect.** `python/ja4ssh.py:8` opens the
  module-level template, and `python/ja4ssh.py:9` and `python/ja4ssh.py:10` hold two mutable
  lists in it. `python/ja4ssh.py:88` and `python/ja4ssh.py:128` each open a window with
  `entry['stats'].append(dict(ja4sh_stats))`, and `dict()` copies one level. Every window
  therefore reads one shared payload list at `python/ja4ssh.py:146`. R8 states that the counters
  reset after each window, and the two payload lists do not reset. **The per-packet vector
  agrees with this library.** `testdata/foxio/wireshark/ssh-r.pcap.json` holds
  `c48s21_c6s5_c4s5` and `c76s76_c104s96_c19s82`, which are the two library values.
  **The library needs no change, because FR-parity-27 already holds the rule.** The mode reads
  the packet lengths of its own window alone, and `TestJA4SSHReadsTheModeOfTheWindowAlone` holds
  that rule. Port issue #96 ruled it. **This change moves no fingerprint value, and it changes
  no behaviour.** Measured on `batch/236-ja4ssh-remainder` at `cc2c522` with the corpus present:
  the run reports 1091 matches before and after, and 1279 deviations before and 1275 after. The
  register holds 198 keys before and 202 after, and no entry reads as closed. Coverage reads
  72.4% before and after. `docs/specs/spec.md` `## Changelog` round 23 records the ruling.
- **JA4L now writes the marker `quic` as the third part of a value on a QUIC connection, and a
  TCP connection keeps two parts.** This is a breaking behaviour change under `v1.0.0`.
  **The maintainer ruled on 2026-08-12 in issue #197, and issue #127 holds the original
  ruling.** The QUIC half of issue #127 reached no code, and issue #197 found the gap. The
  deciding rule is that the library matches the port one to one, and that it follows the FoxIO
  material where that leaves a choice. **The port writes the marker.**
  `ja4plus/fingerprinters/ja4l.py:62` defines `QUIC_MARKER = "quic"`, and the port writes three
  parts at `:549` and at `:602`. It writes two parts on a TCP connection at `:446`, `:466` and
  `:482`. `python/ja4.py` is FoxIO's reference Python inside the corpus, and it is not the port.
  The FoxIO material reaches the same answer, because `.claude/rules/rulings.md` ranks an image
  first and `docs/specs/foxio/JA4L.md` R3 states that a value holds three parts. The literal
  `quic` follows `wireshark/source/packet-ja4.c:1441` and `:1447`. **The entry below records the
  reading that reached this ruling, and the QUIC part count is no longer open.**
  **The match count falls, and the ruling accepts that.** Measured on
  `batch/210-session5-followups` at `0751acc` with the corpus present: the marker moves the
  library value on 32 comparisons, across 3 captures. It closes 2 per-packet comparisons, and it
  opens 13 per-stream comparisons that match without it. The run reports 1076 matches before and
  1065 after. Thirteen entries reach `testdata/deviations.json` with `"capability": false` and
  the ruling `#197`, and each reason states the per-stream divergence alone. The register holds
  185 keys before and 198 after, and no entry reads as closed. `docs/specs/spec.md`
  `## Changelog` round 18 records the ruling.
- **The JA4L third part reaches a recorded reading, and it moves no fingerprint.**
  `docs/specs/foxio/JA4L.md` R35 states the reading, and `docs/specs/spec.md` `## Changelog`
  round 16 states the measurement. On a TCP connection the third number of a per-packet vector
  is the Wireshark part c, which R24 names as the numerator of `ja4.ja4l_delta`. The
  `tcpdump-geneve.pcap` frame 13 vector holds `ja4.ja4l` as `93_64_124` and `ja4.ja4l_delta`
  as `1.3`, and `124 / 93` reads `1.3`. Issue #127 declines that part c, so this release adds
  one test that holds the two-part TCP form. **On a QUIC connection the third part is the
  marker `quic`, and the part count stays open.** The two FoxIO vector sets state two
  different part counts for one QUIC connection. On stream 36 of `ssh2.pcapng` the per-stream
  vector holds `JA4L-C` as `169_128`, and the per-packet vector holds `ja4.ja4l` as
  `169_128_quic` on frame 1147. The marker moves the library value on 16 per-packet
  comparisons and on 16 per-stream comparisons, across 3 captures. It closes 2 per-packet
  comparisons, and it opens 13 per-stream comparisons that match exactly today.
  **Issue #197 holds the question, and the maintainer rules.** The register holds 185 keys
  before and after, and no entry reads as closed.
- **JA4L now fills the TCP client measurement point from the packet that the Python
  reference names, and the client value of a TCP connection moves.** This is a breaking
  behaviour change under `v1.0.0`. **The maintainer ruled on 2026-08-12 in issue #196.**
  Point `C` reads every packet that carries `ACK`, carries no `SYN`, and holds the relative
  sequence number `1` and the relative acknowledgement number `1`. A later such packet
  replaces the point. A packet that carries a whole HTTP request moves no point, because the
  reference keeps such a packet under a separate cache. Earlier releases read the first packet
  that carried `ACK` and no `SYN`, they tested no sequence number, and the point never moved.
  **The four FoxIO implementations state three different rules, so this is a ruling and not a
  reading.** `docs/specs/foxio/JA4L.md` R33 states the four rules, and R34 states that the two
  FoxIO vector sets hold two different values for stream 0 of `badcurveball.pcap`. Python
  states the rule that this change implements, at `python/ja4.py:570`. Wireshark, Rust and
  Zeek each fill the point once and never move it. `docs/specs/spec.md` `## Changelog` round
  15 records the ruling. **The ruling knowingly gives up the per-packet vector**, which holds
  `2177_64_114797` on frame 9 of `badcurveball.pcap` while the library writes part a as
  `2181`. Thirty-five entries reach `testdata/deviations.json` for that divergence, each with
  `"capability": false` and the ruling `#196`. Each reason states the part a divergence alone,
  because issue #197 owns the third part. The conformance harness now compares the last
  emission for a per-stream method that the vector holds once. The library keeps its
  per-packet streaming contract, it suppresses no intermediate value, and it gains no flush.
  **Two further repairs land in the same change, and the reference is unanimous on both.**
  Point `A` and point `B` no longer move, so a repeated SYN-ACK reports no second server
  value; `python/common.py:101` names both fields. The two endpoint names of a relative number
  read the grouping address pair, so the mirrored session of `gre-erspan-vxlan.pcap` keeps its
  client value. Measured on `epic/48-parity-tls-latency` at `3e7a47a` with the corpus present:
  43 `JA4L-C` comparisons moved to match on 22 captures, and 35 per-packet `JA4L` comparisons
  gained a registered divergence. The per-stream set reports 703 matches, 514 deviations and
  150 accepted deviations before the change, and 744 matches, 457 deviations and 150 accepted
  deviations after it. The per-packet set reports 332 matches, 834 deviations and 0 accepted
  deviations before the change, and 332 matches, 833 deviations and 35 accepted deviations
  after it. The register holds 150 keys before and 185 after. Every `JA4L-C` comparison of the
  per-stream set now matches. Issues #205 and #206 hold the two comparisons the harness change
  leaves worse, both on `chrome-cloudflare-quic-with-secrets.pcapng` stream 0.
- **JA4L and JA4LS now report half of the measured time, and every latency value moves.**
  This is a breaking behaviour change under `v1.0.0`. The `JA4L.png` image labels part a
  `One-way TCP latency in µs (1ms = 1,000µs)`. `docs/specs/foxio/JA4L.md` R6 states that
  part a is half of the measured time, because one measurement covers a round trip.
  Earlier releases reported the whole time between the two measurement points. Every value
  was therefore exactly twice the FoxIO vector, and JA4L matched on no capture. R6 cites
  four FoxIO reference implementations that each divide by 2. The two integer references
  truncate the half toward zero, and Go integer division truncates the same way. Every
  FoxIO reference agrees, so this is a reading and not a ruling. The conformance run
  reports 943 matches and 3247 deviations before the change. It reports 1011 matches and
  3179 deviations after it. The register key count stays at 0. On the per-stream vector
  set, JA4LS falls from 59 deviations to 3, and JA4L falls from 56 deviations to 44.
  Twenty-four captures move, and JA4LS now matches on every stream of twenty-one of them.
  The per-packet counts stay at 308 matches and 1777 deviations. A per-packet JA4L vector
  carries a third part that the library does not yet produce. Issue #166 holds the
  measurement, and the run measured the change on `batch/184-ja4l-repairs` at `f4aa6e6`.
- **JA4L now fills the two QUIC client measurement points in the reference direction, and
  the client value of a QUIC connection moves.** This is a breaking behaviour change under
  `v1.0.0`. A server Handshake packet fills point C, and a client Handshake packet fills
  point D and completes the value. Every server Handshake packet moves point C until point
  D fills, so the last one supplies the point. A long-header packet of another type fills
  neither point. Earlier releases read point C from a client packet and point D from a
  server packet, and they read every long-header type, so the library reported the client
  value on a server packet and reported no value at all on three connections of
  `tls3.pcapng`. `ja4plus/fingerprinters/ja4l.py:580-599` states both rules, and every
  FoxIO reference agrees, so this is a reading and not a ruling. The conformance run
  reports 3251 deviations before the change and 3247 after it, the match count stays at
  943, and the register key count stays at 0. Three captures move:
  `chrome-cloudflare-quic-with-secrets.pcapng`, `ssh2.pcapng` and `tls3.pcapng`. On the
  per-packet vector set, seven JA4L client values reach the packet the vector names, and
  four values that sat on a server packet go away. On the per-stream vector set,
  `tls3.pcapng` streams 22, 23 and 24 produce a JA4L-C value again, and each one is twice
  the vector value, which #166 halves. Issue #186 holds the measurement, and the run
  measured the change on `batch/184-ja4l-repairs` at `4d46f47`.
- **JA4L and JA4LS now read a UDP flow only when the flow carries QUIC, and the library
  produces no value for another UDP flow.** This is a breaking behaviour change under
  `v1.0.0`. The library reads the UDP payload for a QUIC long header, and it reads the
  direction of the flow from the UDP port 443 alone. A flow whose two ports are 443 names
  no server, so the library produces no value for it. Earlier releases timed every UDP
  flow, and they read the direction from the address that sent the first packet. An NTP
  flow therefore produced a JA4L value that the reference does not produce.
  `ja4plus/fingerprinters/ja4l.py:554-566` states the rule, and every FoxIO reference
  agrees, so this is a reading and not a ruling. The library stops producing 193 values
  across six captures of the FoxIO corpus: `gre-sample.pcap`, `latest.pcapng`,
  `ssh2.pcapng`, `sshv1.pcap`, `tls3.pcapng` and `v6.pcap`. The conformance run reports
  3441 deviations before the change and 3251 after it, and the register key count stays
  at 0. Issue #173 holds the measurement, and the run measured the change on
  `batch/184-ja4l-repairs` at `c1f13d5`.
- **A tunneled connection now carries two keys, and the fingerprint of such a connection
  moves.** This is a breaking behaviour change under `v1.0.0`. A `FingerprintResult` for a
  GRE, ERSPAN, VXLAN or Geneve packet holds the outer address pair with the inner port
  pair, and the first packet of the connection fixes that pairing. The library collects
  packets into one connection by the inner address pair and the inner port pair, and
  `GetShardKey` returns that grouping pair. A JA4L value and a JA4LS value read the
  time-to-live of the outer address layer. Earlier releases read the outer address pair
  for both keys and read the tunnel transport layer for the port pair, so a mirrored
  capture merged both directions of one session into one connection and a VXLAN packet
  reported the tunnel port 4789. The three tunneled captures of the FoxIO corpus move:
  `gre-sample.pcap`, `gre-erspan-vxlan.pcap` and `tcpdump-geneve.pcap`. The maintainer
  ruled this on 2026-08-11, and `docs/specs/spec.md` `## Changelog` row 12 records it.
- **The JA4 and JA4S QUIC branches now read the inner UDP layer of a tunneled packet.**
  The first tunnel repair reached the paths that call the parser helper. These two branches
  read the outer UDP layer directly. They reported the tunnel port, and they grouped a
  tunneled connection by the outer address pair. #170 routes both branches through the
  helper. No capture of the FoxIO corpus carries QUIC inside a tunnel, so no value moves
  and `quic_tunnel_test.go` holds the behaviour.
- The parser reads no fingerprint from a packet that nests more than four tunnel layers,
  and it returns a non-fatal error that names the limit. It returns the same result for a
  tunnel whose inner packet it does not read, such as a GRE header that names an unknown
  protocol type or a truncated inner frame. No released value moves, because no capture of
  the FoxIO corpus nests more than three tunnel layers.
- **A changed fingerprint.** The library produces the JA4 value
  `q13d0310h3_55b375c5d22e_cd85d2d88918` on `quic-with-several-tls-frames.pcapng` and on
  `quic-tls-handshake.pcapng`, and it produced none before. The FoxIO Rust implementation
  produces the same value on both captures. On
  `chrome-cloudflare-quic-with-secrets.pcapng` stream 0 the JA4 value moves from
  `q12i030000_55b375c5d22e_000000000000` to `q13d0310h3_55b375c5d22e_cd85d2d88918`, and the
  raw form moves from `q12i030000_1301,1302,1303_` to
  `q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201`.
  The earlier value read a part of the client hello, so it named three cipher suites and no
  extension. A released version produced it, so this is a breaking behaviour change under
  `v1.0.0`. Issue #42 holds the measurement.
- `ClientHelloFromCryptoFragments` returns no client hello while a fragment of the
  handshake message is still missing. It parsed a part of the message before, which
  produced a fingerprint of a cipher list that the client never sent.
- The QUIC fragment buffer of one connection reaches 16384 bytes. The JA4 fingerprinter
  drops the connection state when a sender passes the bound, because an unbounded buffer is
  a memory-exhaustion path. `parser.MaxCryptoBufferBytes` holds the bound, and the port
  holds the same value.
- The license correction. The repository states two licenses, and it names which material
  each one covers. The original Go code carries the BSD 3-Clause license.
  FoxIO License 1.1 covers ten of the eleven methods that this project implements, and
  that license permits non-commercial use only. `NOTICE` names those ten, and it holds
  the FoxIO terms. Earlier releases named the BSD 3-Clause license alone, so a commercial
  user read a permission that FoxIO does not grant. `docs/audit/license-decision.md`
  records the decision behind the correction.
- The module needs Go 1.24 or later. It needed Go 1.22 before this change, so a consumer
  on Go 1.22 or Go 1.23 must move to Go 1.24.

## [v0.3.0] - 2026-04-08

### Added

- The JA4D fingerprinter, which reads a DHCP message.
- `CleanupConnection` on the `Fingerprinter` interface. A caller removes the state of one
  connection, so a long-running monitor holds no dead entry.
- `GetShardKey` on the processor. It returns one key for both directions of a connection,
  so a sharded caller routes both directions to one processor.

### Changed

- `FingerprintResult.Type` holds a lower-case method name for every method. JA4, JA4S and
  JA4X held an upper-case value before this release.

## [v0.2.0] - 2026-04-08

### Added

- IPv6 support in every method that reads an IP header.
- QUIC detection in JA4S.
- HASSH extraction from an SSH KEXINIT message, for the client and for the server.
- TCP stream reassembly in JA4H, so an HTTP request that spans two segments produces a
  fingerprint.
- UDP and QUIC timing in JA4L, plus the distance estimate and the operating-system
  estimate.
- The `JA4_ro` raw form, which holds the original wire order.
- `InterpretJA4SSH`, which names the session type of a JA4SSH value.
- CRYPTO frame accumulation in the QUIC parser, so a ClientHello that spans two Initial
  packets produces a fingerprint. The release exports `CryptoFragment`,
  `DecryptQUICInitialCrypto` and `ClientHelloFromCryptoFragments`.

### Fixed

- JA4S hashes the extension list in wire order. It sorted the list before this release.
- JA4SSH breaks a tie in the packet-size mode on the value it reads first.
- JA4SSH produces a fingerprint on each packet after it reads both HASSH values.

## [v0.1.0] - 2026-04-06

### Added

- Package `ja4plus`, which holds the `Fingerprinter` interface and one fingerprinter per
  method.
- The JA4 fingerprinter, for a TLS ClientHello over TCP or over QUIC.
- The JA4S fingerprinter, for a TLS ServerHello.
- The JA4H fingerprinter, for an HTTP request.
- The JA4X fingerprinter, for an X.509 certificate.
- The JA4SSH fingerprinter, which produces one fingerprint for each window of SSH
  packets.
- The JA4T fingerprinter and the JA4TS fingerprinter, for a TCP SYN and for a TCP
  SYN-ACK.
- The JA4L fingerprinter, which measures the latency of a connection.
- The processor, which runs every fingerprinter over one packet.
- The fingerprint lookup, which reads the embedded FoxIO database.
- The `ja4plus` command-line program.
- Package `internal/parser`, which decodes TLS, QUIC, HTTP, SSH and X.509. It also
  detects a GREASE value and computes a truncated SHA-256 hash.
- The CI workflow and the release workflow.
- The README, which documents the interface, the command-line program and the format of
  each fingerprint.

[Unreleased]: https://github.com/Crank-Git/ja4plus-go/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/Crank-Git/ja4plus-go/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/Crank-Git/ja4plus-go/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/Crank-Git/ja4plus-go/releases/tag/v0.1.0
