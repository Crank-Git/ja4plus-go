---
name: conformance
description: Fetch the FoxIO corpus and check ja4plus-go against the reference vectors. Use when asked about spec compliance, a deviation, whether a fingerprint is correct, or to compare output with FoxIO.
allowed-tools: Bash, Read
---

# Check conformance against the FoxIO reference

The library claims to implement the FoxIO JA4+ specification. This procedure tests that
claim against FoxIO's own captures and expected values.

## 1. Fetch the corpus

```
make corpus
```

The script reads the commit in `testdata/foxio.pin` and fetches the FoxIO repository at
that commit. It writes three directories.

| Directory | Holds |
|---|---|
| `testdata/foxio/pcap/` | 38 captures. |
| `testdata/foxio/python/` | 37 per-stream vectors. |
| `testdata/foxio/wireshark/` | 37 per-packet vectors. |

The corpus is not tracked in git. It is FoxIO-licensed material, so the project fetches it
and does not redistribute it.

A second run downloads nothing. `testdata/foxio/.fetched` records the fetched commit.

## 2. Run the suite

```
make conformance
```

The suite reads every capture, runs one `Processor` over it in capture order, and compares
each fingerprint with the vector as an exact string match.

## 3. Read the report

Read `docs/audit/conformance.md`. It holds a summary and one row per capture and per
method.

| Result | Meaning |
|---|---|
| `match` | The library output equals the vector, character for character. |
| `deviation` | The two differ, or one produced a fingerprint the other did not. |
| `not applicable` | The vector set holds no value for that method on that capture. |

A deviation row holds the expected value and the produced value.

## Which vector set decides

Some methods appear in one set only.

- The **per-stream** set covers JA4, JA4S, JA4H, JA4X and JA4SSH. It carries the raw forms
  `JA4_r`, `JA4_o` and `JA4_ro`.
- The **per-packet** set covers every method, including JA4D and JA4D6.
- **The per-packet set decides JA4D and JA4D6.** The per-stream vector for `dhcpv6.pcap`
  is an empty list, so the Python reference does not cover those methods.

## To close a deviation

`docs/specs/features/05-conformance-gaps.md` FR-gaps-1, FR-gaps-2 and FR-gaps-3 state the
rule. Every closure follows all three.

1. **Read the deviation row in `docs/audit/conformance.md`.** The row names the capture,
   the vector set, the method and the two values.
2. **Read the FoxIO reference for that method and that capture.** Cite a file and a line
   at the pinned commit. `.claude/rules/rulings.md` states what counts as evidence.
3. **Write the failing test first.** FR-gaps-2 requires a test that names the capture and
   the method. Write both names in the test name or in a comment above it.
4. **Change the library, and never the vector.** FR-gaps-4 gives the reference the
   decision.
5. **Record a changed fingerprint in `CHANGELOG.md`.** FR-gaps-3 requires one entry for
   each changed fingerprint. A fingerprint that a released version produced is a breaking
   behaviour change under `v1.0.0`.
6. **Run the whole suite.** The deviation count falls, and no new deviation appears.
7. **State the measurement in the pull request.** `.claude/rules/parity.md` names four
   numbers.
   1. How many values moved.
   2. On which captures.
   3. The conformance count before and after.
   4. The register key count before and after.

**Every deviation reaches one of three ends.** FR-gaps-1 allows no fourth.

| End | Where it lands |
|---|---|
| The closure | The code, plus the test of step 3. |
| A new requirement | `docs/specs/features/05-conformance-gaps.md`. |
| An accepted exclusion | `docs/audit/conformance-exclusions.md`, with the maintainer's name and the date. |

**A closure that no test holds is not a closure.** A later change reverses it in silence.

**Stop before you invent a rule.** `.claude/rules/rulings.md` `## Stop conditions` names
every case where the maintainer decides. A reference split is one of them.

## Which record a fact reaches

**This project holds two records, and they hold two distinct classes of fact.** The
maintainer ruled on 2026-08-11, in issue #38.

| Record | What it holds |
|---|---|
| `testdata/deviations.json`, the register | **A decline.** This project compared its output against a FoxIO value and chose to differ. |
| `docs/audit/conformance-exclusions.md`, the exclusions page | **An exclusion.** The suite makes no comparison at all. |

**One question settles which record a fact reaches.** Does the guard "an entry whose
comparison now matches fails the suite" make sense for this fact? **Yes, and it is a
register entry. No, and it is an exclusion.**

`.claude/rules/parity.md:71` states that guard. An exclusion reaches no comparison that
could later match, so the guard can evaluate nothing.

`dtls-udp.notest.cap` decides the boundary. FoxIO marks it `notest`, so it yields no
stream and no method, and it reaches no `<capture>/<stream>/<method>` register key.
FR-gaps-19 records `not applicable` for it, and FR-gaps-20 requires an exclusions entry.

**Write no entry in either record yourself.** The register is empty today, and the
exclusions page holds the one entry that FR-gaps-20 requires. Only the maintainer accepts
an entry.

## Rules

- **The FoxIO reference decides every disputed result.** When a library test disagrees
  with a vector, the library is wrong. Never change a vector.
- **An extra fingerprint is as wrong as a missing one.** The suite reports both.
- **The bar is byte-identical, with no exception.** A deviation is closed, or it records
  its reason in `docs/audit/conformance-exclusions.md` and the maintainer accepts it by
  name and by date.
- `dtls-udp.notest.cap` carries the FoxIO `notest` marker. FoxIO excludes it from their
  own suite, so the report records it as `not applicable`.

## To move the pin

Change `testdata/foxio.pin` to the new FoxIO commit, in a commit that does nothing else.
Run `make corpus` and `make conformance`. A new deviation means FoxIO changed a
definition. Open an issue for it.
