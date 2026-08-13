---
name: release
description: Run every pre-release gate for ja4plus-go and then cut a tagged release. Use when asked to release, cut a version, tag, publish, run the release gates, or check whether the project is ready to ship.
allowed-tools: Bash, Read, Grep
---

# Cut a release

GoReleaser builds the tag. `docs/specs/features/10-release.md` holds the requirements and
`docs/specs/features/16-pre-release-validation.md` holds the pre-release cases.

**A published tag cannot be moved, and a deleted tag stays in the module proxy cache.**
Every gate runs before the tag, never after it.

## 1. Run every gate

```
make test && make lint && make vuln && make conformance && make docs && make prerelease
```

Nothing proceeds until all six pass. **Report a failure with its output.** Do not
summarise a red gate as "mostly passing".

## 2. Check the release blockers

These are not covered by the commands above. Check each one by hand.

| Blocker | How to check |
|---|---|
| `docs/audit/license-decision.md` records the maintainer's decision. | Read the file. |
| Every entry in `docs/audit/conformance-exclusions.md` carries the maintainer's acceptance, by name and by date. | Read the file. |
| `testdata/deviations.json` holds no entry whose comparison now matches. | `make conformance` fails if one does. |
| Every register row of `features/08-python-parity.md` is closed. | Read the feature file. |
| No tracked document applies the count of ten to methods. | `go test -run TestMethodCount ./...` |
| Every `LIVED` mutation of the most recent sweep is settled. | Read `docs/mutation_settlements/`. |
| The README links to the documentation site, and the link resolves. | Read and follow it. |

## 3. Check the artifact configuration

```
goreleaser check
goreleaser release --snapshot --clean
```

Then confirm three properties of the snapshot.

1. **Five artifacts**: Linux amd64, Linux arm64, Darwin amd64, Darwin arm64, Windows amd64.
2. **Every one built with `CGO_ENABLED=0`.** No artifact carries the `libpcap` build tag.
   A released binary that links libpcap is a release defect.
3. A checksum file and a software bill of materials exist.

## 4. Update the record

- `CHANGELOG.md` describes the released behaviour and nothing else.
- **Breaking changes are named as breaking.** `CloseOpenWindows` is not one. It sits on the
  optional interface `WindowCloser`, and the exported `Fingerprinter` interface does not
  change. JA4LS is a new method and it breaks nothing, and the CHANGELOG states it and
  states eleven methods through ten fingerprinters.
- `docs/api/v1.md` records every exported name.

## 5. Tag

The tag is created on `master`, never on `dev`. Promotion from `dev` to `master` is a
separate step the maintainer approves.

**Ask the maintainer before you create a tag or push one.** A tag is outward-facing and it
cannot be taken back.

## After the release

Run the binary cases of `make prerelease` against the published artifacts, on each platform
a runner offers. **A platform no runner offers is recorded as unchecked in the release
notes.** It is never reported as passing.

## The v1.0.0 freeze

After `v1.0.0` the exported names and signatures stay stable for the whole `v1` series.
Breaking that promise means `v2` and a changed import path.

**Before you tag `v1.0.0`, confirm the maintainer settled every open R9 question of
`docs/specs/spec.md`.** R9 question 2 is settled already. The maintainer ruled on 2026-08-11
that `CloseOpenWindows` sits on the optional interface `WindowCloser`, and #53 records the
ruling. Never re-ask that question.
