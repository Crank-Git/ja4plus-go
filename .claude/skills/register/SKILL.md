---
name: register
description: Record or verify an accepted difference from a FoxIO value in testdata/deviations.json. Use when a conformance deviation will not be closed, when asked about a decline, a divergence, a ruling, or why a fingerprint differs from FoxIO on purpose.
allowed-tools: Bash, Read, Edit, Grep
---

# Record an accepted difference

`testdata/deviations.json` is the register. It holds one entry for each difference from a
FoxIO value that this project accepts on purpose.

**An entry is an accepted difference, not a hidden failure.** A deviation the register does
not hold is a defect. **A register entry whose comparison now matches fails the conformance
suite**, so a closed deviation cannot sit in the file unnoticed.

Read `.claude/rules/rulings.md` before you add an entry. Read
`.claude/rules/parity.md` when the entry also affects the Python port.

## 1. Confirm that the difference needs an entry

Most deviations do not. Work through these in order.

| The situation | What to do |
|---|---|
| Every FoxIO implementation agrees, and this project differs. | **Change the code.** No entry. |
| The FoxIO implementations disagree with each other. | A reference split. **Stop and ask the maintainer.** |
| The reference produces a value that describes the capture and not the connection. | A reference defect. **Stop and ask the maintainer.** |
| The reference file holds no key for the method at all. | The comparison is unreachable, not failed. An entry records it. |
| This project chose not to build a capability. | A capability decline. An entry records it. |

**Only the maintainer rules.** An engineer records a reading and opens an issue.
`.claude/rules/rulings.md` holds the stop conditions.

## 2. Write the entry

```json
{
  "key": "ssh2.pcapng/15/JA4L-S",
  "capability": false,
  "ours": "6252_58",
  "theirs": "6252_58 6252_58",
  "ruling": "#272",
  "reason": "A retransmitted SYN-ACK moves neither point B nor the server time-to-live, so the repeat describes no second measurement."
}
```

| Field | Rule |
|---|---|
| `key` | The capture, the stream and the method. It must name a capture the corpus holds. |
| `capability` | `false` for a value decline. `true` for a capability decline. |
| `ours` | Verbatim. Never reword a fingerprint value. |
| `theirs` | Verbatim. |
| `ruling` | The issue that holds the ruling and the measurement. |
| `reason` | One sentence. |

**A value decline could be closed by an implementation change on either side. A capability
decline could not**, because the difference is the scope this project chose. Getting this
field wrong tells the next reader that a permanent boundary is a bug worth fixing.

## 3. Verify

```
make conformance
```

The suite reads the register and expects each named comparison to differ. Check three
things in the report.

1. The deviation the entry names is now expected, not failed.
2. No other comparison moved.
3. The register key count changed by exactly the number of entries you added.

State those three numbers in the pull request.

## To close an entry

When a change makes a registered comparison match, **delete the entry in the same commit**.
The suite fails otherwise, and that failure is the point: it reports that the register
describes a difference that no longer exists.

## Never

- Never add an entry to make a red suite green. That is what a defect looks like from the
  inside.
- Never write a `reason` that restates the `key`. State the mechanism.
- Never reword a value in `ours` or `theirs`. `.claude/rules/ste.md` bars it.
- Never add an entry for a ruling the maintainer has not made.
