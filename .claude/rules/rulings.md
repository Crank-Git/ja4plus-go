# Rulings, readings and evidence

This project settles disputed fingerprint values from evidence. **This file states what
counts as evidence, who decides, and where the decision is recorded.** Read it before you
write a sentence that begins "FoxIO says".

`.claude/rules/parity.md` holds the rules that govern the Python port. Its
`## Where a difference comes from` section states the two shapes of reference defect this
project declines.

## The two words

| Word | What it is | Who produces it |
|---|---|---|
| **reading** | One recorded conclusion about what a source states, with the evidence that supports it. | An engineer. |
| **ruling** | One determination where no source settles the question. | **The maintainer, and nobody else.** |

Never write "we decided" for a reading, and never write "the spec says" for a ruling. The
port settled this vocabulary in `Crank-Git/ja4plus#533`, and both repositories use it.

**`## What a delegated session may rule` below states each case where a delegated project
manager makes a ruling.** The maintainer granted a narrow delegation on 2026-08-12, and the
maintainer widened it on 2026-08-13. The table holds for every other question.

## A reading cites a file and a line

A claim about a source is worthless without the location. Write
`wireshark/source/packet-ja4.c:1595`, not "the Wireshark dissector".

**Read the source at the pinned commit.** `testdata/foxio.pin` holds it. A reading of a
moving branch is a reading of something the next person cannot see.

**Never describe an external interface from memory.** `.claude/rules/external-apis.md`
holds the rule and the interface list.

## A citation names its repository

**A bare `#N` names an issue of this repository.** A citation of an issue of the port names
the port. Write `the port's issue #N` in a sentence, or `Crank-Git/ja4plus#N` in a table
cell. The tree also holds `port issue #N`, and that form reads the same way.

**A bare number that names the port is a defect.** `#127` names the JA4L part count in
this repository, and it names the JA4 ALPN value in the port. A reader who reads the number
alone conflates an ALPN ruling with a JA4L ruling. Issue #255 records the collision, and
issue #254 records the same defect in the file namespace.

**One question carries a different number in each repository.** The JA4L part count is issue
#127 here and issue #225 in the port. When a reader needs both halves, write both numbers.

Two pages carry a local rule, and each one states that rule.

- **The `Ruling` column of the register in `docs/specs/spec.md`.** Its preamble states that
  the column names the port issue, so a bare number in that column names the port. A cell
  that names an issue of this repository says so.
- **`docs/specs/foxio/port-register.md`.** It is a verbatim copy of a section of the port's
  specification, so a bare number in it names the port. `docs/specs/foxio/README.md` holds
  that reading. **Never edit the copy.**

## Text copied from FoxIO material is verbatim

`.claude/rules/ste.md` bars a rewording of copied text. **A reworded quotation is no longer
evidence.** This covers a fingerprint value, an error message, a comment in a reference
implementation, and a sentence of a FoxIO specification.

Reproduce it exactly, in a code span or a block quote, and cite the location.

## The source ranking

1. **A FoxIO image under `technical_details/`.** It decides schema: the part count, the
   field widths, the character counts.
2. **A FoxIO reference implementation.** It decides behavior where the image is silent.
3. **A deleted FoxIO text specification.** It corroborates, and **it never outranks an
   image**. `docs/specs/foxio/deleted-text-specifications.md` holds the seven of them.
4. **A Zeek baseline.** It is not a reference value for every method.
   `docs/specs/foxio/zeek.md` names each exception.

**Three methods reach no image of their own name: JA4LS, JA4TS and JA4TScan.** `JA4T.png`
titles itself `JA4T/S: TCP Fingerprint`, so it specifies the schema of JA4TS. The image
states no separate server rule, so the implementations state the packet rule for JA4TS.
For JA4LS the implementations state every rule, because `JA4L.png` states no server rule.
For JA4TScan FoxIO publishes nothing at all, which is why `docs/specs/spec.md` `Non-goals`
declines it.

**Rank 3 never outranks an image, and a question that no image addresses reaches no image
to outrank.** `### A rank 3 source, and the source ranking` below states the reconciliation,
and it states the measurement that supports it.

## Where a ruling is recorded

A ruling that records nothing is a ruling the next reader re-litigates. Every one carries
at least one of these.

- **An entry in `testdata/deviations.json`**, when a vector reaches the value. The entry
  states `capability` — `false` for a value decline, `true` for a capability decline — plus
  the issue and one sentence of reason.
- **A test that builds the separating packet**, when no vector reaches the value. The test
  fails when the ruling is reversed, and it names the issue in a comment.
- **A row in the register**, when the ruling also affects the Python port.

## Stop conditions

Stop and ask the maintainer when any of these is true. Do not pick an answer.

- The FoxIO implementations disagree with each other.
- The FoxIO image and an implementation disagree.
- The reference produces a value that describes the capture rather than the connection.
- No FoxIO source addresses the input at all.
- Closing a deviation would require inventing a rule no source states.

**A guess here is worse than a delay.** A rule this project invents makes it answer
differently from every FoxIO implementation on the same bytes, and comparison is the only
thing a fingerprint is for.

**The widened delegation of 2026-08-13 names one exception to the first stop condition.**
Where the implementations differ, a FoxIO text specification that states the answer settles
the question, and no image contradicts that specification.
`### The widened delegation of 2026-08-13` below states the exception and its limits. The
other four stop conditions hold without a change.

## What a delegated session may rule

**The maintainer delegates a session to a project manager, and this section states what
that delegation permits.** The maintainer granted two delegations, and both hold today.

| Delegation | Date | What it reaches | Where the grant lives |
|---|---|---|---|
| The narrow delegation | 2026-08-12 | A schema violation. | #246 |
| The widened delegation | 2026-08-13 | Four open questions, under three decisive cases. | Comment 5276145707 of #108 |

### The narrow delegation of 2026-08-12

**A schema violation has one right answer, and a reference split has none.** That sentence
is the boundary. The project manager rules a schema violation under a delegation. It rules
no reference split, and it rules no other question.

**A delegated ruling is a ruling, and never a reading.** A reading concludes what one
source states. A delegated ruling decides what the library does where a published FoxIO
value contradicts a published FoxIO rule. No source settles that question, because FoxIO
publishes both of them.

A delegated ruling is permitted only when every one of these is true.

1. A published rule states the answer, and that rule ranks at 1 or at 2 in the source
   ranking above.
2. Every FoxIO implementation enforces that rule. One implementation that departs makes
   the question a reference split, and this section bars a reference split.
3. A recorded measurement proves the violation, and each citation names a file and a line.
4. The register entry or the test carries a provisional marker, and it names the issue.
5. The entry names a reversal path, so the maintainer reverses the ruling with one action.

**A question that fails one condition leaves the narrow delegation.** The project manager
reads it against the widened delegation below. A question that fails both delegations belongs
to the maintainer. The project manager labels that issue `status:needs-feedback`, and it
builds nothing that depends on the answer.

**Each stop condition above holds for this delegation without a change.** Each one names a
question that no rank 1 source and no rank 2 source settles, so the narrow delegation reaches
none of them.

**The maintainer confirms a delegated ruling, or reverses it.** A delegated ruling that the
maintainer has not confirmed stays provisional. A later reader reads a provisional ruling
as unconfirmed, and never as settled.

### The widened delegation of 2026-08-13

**The maintainer widened the delegation on 2026-08-13.** The grant lives in comment
5276145707 of #108, and this file quotes it. The grant states its own scope:

> **The maintainer granted the project manager authority to read the four open questions and to
> apply a recommendation where the evidence is decisive.** #289, #300, #346 and #369 are the four.

**The grant states three decisive cases, and it states that nothing else is decisive.**

> ### What counts as decisive, and nothing else does
>
> A question is settled by the project manager only when one of these holds.
>
> 1. **Every FoxIO implementation agrees**, and the disagreement is with a requirement of this
>    project rather than with a reference. `.claude/rules/parity.md` `## Where a difference comes
>    from` row 1 governs it.
> 2. **A FoxIO text specification states the answer**, and no image contradicts it.
>    `.claude/rules/rulings.md` ranks a deleted text specification at 3, and it never outranks an
>    image.
> 3. **The port ships the rule and the maintainer has already set the precedent twice.** The JA4TS
>    delay rounding and the JA4T SYN selection each lived in the port's code and not in its
>    register, and the maintainer chose to match the port and to file a port issue both times, on
>    2026-08-13.

**The grant states what stays with the maintainer.**

> ### What stays with the maintainer
>
> **A genuine reference split.** Two FoxIO implementations disagree and no FoxIO text settles it.
> `.claude/rules/rulings.md` names that a stop condition, because a wrong pick makes this library
> answer differently from a FoxIO implementation on the same bytes.
>
> **A parked question carries its reading**, so the maintainer rules in one round rather than three.

**The grant makes every applied answer provisional.**

> ### Every applied answer is provisional
>
> **Each one carries a marker and a named reversal path**, as the five amendments of Epic 12 do.
> **The maintainer confirms each one or reverses it with one action.**

**Decisive case 2 and the first stop condition can both name one question, and the grant
separates them.** A reference split needs two conditions. The implementations disagree, and
no FoxIO text settles the disagreement. The grant states that separation for #369:

> **#369 is weaker than a split.** The port's `ja4plus/fingerprinters/ja4ts.py` cites the deleted
> `technical_details/JA4T.md`: `The max is 10 retransmissions counted and the timeout is 2 minutes
> after the last SYNACK.` **A FoxIO text specification, the Zeek package and the port each state
> ten, and the Wireshark dissector states nine.**

**The grant names four questions by number, and it names no fifth.** The Epic 12 amendments
of the table below apply the three cases to a requirement of this project rather than to one
of the four. Each one is provisional, and each one names a reversal path. **The maintainer
states whether the grant reaches a question that the four do not name.** This file records
that question, and it invents no answer.

### How the two delegations relate

**The two delegations reach different questions, and neither one repeals the other.**

- The narrow delegation reaches a schema violation: a published FoxIO value contradicts a
  published FoxIO rule that every implementation enforces.
- The widened delegation reaches the four open questions, under the three decisive cases.
- **A question that fails the five narrow conditions can still meet a decisive case.** #369
  question 1 is that question: it fails narrow condition 1 and narrow condition 2, and it
  meets decisive case 2.
- **A genuine reference split fails both.** The narrow delegation bars it, and the grant
  reserves it.
- **Every delegated decision is provisional under both delegations**, and each one names a
  reversal path.

### A rank 3 source, and the source ranking

**`## The source ranking` states that a rank 3 source never outranks an image, and decisive
case 2 admits a rank 3 source. The two agree.** A rank order separates two sources that each
address one question. Where no image addresses the question, a rank 3 source outranks no
image, because no image states an answer.

**So a rank 3 source states the answer only where each of these holds.**

1. No image addresses the question.
2. No image contradicts the rank 3 source.
3. The rank 3 source states the answer, and a reader reproduces the reading from the text.

**A rank 3 source that an image contradicts settles nothing**, and the second stop condition
above sends that question to the maintainer.

**The JA4TS part e count is the measured case.** `JA4T.png` addresses part e in three rules
of `docs/specs/foxio/JA4T.md`, and no one of them states a count. R13 records the image
label `TCP Retransmission Timings (only on JA4TScan)`. R14 records the separator. R15
records the reset letter. R18 states `The image states no count of its own.` The deciding
source is `docs/specs/foxio/deleted-text-specifications.md`, under the `### JA4T.md`
heading. It states
`The max is 10 retransmissions counted and the timeout is 2 minutes after the last SYNACK.`
**Each of the three tests above holds, so the rank 3 source states the count and it outranks
no image.**

### Every delegated decision of session 9

**Session 9 applied four decisions under the widened delegation on 2026-08-13, and it made
one scope decision beside them.** Each one is provisional until the maintainer confirms it.
The `Case` column names the decisive case of the grant.

| What was applied | Case | Where it is recorded | Reversal path |
|---|---|---|---|
| #346 — the library carries step 2 of the JA4SSH client direction. | 3 | Issue #346, comment 5281493518. **#413 builds the work**, and no line of the tree carries step 2 today. | Issue #346. A reversal records the decline of step 2, with the reason. |
| #369 question 1 — JA4TS part e holds ten delays. | 2 | `docs/specs/foxio/JA4T.md` R18, and issue #369, comment 5276169622. | Issue #369. |
| The FR-ja4ls-7 amendment — part b writes the observed time-to-live, and no branch computes a hop count. | 1 | `docs/specs/features/12-ja4ls.md` `### The method` and FR-ja4ls-7, and `ja4ls_emission_test.go`. | Issue #60. |
| The FR-ja4ls-8 amendment — no propagation factor reaches the value. | 1 | `docs/specs/features/12-ja4ls.md` `### The method` and FR-ja4ls-8, and `ja4ls_emission_test.go`. | Issue #60. |
| The FR-ja4ls-22 amendment — the requirement names the per-stream vector set alone. | None. **This is a scope decision, and never a ruling.** | `docs/specs/features/12-ja4ls.md` `### Conformance`. | Comment 5276074116 of #63. |

**The FR-ja4ls-22 amendment writes no register entry, and it states no rule about a
fingerprint value.** `docs/specs/features/12-ja4ls.md` `### Conformance` states that
reading, and the table holds the row because the reader needs one list of every provisional
decision.

**One more requirement carries a provisional amendment, and no delegation produced it.**
FR-ja4ls-11 named a type filter that `Processor` does not hold, #61 measured the absence, and
`docs/specs/features/12-ja4ls.md` names issue #61 as the reversal path, at FR-ja4ls-11.

### Three examples of the narrow delegation

**Each example below reads the five narrow conditions.** The widened delegation names four
questions, and no one of the three is one of the four.

**#223 is a delegated ruling, and the maintainer confirmed it on 2026-08-12.** A published
FoxIO value contradicts a rule that every implementation enforces.
`docs/specs/foxio/JA4SSH.md` R13 is a rank 1 rule, and it states that the mode is `0` when
the side sent no SSH packet. `zeek/ja4ssh/main.zeek:63`,
`wireshark/source/packet-ja4.c:400`, `rust/ja4/src/ssh.rs:284` and `python/ja4ssh.py:51`
each enforce R13. `testdata/foxio/python/ssh-scp-1050.pcap.json` holds
`c112s1460_c0s200_c36s0`, which pairs a client mode of `112` with a client packet count of
`0`. The five narrow conditions each hold, and one answer is right.

**#216 belongs to the maintainer, and the project manager ruled nothing.** The question is
whether `CleanupConnection` emits the JA4SSH window that a connection holds open. Both
candidate answers change the exported surface, and no FoxIO source addresses a state table.
Narrow condition 1 fails, and the choice is a genuine one.

**#247 belongs to the maintainer, and the project manager ruled nothing.** The question is
the JA4L part count on a TCP connection. `docs/specs/foxio/JA4L.md` R3 is a rank 1 image
rule that states three parts, and ruling #127 declines part c on a TCP connection. The four
FoxIO implementations split two against two, so narrow condition 2 fails. The maintainer ruled the
question on 2026-08-12, and round 25 of the `## Changelog` of `docs/specs/spec.md` records
that ruling.

## Every ruling is reversible

No ruling in this project is permanent. Each one records the date, the issue and the
measurement, so a later reader can reverse it with a new fact rather than a new opinion.

**Reversing a ruling that the register shares with the port is a two-repository change.**
