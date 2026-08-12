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
port settled this vocabulary in its issue #533, and both repositories use it.

## A reading cites a file and a line

A claim about a source is worthless without the location. Write
`wireshark/source/packet-ja4.c:1595`, not "the Wireshark dissector".

**Read the source at the pinned commit.** `testdata/foxio.pin` holds it. A reading of a
moving branch is a reading of something the next person cannot see.

**Never describe an external interface from memory.** `.claude/rules/external-apis.md`
holds the rule and the interface list.

## Text copied from FoxIO material is verbatim

`.claude/rules/ste.md` bars a rewording of copied text. **A reworded quotation is no longer
evidence.** This covers a fingerprint value, an error message, a comment in a reference
implementation, and a sentence of a FoxIO specification.

Reproduce it exactly, in a code span or a block quote, and cite the location.

## The source ranking

1. **A FoxIO image under `technical_details/`.** It decides schema: the part count, the
   field widths, the character counts.
2. **A FoxIO reference implementation.** It decides behaviour where the image is silent.
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

## What a delegated session may rule

**The maintainer delegates a session to a project manager, and this section states what
that delegation permits.** The maintainer approved the carve-out on 2026-08-12, and #246
records it.

**A schema violation has one right answer, and a reference split has none.** That sentence
is the boundary. The project manager rules a schema violation under a delegation. It rules
no reference split, and it rules no other question.

A delegated ruling is permitted only when every one of these is true.

1. A published rule states the answer, and that rule ranks at 1 or at 2 in the source
   ranking above.
2. Every FoxIO implementation enforces that rule. One implementation that departs makes
   the question a reference split, and a reference split is barred.
3. A recorded measurement proves the violation, and each citation names a file and a line.
4. The register entry or the test carries a provisional marker, and it names the issue.
5. The entry names a reversal path, so the maintainer reverses the ruling with one action.

**A question that fails one condition belongs to the maintainer.** The project manager
labels the issue `status:needs-feedback`, and it builds nothing that depends on the answer.

**The stop conditions above hold without a change.** Each one names a question that no rank
1 source and no rank 2 source settles, so no delegation reaches it.

**The maintainer confirms a delegated ruling, or reverses it.** A delegated ruling that the
maintainer has not confirmed stays provisional. A later reader reads a provisional ruling
as unconfirmed, and never as settled.

### Three examples

**#223 is a delegated ruling, and the maintainer confirmed it on 2026-08-12.** A published
FoxIO value contradicts a rule that every implementation enforces.
`docs/specs/foxio/JA4SSH.md` R13 is a rank 1 rule, and it states that the mode is `0` when
the side sent no SSH packet. `zeek/ja4ssh/main.zeek:63`,
`wireshark/source/packet-ja4.c:400`, `rust/ja4/src/ssh.rs:284` and `python/ja4ssh.py:51`
each enforce R13. `testdata/foxio/python/ssh-scp-1050.pcap.json` holds
`c112s1460_c0s200_c36s0`, which pairs a client mode of `112` with a client packet count of
`0`. The five conditions each hold, and one answer is right.

**#216 belongs to the maintainer, and the project manager ruled nothing.** The question is
whether `CleanupConnection` emits the JA4SSH window that a connection holds open. Both
candidate answers change the exported surface, and no FoxIO source addresses a state table.
Condition 1 fails, and the choice is a genuine one.

**#247 belongs to the maintainer, and the project manager ruled nothing.** The question is
the JA4L part count on a TCP connection. `docs/specs/foxio/JA4L.md` R3 is a rank 1 image
rule that states three parts, and ruling #127 declines part c on a TCP connection. The four
FoxIO implementations split two against two, so condition 2 fails. The maintainer ruled the
question on 2026-08-12, and round 25 of the `## Changelog` of `docs/specs/spec.md` records
that ruling.

## Every ruling is reversible

No ruling in this project is permanent. Each one records the date, the issue and the
measurement, so a later reader can reverse it with a new fact rather than a new opinion.

**Reversing a ruling that the register shares with the port is a two-repository change.**
