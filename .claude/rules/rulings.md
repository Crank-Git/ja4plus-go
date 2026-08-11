# Rulings, readings and evidence

This project settles disputed fingerprint values from evidence. **This file states what
counts as evidence, who decides, and where the decision is recorded.** Read it before you
write a sentence that begins "FoxIO says".

`.claude/rules/parity.md` holds the rules that govern the Python port.
`.claude/rules/conformance.md` holds the two shapes of reference defect this project
declines.

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

**Three methods have no image at all: JA4LS, JA4TS and JA4TScan.** For JA4LS and JA4TS the
implementations state every rule. For JA4TScan FoxIO publishes nothing at all, which is why
`docs/specs/spec.md` `Non-goals` declines it.

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

## Every ruling is reversible

No ruling in this project is permanent. Each one records the date, the issue and the
measurement, so a later reader can reverse it with a new fact rather than a new opinion.

**Reversing a ruling that the register shares with the port is a two-repository change.**
