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

## Rules

- **The FoxIO reference decides every disputed result.** When a library test disagrees
  with a vector, the library is wrong. Never change a vector.
- **An extra fingerprint is as wrong as a missing one.** The suite reports both.
- **The bar is byte-identical, with no exception.** A deviation is closed, or it records
  its reason in `docs/audit/conformance-exceptions.md` and the maintainer accepts it by
  name and by date.
- `dtls-udp.notest.cap` carries the FoxIO `notest` marker. FoxIO excludes it from their
  own suite, so the report records it as `not applicable`.

## To move the pin

Change `testdata/foxio.pin` to the new FoxIO commit, in a commit that does nothing else.
Run `make corpus` and `make conformance`. A new deviation means FoxIO changed a
definition. Open an issue for it.
