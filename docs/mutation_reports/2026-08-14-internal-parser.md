# Mutation report — 2026-08-14 — `./internal/parser`

<!-- This file is generated. `make mutate` writes it. Do not edit it by hand. -->

**A mutation that survives names a test that runs a line and asserts nothing about it.**
It is not always a defect. `docs/specs/features/15-mutation-sweep.md` holds the requirements,
and FR-mutation-11 states that every `LIVED` mutation is settled.

## The run

| Field | Value |
|---|---|
| Tool | `gremlins` |
| Tool version | `v0.6.0` |
| Date, UTC | 2026-08-14 |
| Go module | `github.com/Crank-Git/ja4plus-go` |
| Swept path | `./internal/parser` |
| Paths the sweep excludes | `cmd/` and `examples/` |
| Elapsed | 289 s |
| Test efficacy | 68.85% |
| Mutation coverage | 81.55% |

**The sweep reads the swept path alone.** `gremlins unleash <path>` reads the whole
directory tree under the path, and it reads no package outside that tree. A package that
the `Swept path` row does not cover holds no row of this report, and its tests are
unmeasured rather than effective.

## The verdict counts

**LIVED: 223.** That count sizes the settlement work of FR-mutation-11.

| Verdict | Count | What it means |
|---|---|---|
| `KILLED` | 493 | A test failed, so the suite catches the change. `go test` exited 1. |
| `LIVED` | 223 | Every test passed, so no test asserts on the change. FR-mutation-11 settles it. |
| `NOT COVERED` | 162 | No test reaches the line, so the tool ran nothing. |
| `TIMED OUT` | 4 | The suite did not finish, and FR-mutation-11 settles it like a `LIVED` mutation. |
| `NOT VIABLE` | 0 | The mutated package did not compile. `go test` exited 2. No settlement is needed. |
| `SKIPPED` | 0 | The mutation sits outside the configured diff. This repository configures none. |
| `RUNNABLE` | 0 | A dry run identified the mutation and ran no test. `make mutate` performs no dry run. |
| **Total** | **882** | Every mutation the tool applied. |

**`mutants_total` of the JSON is not the total above.** `fileReport` in
`internal/report/report.go` of `gremlins` v0.6.0 sets it to the killed, lived and
not-viable count alone, so it reports 716 here. This report counts every mutation entry.

## Every mutation

| File | Line | Column | Mutation | Verdict |
|---|---|---|---|---|
| `grease.go` | 6 | 24 | `CONDITIONALS_NEGATION` | `KILLED` |
| `grease.go` | 6 | 48 | `CONDITIONALS_NEGATION` | `KILLED` |
| `hash.go` | 14 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 55 | 46 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `http.go` | 55 | 70 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `http.go` | 92 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `http.go` | 92 | 9 | `INVERT_NEGATIVES` | `KILLED` |
| `http.go` | 95 | 54 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `http.go` | 95 | 54 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 95 | 67 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `http.go` | 95 | 67 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 95 | 80 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `http.go` | 95 | 80 | `CONDITIONALS_NEGATION` | `LIVED` |
| `http.go` | 120 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `http.go` | 125 | 14 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `http.go` | 125 | 14 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `http.go` | 134 | 21 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `http.go` | 134 | 21 | `INVERT_NEGATIVES` | `NOT COVERED` |
| `http.go` | 134 | 31 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `http.go` | 134 | 50 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `http.go` | 134 | 50 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `http.go` | 148 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `http.go` | 148 | 25 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `http.go` | 148 | 25 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `http.go` | 157 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 177 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `http.go` | 177 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 189 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 196 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 201 | 14 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `http.go` | 201 | 14 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 217 | 36 | `ARITHMETIC_BASE` | `KILLED` |
| `http.go` | 217 | 36 | `INVERT_NEGATIVES` | `KILLED` |
| `http.go` | 220 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 220 | 44 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 224 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 235 | 44 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `http.go` | 235 | 44 | `CONDITIONALS_NEGATION` | `KILLED` |
| `http.go` | 237 | 36 | `ARITHMETIC_BASE` | `KILLED` |
| `icmp_quoted.go` | 71 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `icmp_quoted.go` | 71 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 76 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 85 | 89 | `ARITHMETIC_BASE` | `KILLED` |
| `icmp_quoted.go` | 85 | 105 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `icmp_quoted.go` | 85 | 105 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 89 | 38 | `ARITHMETIC_BASE` | `KILLED` |
| `icmp_quoted.go` | 90 | 18 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `icmp_quoted.go` | 90 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 90 | 57 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `icmp_quoted.go` | 90 | 57 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 98 | 59 | `ARITHMETIC_BASE` | `KILLED` |
| `icmp_quoted.go` | 98 | 83 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 103 | 47 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 108 | 20 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `icmp_quoted.go` | 108 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 113 | 52 | `ARITHMETIC_BASE` | `KILLED` |
| `icmp_quoted.go` | 114 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `icmp_quoted.go` | 114 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 114 | 54 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `icmp_quoted.go` | 114 | 54 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 158 | 31 | `CONDITIONALS_NEGATION` | `LIVED` |
| `icmp_quoted.go` | 159 | 29 | `CONDITIONALS_NEGATION` | `LIVED` |
| `icmp_quoted.go` | 160 | 29 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 161 | 29 | `CONDITIONALS_NEGATION` | `LIVED` |
| `icmp_quoted.go` | 162 | 29 | `CONDITIONALS_NEGATION` | `LIVED` |
| `icmp_quoted.go` | 163 | 29 | `CONDITIONALS_NEGATION` | `KILLED` |
| `icmp_quoted.go` | 164 | 29 | `CONDITIONALS_NEGATION` | `LIVED` |
| `icmp_quoted.go` | 165 | 29 | `CONDITIONALS_NEGATION` | `LIVED` |
| `icmp_quoted.go` | 166 | 29 | `CONDITIONALS_NEGATION` | `LIVED` |
| `packet.go` | 47 | 9 | `INCREMENT_DECREMENT` | `KILLED` |
| `packet.go` | 63 | 18 | `ARITHMETIC_BASE` | `KILLED` |
| `packet.go` | 78 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `packet.go` | 82 | 11 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `packet.go` | 82 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `packet.go` | 128 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `packet.go` | 132 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `packet.go` | 149 | 60 | `CONDITIONALS_NEGATION` | `KILLED` |
| `packet.go` | 154 | 60 | `CONDITIONALS_NEGATION` | `KILLED` |
| `packet.go` | 187 | 33 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 52 | 9 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 52 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 58 | 40 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 60 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 60 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 60 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 63 | 51 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 64 | 17 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 66 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 66 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 66 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 69 | 52 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 70 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 70 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 71 | 17 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 73 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 73 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 73 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 76 | 52 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 77 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 77 | 45 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 78 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 78 | 45 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 79 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 79 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 80 | 17 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 91 | 24 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 92 | 29 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 92 | 31 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 92 | 46 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 92 | 48 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 97 | 13 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 98 | 18 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 102 | 40 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 125 | 56 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 126 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 131 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 135 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 139 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 160 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 183 | 18 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 183 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 186 | 21 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 189 | 47 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 202 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 203 | 26 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 206 | 25 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 217 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 217 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 223 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 229 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 237 | 34 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 239 | 34 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 250 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 250 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 254 | 5 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 255 | 8 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 255 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 255 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 259 | 28 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 263 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 263 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 267 | 5 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 268 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 268 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 268 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 275 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 279 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 279 | 23 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 279 | 23 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 286 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 295 | 13 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 295 | 15 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 295 | 32 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 295 | 32 | `CONDITIONALS_NEGATION` | `LIVED` |
| `quic.go` | 295 | 46 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 297 | 14 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 297 | 31 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 297 | 31 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 304 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 310 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 311 | 17 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 311 | 21 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 311 | 21 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 314 | 47 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 318 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 330 | 37 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 333 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 333 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 333 | 29 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 334 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 334 | 34 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 339 | 16 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 339 | 16 | `CONDITIONALS_NEGATION` | `LIVED` |
| `quic.go` | 339 | 29 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 340 | 41 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 346 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 346 | 16 | `CONDITIONALS_NEGATION` | `LIVED` |
| `quic.go` | 346 | 22 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 347 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 347 | 19 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 347 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 347 | 21 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 347 | 42 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 351 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 354 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 356 | 28 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 356 | 28 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 357 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 357 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 357 | 28 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 357 | 36 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 357 | 36 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 365 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 369 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 373 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 378 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 387 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 417 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 417 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 421 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 425 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 431 | 34 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 433 | 34 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 441 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 441 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 445 | 5 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 446 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 446 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 446 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 450 | 28 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 452 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 452 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 456 | 5 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 457 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 457 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 457 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 462 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 466 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 466 | 23 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 466 | 23 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 471 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 476 | 13 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 476 | 30 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 476 | 30 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 480 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 483 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 484 | 17 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 484 | 21 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 484 | 21 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 487 | 47 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 489 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 495 | 37 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 496 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 496 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 496 | 29 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 497 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 497 | 34 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 500 | 16 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 500 | 16 | `CONDITIONALS_NEGATION` | `LIVED` |
| `quic.go` | 500 | 29 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 501 | 41 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 505 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 505 | 16 | `CONDITIONALS_NEGATION` | `LIVED` |
| `quic.go` | 505 | 22 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 506 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 506 | 19 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 506 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 506 | 21 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 506 | 42 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 508 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 509 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 510 | 28 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 510 | 28 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 511 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 511 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 511 | 28 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 511 | 36 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 511 | 36 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 515 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 517 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 521 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 528 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 528 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 533 | 7 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 562 | 10 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 562 | 30 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 562 | 30 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 588 | 22 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 588 | 22 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 592 | 29 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 592 | 63 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 592 | 63 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 609 | 20 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 609 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 609 | 33 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 609 | 33 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 612 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 619 | 13 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 619 | 29 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 619 | 29 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 622 | 29 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 630 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 633 | 8 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 644 | 10 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 644 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 650 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 650 | 49 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 651 | 7 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 655 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 656 | 7 | `INCREMENT_DECREMENT` | `KILLED` |
| `quic.go` | 660 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 667 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 672 | 10 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 672 | 23 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 672 | 23 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 680 | 32 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 687 | 16 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 687 | 37 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 688 | 7 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 691 | 11 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 697 | 11 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 703 | 11 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 709 | 11 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 714 | 26 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 714 | 26 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 714 | 41 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 717 | 12 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 723 | 12 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 729 | 17 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 730 | 19 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 730 | 19 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 730 | 25 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 732 | 13 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 755 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 764 | 30 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 764 | 30 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 773 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 774 | 10 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 774 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 779 | 14 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 802 | 25 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 802 | 25 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 803 | 18 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 803 | 46 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 803 | 46 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 811 | 18 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 811 | 18 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 811 | 41 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 816 | 20 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 821 | 13 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 828 | 34 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 830 | 34 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 841 | 9 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 841 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 845 | 5 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 846 | 8 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 846 | 17 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 846 | 17 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 852 | 9 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 852 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 856 | 5 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 857 | 8 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 857 | 17 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 857 | 17 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 864 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 868 | 8 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 868 | 23 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 868 | 23 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 875 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 881 | 13 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 881 | 30 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 881 | 30 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 887 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 892 | 27 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 893 | 17 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 893 | 21 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 893 | 21 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 896 | 47 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 899 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 906 | 37 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 908 | 16 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 908 | 16 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 908 | 29 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 909 | 21 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 909 | 34 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 913 | 16 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 913 | 16 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 913 | 29 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 914 | 41 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 919 | 16 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 919 | 16 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 919 | 22 | `INCREMENT_DECREMENT` | `NOT COVERED` |
| `quic.go` | 920 | 19 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 920 | 19 | `INVERT_NEGATIVES` | `NOT COVERED` |
| `quic.go` | 920 | 21 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 920 | 21 | `INVERT_NEGATIVES` | `NOT COVERED` |
| `quic.go` | 920 | 42 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 923 | 27 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 925 | 23 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 926 | 28 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 926 | 28 | `INVERT_NEGATIVES` | `NOT COVERED` |
| `quic.go` | 927 | 12 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 927 | 12 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 927 | 28 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 927 | 36 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 927 | 36 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 932 | 44 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 935 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 939 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 944 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 952 | 20 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 957 | 20 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 962 | 18 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 967 | 29 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 976 | 9 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 979 | 8 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 1016 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1020 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1026 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1031 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1036 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1052 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1057 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1062 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1066 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1067 | 17 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 1067 | 35 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1067 | 35 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1069 | 21 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 1072 | 74 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1073 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1081 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1082 | 13 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 1082 | 33 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1082 | 33 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1089 | 18 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 1089 | 31 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1090 | 58 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 1097 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1097 | 19 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 1097 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1097 | 21 | `INVERT_NEGATIVES` | `KILLED` |
| `quic.go` | 1097 | 52 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1100 | 20 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1101 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 1101 | 8 | `INVERT_NEGATIVES` | `LIVED` |
| `quic.go` | 1101 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1101 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1106 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1111 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1116 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1128 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1128 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1132 | 21 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1133 | 25 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1133 | 25 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1133 | 51 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1133 | 51 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1138 | 16 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1139 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1139 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1146 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1146 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1151 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1151 | 34 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1162 | 10 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1162 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1167 | 13 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1167 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1171 | 12 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1172 | 10 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `quic.go` | 1172 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1180 | 8 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 1185 | 18 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `quic.go` | 1185 | 18 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 1185 | 39 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `quic.go` | 1185 | 39 | `INVERT_NEGATIVES` | `NOT COVERED` |
| `quic.go` | 1193 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1198 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `quic.go` | 1198 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1198 | 33 | `ARITHMETIC_BASE` | `LIVED` |
| `quic.go` | 1198 | 33 | `INVERT_NEGATIVES` | `LIVED` |
| `quic.go` | 1202 | 18 | `ARITHMETIC_BASE` | `KILLED` |
| `quic.go` | 1209 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1210 | 25 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1213 | 24 | `CONDITIONALS_NEGATION` | `KILLED` |
| `quic.go` | 1219 | 13 | `CONDITIONALS_NEGATION` | `LIVED` |
| `quic.go` | 1220 | 25 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `quic.go` | 1223 | 24 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 18 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 18 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 23 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 23 | 37 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 23 | 58 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 23 | 79 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 34 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 34 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 34 | 38 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 34 | 38 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 34 | 62 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 34 | 62 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 43 | 27 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 43 | 27 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 49 | 13 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 49 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 59 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 59 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 64 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 64 | 37 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 64 | 58 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 64 | 79 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 72 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 72 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 77 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 77 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 77 | 38 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 77 | 38 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 85 | 27 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 85 | 27 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 92 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 124 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 124 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 128 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 135 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 135 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 135 | 23 | `INCREMENT_DECREMENT` | `LIVED` |
| `ssh.go` | 136 | 9 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh.go` | 136 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 136 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 139 | 63 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh.go` | 141 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh.go` | 141 | 22 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 141 | 22 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 144 | 47 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh.go` | 148 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 148 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh.go` | 160 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 160 | 16 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh.go` | 163 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh.go` | 163 | 16 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh.go` | 173 | 10 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh.go` | 178 | 33 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 178 | 39 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 178 | 60 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 178 | 66 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 178 | 80 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 178 | 86 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 180 | 33 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 180 | 39 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 180 | 60 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 180 | 66 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 180 | 80 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 180 | 86 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `ssh.go` | 190 | 15 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `ssh.go` | 190 | 15 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh.go` | 194 | 18 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `ssh.go` | 194 | 18 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh.go` | 194 | 38 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `ssh.go` | 194 | 38 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh.go` | 197 | 15 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `ssh.go` | 197 | 15 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh.go` | 201 | 13 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh_tracker.go` | 104 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh_tracker.go` | 104 | 19 | `INVERT_NEGATIVES` | `KILLED` |
| `ssh_tracker.go` | 117 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 126 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 132 | 34 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `ssh_tracker.go` | 132 | 34 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 138 | 14 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 147 | 13 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 161 | 13 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh_tracker.go` | 161 | 13 | `INVERT_NEGATIVES` | `KILLED` |
| `ssh_tracker.go` | 162 | 13 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 162 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 167 | 18 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh_tracker.go` | 182 | 16 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `ssh_tracker.go` | 182 | 16 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `ssh_tracker.go` | 189 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 196 | 20 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 196 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 196 | 59 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 196 | 59 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 225 | 23 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 225 | 23 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 225 | 47 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 225 | 68 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 225 | 68 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 230 | 26 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `ssh_tracker.go` | 230 | 26 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 253 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 277 | 19 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 277 | 19 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 289 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 289 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 290 | 20 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 290 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 300 | 42 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh_tracker.go` | 304 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 304 | 15 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 317 | 15 | `CONDITIONALS_BOUNDARY` | `TIMED OUT` |
| `ssh_tracker.go` | 317 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 318 | 18 | `CONDITIONALS_BOUNDARY` | `TIMED OUT` |
| `ssh_tracker.go` | 318 | 18 | `CONDITIONALS_NEGATION` | `TIMED OUT` |
| `ssh_tracker.go` | 320 | 33 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh_tracker.go` | 320 | 33 | `INVERT_NEGATIVES` | `LIVED` |
| `ssh_tracker.go` | 320 | 51 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 320 | 51 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 326 | 38 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh_tracker.go` | 326 | 38 | `INVERT_NEGATIVES` | `LIVED` |
| `ssh_tracker.go` | 327 | 21 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 327 | 21 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 327 | 38 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 327 | 38 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 327 | 56 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 327 | 56 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 328 | 41 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh_tracker.go` | 335 | 19 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 338 | 22 | `CONDITIONALS_NEGATION` | `LIVED` |
| `ssh_tracker.go` | 348 | 33 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh_tracker.go` | 348 | 33 | `INVERT_NEGATIVES` | `LIVED` |
| `ssh_tracker.go` | 349 | 18 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh_tracker.go` | 349 | 18 | `INVERT_NEGATIVES` | `LIVED` |
| `ssh_tracker.go` | 349 | 28 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 349 | 28 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 356 | 66 | `ARITHMETIC_BASE` | `KILLED` |
| `ssh_tracker.go` | 362 | 20 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 362 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 362 | 59 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `ssh_tracker.go` | 362 | 59 | `CONDITIONALS_NEGATION` | `KILLED` |
| `ssh_tracker.go` | 372 | 19 | `ARITHMETIC_BASE` | `LIVED` |
| `ssh_tracker.go` | 372 | 19 | `INVERT_NEGATIVES` | `LIVED` |
| `tcp_stream.go` | 120 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 129 | 21 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tcp_stream.go` | 129 | 21 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 129 | 53 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tcp_stream.go` | 129 | 53 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 170 | 24 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tcp_stream.go` | 170 | 24 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 186 | 26 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tcp_stream.go` | 186 | 26 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 205 | 16 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tcp_stream.go` | 205 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 216 | 19 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tcp_stream.go` | 216 | 19 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 227 | 37 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 239 | 14 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tcp_stream.go` | 239 | 14 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 247 | 14 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tcp_stream.go` | 247 | 14 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 248 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `tcp_stream.go` | 248 | 27 | `INVERT_NEGATIVES` | `KILLED` |
| `tcp_stream.go` | 249 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tcp_stream.go` | 249 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 251 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `tcp_stream.go` | 256 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tcp_stream.go` | 256 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 262 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tcp_stream.go` | 272 | 8 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tcp_stream.go` | 273 | 43 | `ARITHMETIC_BASE` | `KILLED` |
| `tcp_stream.go` | 281 | 8 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tcp_stream.go` | 282 | 43 | `ARITHMETIC_BASE` | `KILLED` |
| `testhelpers.go` | 24 | 24 | `ARITHMETIC_BASE` | `KILLED` |
| `testhelpers.go` | 108 | 16 | `ARITHMETIC_BASE` | `KILLED` |
| `testhelpers.go` | 108 | 20 | `ARITHMETIC_BASE` | `KILLED` |
| `testhelpers.go` | 132 | 27 | `ARITHMETIC_BASE` | `KILLED` |
| `testhelpers.go` | 150 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 50 | 18 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 50 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 53 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 57 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 57 | 45 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 75 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 75 | 22 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 75 | 22 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 76 | 19 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 80 | 34 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 80 | 59 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 84 | 15 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 84 | 19 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 85 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 85 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 86 | 11 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 86 | 11 | `INVERT_NEGATIVES` | `KILLED` |
| `tls.go` | 92 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 92 | 9 | `INVERT_NEGATIVES` | `KILLED` |
| `tls.go` | 104 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 104 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 109 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 109 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 117 | 17 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 119 | 18 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 119 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 119 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 122 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 122 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 125 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 128 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 128 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 140 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 140 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 140 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 144 | 11 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 147 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 147 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 147 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 150 | 59 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 153 | 46 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 154 | 16 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 154 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 155 | 9 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 155 | 11 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 155 | 14 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 155 | 14 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 158 | 26 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 158 | 54 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 158 | 56 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 165 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 165 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 165 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 169 | 11 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 172 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 172 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 172 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 175 | 57 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 177 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 178 | 19 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 178 | 19 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tls.go` | 182 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 182 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 182 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 183 | 58 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 184 | 28 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 184 | 53 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 185 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 186 | 30 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 187 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 187 | 17 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tls.go` | 206 | 22 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 215 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 215 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 218 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 226 | 17 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 228 | 18 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 228 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 228 | 21 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 231 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 231 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 234 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 237 | 18 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 237 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 249 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 249 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 249 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 253 | 11 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 256 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 256 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 256 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 259 | 63 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 263 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 263 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 263 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 269 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 269 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 269 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 272 | 57 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 274 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 275 | 19 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 275 | 19 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tls.go` | 279 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 279 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 279 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 280 | 58 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 281 | 28 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 281 | 53 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 282 | 23 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 283 | 30 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 284 | 17 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 284 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 294 | 22 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 294 | 22 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 304 | 20 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 304 | 20 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 310 | 22 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 314 | 31 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 314 | 31 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 374 | 20 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 378 | 11 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 383 | 30 | `ARITHMETIC_BASE` | `NOT COVERED` |
| `tls.go` | 383 | 30 | `INVERT_NEGATIVES` | `NOT COVERED` |
| `tls.go` | 389 | 16 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 409 | 12 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 409 | 12 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 409 | 24 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 409 | 24 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 409 | 38 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 409 | 38 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 409 | 50 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 409 | 50 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 409 | 64 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 409 | 64 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 409 | 76 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 409 | 76 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 416 | 11 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 416 | 11 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 416 | 24 | `CONDITIONALS_BOUNDARY` | `NOT COVERED` |
| `tls.go` | 416 | 24 | `CONDITIONALS_NEGATION` | `NOT COVERED` |
| `tls.go` | 421 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 421 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 426 | 8 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 426 | 11 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 426 | 11 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 430 | 5 | `INCREMENT_DECREMENT` | `KILLED` |
| `tls.go` | 431 | 49 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 434 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 434 | 24 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 434 | 37 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 434 | 37 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 435 | 36 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 436 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 445 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 445 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 450 | 11 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 451 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 451 | 9 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tls.go` | 456 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 456 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 456 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 457 | 46 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 466 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 466 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 471 | 11 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 472 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 472 | 9 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tls.go` | 477 | 10 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 477 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 478 | 9 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 478 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 478 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 482 | 6 | `INCREMENT_DECREMENT` | `KILLED` |
| `tls.go` | 483 | 9 | `ARITHMETIC_BASE` | `LIVED` |
| `tls.go` | 483 | 19 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 483 | 19 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 486 | 52 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 494 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 494 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 499 | 11 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 500 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `tls.go` | 500 | 9 | `CONDITIONALS_NEGATION` | `LIVED` |
| `tls.go` | 505 | 9 | `ARITHMETIC_BASE` | `KILLED` |
| `tls.go` | 505 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `tls.go` | 505 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `tls.go` | 506 | 46 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_identifiers.go` | 77 | 34 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 88 | 17 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `x509_identifiers.go` | 88 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 88 | 34 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 152 | 18 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `x509_identifiers.go` | 152 | 18 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 153 | 16 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 180 | 30 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `x509_identifiers.go` | 180 | 30 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 187 | 42 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `x509_identifiers.go` | 187 | 42 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 217 | 30 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `x509_identifiers.go` | 217 | 30 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 237 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_identifiers.go` | 237 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 237 | 24 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 256 | 12 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_identifiers.go` | 256 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 263 | 17 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 265 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 265 | 28 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_identifiers.go` | 265 | 28 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 265 | 59 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_identifiers.go` | 265 | 59 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 265 | 67 | `ARITHMETIC_BASE` | `LIVED` |
| `x509_identifiers.go` | 270 | 42 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_identifiers.go` | 277 | 13 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_identifiers.go` | 277 | 13 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 284 | 12 | `CONDITIONALS_BOUNDARY` | `KILLED` |
| `x509_identifiers.go` | 284 | 12 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_identifiers.go` | 284 | 20 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_identifiers.go` | 284 | 20 | `INVERT_NEGATIVES` | `KILLED` |
| `x509_identifiers.go` | 287 | 26 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_identifiers.go` | 287 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_utils.go` | 20 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_utils.go` | 26 | 15 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_utils.go` | 26 | 15 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_utils.go` | 39 | 30 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_utils.go` | 39 | 34 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_utils.go` | 57 | 9 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_utils.go` | 57 | 9 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_utils.go` | 64 | 10 | `CONDITIONALS_BOUNDARY` | `TIMED OUT` |
| `x509_utils.go` | 64 | 10 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_utils.go` | 70 | 25 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_utils.go` | 70 | 25 | `INVERT_NEGATIVES` | `KILLED` |
| `x509_utils.go` | 70 | 31 | `CONDITIONALS_BOUNDARY` | `LIVED` |
| `x509_utils.go` | 70 | 31 | `CONDITIONALS_NEGATION` | `KILLED` |
| `x509_utils.go` | 70 | 44 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_utils.go` | 70 | 49 | `ARITHMETIC_BASE` | `KILLED` |
| `x509_utils.go` | 70 | 49 | `INVERT_NEGATIVES` | `KILLED` |
