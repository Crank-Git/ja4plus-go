# FoxIO source material

Every ruling in this project cites a FoxIO source. This directory holds the readings and
the transcriptions of that source material. A reader checks a citation here, with no clone
of the FoxIO repository.

This page is the inventory. It records where the material comes from, which commit the
project reads, and what each file measures. **The pages in this directory record what a
source states. A page decides no value.** `.claude/rules/rulings.md` states who rules.

## The source

| Fact | Value |
|---|---|
| Repository | <https://github.com/FoxIO-LLC/ja4> |
| Directory | `technical_details/` |
| Pinned commit | `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` |
| Commit date | 2026-07-21 |
| Retrieval date | 2026-08-11 |
| Pin file | `testdata/foxio.pin` |

The pinned commit equals the commit in `testdata/foxio.pin`. A test holds that equality,
because a moved pin that leaves this page behind records a hash of material the project no
longer reads.

Each file below is at
<https://github.com/FoxIO-LLC/ja4/tree/27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8/technical_details>.
Append the file name to that address to reach one file. **This directory reproduces no
FoxIO image.** It links to each one.

## How to read a citation

A citation on a page of this directory names a path in the FoxIO repository at the pinned
commit. `make corpus` writes that repository to `testdata/foxio/reference/`, at
`scripts/fetch-corpus.sh:167`.

**Join a citation to `testdata/foxio/reference/`.** Read `python/ja4.py:161` as line 161
of `testdata/foxio/reference/python/ja4.py`.

**`scripts/fetch-corpus.sh:149` moves three directories out of the staged tree first**, so
a citation of one of the three reaches no path under `testdata/foxio/reference/`.
`scripts/fetch-corpus.sh:102` names the three. Join a citation of one of the three to the
corpus directory of the right-hand column.

| The FoxIO path a citation names | Where `make corpus` writes it | What it holds |
|---|---|---|
| `pcap` | `testdata/foxio/pcap/` | The captures |
| `python/test/testdata` | `testdata/foxio/python/` | The per-stream vectors |
| `wireshark/test/testdata` | `testdata/foxio/wireshark/` | The per-packet vectors |

**`testdata/foxio/python/` holds no source file, and it is never the base of a citation.**
A reader who joins `python/ja4.py` to `testdata/foxio/` lands in the vector directory and
reaches nothing. **That failure is silent.** Issue #254 records the measurement, and one
wrong citation reached a ruling on 2026-08-12.

**`python/ja4.py` is the FoxIO reference program, and it is never the port.** The port is
the Python implementation at `Crank-Git/ja4plus`, and the two disagree. A citation of the
port names a path of the port, and `docs/specs/foxio/port-register.md` holds the port
material this project copies.

Two pages of this directory cite a path that `testdata/foxio/reference/` does not hold,
and each one states its own base.

- `docs/specs/foxio/deleted-text-specifications.md` reads `technical_details/` at the
  parent of FoxIO commit `b6f3ff4`. That commit is not the pin, and five of the seven
  recovered files exist at no commit after `b6f3ff4`. The page names the commit at each
  recovered file.
- `docs/specs/foxio/port-register.md` is a verbatim copy of a section of the port's
  specification. Its citations name paths of the port, and no reader edits the copy.

**If `testdata/foxio/reference/` is absent, run `make corpus`.** A corpus that an earlier
version of `scripts/fetch-corpus.sh` wrote names the pinned commit and holds no reference
tree. `scripts/fetch-corpus.sh:55` now reads the directories as well as the commit, so the
next run fetches the corpus again.

## The inventory

The directory holds twelve files at the pinned commit: three text files and nine images.

| File | Bytes | SHA-256 |
|---|---|---|
| `JA4.md` | 9153 | `14a9623ad05d6f8b5ccbff2023dc6fce10ff012dc2d202b497e3bc029aa75c94` |
| `JA4.png` | 61637 | `1bd63c14b3b96c2b70bfa8e85632450c9396af9a13e274489c0cb02f2a7e9615` |
| `JA4D.png` | 50518 | `3d862024be16c0b4679179d5433e1dc823a4721ded5b8912de1876edc4895268` |
| `JA4D6.png` | 45911 | `26b06ae218761e532d04687131b52c88f7293f9f6f81b4e9c97f81cd8a078ff9` |
| `JA4H.md` | 278 | `7c96d53af6f51f88bb90b0d6582e10c8b2984e449cfe32940cc51b44fd4eec96` |
| `JA4H.png` | 82051 | `08592925d1371d64bf42eeed90506dddf30e4451ba062485ae437abe6c556b80` |
| `JA4L.png` | 162323 | `04036284edfcf0d8e94f3ca6660b1ab688813df7bfb82b0f001b65d7daa07354` |
| `JA4S.png` | 48611 | `a4d303c3c51c2862d86abd69d6dfe6d28a43e86556a91d2c1c8261fa4de15458` |
| `JA4SSH.png` | 92290 | `98524e55021e9d0bc42efe35e6aa0fdf002df38e65311a34d34a1bcc45e78e8c` |
| `JA4T.png` | 39410 | `1a76d4ac7645b794bdb7a29fd00d2eeaf46395af3f66c0b86b76a1f6dcef76f2` |
| `JA4X.png` | 92247 | `71f3bd839ca7e228da8ee69dce69de870d5ee69f3e91534356bae1a48d7f322a` |
| `README.md` | 1567 | `f02d776f50c1b805c3c5ad0c6ed6bf33f6d51aeb2888b69f803eb7a35099b8e6` |

The twelve files hold 685996 bytes. The byte count of each row equals the blob size that
`git ls-tree -r --long 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8 technical_details/`
reports.

## Reproduce the measurement

`scripts/fetch-corpus.sh:149` moves `pcap`, `python/test/testdata` and
`wireshark/test/testdata` into `testdata/foxio/`. `scripts/fetch-corpus.sh:167` then writes
the rest of the FoxIO repository to `testdata/foxio/reference/`.
`testdata/foxio/reference/technical_details/` therefore holds each file of the table above,
so `make corpus` reproduces every row.

**The command below clones FoxIO-licensed material into the working directory.** This
repository commits no part of that material. `NOTICE` holds the FoxIO terms.

If you hold no corpus, run the command below from an empty directory.

```sh
git clone https://github.com/FoxIO-LLC/ja4.git &&
  git -C ja4 checkout 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8 &&
  wc -c ja4/technical_details/* &&
  shasum -a 256 ja4/technical_details/*
```

The command writes the byte count of each file, and then the SHA-256 hash of each file.
`wc` adds one total line, and the table holds no row for it. Compare each file line
against the table above. If one line differs, stop. Tell the maintainer. A changed hash
means the material behind a citation changed.

## What the material specifies

| Fact | Evidence on this page |
|---|---|
| One method holds a complete text specification, and that method is JA4. | `JA4.md` holds 9153 bytes. |
| `JA4H.md` builds no fingerprint. | `JA4H.md` holds 278 bytes. |
| Nine images carry the method specifications. | The table holds nine `.png` rows. |

`docs/specs/features/11-foxio-reference.md` states which method each image specifies, and
names the three methods that no image specifies.
