# FoxIO source material

Every ruling in this project cites a FoxIO source. This directory holds the readings and
the transcriptions of that source material, so that a reader checks a citation without a
clone of the FoxIO repository.

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

`scripts/fetch-corpus.sh` fetches `pcap/`, `python/test/testdata` and
`wireshark/test/testdata`. It fetches no part of `technical_details/`, so it reproduces
nothing on this page. Run this command instead, from an empty directory.

```sh
git clone https://github.com/FoxIO-LLC/ja4.git &&
  git -C ja4 checkout 27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8 &&
  wc -c ja4/technical_details/* &&
  shasum -a 256 ja4/technical_details/*
```

The command writes the byte count of each file, and then the SHA-256 hash of each file.
`wc` adds one total line, and the table holds no row for it. Compare each file line
against the table above. If one line differs, stop and tell the maintainer. A changed hash
means the material behind a citation changed.

**The command clones FoxIO-licensed material into the working directory.** This repository
commits no part of that material. `NOTICE` holds the FoxIO terms.

## What the material specifies

| Fact | Evidence on this page |
|---|---|
| One method holds a complete text specification, and that method is JA4. | `JA4.md` holds 9153 bytes. |
| `JA4H.md` builds no fingerprint. | `JA4H.md` holds 278 bytes. |
| Nine images specify a method or two. | The table holds nine `.png` rows. |

`docs/specs/features/11-foxio-reference.md` states which method each image specifies, and
names the three methods that no image specifies.
