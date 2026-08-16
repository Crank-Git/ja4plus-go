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

**A citation on a page of this directory names a path, and it joins to one of the bases in
the table below.** The table states the form each base takes and where a reader resolves
it. **Try the bases in the order of the table**, because the first row is the common case
and the last two rows reach no file of this checkout.

`make corpus` writes the FoxIO repository to `testdata/foxio/reference/`, at
`scripts/fetch-corpus.sh:167`.

| N | Base | A citation of that base | Where a reader resolves it |
|---|---|---|---|
| 1 | The FoxIO repository at the pin | `python/ja4.py:161` | Line 161 of `testdata/foxio/reference/python/ja4.py` |
| 2 | `technical_details/` at the pin | `JA4T.png`, `JA4H.md` | `testdata/foxio/reference/technical_details/JA4T.png` |
| 3 | A moved corpus directory | `pcap/badcurveball.pcap` | The right-hand column of `### The three moved directories` below |
| 4 | A recovered file of `docs/specs/foxio/deleted-text-specifications.md` | `JA4L.md:19` | Line 19 of the block that the `### JA4L.md` heading of that page carries |
| 5 | This repository | `.claude/rules/rulings.md:4` | Line 4 of that file, from the root of this checkout |
| 6 | The FoxIO repository at a commit that the sentence names | `technical_details/JA4L.md` | The FoxIO repository at that commit. FoxIO deleted the file before the pin, so the corpus holds it at no path. |
| 7 | The port repository `Crank-Git/ja4plus` | `ja4plus/fingerprinters/ja4ssh.py` | The port, at the tag that the sentence around the citation names |

**Every page of this directory uses more than one base, and this page states no count of
pages.** A count of pages goes stale at the next edit. The stale rule then sends a reader
to a path that no tree holds. #254 records that failure.

**Where two bases can hold one citation, the sentence around it names the repository or
the commit.** `docs/specs/foxio/zeek.md:124` cites `docs/specs/foxio/JA4T.md`, and this
repository holds a file of that path. The sentence names `Crank-Git/ja4plus` and a commit,
so the citation reads at base 7 and never at base 5.

### The three moved directories

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
port names a path of the port under `ja4plus/`, and the sentence around it names the tag.

**This repository copies no page of the port.** #758 removed the one copy on 2026-08-16
UTC, and `.claude/rules/ste.md`
`### A value of another repository is cited, and never mirrored` states the rule.

### Two bases that reach no file of this checkout

- **Base 6.** `docs/specs/foxio/deleted-text-specifications.md` reads `technical_details/`
  at the parent of FoxIO commit `b6f3ff4`. That commit is not the pin, and five of the
  seven recovered files exist at no commit after `b6f3ff4`. The page names the commit at
  each recovered file. **Base 4 reaches the same text without a clone**, because the page
  reproduces each recovered file verbatim.
- **Base 7.** A citation of base 7 names a path of the port under `ja4plus/`, and the
  sentence around it names the tag. `ja4plus/fingerprinters/ja4x.py:341` at tag `v1.1.0`
  is one, and `ja4x_stream_key_test.go` writes it. **A reader resolves it in
  `Crank-Git/ja4plus` at that tag**, and this checkout
  holds no copy of it. `parity_table_test.go` states the tag and the commit it points at,
  in `portReadVersion` and `portReadCommit`.
  **A citation of base 7 opens with `ja4plus/`, and that root names a directory of the port
  alone.** This repository holds no directory of that name, so the root decides the
  repository without help from the sentence around it.

### The measurement of every citation

**On 2026-08-12 a resolver read the thirteen pages of this directory and resolved every
path-shaped code span against the fetched corpus and this checkout.** #331 records the
run. A path-shaped span carries a file extension of the corpus, and it carries an optional
`:line` suffix. The resolver read 822 of them.

**The counts below record one run on one date, and the rule above needs none of them.** A
later edit of any page moves a count, and it breaks no rule of this page.

| Base | Spans that resolve under it |
|---|---|
| 1 The FoxIO repository at the pin | 621 |
| 1 The FoxIO repository at the pin, from a bare file name | 15 |
| 2 `technical_details/` at the pin | 27 |
| 3 A moved corpus directory | 26 |
| 4 A recovered file of `docs/specs/foxio/deleted-text-specifications.md` | 19 |
| 5 This repository | 83 |
| 6 The FoxIO repository at a named commit | 10 |
| 7 The port repository | 18 |
| No base | 3 |

**A bare file name is a short form of base 1.** This page writes `ja4.py`, and that name
reaches one file of the FoxIO tree. The resolver found each such name at exactly one path.

**No citation names a line past the end of the file it names.** The resolver compared each
`:line` suffix against the line count of the resolved file. For base 4 it read the line
count of the recovered file.

**#758 removed one page of this directory on 2026-08-16 UTC, and the run of 2026-08-12 read
that page.** It held a verbatim copy of a section of the port's specification, and it
carried spans of base 7, of base 1 under a bare source file name, and of no base. **So each
count of the table above is now high by an amount that this paragraph does not state.** The
table records one run on one date, and a later record corrects it rather than rewrites it.
Re-run the resolver for a current count.

**The three spans that the table counts under no base each name `ja4l.py`**, and the FoxIO
`python/` directory holds no file of that name at the pin. The removed page wrote one of
them, and the paragraph of this page that reported that defect wrote the other two. **This
sentence writes the name once**, and the exception table of `foxio_citation_base_test.go`
holds that one occurrence with its reason.

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
