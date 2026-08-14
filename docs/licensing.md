# Licensing

!!! danger "Two licenses cover this repository, and one of them permits non-commercial use only"

    **The original Go code is BSD 3-Clause.** FoxIO licenses every method except JA4 under
    FoxIO License 1.1. **FoxIO License 1.1 permits non-commercial use only.**

    **Never describe this library as BSD 3-Clause without that qualification.** The
    qualification is the whole point of this page.

**This project gives no legal advice.** This page states which license covers which
material, and it names where each text lives. A commercial user contacts FoxIO.

## Which license covers which material

| Material | License | Where the text lives |
|---|---|---|
| The original Go code of this repository | BSD 3-Clause | `LICENSE` at the repository root. |
| The JA4 method | BSD 3-Clause, from FoxIO | `LICENSE-JA4`, at FoxIO. |
| The methods that the next section names | FoxIO License 1.1 | `NOTICE` at the repository root. |
| `data/ja4plus-mapping.csv` | FoxIO License 1.1 | FoxIO publishes the file. |

**`NOTICE` at the repository root holds the FoxIO terms**, and it reproduces the full text
of FoxIO License 1.1. Read `NOTICE` before you use this library.

## The methods that FoxIO License 1.1 covers

`NOTICE` names each method that this library implements under FoxIO License 1.1:

```text
JA4S
JA4H
JA4T
JA4TS
JA4L
JA4LS
JA4X
JA4SSH
JA4D
JA4D6
```

**JA4 is not in that list**, and the reason is the next section.

## JA4 carries a different license from the other methods

FoxIO licenses JA4 under the BSD 3-Clause license, and it publishes that text as
`LICENSE-JA4` at
<https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4>.

**So a commercial user may use JA4.** Each method in the list above carries FoxIO License
1.1 instead, and that license permits non-commercial use only.

**Read the two texts, and never this summary alone.** This page points at them.

## This list is not the FoxIO list

**The list above is the set of methods that this library implements under FoxIO License
1.1. It asserts no equality with the FoxIO list.**

Three FoxIO records at commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` name three
different sets:

| FoxIO record | How many methods it names |
|---|---|
| `License FAQ.md:5` | Twelve. |
| `README.md:293` | Nine. |
| `LICENSE:3` | Thirteen, and it spells the scanner `JA4SScan`. |

The FoxIO record at `README.md:293` names nine methods, and the list above holds ten
names. **The two sets are different.** The FoxIO nine holds JA4TScan, and it holds neither
JA4D nor JA4D6.

**Read the FoxIO records for the FoxIO list.** `testdata/foxio.pin` holds the commit that
this project read.

## Non-commercial use

**FoxIO License 1.1 permits non-commercial use only.** The verbatim text in `NOTICE`
states what that term covers, and this page does not restate it.

FoxIO publishes FoxIO License 1.1 at
<https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>.

**A commercial user contacts FoxIO** at <https://foxio.io> for those methods.

## The mapping file

`data/ja4plus-mapping.csv` comes from FoxIO, and FoxIO License 1.1 covers it. The library
embeds that file, and `ja4plus db update` downloads a newer copy of it.

`data/README.md` names the source of the file.

## The commit that this project read

This project read the FoxIO License 1.1 text from `LICENSE` at commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8` of <https://github.com/FoxIO-LLC/ja4>.
`testdata/foxio.pin` holds that commit.

**A later FoxIO change to the license produces a new issue in this repository.** Cite the
pinned commit when you cite a FoxIO record, because a record at a later commit can name a
different set.

## Where each text lives

| File | What it holds |
|---|---|
| `LICENSE` | The BSD 3-Clause text, and the copyright holder of the original Go code. |
| `NOTICE` | The split, the method list, and the full verbatim text of FoxIO License 1.1. |
| `data/README.md` | The source of the embedded mapping file. |
| `testdata/foxio.pin` | The FoxIO commit that every citation of this project names. |

Read each file in the repository at <https://github.com/Crank-Git/ja4plus-go>.
