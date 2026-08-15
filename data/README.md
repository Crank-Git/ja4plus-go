# The FoxIO fingerprint mapping

This directory holds one file: `data/ja4plus-mapping.csv`.

## The source

**FoxIO publishes `data/ja4plus-mapping.csv`, and this project embeds a copy of it.** The
file maps a JA4+ fingerprint to the application, the library, the device or the operating
system that produces it.

FoxIO publishes the file at
<https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv>. The `ja4plus db update`
command downloads the current copy from
<https://github.com/FoxIO-LLC/ja4/raw/main/ja4plus-mapping.csv>, which
`ja4PlusMappingURL` in `cmd/ja4plus/main.go` names. This project read the FoxIO reference at
commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`, which `testdata/foxio.pin` holds.

## The license

**`data/ja4plus-mapping.csv` is FoxIO material, and FoxIO License 1.1 covers it.** FoxIO
License 1.1 permits non-commercial use only. It is not the BSD 3-Clause license that
covers the original Go code in this repository.

`NOTICE` at the repository root holds the FoxIO terms. FoxIO publishes the license text at
<https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE>. A commercial user must contact FoxIO.

## The format

The first line of `data/ja4plus-mapping.csv` is the column header, and `loadDB` of
`lookup.go` reads it as one. **Never add a comment line above the header.** The loader
tests no line for a comment marker. A comment line therefore becomes the header, and every
lookup then fails. This file carries the attribution for that reason.
