// Package ja4plus computes JA4+ network fingerprints from the packets that gopacket
// decodes.
//
// # License
//
// This repository holds material under two licenses, and NOTICE at the repository root
// states which license covers which material.
//
// The BSD 3-Clause license covers the original Go code, and LICENSE at the repository
// root holds that text. FoxIO licenses the JA4 method under BSD 3-Clause, and it
// publishes that text as LICENSE-JA4.
//
// FoxIO License 1.1 covers the other methods that this package implements: JA4S, JA4H,
// JA4T, JA4TS, JA4L, JA4X, JA4SSH, JA4D and JA4D6. FoxIO License 1.1 permits
// non-commercial use only. A commercial user contacts FoxIO for those methods, and this
// project gives no legal advice.
//
// This package embeds the file data/ja4plus-mapping.csv, and that file comes from FoxIO.
// FoxIO License 1.1 covers it, so every program that links this package carries FoxIO
// material. data/README.md names the source of the file.
//
// FoxIO publishes FoxIO License 1.1 at
// https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE.
package ja4plus
