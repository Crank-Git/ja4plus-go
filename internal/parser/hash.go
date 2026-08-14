package parser

import (
	"crypto/sha256"
	"encoding/hex"
)

const EmptyHash = "000000000000"

// TruncatedHash computes SHA-256 of the input string and returns the first
// 12 hex characters (6 bytes) of the lowercase hex digest.
// Returns "000000000000" for empty input (NOT the SHA-256 of an empty string).
func TruncatedHash(input string) string {
	if input == "" {
		return EmptyHash
	}
	return TruncatedHashNoSentinel(input)
}

// TruncatedHashNoSentinel returns the first 12 characters of the lowercase SHA-256 hex
// digest of the input. It hashes the empty string, so an empty list reaches
// `e3b0c44298fc` and never the zero sentinel.
//
// JA4H part b is the one caller outside this file, and `TruncatedHash` above calls it for
// a non-empty input. R18 of `docs/specs/foxio/JA4H.md` states
// `Truncated SHA256 hash of Headers, in the order they appear`, and it names no sentinel.
// R27 of the same page confines the sentinel to part c and to part d. The Rust reference
// and the Zeek package write the sentinel in part b, and a rank 1 image rule outranks an
// implementation. The maintainer ruled the split on 2026-08-14, and issue #527 is the
// reversal path. The port half is `Crank-Git/ja4plus#612`.
func TruncatedHashNoSentinel(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])[:12]
}
