package ja4plus

import (
	"crypto/sha256"
	"encoding/hex"
)

const emptyHash = "000000000000"

// TruncatedHash computes SHA-256 of the input string and returns the first
// 12 hex characters (6 bytes) of the lowercase hex digest.
// Returns "000000000000" for empty input (NOT the SHA-256 of an empty string).
func TruncatedHash(input string) string {
	if input == "" {
		return emptyHash
	}
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])[:12]
}
