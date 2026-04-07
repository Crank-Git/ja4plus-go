package ja4plus

import (
	"fmt"
	"strconv"
	"strings"
)

// OIDToHex converts a dotted OID string to its ASN.1 DER hex encoding.
//
// The first two components are combined per ASN.1 rules: first*40 + second.
// Subsequent components use Variable-Length Quantity (VLQ) encoding.
//
// Example: "2.5.4.3" → "550403" (0x55 = 2*40+5, 0x04 = 4, 0x03 = 3)
func OIDToHex(oidString string) string {
	parts := strings.Split(oidString, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return ""
		}
		nums[i] = v
	}

	if len(nums) < 2 {
		// Single component: just encode as hex byte(s).
		var sb strings.Builder
		for _, n := range nums {
			sb.WriteString(fmt.Sprintf("%02x", n))
		}
		return sb.String()
	}

	// First two components combined per ASN.1 rules.
	encoded := []byte{byte(nums[0]*40 + nums[1])}

	// Remaining components use VLQ encoding.
	for _, val := range nums[2:] {
		encoded = append(encoded, vlqEncode(val)...)
	}

	var sb strings.Builder
	for _, b := range encoded {
		sb.WriteString(fmt.Sprintf("%02x", b))
	}
	return sb.String()
}

// vlqEncode encodes a non-negative integer as Variable-Length Quantity bytes.
// Values < 128 produce a single byte. Larger values are split into 7-bit
// groups with the high bit set on all but the last byte.
func vlqEncode(val int) []byte {
	if val < 0x80 {
		return []byte{byte(val)}
	}

	var vlq []byte
	vlq = append(vlq, byte(val&0x7F))
	val >>= 7
	for val > 0 {
		vlq = append(vlq, byte((val&0x7F)|0x80))
		val >>= 7
	}

	// Reverse to big-endian order.
	for i, j := 0, len(vlq)-1; i < j; i, j = i+1, j-1 {
		vlq[i], vlq[j] = vlq[j], vlq[i]
	}
	return vlq
}
