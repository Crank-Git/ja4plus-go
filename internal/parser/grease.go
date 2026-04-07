package parser

// IsGreaseValue checks if a TLS value is a GREASE value.
// GREASE values match the pattern 0x?A?A where the high byte equals the low byte.
func IsGreaseValue(value uint16) bool {
	return (value&0x0F0F) == 0x0A0A && (value>>8) == (value&0xFF)
}

// FilterGreaseValues returns a new slice with all GREASE values removed.
func FilterGreaseValues(values []uint16) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, v := range values {
		if !IsGreaseValue(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
