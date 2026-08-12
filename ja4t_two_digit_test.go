package ja4plus

import (
	"testing"

	"github.com/google/gopacket/layers"
)

// The two-digit form of JA4T and JA4TS. Ruling #125 adopted it from `Crank-Git/ja4plus`,
// which settled the question as its own #215 on 2026-08-08.
//
// The three FoxIO implementations disagree, so the authority rule settles nothing. Two of
// the three write the two-digit form, and the ruling follows them. Zeek writes `"00"` for
// an empty option list at `zeek/ja4t/main.zeek:201`, `fmt("%02d", ...)` for part c at
// `zeek/ja4t/main.zeek:204` and `"00"` for a zero part d at `zeek/ja4t/main.zeek:207`.
// Wireshark writes the same three forms at `wireshark/source/packet-ja4.c:664-673`. Rust
// writes one digit at `rust/ja4/src/tcp.rs:129`, `rust/ja4/src/tcp.rs:139` and
// `rust/ja4/src/tcp.rs:140`. `docs/specs/foxio/JA4T.md` R26, R27 and R28 hold the reading.
//
// The rule keys on the value, and never on the presence of the option. A SYN that carries
// a Window Scale option of zero writes the same part as a SYN that carries no such
// option. `wireshark/source/packet-ja4.c:668` tests `data->window_scale == 0`, and
// `zeek/ja4t/main.zeek:206` tests `c$fp$ja4t$syn_opts$window_scale == 0`. Both read the
// value. The tests below build the present-and-zero packet, which no corpus capture
// reaches.
//
// Part c and part d take different forms above zero, and both references agree on that.
// Part c writes `%02d`, so a segment size below 10 carries a leading zero. Part d writes
// `%d`, so a window scale above zero carries none.

// tcpOptionMSS returns a TCP maximum segment size option that carries the value.
func tcpOptionMSS(value uint16) layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   mssOptionData(value),
	}
}

// tcpOptionWindowScale returns a TCP window scale option that carries the shift.
func tcpOptionWindowScale(shift byte) layers.TCPOption {
	return layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{shift},
	}
}

// tcpOptionNop returns a TCP no-operation option.
//
// Each option list below reaches a length of four bytes, or a multiple of four. gopacket
// pads a shorter list to a 32-bit boundary, and a pad byte decodes as option kind 0.
func tcpOptionNop() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
}

// FR-parity-34. The port holds the same rule as its own #215.
func TestJA4TWritesTwoZeroDigitsForAnEmptyOptionList(t *testing.T) {
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, nil)

	const want = "8192_00_00_00"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN that carries no option is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35. The packet carries no maximum segment size option.
func TestJA4TWritesTwoZeroDigitsForAnAbsentSegmentSize(t *testing.T) {
	options := []layers.TCPOption{tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, options)

	const want = "8192_3-1_00_7"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN that carries no segment size is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35. The packet carries a maximum segment size option whose value is zero, so
// the rule keys on the value and not on the presence of the option.
func TestJA4TWritesTwoZeroDigitsForASegmentSizeOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(0), tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_00_7"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose segment size is zero is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35. Zeek and Wireshark both write part c as `%02d`, so a segment size below 10
// carries a leading zero.
func TestJA4TPadsASegmentSizeBelowTenToTwoDigits(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(5), tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_05_7"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose segment size is 5 is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36. The packet carries no window scale option.
func TestJA4TWritesTwoZeroDigitsForAnAbsentWindowScale(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1460)}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 8192, options)

	const want = "8192_2_1460_00"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN that carries no window scale is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36. The packet carries a window scale option whose value is zero, so the rule
// keys on the value and not on the presence of the option. No corpus capture reaches this
// value, and this test is the record of the ruling.
func TestJA4TWritesTwoZeroDigitsForAWindowScaleOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1460), tcpOptionWindowScale(0), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_1460_00"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose window scale is zero is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36. Zeek and Wireshark both write part d as `%d` above zero, so a window scale
// of 5 carries no leading zero. The two-digit form covers the zero value alone.
func TestJA4TWritesOneDigitForAWindowScaleAboveZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1460), tcpOptionWindowScale(5), tcpOptionNop()}
	pkt := buildTCPPacket(t, 12345, 80, true, false, 1024, options)

	const want = "1024_2-3-1_1460_5"
	if got := ComputeJA4T(pkt); got != want {
		t.Errorf("JA4T of a SYN whose window scale is 5 is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-34, FR-parity-35 and FR-parity-36 each cover JA4TS. The image titles itself
// `JA4T/S: TCP Fingerprint`, and `generateTCPFingerprint` writes both methods, so one
// repair covers both.
func TestJA4TSWritesTwoZeroDigitsForAnEmptyOptionList(t *testing.T) {
	pkt := buildTCPPacket(t, 443, 12345, true, true, 8540, nil)

	const want = "8540_00_00_00"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS of a SYN-ACK that carries no option is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-35 on the server side. The SYN-ACK carries a segment size option of zero, so
// the rule keys on the value here too.
func TestJA4TSWritesTwoZeroDigitsForASegmentSizeOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(0), tcpOptionWindowScale(7), tcpOptionNop()}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 8540, options)

	const want = "8540_2-3-1_00_7"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS of a SYN-ACK whose segment size is zero is %q, and the reference writes %q", got, want)
	}
}

// FR-parity-36 on the server side. The SYN-ACK carries a window scale option of zero.
func TestJA4TSWritesTwoZeroDigitsForAWindowScaleOfZero(t *testing.T) {
	options := []layers.TCPOption{tcpOptionMSS(1220), tcpOptionWindowScale(0), tcpOptionNop()}
	pkt := buildTCPPacket(t, 443, 12345, true, true, 8540, options)

	const want = "8540_2-3-1_1220_00"
	if got := ComputeJA4TS(pkt); got != want {
		t.Errorf("JA4TS of a SYN-ACK whose window scale is zero is %q, and the reference writes %q", got, want)
	}
}
