package scan

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The cases below port `tests/test_ja4tscan_frames.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. S2 and S3 of the port's `docs/specs/foxio/JA4TScan.md` state the header values
// and the option bytes of the FoxIO SYN. The source port, the sequence number and the
// timestamp value vary between runs, so each case names them and compares every other byte.

var (
	testScannerMAC = [6]byte{0x02, 0, 0, 0, 0, 0x01}
	testGatewayMAC = [6]byte{0x02, 0, 0, 0, 0, 0x02}
	testScannerIP  = netip.MustParseAddr("198.51.100.1")
	testTargetIP   = netip.MustParseAddr("192.0.2.10")
)

func testSYN() synFrame {
	return synFrame{
		srcMAC:    testScannerMAC,
		dstMAC:    testGatewayMAC,
		srcIP:     testScannerIP.As4(),
		dstIP:     testTargetIP.As4(),
		srcPort:   40112,
		dstPort:   443,
		sequence:  0x01020304,
		timestamp: 0x0A0B0C0D,
	}
}

// onesSum returns the ones' complement sum of RFC 1071, folded to 16 bits. A header that
// carries a correct checksum sums to 0xFFFF.
func onesSum(data []byte) uint32 {
	if len(data)%2 == 1 {
		data = append(append([]byte{}, data...), 0)
	}

	var total uint32
	for index := 0; index < len(data); index += 2 {
		total += uint32(binary.BigEndian.Uint16(data[index:]))
	}

	for total>>16 != 0 {
		total = total&0xFFFF + total>>16
	}

	return total
}

func TestTheSYNFrameOpensWithAnEthernetHeaderForIPv4(t *testing.T) {
	frame := buildSYN(testSYN())

	if !bytes.Equal(frame[0:6], testGatewayMAC[:]) || !bytes.Equal(frame[6:12], testScannerMAC[:]) {
		t.Errorf("the Ethernet addresses are %x and %x", frame[0:6], frame[6:12])
	}

	if !bytes.Equal(frame[12:14], []byte{0x08, 0x00}) {
		t.Errorf("the EtherType is %x, want 0800", frame[12:14])
	}

	if len(frame) != 14+20+40 {
		t.Errorf("the frame holds %d bytes, want 74", len(frame))
	}
}

func TestTheIPHeaderCarriesTheIdentification54321AndTheTimeToLive255(t *testing.T) {
	ip := buildSYN(testSYN())[14:34]

	checks := []struct {
		name      string
		got, want int
	}{
		{"version and header length", int(ip[0]), 0x45},
		{"total length", int(binary.BigEndian.Uint16(ip[2:4])), 60},
		{"identification", int(binary.BigEndian.Uint16(ip[4:6])), 54321},
		{"flags and fragment offset", int(binary.BigEndian.Uint16(ip[6:8])), 0},
		{"time to live", int(ip[8]), 255},
		{"protocol", int(ip[9]), 6},
		{"checksum sum", int(onesSum(ip)), 0xFFFF},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}

	if !bytes.Equal(ip[12:16], []byte{198, 51, 100, 1}) || !bytes.Equal(ip[16:20], []byte{192, 0, 2, 10}) {
		t.Errorf("the addresses are %v and %v", ip[12:16], ip[16:20])
	}
}

func TestTheTCPHeaderCarriesSYNAloneAndTheWindow65535(t *testing.T) {
	tcp := buildSYN(testSYN())[34:]

	checks := []struct {
		name      string
		got, want uint32
	}{
		{"source port", uint32(binary.BigEndian.Uint16(tcp[0:2])), 40112},
		{"destination port", uint32(binary.BigEndian.Uint16(tcp[2:4])), 443},
		{"sequence number", binary.BigEndian.Uint32(tcp[4:8]), 0x01020304},
		{"acknowledgment number", binary.BigEndian.Uint32(tcp[8:12]), 0},
		{"data offset", uint32(tcp[12] >> 4), 10},
		{"flags", uint32(tcp[13]), 0x02},
		{"window", uint32(binary.BigEndian.Uint16(tcp[14:16])), 65535},
		{"urgent pointer", uint32(binary.BigEndian.Uint16(tcp[18:20])), 0},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}
}

func TestTheTCPChecksumCoversThePseudoHeader(t *testing.T) {
	frame := buildSYN(testSYN())
	tcp := frame[34:]

	pseudo := append(append([]byte{}, frame[26:34]...), 0, 6, 0, byte(len(tcp)))
	if sum := onesSum(append(pseudo, tcp...)); sum != 0xFFFF {
		t.Errorf("the TCP checksum sums to %#x, want 0xffff", sum)
	}
}

func TestTheOptionsAreTheFoxIOBytesThenTheTimestampThenOneZeroByte(t *testing.T) {
	options := buildSYN(testSYN())[54:]
	want := []byte{
		0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x04, 0x02, 0x08, 0x0a,
		0x0a, 0x0b, 0x0c, 0x0d,
		0x00, 0x00, 0x00, 0x00,
		0x00,
	}

	if !bytes.Equal(options, want) {
		t.Errorf("the options are %x, want %x", options, want)
	}
}

// S3 of the port's `docs/specs/foxio/JA4TScan.md` at tag `v1.3.0` records the JA4T value
// that a measurement of the FoxIO SYN read.
func TestThisProjectReadsTheFoxIOJA4TOfTheSYN(t *testing.T) {
	packet := gopacket.NewPacket(buildSYN(testSYN()), layers.LayerTypeEthernet, gopacket.Default)
	if got := ja4plus.ComputeJA4T(packet); got != "65535_2-3-4-8-0_1460_7" {
		t.Errorf("the JA4T value of the SYN is %q, want 65535_2-3-4-8-0_1460_7", got)
	}
}

// synAckFrame returns an Ethernet frame that carries a SYN-ACK from the target to the
// scanner. The options are MSS 1460, NOP and Window Scale 8.
func synAckFrame(t testing.TB) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC: net.HardwareAddr(testGatewayMAC[:]), DstMAC: net.HardwareAddr(testScannerMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: testTargetIP.AsSlice(), DstIP: testScannerIP.AsSlice(),
	}
	tcp := &layers.TCP{
		SrcPort: 443, DstPort: 40112, Seq: 77, Ack: 0x01020305, SYN: true, ACK: true, Window: 64240,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set the checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp); err != nil {
		t.Fatalf("serialize the SYN-ACK frame: %v", err)
	}

	return buffer.Bytes()
}

func TestASynAckFrameProducesEveryFieldTheScannerReads(t *testing.T) {
	frame := synAckFrame(t)

	got, ok := parseFrame(frame)
	if !ok {
		t.Fatal("parseFrame reads no reply from a SYN-ACK frame")
	}

	if got.srcIP != testTargetIP || got.dstIP != testScannerIP || got.srcPort != 443 || got.dstPort != 40112 {
		t.Errorf("the endpoints are %v:%d and %v:%d", got.srcIP, got.srcPort, got.dstIP, got.dstPort)
	}

	if got.acknowledgment != 0x01020305 || got.flags != 0x12 {
		t.Errorf("the acknowledgment is %#x and the flags are %#x", got.acknowledgment, got.flags)
	}

	if !bytes.Equal(got.header, frame[34:]) {
		t.Errorf("the header is %x, want %x", got.header, frame[34:])
	}
}

func TestAMalformedFrameProducesNoReply(t *testing.T) {
	base := synAckFrame(t)

	edit := func(change func(frame []byte) []byte) []byte {
		return change(append([]byte{}, base...))
	}

	cases := map[string][]byte{
		"an empty frame": {},
		"a frame shorter than an Ethernet header": base[:13],
		"a frame that carries no IPv4":            edit(func(f []byte) []byte { f[12], f[13] = 0x86, 0xdd; return f }),
		"an IP version other than 4":              edit(func(f []byte) []byte { f[14] = 0x65; return f }),
		"an IP header length of 0":                edit(func(f []byte) []byte { f[14] = 0x40; return f }),
		"an IP header length of 16 bytes":         edit(func(f []byte) []byte { f[14] = 0x44; return f }),
		"an IP header length past the frame":      edit(func(f []byte) []byte { f[14] = 0x4f; return f }),
		"an IP total length below the IP header":  edit(func(f []byte) []byte { binary.BigEndian.PutUint16(f[16:18], 19); return f }),
		"an IP total length past the frame":       edit(func(f []byte) []byte { binary.BigEndian.PutUint16(f[16:18], 1500); return f }),
		"a first fragment":                        edit(func(f []byte) []byte { binary.BigEndian.PutUint16(f[20:22], 0x2000); return f }),
		"a later fragment":                        edit(func(f []byte) []byte { binary.BigEndian.PutUint16(f[20:22], 0x0001); return f }),
		"a protocol other than TCP":               edit(func(f []byte) []byte { f[23] = 1; return f }),
		"a TCP header cut short":                  edit(func(f []byte) []byte { binary.BigEndian.PutUint16(f[16:18], 32); return f[:14+32] }),
		"a TCP data offset of 0":                  edit(func(f []byte) []byte { f[46] &= 0x0f; return f }),
		"a TCP data offset of 16 bytes":           edit(func(f []byte) []byte { f[46] = 0x40 | f[46]&0x0f; return f }),
		"a TCP data offset past the segment":      edit(func(f []byte) []byte { f[46] = 0xf0 | f[46]&0x0f; return f }),
	}

	for name, frame := range cases {
		if _, ok := parseFrame(frame); ok {
			t.Errorf("%s produces a reply", name)
		}
	}
}

func TestTrailingEthernetPaddingStaysOutOfTheHeader(t *testing.T) {
	frame := synAckFrame(t)

	got, ok := parseFrame(append(append([]byte{}, frame...), make([]byte, 6)...))
	if !ok {
		t.Fatal("parseFrame reads no reply from a padded frame")
	}

	if !bytes.Equal(got.header, frame[34:]) {
		t.Errorf("the header is %x, want %x", got.header, frame[34:])
	}
}

func TestEveryTruncationOfASynAckFrameRaisesNothing(t *testing.T) {
	frame := synAckFrame(t)
	for end := range len(frame) {
		_, _ = parseFrame(frame[:end])
	}
}

func TestTheSYNFrameParsesAsTheSYNOfTheTarget(t *testing.T) {
	got, ok := parseFrame(buildSYN(testSYN()))
	if !ok {
		t.Fatal("parseFrame reads no reply from the SYN frame")
	}

	if got.srcIP != testScannerIP || got.dstIP != testTargetIP || got.flags != 0x02 {
		t.Errorf("the SYN reads as %v to %v with the flags %#x", got.srcIP, got.dstIP, got.flags)
	}
}

// FuzzParseFrameReadsAnyFrame holds the bound of the reply reader. Every frame is hostile
// input, so no frame panics the reader, and an accepted header lies inside the frame.
func FuzzParseFrameReadsAnyFrame(f *testing.F) {
	f.Add(synAckFrame(f))
	f.Add(buildSYN(testSYN()))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, frame []byte) {
		got, ok := parseFrame(frame)
		if !ok {
			return
		}

		if len(got.header) < 20 || len(got.header) > len(frame) {
			t.Fatalf("the reader accepts a header of %d bytes from a frame of %d bytes", len(got.header), len(frame))
		}

		_, _ = Value([]Response{{Header: got.header}})
	})
}
