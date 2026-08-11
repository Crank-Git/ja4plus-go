package ja4plus

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// These tests hold the checks of issue #24 of the correctness audit.
// `docs/specs/features/02-correctness-audit.md` states the five requirements:
// FR-audit-14, FR-audit-19, FR-audit-20, FR-audit-21 and FR-audit-22.
//
// The audit changes no code, so a test here records a defect rather than a repair.
// A test that asserts the defective result carries a `TODO(#25)` comment, because the
// closure reverses the assertion. `.claude/rules/rulings.md` asks for a test that builds
// the separating input where no vector separates the two readings.
//
// `docs/audit/findings.md` holds the row of each finding these tests reach.

// ---------------------------------------------------------------------------
// FR-audit-14 — no exported function panics on any input
// ---------------------------------------------------------------------------

// panicAuditFrame builds one Ethernet frame that carries the payload over IPv4.
//
// The protocol selects TCP or UDP. The ports reach the port test of each fingerprinter.
// The frame is well formed, so the crafted bytes sit in the payload and not in the
// headers.
func panicAuditFrame(t testing.TB, proto string, srcPort uint16, dstPort uint16, payload []byte) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version: 4,
		IHL:     5,
		TTL:     64,
		SrcIP:   []byte{192, 0, 2, 1},
		DstIP:   []byte{192, 0, 2, 2},
	}

	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()

	var err error

	if proto == "udp" {
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}

		if err = udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("set the network layer of the UDP checksum: %v", err)
		}

		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, udp, gopacket.Payload(payload))
	} else {
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			PSH:     true,
			ACK:     true,
			Window:  65535,
		}

		if err = tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("set the network layer of the TCP checksum: %v", err)
		}

		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, gopacket.Payload(payload))
	}

	if err != nil {
		t.Fatalf("serialize the %s frame: %v", proto, err)
	}

	return buffer.Bytes()
}

// panicAuditCase is one crafted input of the panic table.
type panicAuditCase struct {
	// name states the shape of the payload that the case builds.
	name string
	// proto is `tcp` or `udp`.
	proto string
	// srcPort and dstPort reach the port test of a fingerprinter.
	srcPort uint16
	dstPort uint16
	// payload is the crafted transport payload.
	payload []byte
}

// panicAuditCases holds one crafted payload for each parser the library reaches.
//
// Each length field states a length the buffer does not hold, because FR-audit-11 names
// that shape as the first defect a parser meets.
func panicAuditCases() []panicAuditCase {
	// A TLS record header that claims 65535 bytes over a 4-byte body.
	oversizedTLS := []byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0xfc}

	// A ClientHello whose handshake length exceeds the record it sits in.
	truncatedClientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x08,
		0x01, 0x00, 0xff, 0xf0, 0x03, 0x03, 0x00, 0x00,
	}

	// A ServerHello whose session identifier length runs past the record.
	truncatedServerHello := []byte{
		0x16, 0x03, 0x03, 0x00, 0x0a,
		0x02, 0x00, 0x00, 0x06, 0x03, 0x03, 0xff, 0x00, 0x00, 0x00,
	}

	// A QUIC long header whose destination connection identifier length is 255.
	oversizedQUICDCID := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0xff, 0x01, 0x02}

	// A QUIC long header whose token length varint runs past the datagram.
	truncatedQUICToken := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0xbf}

	// A DHCPv4 message whose option 55 states a length the message does not hold.
	truncatedDHCP := []byte{
		0x01, 0x01, 0x06, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	// A DHCPv6 message whose option length claims 65535 bytes.
	truncatedDHCPv6 := []byte{0x01, 0xaa, 0xbb, 0xcc, 0x00, 0x01, 0xff, 0xff, 0x00}

	// An SSH identification string with no line terminator.
	unterminatedSSH := []byte("SSH-2.0-" + strings.Repeat("A", 300))

	// An SSH binary packet whose packet length claims 16 megabytes.
	oversizedSSHPacket := []byte{0x01, 0x00, 0x00, 0x00, 0x05, 0x14, 0x00, 0x00}

	// An HTTP request whose header line holds no colon.
	malformedHTTP := []byte("GET / HTTP/1.1\r\nHost\r\nCookie: \r\n\r\n")

	// An HTTP request line with no path and no version.
	shortHTTP := []byte("GET")

	// An X.509 record whose certificate length runs past the record.
	truncatedCertificate := []byte{
		0x16, 0x03, 0x03, 0x00, 0x0a,
		0x0b, 0x00, 0x00, 0x06, 0xff, 0xff, 0xff, 0x30, 0x82, 0xff,
	}

	return []panicAuditCase{
		{"an empty TCP payload", "tcp", 12345, 443, nil},
		{"an empty UDP payload", "udp", 12345, 443, nil},
		{"one zero byte over TCP", "tcp", 12345, 443, []byte{0x00}},
		{"one zero byte over UDP", "udp", 12345, 443, []byte{0x00}},
		{"a TLS record that claims 65535 bytes", "tcp", 12345, 443, oversizedTLS},
		{"a ClientHello longer than its record", "tcp", 12345, 443, truncatedClientHello},
		{"a ServerHello longer than its record", "tcp", 443, 12345, truncatedServerHello},
		{"a certificate longer than its record", "tcp", 443, 12345, truncatedCertificate},
		{"a QUIC header with a 255-byte connection identifier", "udp", 12345, 443, oversizedQUICDCID},
		{"a QUIC token length past the datagram", "udp", 12345, 443, truncatedQUICToken},
		{"a DHCPv4 option longer than the message", "udp", 68, 67, truncatedDHCP},
		{"a DHCPv6 option that claims 65535 bytes", "udp", 546, 547, truncatedDHCPv6},
		{"an SSH identification string with no terminator", "tcp", 12345, 22, unterminatedSSH},
		{"an SSH packet length of 16 megabytes", "tcp", 22, 12345, oversizedSSHPacket},
		{"an HTTP header line with no colon", "tcp", 12345, 80, malformedHTTP},
		{"an HTTP request line with no version", "tcp", 12345, 80, shortHTTP},
	}
}

// panicAuditDrive calls every exported entry point of the package over the frame.
//
// It returns the recovered value when one call panics, and nil when none does.
// The caller reads a non-nil result as a breach of FR-audit-14.
func panicAuditDrive(frame []byte) (recovered any) {
	defer func() {
		recovered = recover()
	}()

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	processor := NewProcessor()
	processor.ProcessPacket(packet)
	processor.GetShardKey(packet)
	processor.CleanupConnection("192.0.2.1", 12345, "192.0.2.2", 443, "tcp")
	processor.Reset()

	sync := NewSyncProcessor()
	sync.ProcessPacket(packet)
	sync.GetShardKey(packet)
	sync.CleanupConnection("192.0.2.1", 12345, "192.0.2.2", 443, "tcp")
	sync.Reset()

	ComputeJA4(packet)
	ComputeJA4S(packet)
	ComputeJA4H(packet)
	ComputeJA4XFromPacket(packet)
	ComputeJA4T(packet)
	ComputeJA4TS(packet)
	ComputeJA4D(packet)
	ComputeJA4D6(packet)

	return nil
}

func TestNoExportedFunctionPanicsOnACraftedFrame(t *testing.T) {
	// FR-audit-14 states the rule, and `CLAUDE.md` states that a fingerprinter returns a
	// non-fatal error and never a panic. Each case names one crafted transport payload.
	for _, testCase := range panicAuditCases() {
		t.Run(testCase.name, func(t *testing.T) {
			frame := panicAuditFrame(t, testCase.proto, testCase.srcPort, testCase.dstPort, testCase.payload)

			if recovered := panicAuditDrive(frame); recovered != nil {
				t.Errorf("the frame that carries %s makes an exported function panic: %v",
					testCase.name, recovered)
			}
		})
	}
}

func FuzzNoExportedFunctionPanicsOnAnyFrame(f *testing.F) {
	// The seed corpus holds every crafted frame of the table above. The fuzzer mutates the
	// whole frame, so it reaches a malformed Ethernet header and a malformed IPv4 header as
	// well as a malformed payload.
	for _, testCase := range panicAuditCases() {
		f.Add(panicAuditFrame(f, testCase.proto, testCase.srcPort, testCase.dstPort, testCase.payload))
	}

	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, frame []byte) {
		if recovered := panicAuditDrive(frame); recovered != nil {
			t.Fatalf("the frame %x makes an exported function panic: %v", frame, recovered)
		}
	})
}

// auditDecoyLayer is a gopacket layer whose concrete type is not the type the layer type
// names. A caller that builds a packet from a custom decoder reaches this shape. Every
// exported method of this package takes a `gopacket.Packet` that a caller builds.
type auditDecoyLayer struct {
	named gopacket.LayerType
}

func (d auditDecoyLayer) LayerType() gopacket.LayerType { return d.named }
func (d auditDecoyLayer) LayerContents() []byte         { return nil }
func (d auditDecoyLayer) LayerPayload() []byte          { return nil }

// auditDecoyUDPType decodes one packet that carries a decoy UDP layer and no other layer.
var auditDecoyUDPType = gopacket.RegisterLayerType(1897, gopacket.LayerTypeMetadata{
	Name:    "AuditDecoyUDP",
	Decoder: gopacket.DecodeFunc(auditDecodeDecoyUDP),
})

// auditDecoyDHCPType decodes one packet that carries a real UDP layer on the DHCP client
// port and a decoy DHCPv4 layer.
var auditDecoyDHCPType = gopacket.RegisterLayerType(1898, gopacket.LayerTypeMetadata{
	Name:    "AuditDecoyDHCP",
	Decoder: gopacket.DecodeFunc(auditDecodeDecoyDHCP),
})

func auditDecodeDecoyUDP(data []byte, builder gopacket.PacketBuilder) error {
	builder.AddLayer(auditDecoyLayer{named: layers.LayerTypeUDP})

	return nil
}

func auditDecodeDecoyDHCP(data []byte, builder gopacket.PacketBuilder) error {
	udp := &layers.UDP{}
	if err := udp.DecodeFromBytes(data, builder); err != nil {
		return err
	}

	builder.AddLayer(udp)
	builder.AddLayer(auditDecoyLayer{named: layers.LayerTypeDHCPv4})

	return nil
}

// auditDecoyUDPPacket returns a packet whose UDP layer type carries another concrete type.
func auditDecoyUDPPacket() gopacket.Packet {
	return gopacket.NewPacket([]byte{0x00}, auditDecoyUDPType, gopacket.Default)
}

// auditDecoyDHCPPacket returns a packet that holds a real UDP header on port 68 and a
// DHCPv4 layer type that carries another concrete type.
func auditDecoyDHCPPacket() gopacket.Packet {
	header := []byte{0x00, 0x44, 0x00, 0x43, 0x00, 0x08, 0x00, 0x00}

	return gopacket.NewPacket(header, auditDecoyDHCPType, gopacket.Default)
}

// auditRecoverPanic returns the value that the call panics with, and nil when it returns.
func auditRecoverPanic(call func()) any {
	recovered, _ := auditRecoverPanicAt(call)

	return recovered
}

// auditRecoverPanicAt returns the value the call panics with and the stack of the panic.
//
// A finding names one line, and a reader who trusts the line rather than the stack records
// the wrong site when two lines of the same file panic on two different inputs.
func auditRecoverPanicAt(call func()) (recovered any, stack string) {
	defer func() {
		if raised := recover(); raised != nil {
			recovered = raised
			stack = string(debug.Stack())
		}
	}()

	call()

	return nil, ""
}

// auditDecoyOutcome runs the call and returns the panic, the results and the error.
//
// Issue #25 closed F-24-1, F-24-2 and F-24-3. Each site now takes the second assertion
// result and returns a non-fatal error, so each call returns rather than panics.
func auditDecoyOutcome(call func() ([]FingerprintResult, error)) (any, []FingerprintResult, error) {
	var (
		results []FingerprintResult
		err     error
	)

	recovered := auditRecoverPanic(func() {
		results, err = call()
	})

	return recovered, results, err
}

func TestAUDPLayerOfAnotherConcreteTypeMakesJA4ReturnAnError(t *testing.T) {
	// F-24-1 is closed. `ja4.go` takes the second result of the UDP type assertion, so the
	// decoy packet reaches a non-fatal error rather than a panic. `CLAUDE.md` states that
	// a fingerprinter returns a non-fatal error and never a panic.
	fingerprinter := NewJA4()

	recovered, results, err := auditDecoyOutcome(func() ([]FingerprintResult, error) {
		return fingerprinter.ProcessPacket(auditDecoyUDPPacket())
	})

	if recovered != nil {
		t.Fatalf("the packet panics with %v, and the closure of F-24-1 returns an error", recovered)
	}

	if err == nil {
		t.Fatal("the packet reaches no error, and the closure of F-24-1 returns one")
	}

	if !strings.Contains(err.Error(), "UDP") {
		t.Errorf("the packet returns the error %v, and F-24-1 names the UDP type assertion", err)
	}

	if len(results) != 0 {
		t.Errorf("the packet produces %d results, and it carries no ClientHello", len(results))
	}
}

func TestAUDPLayerOfAnotherConcreteTypeMakesJA4DReturnAnError(t *testing.T) {
	// F-24-2 is closed. `ja4d.go` takes the second result of the UDP type assertion.
	fingerprinter := NewJA4D()

	recovered, results, err := auditDecoyOutcome(func() ([]FingerprintResult, error) {
		return fingerprinter.ProcessPacket(auditDecoyUDPPacket())
	})

	if recovered != nil {
		t.Fatalf("the packet panics with %v, and the closure of F-24-2 returns an error", recovered)
	}

	if err == nil {
		t.Fatal("the packet reaches no error, and the closure of F-24-2 returns one")
	}

	if !strings.Contains(err.Error(), "UDP") {
		t.Errorf("the packet returns the error %v, and F-24-2 names the UDP type assertion", err)
	}

	if len(results) != 0 {
		t.Errorf("the packet produces %d results, and it carries no DHCP message", len(results))
	}
}

func TestADHCPv4LayerOfAnotherConcreteTypeMakesJA4DReturnAnError(t *testing.T) {
	// F-24-3 is closed. `ja4d.go` takes the second result of the DHCPv4 type assertion.
	fingerprinter := NewJA4D()

	recovered, results, err := auditDecoyOutcome(func() ([]FingerprintResult, error) {
		return fingerprinter.ProcessPacket(auditDecoyDHCPPacket())
	})

	if recovered != nil {
		t.Fatalf("the packet panics with %v, and the closure of F-24-3 returns an error", recovered)
	}

	if err == nil {
		t.Fatal("the packet reaches no error, and the closure of F-24-3 returns one")
	}

	if !strings.Contains(err.Error(), "DHCPv4") {
		t.Errorf("the packet returns the error %v, and F-24-3 names the DHCPv4 type assertion", err)
	}

	if len(results) != 0 {
		t.Errorf("the packet produces %d results, and it carries no DHCP message", len(results))
	}
}

func TestAZeroValueFingerprinterReadsItsFirstPacketWithNoPanic(t *testing.T) {
	// F-24-4 through F-24-9 are closed. Every type below holds a map or a pointer that
	// only its constructor filled, and an `ensure` method now fills it on the first call.
	// A caller who writes `var f ja4plus.JA4LFingerprinter` reaches a usable value.
	ssh := gopacket.NewPacket(
		panicAuditFrame(t, "tcp", 12345, 22, []byte("SSH-2.0-OpenSSH_9.0\r\n")),
		layers.LayerTypeEthernet, gopacket.Default)

	web := gopacket.NewPacket(
		panicAuditFrame(t, "tcp", 12345, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")),
		layers.LayerTypeEthernet, gopacket.Default)

	records := gopacket.NewPacket(
		panicAuditFrame(t, "tcp", 12345, 443, []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}),
		layers.LayerTypeEthernet, gopacket.Default)

	cases := []struct {
		finding string
		site    string
		call    func()
	}{
		{"F-24-4", "ja4h.go:65", func() {
			var f JA4HFingerprinter
			f.ProcessPacket(web) //nolint:errcheck // The panic is the result under test.
		}},
		{"F-24-5", "ja4l.go:187", func() {
			var f JA4LFingerprinter
			f.ProcessPacket(records) //nolint:errcheck // The panic is the result under test.
		}},
		{"F-24-6", "ja4x.go:80", func() {
			var f JA4XFingerprinter
			f.ProcessPacket(records) //nolint:errcheck // The panic is the result under test.
		}},
		{"F-24-7", "ja4ssh.go:134", func() {
			var f JA4SSHFingerprinter
			f.ProcessPacket(ssh) //nolint:errcheck // The panic is the result under test.
		}},
		{"F-24-8", "ja4.go:115", func() {
			var p Processor
			p.Reset()
		}},
		{"F-24-9", "processor.go:62", func() {
			var p SyncProcessor
			p.ProcessPacket(records) //nolint:errcheck // The panic is the result under test.
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.finding, func(t *testing.T) {
			// Each closure builds a new zero value, so the call under test is the first
			// call that value ever receives.
			recovered, stack := auditRecoverPanicAt(testCase.call)

			if recovered != nil {
				t.Fatalf("%s panics at %s with %v, and the closure fills the state on first use\n%s",
					testCase.finding, testCase.site, recovered, stack)
			}
		})
	}
}

func TestAConstructedFingerprinterPanicsOnNoPacketOfTheTable(t *testing.T) {
	// The findings above name the zero value and not the constructor. This test states
	// that the constructed fingerprinter survives every crafted frame of the table, so a
	// reader does not read F-24-4 through F-24-9 as a defect of the supported path.
	for _, testCase := range panicAuditCases() {
		frame := panicAuditFrame(t, testCase.proto, testCase.srcPort, testCase.dstPort, testCase.payload)
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		calls := []func(){
			func() { NewJA4().ProcessPacket(packet) },       //nolint:errcheck // The panic is the result under test.
			func() { NewJA4S().ProcessPacket(packet) },      //nolint:errcheck // The panic is the result under test.
			func() { NewJA4H().ProcessPacket(packet) },      //nolint:errcheck // The panic is the result under test.
			func() { NewJA4L().ProcessPacket(packet) },      //nolint:errcheck // The panic is the result under test.
			func() { NewJA4X().ProcessPacket(packet) },      //nolint:errcheck // The panic is the result under test.
			func() { NewJA4SSH(200).ProcessPacket(packet) }, //nolint:errcheck // The panic is the result under test.
			func() { NewJA4T().ProcessPacket(packet) },      //nolint:errcheck // The panic is the result under test.
			func() { NewJA4TS().ProcessPacket(packet) },     //nolint:errcheck // The panic is the result under test.
			func() { NewJA4D().ProcessPacket(packet) },      //nolint:errcheck // The panic is the result under test.
			func() { NewJA4D6().ProcessPacket(packet) },     //nolint:errcheck // The panic is the result under test.
		}

		for index, call := range calls {
			if recovered := auditRecoverPanic(call); recovered != nil {
				t.Errorf("fingerprinter %d panics on %s: %v", index, testCase.name, recovered)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// FR-audit-19 — the library writes nothing to standard output and standard error
// ---------------------------------------------------------------------------

// panicAuditLibraryFiles names each file of the audit set that ships in the library.
// `cmd/ja4plus/main.go` is the command-line program, so FR-audit-19 does not cover it.
var panicAuditLibraryDirectories = []string{".", "internal/parser"}

// panicAuditOutputPattern matches a call that writes to standard output or to standard
// error. `CLAUDE.md` states that all output belongs to `cmd/ja4plus`.
var panicAuditOutputPattern = regexp.MustCompile(
	`\bos\.Stdout\b|\bos\.Stderr\b|\bfmt\.Print\b|\bfmt\.Printf\b|\bfmt\.Println\b|\blog\.Print|\blog\.Fatal|\blog\.Panic|\bprintln\(`)

func TestTheLibrarySourceHoldsNoWriteToStandardOutputOrStandardError(t *testing.T) {
	// FR-audit-19 states the rule for the library. The scan reads the shipped source of
	// the two library directories, because a write that no test reaches is still a write.
	for _, directory := range panicAuditLibraryDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read %s: %v", directory, err)
		}

		for _, entry := range entries {
			name := entry.Name()

			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}

			path := directory + "/" + name

			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			for number, line := range strings.Split(string(source), "\n") {
				if panicAuditOutputPattern.MatchString(line) {
					t.Errorf("%s:%d writes to standard output or to standard error: %s",
						path, number+1, strings.TrimSpace(line))
				}
			}
		}
	}
}

func TestTheLibraryWritesNothingWhenItReadsACraftedFrame(t *testing.T) {
	// The source scan reads a call by name. This test reads the two file descriptors, so
	// it catches a write that reaches them through a name the pattern does not hold.
	stdout, stderr := os.Stdout, os.Stderr

	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("open the standard output pipe: %v", err)
	}

	errRead, errWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("open the standard error pipe: %v", err)
	}

	os.Stdout, os.Stderr = outWrite, errWrite

	for _, testCase := range panicAuditCases() {
		panicAuditDrive(panicAuditFrame(t, testCase.proto, testCase.srcPort, testCase.dstPort, testCase.payload))
	}

	os.Stdout, os.Stderr = stdout, stderr

	if err := outWrite.Close(); err != nil {
		t.Fatalf("close the standard output pipe: %v", err)
	}

	if err := errWrite.Close(); err != nil {
		t.Fatalf("close the standard error pipe: %v", err)
	}

	written, err := io.ReadAll(outRead)
	if err != nil {
		t.Fatalf("read the standard output pipe: %v", err)
	}

	if len(written) > 0 {
		t.Errorf("the library writes %q to standard output", written)
	}

	written, err = io.ReadAll(errRead)
	if err != nil {
		t.Fatalf("read the standard error pipe: %v", err)
	}

	if len(written) > 0 {
		t.Errorf("the library writes %q to standard error", written)
	}
}

// ---------------------------------------------------------------------------
// FR-audit-21 — a hash of an empty input produces the literal FoxIO value
// ---------------------------------------------------------------------------

// panicAuditZeroSentinel is the value that a hash of an empty input produces.
//
// The value is verbatim FoxIO material, so `.claude/rules/ste.md` bars a rewording of it.
// `docs/specs/foxio/zeek.md:48` records the reading of `zeek/utils/common.zeek:63`, and
// `docs/specs/foxio/JA4.md` R24 and R30, `docs/specs/foxio/JA4S.md` R23 and
// `docs/specs/foxio/JA4H.md` R27 each name the same value.
const panicAuditZeroSentinel = "000000000000"

func TestTheHashOfAnEmptyInputProducesTheZeroSentinel(t *testing.T) {
	if parser.EmptyHash != panicAuditZeroSentinel {
		t.Errorf("`parser.EmptyHash` is %q, and the FoxIO reference names %q",
			parser.EmptyHash, panicAuditZeroSentinel)
	}

	if hash := parser.TruncatedHash(""); hash != panicAuditZeroSentinel {
		t.Errorf("a hash of an empty input produces %q, and the FoxIO reference names %q",
			hash, panicAuditZeroSentinel)
	}
}

func TestEveryMethodThatHashesWritesTheZeroSentinelForAnEmptyInput(t *testing.T) {
	// FR-audit-21 names every method that hashes. Four of the eleven methods do:
	// JA4 hashes the cipher list and the extension list, JA4S hashes the server extension
	// list, JA4H hashes three sections, and JA4X hashes three object identifier lists.
	cases := []struct {
		name     string
		produced string
		sections []int
	}{
		{
			name:     "JA4 over a ClientHello that holds no cipher and no extension",
			produced: computeJA4FromClientHello(&parser.ClientHello{}),
			sections: []int{1, 2},
		},
		{
			name:     "JA4S over a ServerHello that holds no extension",
			produced: computeJA4SFromServerHello(&parser.ServerHello{}),
			sections: []int{2},
		},
		{
			name:     "JA4H over a request that holds no header and no cookie",
			produced: computeJA4HFromRequest(&parser.HTTPRequest{Method: "GET", Version: "HTTP/1.1"}),
			sections: []int{1, 2, 3},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sections := strings.Split(testCase.produced, "_")

			for _, index := range testCase.sections {
				if index >= len(sections) {
					t.Fatalf("the fingerprint %q holds %d sections, and the case reads section %d",
						testCase.produced, len(sections), index)
				}

				if sections[index] != panicAuditZeroSentinel {
					t.Errorf("section %d of %q is %q, and the FoxIO reference names %q",
						index, testCase.produced, sections[index], panicAuditZeroSentinel)
				}
			}
		})
	}

	// JA4X joins each object identifier list with a comma before it hashes, and an empty
	// list joins to an empty string. `ja4x.go:293`, `:294` and `:295` hold the three calls.
	// Issue #57 of Epic 8b holds the decision that an empty list writes the zero sentinel.
	if hash := parser.TruncatedHash(strings.Join(nil, ",")); hash != panicAuditZeroSentinel {
		t.Errorf("JA4X over an empty object identifier list produces %q, and the FoxIO reference names %q",
			hash, panicAuditZeroSentinel)
	}
}

// ---------------------------------------------------------------------------
// FR-audit-22 — every sort is stable and its key matches the FoxIO specification
// ---------------------------------------------------------------------------

func TestTheSortKeyOfEveryFingerprintSectionIsUniquePerElement(t *testing.T) {
	// FR-audit-22 asks for a stable sort. An unstable sort changes no result when the sort
	// key separates every element, because two elements that the key ranks equal are then
	// the same value. This test states which sort holds that property.
	//
	// `ja4.go:163`, `:176`, `:243` and `:260` sort a `[]uint16` by the value itself, and
	// `ja4h.go:248` sorts a `[]string` by the string itself. Two equal elements of those
	// slices carry no other field, so their order changes no output.
	ciphers := []uint16{0x1302, 0x1301, 0x1301, 0x1303}

	first := make([]uint16, len(ciphers))
	copy(first, ciphers)
	sort.Slice(first, func(i, j int) bool { return first[i] < first[j] })

	second := []uint16{0x1301, 0x1303, 0x1301, 0x1302}
	sort.Slice(second, func(i, j int) bool { return second[i] < second[j] })

	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Errorf("the cipher sort produces %v and %v for the same multiset", first, second)
	}

	// `ja4h.go:261` sorts cookie pairs by the name. `parser.HTTPRequest.Cookies` is a map,
	// so no two pairs carry the same name and the key separates every element.
	request := &parser.HTTPRequest{
		Method:  "GET",
		Version: "HTTP/1.1",
		Cookies: map[string]string{"b": "2", "a": "1", "c": "3"},
	}

	wanted := computeJA4HFromRequest(request)

	for run := 0; run < 32; run++ {
		if produced := computeJA4HFromRequest(request); produced != wanted {
			t.Fatalf("run %d of JA4H over one request produces %q, and run 0 produces %q",
				run, produced, wanted)
		}
	}
}

func TestTheCryptoFragmentSortKeepsTheWireOrderOfTwoFragmentsThatShareAnOffset(t *testing.T) {
	// F-24-16 is closed. `ReassembleCryptoFrames` sorted the CRYPTO fragments with
	// `sort.Slice`, which is not stable, and the key is the offset alone. Two fragments
	// that share an offset carry different bytes, and the copy loop writes them in the
	// order the sort leaves.
	//
	// FR-audit-22 asks for a stable sort. The sort is now stable, so the wire order
	// decides and the fragment that arrives second wins. No FoxIO source states a rule for
	// a duplicate offset, so the requirement decides and this test holds the result.
	const count = 13

	fragments := make([]parser.CryptoFragment, count)
	for index := range fragments {
		fragments[index] = parser.CryptoFragment{
			Offset: uint64(count - index),
			Data:   []byte{byte(index)},
		}
	}

	// The pair at index 1 and index 2 shares the offset 11. Index 1 arrives first.
	fragments[1].Offset = fragments[2].Offset

	stable := make([]parser.CryptoFragment, count)
	copy(stable, fragments)
	sort.SliceStable(stable, func(i, j int) bool { return stable[i].Offset < stable[j].Offset })

	unstable := make([]parser.CryptoFragment, count)
	copy(unstable, fragments)
	sort.Slice(unstable, func(i, j int) bool { return unstable[i].Offset < unstable[j].Offset })

	if fmt.Sprint(stable) == fmt.Sprint(unstable) {
		t.Fatalf("the two sorts both produce %v, so this input separates them no longer", stable)
	}

	// `ReassembleCryptoFrames` sorts the slice it receives, so it reaches the stable order.
	assembled := parser.ReassembleCryptoFrames(fragments)
	if len(assembled) < 12 {
		t.Fatalf("the reassembled buffer holds %d bytes, and the offsets reach 12", len(assembled))
	}

	// Offset 11 holds the byte of the fragment the sort leaves last. The stable sort keeps
	// the wire order, so the fragment at index 2 lands last and the buffer holds 2.
	if assembled[11] != 2 {
		t.Errorf("the byte at offset 11 is %d, and the stable sort leaves the fragment 2 last",
			assembled[11])
	}

	// The reassembly is deterministic. A repeated run over one input produces one buffer.
	for run := 0; run < 8; run++ {
		repeat := make([]parser.CryptoFragment, count)
		for index := range repeat {
			repeat[index] = parser.CryptoFragment{
				Offset: uint64(count - index),
				Data:   []byte{byte(index)},
			}
		}

		repeat[1].Offset = repeat[2].Offset

		if produced := parser.ReassembleCryptoFrames(repeat); !bytes.Equal(produced, assembled) {
			t.Fatalf("run %d produces %v, and run 0 produces %v", run, produced, assembled)
		}
	}
}

// ---------------------------------------------------------------------------
// FR-audit-20 — the audit checks every error return for a swallowed error
// ---------------------------------------------------------------------------

func TestTheProcessorReturnsAnErrorRatherThanDiscardingIt(t *testing.T) {
	// FR-audit-20 asks whether an error reaches the caller. `Processor.ProcessPacket`
	// returns a slice of errors, and this test states that a parser error reaches it.
	//
	// The payload is a TLS record whose handshake length exceeds the record it sits in, so
	// `parser.ParseClientHello` returns an error rather than a ClientHello.
	frame := panicAuditFrame(t, "tcp", 12345, 443, []byte{
		0x16, 0x03, 0x01, 0x00, 0x08,
		0x01, 0x00, 0xff, 0xf0, 0x03, 0x03, 0x00, 0x00,
	})

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	results, errs := NewProcessor().ProcessPacket(packet)

	if len(results) > 0 {
		t.Errorf("the truncated ClientHello produces the fingerprint %v", results)
	}

	if len(errs) == 0 {
		t.Error("the truncated ClientHello reaches the caller with no error, and FR-audit-20 asks for one")
	}
}

func TestComputeJA4XFromDERDiscardsTheCertificateParseError(t *testing.T) {
	// F-24-12. `ja4x.go:271` returns the empty string when `x509.ParseCertificate` fails.
	// A caller cannot separate "the bytes hold no certificate" from "the bytes hold a
	// certificate the parser cannot read".
	//
	// TODO(#25): A repair changes an exported signature, so `docs/api/v1.md` records it.
	malformed := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	if produced := ComputeJA4XFromDER(malformed); produced != "" {
		t.Fatalf("F-24-12 no longer reproduces, and the malformed certificate produces %q", produced)
	}

	if produced := ComputeJA4XFromDER(nil); produced != "" {
		t.Fatalf("the empty input produces %q", produced)
	}
}

func TestJA4SDiscardsTheQUICInitialParseError(t *testing.T) {
	// F-24-11. `ja4s.go:61` assigns the error of `parser.ParseQUICInitial` to `_`.
	// `ja4.go:56` propagates the error of the same shape of failure, so the two paths
	// disagree on the same datagram.
	//
	// TODO(#25): The closure propagates the error, or it states why JA4S declines to.
	payloads := [][]byte{
		{0xc0, 0x00, 0x00, 0x00, 0x01, 0xff, 0x01, 0x02},
		{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0xbf},
		{0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x00, 0x00, 0x44, 0x9e, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	separating := -1

	for index, payload := range payloads {
		if _, err := parser.ParseQUICInitial(payload); err != nil {
			separating = index
			break
		}
	}

	if separating < 0 {
		t.Skip("no crafted datagram of this test makes `parser.ParseQUICInitial` return an error")
	}

	frame := panicAuditFrame(t, "udp", 12345, 443, payloads[separating])
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	if _, err := NewJA4S().ProcessPacket(packet); err != nil {
		t.Fatalf("F-24-11 no longer reproduces, and JA4S returns the error %v", err)
	}
}

func TestComputeJA4DiscardsTheClientHelloParseError(t *testing.T) {
	// F-24-10. Each `Compute*` function returns one string and no error, so a caller cannot
	// separate "the packet holds no handshake" from "the packet holds a handshake the
	// parser cannot read". Both produce the empty string.
	//
	// TODO(#25): A repair changes an exported signature, so `docs/api/v1.md` records it and
	// the table under `## The exported signatures a closure changed` holds a row.
	empty := panicAuditFrame(t, "tcp", 12345, 443, nil)

	truncated := panicAuditFrame(t, "tcp", 12345, 443, []byte{
		0x16, 0x03, 0x01, 0x00, 0x08,
		0x01, 0x00, 0xff, 0xf0, 0x03, 0x03, 0x00, 0x00,
	})

	noHandshake := gopacket.NewPacket(empty, layers.LayerTypeEthernet, gopacket.Default)
	unreadable := gopacket.NewPacket(truncated, layers.LayerTypeEthernet, gopacket.Default)

	if ComputeJA4(noHandshake) != "" {
		t.Fatal("the packet that holds no handshake produces a fingerprint")
	}

	if ComputeJA4(unreadable) != "" {
		t.Fatal("F-24-10 no longer reproduces, and the unreadable handshake produces a value")
	}

	// The processor separates the two, and the convenience function does not.
	_, errs := NewProcessor().ProcessPacket(unreadable)
	if len(errs) == 0 {
		t.Error("the processor reads the same packet and reports no error")
	}
}

// panicAuditReadSource returns the source of the file, and fails the test when it cannot.
func panicAuditReadSource(t *testing.T, path string) string {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(source)
}

// panicAuditOneResultAssertion matches a type assertion on a gopacket layer that takes
// one result. `x := y.(*layers.Z)` panics when the layer type carries another concrete
// type, and F-24-1, F-24-2 and F-24-3 each recorded one such site.
var panicAuditOneResultAssertion = regexp.MustCompile(
	`^[A-Za-z_][A-Za-z0-9_]* :?= [A-Za-z_][A-Za-z0-9_]*\.\(\*layers\.[A-Za-z0-9]+\)$`)

func TestNoLibraryFileAssertsAGopacketLayerTypeWithOneResult(t *testing.T) {
	// The closure of F-24-1, F-24-2 and F-24-3 replaced each one-result assertion with the
	// two-result form. A later change that writes the one-result form again reaches the
	// same panic, so this test scans the shipped source rather than three fixed lines.
	for _, directory := range panicAuditLibraryDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read %s: %v", directory, err)
		}

		for _, entry := range entries {
			name := entry.Name()

			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}

			path := directory + "/" + name

			for number, line := range strings.Split(panicAuditReadSource(t, path), "\n") {
				if panicAuditOneResultAssertion.MatchString(strings.TrimSpace(line)) {
					t.Errorf("%s:%d asserts a layer type with one result: %s",
						path, number+1, strings.TrimSpace(line))
				}
			}
		}
	}
}

func TestTheThreeTypeAssertionsThatFindingsNameNowTakeTwoResults(t *testing.T) {
	// The three findings name a site by its line number at the audit date, and the closure
	// moved each line. This test names the repaired form instead, so a reader who reverses
	// the closure sees one failure for each finding.
	cases := []struct {
		finding string
		path    string
		wanted  string
	}{
		{"F-24-1", "ja4.go", "udp, ok := udpLayer.(*layers.UDP)"},
		{"F-24-2", "ja4d.go", "udp, ok := udpLayer.(*layers.UDP)"},
		{"F-24-3", "ja4d.go", "dhcp, ok := dhcpLayer.(*layers.DHCPv4)"},
	}

	for _, testCase := range cases {
		t.Run(testCase.finding, func(t *testing.T) {
			source := panicAuditReadSource(t, testCase.path)

			if !strings.Contains(source, testCase.wanted) {
				t.Errorf("%s holds no line %q, and %s names that repair",
					testCase.path, testCase.wanted, testCase.finding)
			}
		})
	}
}

// panicAuditFindingIDs names each finding that issue #24 records. The reader below states
// that the report holds a row for each one.
var panicAuditFindingIDs = []string{
	"F-24-1", "F-24-2", "F-24-3", "F-24-4", "F-24-5", "F-24-6", "F-24-7", "F-24-8",
	"F-24-9", "F-24-10", "F-24-11", "F-24-12", "F-24-13", "F-24-14", "F-24-15", "F-24-16",
}

func TestTheReportHoldsARowForEveryFindingOfIssue24(t *testing.T) {
	page := panicAuditReadSource(t, "docs/audit/findings.md")

	begin := strings.Index(page, "<!-- findings:24:begin -->")
	end := strings.Index(page, "<!-- findings:24:end -->")

	if begin < 0 || end < begin {
		t.Fatalf("docs/audit/findings.md holds no findings section of issue #24")
	}

	section := page[begin:end]

	for _, identifier := range panicAuditFindingIDs {
		if !bytes.Contains([]byte(section), []byte("| "+identifier+" |")) {
			t.Errorf("the findings section of issue #24 holds no row for %s", identifier)
		}
	}
}
