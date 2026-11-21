package ja4plus

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// These tests hold the checks of issue #24 of the correctness audit.
// `docs/specs/features/02-correctness-audit.md` states the five requirements:
// FR-audit-14, FR-audit-19, FR-audit-20, FR-audit-21 and FR-audit-22.
//
// The audit changes no code, so a test here records a defect rather than a repair.
// Issue #25 closed every finding of this file. It reversed each assertion in the commit
// that closed the finding, so no `TODO(#25)` comment remains.
// `.claude/rules/rulings.md` asks for a test that builds the separating input where no
// vector separates the two readings.
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
	// F-24-1 is closed. `ja4.go` takes the second result of the UDP type assertion in
	// foreignUDPLayerError, so the decoy packet reaches a non-fatal error rather than a
	// panic. `CLAUDE.md` states that a fingerprinter returns a non-fatal error and never a
	// panic.
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
// `docs/specs/foxio/zeek.md:48` records the reading of `zeek/scripts/fingerprints/utils/common.zeek:63`, and
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
	// FR-audit-21 names every method that hashes. Four of the twelve methods do:
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
			// Section 1 is JA4H part b, and it holds a hash rather than the sentinel. R18 of
			// `docs/specs/foxio/JA4H.md` names no sentinel, and R27 confines the sentinel to
			// part c and to part d. The maintainer ruled the split on 2026-08-14, and
			// `TestJA4HPartBHashesAnEmptyHeaderList` holds the ruled value. Issue #527 is the
			// reversal path.
			name:     "JA4H over a request that holds no header and no cookie",
			produced: computeJA4HFromRequest(&parser.HTTPRequest{Method: "GET", Version: "HTTP/1.1"}),
			sections: []int{2, 3},
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

func TestComputeJA4XFromDERReturnsTheEmptyStringForACertificateItCannotRead(t *testing.T) {
	// F-24-12 closes as `no change needed`. `ja4x.go:271` returns the empty string when
	// `x509.ParseCertificate` fails, so a caller separates "the bytes hold no certificate"
	// from "the bytes hold a certificate the parser cannot read" no more.
	//
	// The maintainer ruled on 2026-08-11 that this shape is correct. The port states the
	// invariant at commit `21299645366591331eb93155355b65a76a3729f3`: a fingerprinter that
	// cannot parse a packet returns nothing, and it does not raise. `ComputeJA4XFromDER` is
	// the one-shot function, and `Processor.ProcessPacket` is the API that carries the
	// error. The signature therefore stays as it is, and Epic 10 freezes it.
	//
	// This test holds the ruling. A later change that returns an error fails here.
	malformed := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	if produced := ComputeJA4XFromDER(malformed); produced != "" {
		t.Fatalf("the malformed certificate produces %q, and the ruling names the empty string", produced)
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
	// F-24-11 stays `unconfirmed`, and issue #24 owns that row. The ruling of 2026-08-11 on
	// F-24-10 and F-24-12 states why JA4S declines to propagate: the port invariant at
	// commit `21299645366591331eb93155355b65a76a3729f3` reads that a fingerprinter which
	// cannot parse a packet returns nothing. The skip below still holds, because no crafted
	// datagram of this test separates the two paths.
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
	// The maintainer ruled on 2026-08-11 that this shape is correct. The port states the
	// invariant at commit `21299645366591331eb93155355b65a76a3729f3`: a fingerprinter that
	// cannot parse a packet returns nothing, and it does not raise. The same invariant
	// closed F-22-14 through F-22-26. `Processor` is the API that carries the error, and
	// the assertion at the end of this test holds that separation.
	//
	// This test holds the ruling. A later change that returns an error fails here.
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

	// The processor separates the two, and the one-shot function does not.
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
		// #170 moved the assertion of F-24-1 into foreignUDPLayerError, because the QUIC
		// branch of ja4.go now reads the UDP layer through the parser helper.
		{"F-24-1", "ja4.go", "if _, held := udpLayer.(*layers.UDP); held {"},
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

// These tests hold the parser findings of issue #22. `docs/audit/findings.md` records each
// one, and the identifier in each test name points at the row.
//
// Every test below asserts the value the library produces today, which is the wrong value.
// The audit changes no code, so a test that asserts the right value would fail on this
// branch and hide every other finding. Issue #25 owns the repair under FR-audit-25, and it
// inverts each assertion in the same commit that closes the finding.
//
// `.claude/rules/rulings.md` asks for a test that builds the separating packet where no
// FoxIO vector reaches the value. F-22-2, F-22-3, F-22-6, F-22-7, F-22-8, F-22-11,
// F-22-12 and F-22-13 are those findings, and the tests below build their input.

// auditParserGreaseSigAlg is the GREASE signature algorithm that F-22-11, F-22-12 and
// F-22-13 use. RFC 8701 reserves it, and `docs/specs/foxio/JA4.md` R31 states that the
// signature algorithm list skips it.
const auditParserGreaseSigAlg = 0x0a0a

// auditParserClientHello builds a ClientHello that carries the extensions the caller
// names. It exists so that no test below reaches a helper of another audit file.
func auditParserClientHello(t *testing.T, extensions []parser.TLSExtension) []byte {
	t.Helper()

	return parser.BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, extensions)
}

func TestF22_1_ALPNValueWritesTheValueTheFoxioVectorHolds(t *testing.T) {
	// **F-22-1 is closed, and issue #50 closed it.** The finding recorded that the library
	// wrote the first and last character of the hexadecimal form of the whole first ALPN
	// value. No FoxIO implementation writes that value.
	//
	// The FoxIO vector for `tls-non-ascii-alpn.pcapng` stream 0 holds
	// `t13d151699_8daaf6152771_e5627efa2ab1`. The library wrote
	// `t13d1516bd_8daaf6152771_e5627efa2ab1` before the repair, and only the two ALPN
	// characters differed. `docs/audit/conformance.md:410` records the pair.
	//
	// `docs/specs/foxio/JA4.md` R19 records a reference split of four results for a
	// non-alphanumeric ALPN value. `.claude/rules/parity.md` rule 1 settles it, because a
	// vector reaches the value, and the vector holds `99`. `python/ja4.py:156-157` writes
	// `9` for each non-ASCII end, and `wireshark/source/packet-ja4.c:1027-1028` writes `99`.
	//
	// The `hexForm` column records the value the finding measured. This test asserts the
	// FoxIO value, so it fails when a reader restores the hexadecimal rule.
	cases := []struct {
		alpn    string
		hexForm string
		foxio   string
	}{
		{"\xbd\x99", "b9", "99"},
		{"\x99", "99", "99"},
		{"\x00h2", "02", "99"},
	}

	for _, testCase := range cases {
		got := parser.ALPNValue([]string{testCase.alpn})
		if got != testCase.foxio {
			t.Errorf("ALPNValue(%q) = %q, the FoxIO reference writes %q, and F-22-1 measured %q",
				testCase.alpn, got, testCase.foxio, testCase.hexForm)
		}
	}
}

func TestF22_2_ParseClientHelloStopsAtTheRecordLength(t *testing.T) {
	// F-22-2 is closed. `ParseClientHello` read the record length and then bounded every
	// later slice by the payload length. A payload that holds two TLS records therefore
	// let the first record's extensions length reach into the second record. The parser
	// then read `0x1603` as an extension type. The bound is now the end of the record.
	hello := auditParserClientHello(t, []parser.TLSExtension{parser.MakeSNIExtension("a.example")})
	second := parser.BuildServerHello(0x0303, 0x1302, []parser.TLSExtension{parser.MakeALPNExtension("h2")})

	payload := make([]byte, 0, len(hello)+len(second))
	payload = append(payload, hello...)
	payload = append(payload, second...)

	honest, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("the honest payload: %v", err)
	}

	if len(honest.Extensions) != 1 || honest.Extensions[0] != parser.ExtSNI {
		t.Fatalf("the honest payload produces the extensions %v, and the ClientHello holds one",
			honest.Extensions)
	}

	// The extensions length field sits after the record header, the handshake header, the
	// version, the random, the session identifier, the cipher suite list and the
	// compression method list.
	const extensionsLengthOffset = 5 + 4 + 2 + 32 + 1 + 2 + 4 + 2

	crafted := make([]byte, len(payload))
	copy(crafted, payload)

	grown := int(crafted[extensionsLengthOffset])<<8 | int(crafted[extensionsLengthOffset+1])
	grown += len(second)
	crafted[extensionsLengthOffset] = byte(grown >> 8)
	crafted[extensionsLengthOffset+1] = byte(grown)

	got, err := parser.ParseClientHello(crafted)
	if err != nil {
		t.Fatalf("the crafted payload: %v", err)
	}

	if len(got.Extensions) != len(honest.Extensions) {
		t.Errorf("the crafted payload produces the extensions %v, and the honest payload produces %v",
			got.Extensions, honest.Extensions)
	}

	// 0x1603 is the content type and the first version byte of the second record. The
	// parser read the two bytes as an extension type, and it now stops before them.
	for _, extension := range got.Extensions {
		if extension == 0x1603 {
			t.Errorf("the crafted payload produces the extension 0x1603, which is the header of the second record")
		}
	}
}

func TestF22_3_ParseServerHelloStopsAtTheRecordLength(t *testing.T) {
	// F-22-3 is closed. `ParseServerHello` held the same shape, so a ServerHello whose
	// extensions length reached past its own record read the next record as extension
	// bytes. The bound is now the end of the record.
	hello := parser.BuildServerHello(0x0303, 0x1301, []parser.TLSExtension{
		parser.MakeSupportedVersionsServerExtension(0x0304),
	})
	second := auditParserClientHello(t, []parser.TLSExtension{parser.MakeALPNExtension("h2")})

	payload := make([]byte, 0, len(hello)+len(second))
	payload = append(payload, hello...)
	payload = append(payload, second...)

	honest, err := parser.ParseServerHello(payload)
	if err != nil {
		t.Fatalf("the honest payload: %v", err)
	}

	// The ServerHello holds no cipher suite list and no compression method list, so its
	// extensions length field sits closer to the start than the ClientHello's.
	const extensionsLengthOffset = 5 + 4 + 2 + 32 + 1 + 2 + 1

	crafted := make([]byte, len(payload))
	copy(crafted, payload)

	grown := int(crafted[extensionsLengthOffset])<<8 | int(crafted[extensionsLengthOffset+1])
	grown += len(second)
	crafted[extensionsLengthOffset] = byte(grown >> 8)
	crafted[extensionsLengthOffset+1] = byte(grown)

	got, err := parser.ParseServerHello(crafted)
	if err != nil {
		t.Fatalf("the crafted payload: %v", err)
	}

	if len(got.Extensions) != len(honest.Extensions) {
		t.Errorf("the crafted payload produces the extensions %v, and the honest payload produces %v",
			got.Extensions, honest.Extensions)
	}
}

func TestF22_4_IsSSHPacketReadsTheWholePacketLength(t *testing.T) {
	// F-22-4 is closed. `IsSSHPacket` compared the padding length against
	// `byte(packetLength)`, and that conversion kept the low 8 bits of a 32-bit length. A
	// packet whose length was 1024 and whose padding length was 8 therefore failed the
	// comparison, because the low byte of 1024 is 0.
	//
	// The comparison now reads the whole 32-bit length, so the guard declines only the
	// packet whose padding length reaches its packet length.
	accepted := []uint32{256, 260, 264, 300, 512, 1024, 1035}

	for _, length := range accepted {
		if !parser.IsSSHPacket(auditParserSSHPacket(length, 8, 20)) {
			t.Errorf("IsSSHPacket declines the packet length %d, and the padding length 8 is below it",
				length)
		}
	}

	// A padding length at or above the packet length is still malformed.
	for _, length := range []uint32{2, 8} {
		if parser.IsSSHPacket(auditParserSSHPacket(length, 8, 20)) {
			t.Errorf("IsSSHPacket accepts the packet length %d, and the padding length 8 is not below it",
				length)
		}
	}
}

func TestF22_5_ParseSSHPacketReadsTheWholePacketLength(t *testing.T) {
	// F-22-5 is closed. `ParseSSHPacket` held the same comparison, so the KEXINIT of a
	// connection whose packet length ended in a low byte at or below the padding length
	// reached no fingerprinter.
	for _, length := range []uint32{1024, 1035} {
		info := parser.ParseSSHPacket(auditParserSSHPacket(length, 8, 20))
		if info == nil || info.Type != "kexinit" {
			t.Errorf("ParseSSHPacket declines the packet length %d, and the padding length 8 is below it",
				length)
		}
	}

	if parser.ParseSSHPacket(auditParserSSHPacket(8, 8, 20)) != nil {
		t.Error("ParseSSHPacket accepts the packet length 8, and the padding length 8 is not below it")
	}
}

// auditParserSSHPacket builds an SSH binary packet header with the length, the padding
// length and the message type the caller names.
func auditParserSSHPacket(length uint32, padding byte, messageType byte) []byte {
	packet := make([]byte, 64)
	binary.BigEndian.PutUint32(packet[:4], length)
	packet[4] = padding
	packet[5] = messageType

	return packet
}

func TestF22_6_OIDToHexEncodesTheFirstTwoArcsAsAVariableLengthQuantity(t *testing.T) {
	// F-22-6 is closed. `OIDToHex` wrote `byte(nums[0]*40 + nums[1])`, and X.690 encodes
	// that sum as a variable-length quantity. A sum at or above 128 therefore lost its
	// high bits. `encoding/asn1` of the standard library is the reference here, because it
	// encodes the same identifier.
	cases := []asn1.ObjectIdentifier{
		{2, 5, 4, 3},
		{2, 100, 3},
		{2, 999, 1},
		{1, 2, 840, 113549, 1, 1, 11},
	}

	for _, oid := range cases {
		text := oid.String()

		der, err := asn1.Marshal(oid)
		if err != nil {
			t.Fatalf("asn1.Marshal(%v): %v", oid, err)
		}

		// The first two bytes hold the tag and the length of these short identifiers.
		wanted := hex.EncodeToString(der[2:])

		if got := parser.OIDToHex(text); got != wanted {
			t.Errorf("OIDToHex(%q) = %q, and X.690 encodes it as %q", text, got, wanted)
		}
	}

	// The truncation made two identifiers collide, so one certificate reached the JA4X
	// value of another. The two now differ.
	if parser.OIDToHex("2.999.1") == parser.OIDToHex("0.55")+"01" {
		t.Errorf("OIDToHex(%q) = %q and OIDToHex(%q) = %q, and the closure of F-22-6 separates them",
			"2.999.1", parser.OIDToHex("2.999.1"), "0.55", parser.OIDToHex("0.55"))
	}
}

func TestF22_7_AddSegmentEvictsNoStreamWhenTheOrderSliceIsEmpty(t *testing.T) {
	// F-22-7 is closed. The eviction indexed `r.order[0]` after a comparison that a stream
	// limit of 0 makes true on the first segment, and `r.order` held nothing yet. The
	// eviction now reads the order slice only when it holds a key.
	var recovered any

	func() {
		defer func() { recovered = recover() }()

		reassembler := parser.NewTCPStreamReassembler(0, 4096)
		reassembler.AddSegment("one", 1, []byte("hello"))
		reassembler.AddSegment("two", 1, []byte("world"))

		if stream := reassembler.GetStream("two"); string(stream) != "world" {
			t.Errorf("GetStream returns %q for the second key, and AddSegment stored %q",
				stream, "world")
		}
	}()

	if recovered != nil {
		t.Errorf("AddSegment panics with %v, and the closure of F-22-7 stores the segment",
			recovered)
	}
}

func TestF22_8_GetStreamReturnsNoByteWhenTheByteLimitIsBelowZero(t *testing.T) {
	// F-22-8 is closed. The slice expression `result[:r.MaxBytes]` panicked for every
	// non-empty result when the byte limit was below 0. A negative maximum holds no byte,
	// so the bound is now 0 and `GetStream` returns nil.
	var recovered any

	func() {
		defer func() { recovered = recover() }()

		reassembler := parser.NewTCPStreamReassembler(10, -1)
		reassembler.AddSegment("one", 1, []byte("hello"))

		if stream := reassembler.GetStream("one"); stream != nil {
			t.Errorf("GetStream returns %q, and a byte limit below 0 holds no byte", stream)
		}
	}()

	if recovered != nil {
		t.Errorf("GetStream panics with %v, and the closure of F-22-8 returns no byte",
			recovered)
	}
}

func TestF22_9_ParseCryptoFramesReturnsTheFragmentsItHoldsWithTheTruncationError(t *testing.T) {
	// `internal/parser/quic.go:553` returns the collected fragments beside the error.
	// `internal/parser/quic.go:337` and `internal/parser/quic.go:803` then answer
	// `return nil, err`, so a complete client hello in an earlier frame reaches no
	// fingerprinter. Issue #42 owns the repair under FR-gaps-21.
	//
	// The frame below carries a one-byte CRYPTO frame at offset 0 and a second CRYPTO
	// frame whose length field names more bytes than the payload holds.
	payload := []byte{
		0x06, 0x00, 0x01, 0x01, // CRYPTO, offset 0, length 1, one byte of data
		0x06, 0x01, 0x08, 0x02, // CRYPTO, offset 1, length 8, one byte of data
	}

	fragments, err := parser.ParseCryptoFrames(payload)
	if err == nil {
		t.Fatalf("ParseCryptoFrames reaches no error, and the payload holds a truncated frame")
	}

	if len(fragments) != 1 {
		t.Fatalf("ParseCryptoFrames returns %d fragments, and the finding F-22-9 records one",
			len(fragments))
	}

	if fragments[0].Offset != 0 || len(fragments[0].Data) != 1 {
		t.Errorf("ParseCryptoFrames returns the fragment %+v, and the payload holds one byte at offset 0",
			fragments[0])
	}
}

func TestF22_11_TheRawJA4SkipsAGreaseSignatureAlgorithm(t *testing.T) {
	// F-22-11 is closed. `docs/specs/foxio/JA4.md` R31 states that the signature algorithm
	// list skips a GREASE value, and `computeJA4RawFromClientHello` wrote the list with no
	// filter. No FoxIO vector reaches this input, so this test is the separating packet
	// that `.claude/rules/rulings.md` asks for.
	hello := auditParserGreaseClientHello(t)

	raw := computeJA4RawFromClientHello(hello)
	if strings.Contains(raw, "0a0a") {
		t.Errorf("the raw JA4 %q holds the GREASE signature algorithm 0a0a, and R31 skips it", raw)
	}

	// The two remaining values stay, and they keep the wire order.
	if !strings.Contains(raw, "0403,0804") {
		t.Errorf("the raw JA4 %q holds no signature algorithm list, and the ClientHello carries two",
			raw)
	}
}

func TestF22_12_TheJA4ExtensionHashSkipsAGreaseSignatureAlgorithm(t *testing.T) {
	// F-22-12 is closed. `ja4ExtensionHash` wrote the same unfiltered list into the hashed
	// string, so the third part of the JA4 differed from the value that R31 states. A
	// ClientHello that carries one GREASE value now hashes to the value of the same
	// ClientHello with no GREASE value.
	withGrease := ja4ExtensionHash(auditParserGreaseClientHello(t))
	withoutGrease := ja4ExtensionHash(auditParserPlainClientHello(t))

	if withGrease != withoutGrease {
		t.Errorf("the hash with the GREASE value is %q, and the hash without it is %q",
			withGrease, withoutGrease)
	}
}

func TestF22_13_TheWireOrderRawJA4SkipsAGreaseSignatureAlgorithm(t *testing.T) {
	// F-22-13 is closed. `computeJA4RawOriginalOrder` wrote the same unfiltered list into
	// the wire-order raw JA4.
	raw := computeJA4RawOriginalOrder(auditParserGreaseClientHello(t))
	if strings.Contains(raw, "0a0a") {
		t.Errorf("the wire-order raw JA4 %q holds the GREASE signature algorithm 0a0a, and R31 skips it",
			raw)
	}
}

// auditParserGreaseClientHello returns a ClientHello whose signature algorithm list opens
// with a GREASE value.
func auditParserGreaseClientHello(t *testing.T) *parser.ClientHello {
	t.Helper()

	payload := auditParserClientHello(t, []parser.TLSExtension{
		parser.MakeSignatureAlgorithmsExtension(auditParserGreaseSigAlg, 0x0403, 0x0804),
	})

	hello, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("the GREASE ClientHello: %v", err)
	}

	if len(hello.SignatureAlgorithms) != 3 || hello.SignatureAlgorithms[0] != auditParserGreaseSigAlg {
		t.Fatalf("the GREASE ClientHello holds the signature algorithms %v", hello.SignatureAlgorithms)
	}

	return hello
}

// auditParserPlainClientHello returns the same ClientHello with no GREASE signature
// algorithm.
func auditParserPlainClientHello(t *testing.T) *parser.ClientHello {
	t.Helper()

	payload := auditParserClientHello(t, []parser.TLSExtension{
		parser.MakeSignatureAlgorithmsExtension(0x0403, 0x0804),
	})

	hello, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("the plain ClientHello: %v", err)
	}

	return hello
}

func TestF22_14_TheQUICHeaderGuardsDeclineAnUnreadableDatagramWithNoError(t *testing.T) {
	// The thirteen `nilerr` sites of `internal/parser/quic.go` are correct as written, and
	// the report records them as `no change needed`. The port collapses "not QUIC" and
	// "QUIC but unreadable" onto one return, and this test holds that shape so that a
	// later change cannot move it without a failing test.
	//
	// The datagram below is a QUIC version 1 long header whose token length varint runs
	// past the end of the datagram.
	datagram := []byte{
		0xc0,                   // long header, Initial, version 1
		0x00, 0x00, 0x00, 0x01, // version 1
		0x00, // DCID length 0
		0x00, // SCID length 0
		0x7f, // token length varint, prefix 1, and the second byte is absent
	}

	hello, err := parser.ParseQUICInitial(datagram)
	if err != nil {
		t.Errorf("ParseQUICInitial returns the error %v, and the record holds a decline with no error", err)
	}

	if hello != nil {
		t.Errorf("ParseQUICInitial returns the ClientHello %+v, and the datagram holds none", hello)
	}
}

// This file holds the evidence of issue #23. The audit checks FR-audit-15 through
// FR-audit-18, and `docs/audit/findings.md` records each finding that these tests reach.
//
// A test whose name starts with `TestTheAuditRecords` states the behavior of a finding
// that stays open. It passes on the code the audit read, and it fails when issue #25
// closes the finding. Issue #25 inverts the assertion in the same commit that closes it.

// auditStateClientIP and auditStateServerIP are the two endpoints of every connection this
// file builds. A fixed address keeps each state table key readable in a failure message.
const (
	auditStateClientIP = "192.168.1.10"
	auditStateServerIP = "10.0.0.5"
)

// auditStateFingerprinters returns every fingerprinter of the processor by name.
// The audit reads each one, because FR-audit-16 names the results slice of every
// fingerprinter and FR-audit-18 names every field that holds state.
// It derives the set from the processor run list, so a new fingerprinter reaches the audit
// with no edit. Issue #148 records the fault a second list produces.
func auditStateFingerprinters(proc *Processor) map[string]Fingerprinter {
	return processorFingerprinters(proc)
}

// auditStateLengths returns the length of every map field and every slice field that the
// fingerprinter reaches, by the path of the field.
// It follows a pointer to a struct, so the map inside the JA4H reassembler is visible.
// It reads an unexported field, because every state field of this package is unexported.
func auditStateLengths(value reflect.Value, path string, lengths map[string]int) {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return
		}

		auditStateLengths(value.Elem(), path, lengths)

		return
	}

	if value.Kind() != reflect.Struct {
		return
	}

	typ := value.Type()

	for index := 0; index < typ.NumField(); index++ {
		field := value.Field(index)
		name := path + "." + typ.Field(index).Name

		switch field.Kind() {
		case reflect.Map, reflect.Slice:
			lengths[name] = field.Len()
		case reflect.Pointer:
			auditStateLengths(field, name, lengths)
		}
	}
}

// auditStateFieldLengths returns the length of every state field of the fingerprinter.
func auditStateFieldLengths(name string, fingerprinter any) map[string]int {
	lengths := map[string]int{}
	auditStateLengths(reflect.ValueOf(fingerprinter), name, lengths)

	return lengths
}

// auditStatePacketSet returns one packet set that gives every fingerprinter state.
// A test of Reset proves nothing about a fingerprinter that holds no state, so each
// fingerprinter needs a packet it reads.
func auditStatePacketSet(t *testing.T) []gopacket.Packet {
	t.Helper()

	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	sshBanner := []byte("SSH-2.0-OpenSSH_9.0\r\n")
	httpRequest := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")

	return []gopacket.Packet{
		// JA4T reads the SYN packet, and JA4L reads the timestamp of it.
		buildTCPPacketWithIPs(t, client, server, 64, 40001, 443, true, false),
		// JA4TS reads the SYN-ACK packet.
		buildTCPPacketWithIPs(t, server, client, 64, 443, 40001, true, true),
		// JA4 reads the TLS client hello.
		buildTCPPacketWithPayload(t, buildClientHelloPayload()),
		// JA4 holds a client hello that the segment cuts, until a later segment completes it.
		buildTCPPacketWithSeq(t, client, server, 40005, 443, 1, tcpHelloLongClientHello()[:1400]),
		// JA4S reads the TLS server hello.
		buildTCPPayloadPacket(t, buildServerHelloPayload(0x1301,
			[]uint16{parser.ExtSupportedVersions}, "")),
		// JA4H reads the HTTP request.
		buildTCPPacketWithSeq(t, client, server, 40002, 80, 1, httpRequest),
		// JA4X reads the TLS certificate record.
		buildTCPPacketWithSeq(t, server, client, 443, 40003, 1,
			buildCertificateRecordPayload(generateSelfSignedCertDER(t))),
		// JA4SSH reads the SSH banner.
		buildSSHPacket(auditStateClientIP, auditStateServerIP, 40004, 22, sshBanner, false),
		// JA4D reads the DHCP message, and JA4D6 reads the DHCPv6 message.
		buildDHCPDiscoverPacket(t),
		buildDHCPv6SolicitPacket(t),
	}
}

// auditStateStatelessTypes names each fingerprinter that holds no state at all.
// Issue #25 removed the results slice, and these three held nothing else. A field that
// returns to one of them needs a removal path, so this list is the reader's warning.
//
// `JA4TSFingerprinter` left this list at issue #56, which gave it the state table
// that part e and the RST value read.
var auditStateStatelessTypes = []string{
	"JA4TFingerprinter", "JA4DFingerprinter", "JA4D6Fingerprinter",
}

// FR-audit-18. Reset clears every field that holds state.
// A monitor that reuses one processor for a second capture reads the state of the first
// one when Reset leaves a field.
func TestReset_ClearsEveryStateFieldOfEveryFingerprinter(t *testing.T) {
	proc := NewProcessor()

	for _, packet := range auditStatePacketSet(t) {
		_, _ = proc.ProcessPacket(packet)
	}

	fingerprinters := auditStateFingerprinters(proc)

	if len(fingerprinters) == 0 {
		t.Fatal("the processor runs no fingerprinter, so this test proves nothing")
	}

	held := 0

	for name, fingerprinter := range fingerprinters {
		fields := auditStateFieldLengths(name, fingerprinter)

		for _, length := range fields {
			held += length
		}

		// A stateless type holds no map field and no slice field, so its removal path is
		// the absence of state. Every other type carries at least one field.
		stateless := slices.Contains(auditStateStatelessTypes, name)

		if stateless && len(fields) != 0 {
			t.Errorf("%s holds the state fields %v, and the record names it stateless", name, fields)
		}

		if !stateless && len(fields) == 0 {
			t.Errorf("%s holds no state field, and the record names it stateful", name)
		}
	}

	if held == 0 {
		t.Fatal("the packet set left no state at all, so this test proves nothing about Reset")
	}

	proc.Reset()

	for name, fingerprinter := range fingerprinters {
		for field, length := range auditStateFieldLengths(name, fingerprinter) {
			if length != 0 {
				t.Errorf("Reset leaves %d entries in %s", length, field)
			}
		}
	}
}

// FR-audit-15 and FR-audit-17. Every state table has a removal path, and
// CleanupConnection reaches it for the connection the caller names.
func TestCleanupConnection_RemovesTheStateTableEntryOfTheNamedConnection(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	// A partial HTTP request stays in the reassembler, because the fast path of
	// JA4H removes a stream it parses in one packet.
	partialRequest := []byte("Host: example.com\r\nAccept: */*\r\n")

	cases := []struct {
		name    string
		state   func(t *testing.T) (Fingerprinter, func() int)
		cleanup func(fingerprinter Fingerprinter)
	}{
		{
			name: "JA4LFingerprinter clears the connections table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4L()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithIPs(t, client, server, 64, 40010, 443, true, false))

				return fingerprinter, func() int { return len(fingerprinter.connections) }
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40010, auditStateServerIP, 443, "tcp")
			},
		},
		{
			name: "JA4SSHFingerprinter clears the connections table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4SSH(0)
				_, _ = fingerprinter.ProcessPacket(buildSSHPacket(auditStateClientIP, auditStateServerIP,
					40011, 22, []byte("SSH-2.0-OpenSSH_9.0\r\n"), false))

				return fingerprinter, func() int { return len(fingerprinter.connections) }
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40011, auditStateServerIP, 22, "tcp")
			},
		},
		{
			name: "JA4HFingerprinter clears the reassembler",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4H()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithSeq(t, client, server, 40012, 80, 1, partialRequest))

				// The reassembler holds its stream table in an unexported field of
				// another package, so the reflect walk reads the count.
				return fingerprinter, func() int {
					return auditStateFieldLengths("JA4HFingerprinter", fingerprinter)["JA4HFingerprinter.reassembler.streams"]
				}
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40012, auditStateServerIP, 80, "tcp")
			},
		},
		{
			name: "JA4Fingerprinter clears the partial client hello table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithSeq(t, client, server, 40014, 443, 1, tcpHelloLongClientHello()[:1400]))

				return fingerprinter, func() int { return len(fingerprinter.tcpHellos) }
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40014, auditStateServerIP, 443, "tcp")
			},
		},
		{
			name: "JA4XFingerprinter clears the streams table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4X()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithSeq(t, server, client, 443, 40013, 1, []byte("not a record")))

				// The reassembler holds its stream table in an unexported field of
				// another package, so the reflect walk reads the count.
				return fingerprinter, func() int {
					return auditStateFieldLengths("JA4XFingerprinter", fingerprinter)["JA4XFingerprinter.reassembler.streams"]
				}
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40013, auditStateServerIP, 443, "tcp")
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter, count := testCase.state(t)

			if count() == 0 {
				t.Fatal("the packet gave the fingerprinter no state, so this test proves no removal path")
			}

			testCase.cleanup(fingerprinter)

			if got := count(); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries in the state table", got)
			}
		})
	}
}

// F-23-11 is closed. JA4 keys its QUIC state by the tuple of the packet that carried the
// client hello, and CleanupConnection built one direction of that tuple. A caller that
// named the server endpoint first removed no entry. The method now reads both
// directions, which matches the sorted five-tuple that GetShardKey returns.
//
// The test seeds the two maps in the form that ProcessPacket writes, because a synthetic
// QUIC Initial packet reaches no decryption.
func TestJA4CleanupConnectionReadsBothDirectionsOfTheTuple(t *testing.T) {
	const dcid = "8394c8f03e515708"

	seed := func() *JA4Fingerprinter {
		fingerprinter := NewJA4()
		fingerprinter.quicFragments[dcid] = []parser.CryptoFragment{{Offset: 0, Data: []byte{0x01}}}
		fingerprinter.dcidToTuple[dcid] = fmt.Sprintf("%s:%d-%s:%d",
			auditStateClientIP, 40020, auditStateServerIP, 443)

		return fingerprinter
	}

	cases := []struct {
		name    string
		cleanup func(*JA4Fingerprinter)
	}{
		{"the caller names the server endpoint first", func(f *JA4Fingerprinter) {
			f.CleanupConnection(auditStateServerIP, 443, auditStateClientIP, 40020, "udp")
		}},
		{"the caller names the client endpoint first", func(f *JA4Fingerprinter) {
			f.CleanupConnection(auditStateClientIP, 40020, auditStateServerIP, 443, "udp")
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter := seed()
			testCase.cleanup(fingerprinter)

			if got := len(fingerprinter.quicFragments); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries in the fragment table", got)
			}

			if got := len(fingerprinter.dcidToTuple); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries in the reverse map", got)
			}
		})
	}
}

// F-23-12 is closed. JA4X keyed the deduplication set by the hash of the certificate.
// CleanupConnection therefore reached no entry of it, and a certificate that two connections
// carried produced one fingerprint. The fingerprinter now holds a stream index of the hashes it
// wrote, and CleanupConnection removes the hashes of the connection the caller names.
// #489 then gave the set key the stream beside the certificate hash.
func TestJA4XCleanupConnectionRemovesTheCertificateHashOfTheConnection(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}
	record := buildCertificateRecordPayload(generateSelfSignedCertDER(t))

	fingerprinter := NewJA4X()

	first, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 40030, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(first) != 1 {
		t.Fatalf("the first connection produced %d results, want 1", len(first))
	}

	fingerprinter.CleanupConnection(auditStateClientIP, 40030, auditStateServerIP, 443, "tcp")

	second, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 40031, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(second) != 1 {
		t.Errorf("the second connection produced %d results, and the closure of F-23-12 produces 1", len(second))
	}

	if got := len(fingerprinter.processedCerts); got != 1 {
		t.Errorf("the deduplication set holds %d entries, and the second connection wrote one", got)
	}

	// A third connection carries the same certificate on a third stream, and it produces
	// one value. #489 keyed the set by the certificate and the stream together, and this
	// assertion read 0 before that change.
	// `TestJA4XProducesOneValueWhenOneStreamRepeatsOneCertificate` of
	// `ja4x_stream_key_test.go` holds the deduplication that one stream still needs.
	third, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 40032, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(third) != 1 {
		t.Errorf("a third connection produced %d results, and the closure of #489 produces 1", len(third))
	}
}

// F-23-13 is closed. JA4L built its state table key from the `proto` argument that the
// caller passes, and no doc comment stated the two tokens the fingerprinter writes. A
// caller that passed another spelling removed no entry. `normalizeKey` now writes one
// case for every token, so the write and the removal reach one key.
func TestJA4LCleanupConnectionReadsTheProtocolArgumentInEitherCase(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	for _, proto := range []string{"TCP", "tcp", "Tcp"} {
		t.Run(proto, func(t *testing.T) {
			fingerprinter := NewJA4L()
			_, _ = fingerprinter.ProcessPacket(
				buildTCPPacketWithIPs(t, client, server, 64, 40040, 443, true, false))

			if got := len(fingerprinter.connections); got != 1 {
				t.Fatalf("the SYN packet produced %d connection entries, want 1", got)
			}

			fingerprinter.CleanupConnection(auditStateClientIP, 40040, auditStateServerIP, 443, proto)

			if got := len(fingerprinter.connections); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries for the token %q", got, proto)
			}
		})
	}
}

// F-23-1 through F-23-10 are closed, and the suspected finding S1 named them.
// Every fingerprinter appended each result to a results slice, no exported method read
// that slice, and only Reset cleared it. Issue #25 removed the slice, because
// ProcessPacket already returns each result to the caller.
//
// This test states that no fingerprinter holds a field that grows with the packet count.
func TestNoFingerprinterKeepsAResultAfterProcessPacketReturnsIt(t *testing.T) {
	const connections = 50

	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	proc := NewProcessor()

	produced := 0

	for index := 0; index < connections; index++ {
		port := uint16(41000 + index)

		first, _ := proc.ProcessPacket(buildTCPPacketWithIPs(t, client, server, 64, port, 443, true, false))
		second, _ := proc.ProcessPacket(buildTCPPacketWithIPs(t, server, client, 64, 443, port, true, true))

		produced += len(first) + len(second)
	}

	if produced == 0 {
		t.Fatal("the packet set produced no result, so this test proves nothing about the state")
	}

	for index := 0; index < connections; index++ {
		proc.CleanupConnection(auditStateClientIP, uint16(41000+index), auditStateServerIP, 443, "tcp")
	}

	// A field whose length reaches the connection count is a results slice under another
	// name. Every remaining field is a connection table that CleanupConnection empties.
	for name, fingerprinter := range auditStateFingerprinters(proc) {
		for field, length := range auditStateFieldLengths(name, fingerprinter) {
			if length != 0 {
				t.Errorf("CleanupConnection leaves %d entries in %s, and the fingerprinter keeps no result",
					length, field)
			}
		}
	}
}

// TestNoFingerprinterTypeHoldsAResultsField states the same rule against the type rather
// than against one run. A later change that adds the field back fails here.
func TestNoFingerprinterTypeHoldsAResultsField(t *testing.T) {
	for name, fingerprinter := range auditStateFingerprinters(NewProcessor()) {
		typ := reflect.TypeOf(fingerprinter).Elem()

		if _, held := typ.FieldByName("results"); held {
			t.Errorf("%s holds a results field, and issue #25 removed it under F-23-1 through F-23-10", name)
		}
	}
}

// The suspected finding S3 states that a goroutine which reads the package-level lookup
// state races another goroutine. #74 replaced that state with one atomic.Pointer, so the
// race detector reports nothing here.
// This test reads the table from eight goroutines and writes none of it.
// TestTheLookupTable_ReportsNoRaceWhenAnUpdateRunsBesideALookup adds the writer.
func TestTheLookupState_ReportsNoRaceWhenGoroutinesReadTheDatabase(t *testing.T) {
	const goroutines = 8

	var group sync.WaitGroup

	sources := make([]string, goroutines)

	for index := 0; index < goroutines; index++ {
		group.Add(1)

		go func(slot int) {
			defer group.Done()

			for round := 0; round < 50; round++ {
				_ = LookupFingerprint("t13d1516h2_8daaf6152771_b186095e22b6")
				sources[slot] = GetDatabaseInfo().Source
			}
		}(index)
	}

	group.Wait()

	for _, source := range sources {
		if source != "embedded" && source != "cache" {
			t.Errorf("GetDatabaseInfo reported the source %q, want embedded or cache", source)
		}
	}
}
