package ja4plus

import (
	"net"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Every benchmark in this file builds its own packet. The corpus is optional and it
// needs a network, so a benchmark that read it would not run on a clean checkout.
//
// Every fingerprinter keeps each result it produces in an internal slice. A benchmark
// loop that never clears the slice measures the growth of that slice. Each loop below
// calls Reset first, so the measurement covers one packet.

// buildClientHelloPayload returns the bytes of one TLS ClientHello record.
// The record carries the four extensions that JA4 reads: SNI, ALPN,
// supported_versions and signature_algorithms.
func buildClientHelloPayload() []byte {
	cipherSuites := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c}

	var extBytes []byte
	appendExt := func(extType uint16, data []byte) {
		extBytes = append(extBytes, byte(extType>>8), byte(extType))
		extBytes = append(extBytes, byte(len(data)>>8), byte(len(data)))
		extBytes = append(extBytes, data...)
	}

	// server_name: list_len(2) + type(1) + host_len(2) + host
	host := []byte("example.com")
	listLen := len(host) + 3
	sni := []byte{byte(listLen >> 8), byte(listLen), 0x00, byte(len(host) >> 8), byte(len(host))}
	sni = append(sni, host...)
	appendExt(parser.ExtSNI, sni)

	// application_layer_protocol_negotiation: list_len(2) + (len(1) + proto)...
	alpn := []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	appendExt(parser.ExtALPN, alpn)

	// supported_versions: list_len(1) + versions
	appendExt(parser.ExtSupportedVersions, []byte{0x04, 0x03, 0x04, 0x03, 0x03})

	// signature_algorithms: list_len(2) + algorithms
	appendExt(parser.ExtSignatureAlgorithms, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04})

	var body []byte
	body = append(body, 0x03, 0x03)          // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len
	cipherLen := len(cipherSuites) * 2
	body = append(body, byte(cipherLen>>8), byte(cipherLen))
	for _, cs := range cipherSuites {
		body = append(body, byte(cs>>8), byte(cs))
	}
	body = append(body, 0x01, 0x00) // compression_methods: len(1) + null
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	handshakeLen := len(body)
	recordLen := handshakeLen + 4

	payload := []byte{0x16, 0x03, 0x01, byte(recordLen >> 8), byte(recordLen)}
	payload = append(payload, 0x01, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	payload = append(payload, body...)
	return payload
}

// buildCertificateRecordPayload returns the bytes of one TLS Certificate record
// that carries the certificate. JA4X reads the certificate out of this record.
func buildCertificateRecordPayload(certDER []byte) []byte {
	certLen := len(certDER)
	listLen := certLen + 3
	handshakeLen := listLen + 3
	recordLen := handshakeLen + 4

	payload := []byte{0x16, 0x03, 0x03, byte(recordLen >> 8), byte(recordLen)}
	payload = append(payload, 0x0b, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	payload = append(payload, byte(listLen>>16), byte(listLen>>8), byte(listLen))
	payload = append(payload, byte(certLen>>16), byte(certLen>>8), byte(certLen))
	payload = append(payload, certDER...)
	return payload
}

// buildDHCPDiscoverPacket returns one DHCPDISCOVER packet on UDP port 67.
// JA4D reads the message type, the maximum message size and the option order.
func buildDHCPDiscoverPacket(tb testing.TB) gopacket.Packet {
	tb.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{0, 0, 0, 0},
		DstIP:    net.IP{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
	}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	_ = udp.SetNetworkLayerForChecksum(ip)

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x12345678,
		ClientHWAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
			layers.NewDHCPOption(layers.DHCPOptClientID, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
			layers.NewDHCPOption(layers.DHCPOptMaxMessageSize, []byte{0x05, 0xdc}),
			layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{1, 3, 6, 42}),
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dhcp); err != nil {
		tb.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildDHCPv6SolicitPacket returns one DHCPv6 SOLICIT packet on UDP port 547.
// JA4D6 reads the message type, the client identifier length and the option order.
func buildDHCPv6SolicitPacket(tb testing.TB) gopacket.Packet {
	tb.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("fe80::1"),
		DstIP:      net.ParseIP("ff02::1:2"),
	}
	udp := &layers.UDP{SrcPort: 546, DstPort: 547}
	_ = udp.SetNetworkLayerForChecksum(ip)

	dhcp := &layers.DHCPv6{
		MsgType:       layers.DHCPv6MsgTypeSolicit,
		TransactionID: []byte{0x00, 0x01, 0x02},
		Options: layers.DHCPv6Options{
			layers.NewDHCPv6Option(layers.DHCPv6OptClientID, []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
			layers.NewDHCPv6Option(layers.DHCPv6OptElapsedTime, []byte{0x00, 0x00}),
			layers.NewDHCPv6Option(layers.DHCPv6OptOro, []byte{0x00, 0x17, 0x00, 0x18}),
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dhcp); err != nil {
		tb.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// The test and the benchmark for one method share the input below. A guard test that
// read a different packet from the benchmark would guard nothing.

// benchHTTPRequest is the HTTP request that JA4H reads.
const benchHTTPRequest = "GET /index.html HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"User-Agent: Mozilla/5.0\r\n" +
	"Accept: text/html\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Cookie: session=abc123; theme=dark\r\n" +
	"Referer: https://example.com/\r\n" +
	"\r\n"

// benchSSHBanner is the SSH banner that JA4SSH reads.
const benchSSHBanner = "SSH-2.0-OpenSSH_8.9\r\n"

// benchClientIP returns the client address that every benchmark uses.
func benchClientIP() net.IP { return net.IP{192, 168, 1, 1} }

// benchServerIP returns the server address that every benchmark uses.
func benchServerIP() net.IP { return net.IP{10, 0, 0, 1} }

// benchServerHelloPayload returns the TLS ServerHello record that JA4S reads.
func benchServerHelloPayload() []byte {
	return buildServerHelloPayload(0x1301, []uint16{parser.ExtSupportedVersions, parser.ExtALPN}, "h2")
}

// benchSYNOptions returns the TCP options that JA4T reads from a SYN packet.
func benchSYNOptions() []layers.TCPOption {
	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1460)},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
	}
}

// benchSYNACKOptions returns the TCP options that JA4TS reads from a SYN-ACK packet.
func benchSYNACKOptions() []layers.TCPOption {
	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssOptionData(1460)},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
	}
}

// TestEachBenchmarkPacketProducesOneFingerprint keeps every benchmark honest.
// A benchmark whose packet produces no fingerprint measures an early return, and it
// reports a time that no reader can use.
func TestEachBenchmarkPacketProducesOneFingerprint(t *testing.T) {
	cases := []struct {
		name string
		run  func(tb testing.TB) []FingerprintResult
	}{
		{"ja4", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4().ProcessPacket(buildTCPPacketWithPayload(tb, buildClientHelloPayload()))
			return r
		}},
		{"ja4s", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4S().ProcessPacket(buildTCPPayloadPacket(tb, benchServerHelloPayload()))
			return r
		}},
		{"ja4h", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4H().ProcessPacket(buildTCPPacketWithPayload(tb, []byte(benchHTTPRequest)))
			return r
		}},
		{"ja4l", func(tb testing.TB) []FingerprintResult {
			fp := NewJA4L()
			_, _ = fp.ProcessPacket(buildTCPPacketWithIPs(tb, benchClientIP(), benchServerIP(), 64, 54321, 443, true, false))
			r, _ := fp.ProcessPacket(buildTCPPacketWithIPs(tb, benchServerIP(), benchClientIP(), 128, 443, 54321, true, true))
			return r
		}},
		{"ja4x", func(tb testing.TB) []FingerprintResult {
			payload := buildCertificateRecordPayload(generateSelfSignedCertDER(tb))
			r, _ := NewJA4X().ProcessPacket(buildTCPPayloadPacket(tb, payload))
			return r
		}},
		{"ja4ssh", func(tb testing.TB) []FingerprintResult {
			pkt := buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, []byte(benchSSHBanner), false)
			r, _ := NewJA4SSH(1).ProcessPacket(pkt)
			return r
		}},
		{"ja4t", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4T().ProcessPacket(buildTCPPacket(tb, 54321, 443, true, false, 65535, benchSYNOptions()))
			return r
		}},
		{"ja4ts", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4TS().ProcessPacket(buildTCPPacket(tb, 443, 54321, true, true, 65535, benchSYNACKOptions()))
			return r
		}},
		{"ja4d", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4D().ProcessPacket(buildDHCPDiscoverPacket(tb))
			return r
		}},
		{"ja4d6", func(tb testing.TB) []FingerprintResult {
			r, _ := NewJA4D6().ProcessPacket(buildDHCPv6SolicitPacket(tb))
			return r
		}},
	}

	// The check reads the processor run list, so a new fingerprinter that reaches no case
	// above fails here. A person still writes the case, because each one builds its own
	// packet. Issue #148 records the fault a hardcoded count produces.
	var names []string
	for _, tc := range cases {
		names = append(names, tc.name)
	}

	assertCoversEveryMethodName(t, "the benchmark cases", names)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := tc.run(t)
			if len(results) == 0 {
				t.Fatalf("%s: the benchmark packet produced no fingerprint", tc.name)
			}
			if results[0].Fingerprint == "" {
				t.Fatalf("%s: the benchmark packet produced an empty fingerprint", tc.name)
			}
		})
	}

	proc := NewProcessor()
	results, errs := proc.ProcessPacket(buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443))
	if len(errs) > 0 {
		t.Fatalf("processor: unexpected errors: %v", errs)
	}
	if len(results) == 0 {
		t.Fatal("processor: the benchmark packet produced no fingerprint")
	}
}

// BenchmarkProcessorProcessesOneSYNPacket measures Processor.ProcessPacket, which runs
// every fingerprinter the processor holds against one packet.
func BenchmarkProcessorProcessesOneSYNPacket(b *testing.B) {
	proc := NewProcessor()
	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proc.Reset()
		_, _ = proc.ProcessPacket(pkt)
	}
}

// BenchmarkSyncProcessorProcessesOneSYNPacket measures SyncProcessor.ProcessPacket.
// FR-concurrency-24 asks for the per-packet cost of both types side by side, so this
// benchmark reads the packet that BenchmarkProcessorProcessesOneSYNPacket reads and runs
// the same loop. The difference between the two times is the cost of the mutex.
// One goroutine drives this loop, so it reports the cost with no contention.
func BenchmarkSyncProcessorProcessesOneSYNPacket(b *testing.B) {
	sp := NewSyncProcessor()
	pkt := buildSYNPacket("192.168.1.1", "10.0.0.1", 54321, 443)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sp.Reset()
		_, _ = sp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4FingerprintsOneClientHello measures JA4 against one TLS ClientHello.
func BenchmarkJA4FingerprintsOneClientHello(b *testing.B) {
	fp := NewJA4()
	pkt := buildTCPPacketWithPayload(b, buildClientHelloPayload())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4SFingerprintsOneServerHello measures JA4S against one TLS ServerHello.
func BenchmarkJA4SFingerprintsOneServerHello(b *testing.B) {
	fp := NewJA4S()
	pkt := buildTCPPayloadPacket(b, benchServerHelloPayload())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4HFingerprintsOneHTTPRequest measures JA4H against one HTTP request.
func BenchmarkJA4HFingerprintsOneHTTPRequest(b *testing.B) {
	fp := NewJA4H()
	pkt := buildTCPPacketWithPayload(b, []byte(benchHTTPRequest))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4LFingerprintsOneTCPHandshake measures JA4L against one SYN and one
// SYN-ACK. JA4L reports a latency only after it reads both packets.
func BenchmarkJA4LFingerprintsOneTCPHandshake(b *testing.B) {
	fp := NewJA4L()
	syn := buildTCPPacketWithIPs(b, benchClientIP(), benchServerIP(), 64, 54321, 443, true, false)
	synAck := buildTCPPacketWithIPs(b, benchServerIP(), benchClientIP(), 128, 443, 54321, true, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(syn)
		_, _ = fp.ProcessPacket(synAck)
	}
}

// BenchmarkJA4XFingerprintsOneCertificate measures JA4X against one TLS Certificate
// record that carries one X.509 certificate.
func BenchmarkJA4XFingerprintsOneCertificate(b *testing.B) {
	fp := NewJA4X()
	pkt := buildTCPPayloadPacket(b, buildCertificateRecordPayload(generateSelfSignedCertDER(b)))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4SSHFingerprintsOneSSHPacket measures JA4SSH against one SSH packet.
// The window is 1 packet, so the fingerprinter reports a result for every packet.
func BenchmarkJA4SSHFingerprintsOneSSHPacket(b *testing.B) {
	fp := NewJA4SSH(1)
	pkt := buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, []byte(benchSSHBanner), false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4TFingerprintsOneSYNPacket measures JA4T against one TCP SYN packet.
func BenchmarkJA4TFingerprintsOneSYNPacket(b *testing.B) {
	fp := NewJA4T()
	pkt := buildTCPPacket(b, 54321, 443, true, false, 65535, benchSYNOptions())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4TSFingerprintsOneSYNACKPacket measures JA4TS against one TCP SYN-ACK packet.
func BenchmarkJA4TSFingerprintsOneSYNACKPacket(b *testing.B) {
	fp := NewJA4TS()
	pkt := buildTCPPacket(b, 443, 54321, true, true, 65535, benchSYNACKOptions())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4DFingerprintsOneDHCPMessage measures JA4D against one DHCPDISCOVER message.
func BenchmarkJA4DFingerprintsOneDHCPMessage(b *testing.B) {
	fp := NewJA4D()
	pkt := buildDHCPDiscoverPacket(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}

// BenchmarkJA4D6FingerprintsOneDHCPv6Message measures JA4D6 against one DHCPv6 SOLICIT message.
func BenchmarkJA4D6FingerprintsOneDHCPv6Message(b *testing.B) {
	fp := NewJA4D6()
	pkt := buildDHCPv6SolicitPacket(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.Reset()
		_, _ = fp.ProcessPacket(pkt)
	}
}
