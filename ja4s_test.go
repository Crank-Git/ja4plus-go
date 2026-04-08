package ja4plus

import (
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPPayloadPacket creates a gopacket with the given bytes as TCP payload.
func buildTCPPayloadPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{192, 168, 1, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: 443,
		DstPort: 12345,
		ACK:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildServerHelloPayload creates a minimal TLS ServerHello TCP payload.
func buildServerHelloPayload(cipherSuite uint16, extensions []uint16, alpn string) []byte {
	// Build extensions block
	var extBytes []byte
	for _, ext := range extensions {
		var extData []byte
		if ext == parser.ExtALPN && alpn != "" {
			// ALPN extension data: list_len(2) + proto_len(1) + proto
			protoBytes := []byte(alpn)
			alpnList := []byte{byte(len(protoBytes))}
			alpnList = append(alpnList, protoBytes...)
			listLen := len(alpnList)
			extData = append(extData, byte(listLen>>8), byte(listLen))
			extData = append(extData, alpnList...)
		} else if ext == parser.ExtSupportedVersions {
			// Server supported_versions: 2 bytes (the selected version)
			extData = []byte{0x03, 0x04} // TLS 1.3
		}
		// Extension header: type(2) + length(2) + data
		extBytes = append(extBytes, byte(ext>>8), byte(ext))
		extBytes = append(extBytes, byte(len(extData)>>8), byte(len(extData)))
		extBytes = append(extBytes, extData...)
	}

	// ServerHello body after record+handshake headers:
	// version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) + ext_len(2) + exts
	bodyLen := 2 + 32 + 1 + 2 + 1 + 2 + len(extBytes)

	var payload []byte
	// TLS record header: type(1) + version(2) + length(2)
	recordLen := 4 + bodyLen // handshake header(4) + body
	payload = append(payload, 0x16, 0x03, 0x03, byte(recordLen>>8), byte(recordLen))

	// Handshake header: type(1) + length(3)
	payload = append(payload, 0x02, 0x00, byte(bodyLen>>8), byte(bodyLen))

	// Version
	payload = append(payload, 0x03, 0x03)

	// Random (32 zero bytes)
	payload = append(payload, make([]byte, 32)...)

	// Session ID length (0)
	payload = append(payload, 0x00)

	// Cipher suite
	payload = append(payload, byte(cipherSuite>>8), byte(cipherSuite))

	// Compression method
	payload = append(payload, 0x00)

	// Extensions length + data
	payload = append(payload, byte(len(extBytes)>>8), byte(len(extBytes)))
	payload = append(payload, extBytes...)

	return payload
}

func TestComputeJA4SFromServerHello_Basic(t *testing.T) {
	sh := &parser.ServerHello{
		Version:           0x0304, // already resolved from supported_versions
		CipherSuite:       0xc02c,
		Extensions:        []uint16{0x002b, 0x0033, 0x0010},
		ALPNProtocol:      "h2",
		SupportedVersions: []uint16{0x0304},
	}

	fp := computeJA4SFromServerHello(sh)

	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}

	// proto=t, ver=13 (TLS 1.3), ext_count=03, alpn=h2
	wantPartA := "t1303h2"
	if parts[0] != wantPartA {
		t.Errorf("part_a = %q, want %q", parts[0], wantPartA)
	}

	if parts[1] != "c02c" {
		t.Errorf("cipher = %q, want %q", parts[1], "c02c")
	}

	if len(parts[2]) != 12 {
		t.Errorf("ext_hash length = %d, want 12", len(parts[2]))
	}

	// Original wire order: 002b,0033,0010 (JA4S does NOT sort extensions)
	expectedHash := parser.TruncatedHash("002b,0033,0010")
	if parts[2] != expectedHash {
		t.Errorf("ext_hash = %q, want %q", parts[2], expectedHash)
	}
}

func TestComputeJA4S_GREASEIncluded(t *testing.T) {
	// CRITICAL: JA4S INCLUDES GREASE in extension count and hash (unlike JA4)
	sh := &parser.ServerHello{
		Version:           0x0304,
		CipherSuite:       0x1301,
		Extensions:        []uint16{0x0A0A, 0x002b, 0x3A3A, 0x0033},
		SupportedVersions: []uint16{0x0304},
	}

	fp := computeJA4SFromServerHello(sh)
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}

	// ext_count=04 (includes GREASE), alpn=00 (no ALPN)
	wantPartA := "t130400"
	if parts[0] != wantPartA {
		t.Errorf("part_a = %q, want %q", parts[0], wantPartA)
	}

	// Original wire order: 0a0a,002b,3a3a,0033 (JA4S does NOT sort extensions)
	expectedHash := parser.TruncatedHash("0a0a,002b,3a3a,0033")
	if parts[2] != expectedHash {
		t.Errorf("ext_hash = %q, want %q (GREASE must be included)", parts[2], expectedHash)
	}
}

func TestComputeJA4S_NoExtensions(t *testing.T) {
	sh := &parser.ServerHello{
		Version:     0x0303,
		CipherSuite: 0x002f,
		Extensions:  nil,
	}

	fp := computeJA4SFromServerHello(sh)
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}

	// TLS 1.2, ext_count=00, alpn=00
	wantPartA := "t120000"
	if parts[0] != wantPartA {
		t.Errorf("part_a = %q, want %q", parts[0], wantPartA)
	}

	if parts[2] != parser.EmptyHash {
		t.Errorf("ext_hash = %q, want %q", parts[2], parser.EmptyHash)
	}
}

func TestComputeJA4S_CipherHexFormat(t *testing.T) {
	testCases := []struct {
		cipher uint16
		want   string
	}{
		{0xc02c, "c02c"},
		{0x002f, "002f"},
		{0x1301, "1301"},
		{0x00ff, "00ff"},
		{0x0000, "0000"},
	}

	for _, tc := range testCases {
		sh := &parser.ServerHello{
			Version:     0x0303,
			CipherSuite: tc.cipher,
		}
		fp := computeJA4SFromServerHello(sh)
		parts := strings.Split(fp, "_")
		if parts[1] != tc.want {
			t.Errorf("cipher 0x%04x: got %q, want %q", tc.cipher, parts[1], tc.want)
		}
	}
}

func TestJA4SFingerprinter_NonServerHello(t *testing.T) {
	// Build a ClientHello-like payload (handshake type 0x01)
	payload := buildServerHelloPayload(0x1301, nil, "")
	payload[5] = 0x01 // Change to ClientHello type

	packet := buildTCPPayloadPacket(t, payload)
	f := NewJA4S()
	results, err := f.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) > 0 {
		t.Errorf("expected no results for non-ServerHello, got %d", len(results))
	}
}

func TestJA4SFingerprinter_ValidServerHello(t *testing.T) {
	extensions := []uint16{parser.ExtSupportedVersions, 0x0033, parser.ExtALPN}
	payload := buildServerHelloPayload(0xc02c, extensions, "h2")
	packet := buildTCPPayloadPacket(t, payload)

	f := NewJA4S()
	results, err := f.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Type != "ja4s" {
		t.Errorf("type = %q, want %q", r.Type, "ja4s")
	}

	parts := strings.Split(r.Fingerprint, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), r.Fingerprint)
	}

	// proto=t, ver=13, ext_count=03, alpn=h2
	if parts[0] != "t1303h2" {
		t.Errorf("part_a = %q, want %q", parts[0], "t1303h2")
	}
	if parts[1] != "c02c" {
		t.Errorf("cipher = %q, want %q", parts[1], "c02c")
	}
}

func TestJA4SFingerprinter_GREASEInPacket(t *testing.T) {
	extensions := []uint16{0x0A0A, parser.ExtSupportedVersions, 0x3A3A}
	payload := buildServerHelloPayload(0x1301, extensions, "")
	packet := buildTCPPayloadPacket(t, payload)

	f := NewJA4S()
	results, err := f.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	parts := strings.Split(results[0].Fingerprint, "_")

	// ext_count=03 (GREASE included), alpn=00
	if parts[0] != "t130300" {
		t.Errorf("part_a = %q, want %q", parts[0], "t130300")
	}

	// Original wire order: 0a0a,002b,3a3a (JA4S does NOT sort extensions)
	expectedHash := parser.TruncatedHash("0a0a,002b,3a3a")
	if parts[2] != expectedHash {
		t.Errorf("ext_hash = %q, want %q", parts[2], expectedHash)
	}
}

func TestJA4S_Reset(t *testing.T) {
	f := NewJA4S()
	f.results = []FingerprintResult{{Type: "ja4s"}}
	f.Reset()
	if f.results != nil {
		t.Errorf("expected nil results after reset, got %v", f.results)
	}
}

func TestComputeJA4S_Convenience(t *testing.T) {
	extensions := []uint16{parser.ExtSupportedVersions, 0x0033}
	payload := buildServerHelloPayload(0x1301, extensions, "")
	packet := buildTCPPayloadPacket(t, payload)

	fp := ComputeJA4S(packet)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}

	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), fp)
	}
}

func TestJA4S_ProtocolDetection(t *testing.T) {
	// Test that computeJA4SFromServerHello uses IsQUIC/IsDTLS correctly
	sh := &parser.ServerHello{
		Version:     0x0303,
		CipherSuite: 0x1301,
		Extensions:  []uint16{0x002b},
	}

	// TCP (default)
	fp := computeJA4SFromServerHello(sh)
	if !strings.HasPrefix(fp, "t") {
		t.Errorf("expected TCP prefix 't', got %q", fp)
	}

	// QUIC
	sh.IsQUIC = true
	fp = computeJA4SFromServerHello(sh)
	if !strings.HasPrefix(fp, "q") {
		t.Errorf("expected QUIC prefix 'q', got %q", fp)
	}
	sh.IsQUIC = false

	// DTLS
	sh.IsDTLS = true
	fp = computeJA4SFromServerHello(sh)
	if !strings.HasPrefix(fp, "d") {
		t.Errorf("expected DTLS prefix 'd', got %q", fp)
	}
}

func TestJA4S_QUICDCIDTracking(t *testing.T) {
	// Test that the fingerprinter tracks QUIC DCIDs
	fp := NewJA4S()
	if len(fp.quicDCIDs) != 0 {
		t.Error("expected empty DCID map on creation")
	}

	fp.Reset()
	if fp.quicDCIDs == nil {
		t.Error("expected non-nil DCID map after reset")
	}
}

func TestComputeJA4S_NilPacket(t *testing.T) {
	// Non-TCP packet should return empty
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{192, 168, 1, 1},
		Protocol: layers.IPProtocolUDP,
		Version:  4,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	fp := ComputeJA4S(pkt)
	if fp != "" {
		t.Errorf("expected empty fingerprint for non-TCP packet, got %q", fp)
	}
}
