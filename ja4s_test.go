package ja4plus

import (
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPPayloadPacket creates a gopacket with the given bytes as TCP payload.
func buildTCPPayloadPacket(t testing.TB, payload []byte) gopacket.Packet {
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
	// Issue #25 removed the results slice, so the QUIC connection identifier table is the
	// only state that Reset clears.
	f := NewJA4S()
	f.quicDCIDs["10.0.0.1:443-10.0.0.2:40000"] = []byte{0x01, 0x02}

	f.Reset()

	if len(f.quicDCIDs) != 0 {
		t.Errorf("Reset leaves %d entries in the QUIC connection identifier table", len(f.quicDCIDs))
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

// TestTheJA4SRawFormHoldsTheExtensionsInTheWireOrder reproduces a published FoxIO value.
//
// `testdata/foxio/python/badcurveball.pcap.json:18` holds `JA4S_r`, and the extension list
// of it is not sorted. A sorted list reads `0000,000b,0010,0023,ff01`, so this vector
// separates the wire order from the sorted order. `rust/ja4/src/tls.rs:467` and
// `wireshark/source/packet-ja4.c:547` each build the raw form from the string the
// fingerprint hashes. `ja4plus/fingerprinters/ja4s.py:179` states the same rule for the
// Python port. Issue #275 records the measurement.
func TestTheJA4SRawFormHoldsTheExtensionsInTheWireOrder(t *testing.T) {
	sh := &parser.ServerHello{
		Version:      0x0303,
		CipherSuite:  0xc02b,
		Extensions:   []uint16{0x0000, 0xff01, 0x000b, 0x0023, 0x0010},
		ALPNProtocol: "http/1.1",
	}

	fingerprint, raw := computeJA4SPair(sh)

	const wantRaw = "t1205h1_c02b_0000,ff01,000b,0023,0010"
	if raw != wantRaw {
		t.Errorf("raw = %q, want %q", raw, wantRaw)
	}

	const wantFingerprint = "t1205h1_c02b_845f7282a956"
	if fingerprint != wantFingerprint {
		t.Errorf("fingerprint = %q, want %q", fingerprint, wantFingerprint)
	}
}

// TestTheJA4SRawFormSharesThePrefixOfTheFingerprint holds the two values to one prefix.
//
// The raw form and the fingerprint differ on the last part alone, so a change to the
// prefix moves both. The raw form counts GREASE and keeps the wire order, as the
// fingerprint does. Issue #275 records the rule.
func TestTheJA4SRawFormSharesThePrefixOfTheFingerprint(t *testing.T) {
	sh := &parser.ServerHello{
		Version:           0x0304,
		CipherSuite:       0x1301,
		Extensions:        []uint16{0x0A0A, 0x002b, 0x3A3A, 0x0033},
		SupportedVersions: []uint16{0x0304},
	}

	fingerprint, raw := computeJA4SPair(sh)

	const wantRaw = "t130400_1301_0a0a,002b,3a3a,0033"
	if raw != wantRaw {
		t.Errorf("raw = %q, want %q", raw, wantRaw)
	}

	if fingerprint != computeJA4SFromServerHello(sh) {
		t.Errorf("computeJA4SPair and computeJA4SFromServerHello disagree: %q", fingerprint)
	}

	wantFingerprint := "t130400_1301_" + parser.TruncatedHash("0a0a,002b,3a3a,0033")
	if fingerprint != wantFingerprint {
		t.Errorf("fingerprint = %q, want %q", fingerprint, wantFingerprint)
	}
}

// TestTheJA4SRawFormEndsWithAnEmptyListOnAServerHelloThatCarriesNoExtension holds the
// empty case to the reference form.
//
// `rust/ja4/src/tls.rs:462` joins an empty extension list to an empty string, and
// `rust/ja4/src/tls.rs:467` appends that string after the separator. The fingerprint
// reaches `parser.EmptyHash` on the same input. Issue #275 records the rule.
func TestTheJA4SRawFormEndsWithAnEmptyListOnAServerHelloThatCarriesNoExtension(t *testing.T) {
	sh := &parser.ServerHello{
		Version:     0x0303,
		CipherSuite: 0x002f,
	}

	fingerprint, raw := computeJA4SPair(sh)

	const wantRaw = "t120000_002f_"
	if raw != wantRaw {
		t.Errorf("raw = %q, want %q", raw, wantRaw)
	}

	if fingerprint != "t120000_002f_"+parser.EmptyHash {
		t.Errorf("fingerprint = %q, want %q", fingerprint, "t120000_002f_"+parser.EmptyHash)
	}
}

// TestTheJA4SResultCarriesTheRawFormAndLeavesRawOriginalOrderEmpty holds the two raw
// fields of a JA4S result.
//
// FoxIO publishes `JA4S_r` and publishes no `JA4S_ro`, so `RawOriginalOrder` stays empty.
// `conformance_adapters_test.go:58` names `JA4S_r` and names no `JA4S_ro`, so a value in
// `RawOriginalOrder` emits a key the vector never holds.
// `ja4plus/fingerprinters/ja4s.py:179` states the same rule. The Python port fills its own
// `raw_original_order` field with the raw form at `ja4plus/fingerprinters/ja4s.py:182`, and
// it emits no `JA4S_ro` key from it. Issue #275 records the rule.
func TestTheJA4SResultCarriesTheRawFormAndLeavesRawOriginalOrderEmpty(t *testing.T) {
	payload := buildServerHelloPayload(0xc02b, []uint16{0x0000, 0xff01, 0x000b}, "")
	packet := buildTCPPayloadPacket(t, payload)

	results, err := NewJA4S().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}

	const wantRaw = "t120300_c02b_0000,ff01,000b"
	if results[0].Raw != wantRaw {
		t.Errorf("Raw = %q, want %q", results[0].Raw, wantRaw)
	}

	if results[0].RawOriginalOrder != "" {
		t.Errorf("RawOriginalOrder = %q, want the empty string", results[0].RawOriginalOrder)
	}

	wantFingerprint := "t120300_c02b_" + parser.TruncatedHash("0000,ff01,000b")
	if results[0].Fingerprint != wantFingerprint {
		t.Errorf("Fingerprint = %q, want %q", results[0].Fingerprint, wantFingerprint)
	}
}
