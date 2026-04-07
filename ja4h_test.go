package ja4plus

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPPacketWithPayload creates a gopacket.Packet containing Ethernet +
// IPv4 + TCP layers with the given payload bytes as TCP application data.
func buildTCPPacketWithPayload(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		ACK:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// truncHash is a test helper that mirrors TruncatedHash for expected-value computation.
func truncHash(s string) string {
	if s == "" {
		return "000000000000"
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func TestJA4H_FullFingerprint(t *testing.T) {
	// GET with headers, cookies, referer, accept-language.
	raw := "GET /page HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Referer: https://example.com/home\r\n" +
		"Cookie: session=abc; theme=dark\r\n" +
		"Accept: text/html\r\n" +
		"\r\n"

	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}

	parts := strings.Split(fp, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %q", len(parts), fp)
	}

	// Part A: ge11cr04enus
	// method=ge, ver=11, cookie=c, referer=r
	// headers excl Cookie,Referer: Host, User-Agent, Accept-Language, Accept = 4
	// lang: en-US,en;q=0.9 -> enus (remove hyphens, lowercase, first comma-sep value = "enus", take 4)
	expectedA := "ge11cr04enus"
	if parts[0] != expectedA {
		t.Errorf("Part A: got %q, want %q", parts[0], expectedA)
	}

	// Part B: hash of "Host,User-Agent,Accept-Language,Accept" (original order, excl Cookie, Referer)
	expectedB := truncHash("Host,User-Agent,Accept-Language,Accept")
	if parts[1] != expectedB {
		t.Errorf("Part B: got %q, want %q", parts[1], expectedB)
	}

	// Part C: sorted cookie names: "session,theme"
	expectedC := truncHash("session,theme")
	if parts[2] != expectedC {
		t.Errorf("Part C: got %q, want %q", parts[2], expectedC)
	}

	// Part D: sorted cookie name=value: "session=abc,theme=dark"
	expectedD := truncHash("session=abc,theme=dark")
	if parts[3] != expectedD {
		t.Errorf("Part D: got %q, want %q", parts[3], expectedD)
	}
}

func TestJA4H_NoCookies(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d", len(parts))
	}

	// cookie flag = n, no referer = n
	if !strings.HasPrefix(parts[0], "ge11nn") {
		t.Errorf("Part A should start with ge11nn, got %q", parts[0])
	}

	// Parts C and D should be empty hashes.
	if parts[2] != "000000000000" {
		t.Errorf("Part C: got %q, want 000000000000", parts[2])
	}
	if parts[3] != "000000000000" {
		t.Errorf("Part D: got %q, want 000000000000", parts[3])
	}
}

func TestJA4H_NoReferer(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: example.com\r\nCookie: id=1\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")
	// method=po, ver=11, cookie=c, referer=n
	if !strings.HasPrefix(parts[0], "po11cn") {
		t.Errorf("Part A should start with po11cn, got %q", parts[0])
	}
}

func TestJA4H_LanguageTruncationAndPadding(t *testing.T) {
	tests := []struct {
		name     string
		lang     string
		expected string // last 4 chars of part A
	}{
		{"Short lang", "fr", "fr00"},
		{"Exact 4", "enus", "enus"},
		{"Long lang", "en-US,en;q=0.9", "enus"},
		{"No lang", "", "0000"},
		{"With hyphen", "zh-CN", "zhcn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "GET / HTTP/1.1\r\nHost: x\r\n"
			if tt.lang != "" {
				raw += "Accept-Language: " + tt.lang + "\r\n"
			}
			raw += "\r\n"

			pkt := buildTCPPacketWithPayload(t, []byte(raw))
			fp := ComputeJA4H(pkt)
			parts := strings.Split(fp, "_")
			partA := parts[0]

			// Lang is last 4 chars of part A.
			gotLang := partA[len(partA)-4:]
			if gotLang != tt.expected {
				t.Errorf("lang code: got %q, want %q (partA=%q)", gotLang, tt.expected, partA)
			}
		})
	}
}

func TestJA4H_HeaderHashUsesOriginalOrder(t *testing.T) {
	// Two requests with same headers in different order must produce different
	// part B hashes (proving we use wire order, not sorted).
	raw1 := "GET / HTTP/1.1\r\nAlpha: 1\r\nBeta: 2\r\nGamma: 3\r\n\r\n"
	raw2 := "GET / HTTP/1.1\r\nGamma: 3\r\nAlpha: 1\r\nBeta: 2\r\n\r\n"

	pkt1 := buildTCPPacketWithPayload(t, []byte(raw1))
	pkt2 := buildTCPPacketWithPayload(t, []byte(raw2))

	fp1 := ComputeJA4H(pkt1)
	fp2 := ComputeJA4H(pkt2)

	parts1 := strings.Split(fp1, "_")
	parts2 := strings.Split(fp2, "_")

	// Part A should be identical (same method, version, flags, count, lang).
	if parts1[0] != parts2[0] {
		t.Errorf("Part A should match: %q vs %q", parts1[0], parts2[0])
	}

	// Part B should differ because header order differs.
	if parts1[1] == parts2[1] {
		t.Error("Part B should differ for different header orders")
	}

	// Verify specific hashes.
	expectedB1 := truncHash("Alpha,Beta,Gamma")
	expectedB2 := truncHash("Gamma,Alpha,Beta")
	if parts1[1] != expectedB1 {
		t.Errorf("fp1 Part B: got %q, want %q", parts1[1], expectedB1)
	}
	if parts2[1] != expectedB2 {
		t.Errorf("fp2 Part B: got %q, want %q", parts2[1], expectedB2)
	}
}

func TestJA4H_CookieNamesSorted(t *testing.T) {
	// Cookie names in part C must be sorted alphabetically regardless of
	// their order in the Cookie header.
	raw := "GET / HTTP/1.1\r\nCookie: zebra=1; alpha=2; middle=3\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")

	// Part C: sorted names = alpha,middle,zebra
	expectedC := truncHash("alpha,middle,zebra")
	if parts[2] != expectedC {
		t.Errorf("Part C: got %q, want %q", parts[2], expectedC)
	}
}

func TestJA4H_CookieValuesSorted(t *testing.T) {
	// Cookie name=value pairs in part D must be sorted by name.
	raw := "GET / HTTP/1.1\r\nCookie: zebra=z; alpha=a; middle=m\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")

	// Part D: sorted pairs = alpha=a,middle=m,zebra=z
	expectedD := truncHash("alpha=a,middle=m,zebra=z")
	if parts[3] != expectedD {
		t.Errorf("Part D: got %q, want %q", parts[3], expectedD)
	}
}

func TestJA4H_ProcessPacket(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))

	fp := NewJA4H()
	results, err := fp.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Type != "ja4h" {
		t.Errorf("Type: got %q, want %q", results[0].Type, "ja4h")
	}
	if results[0].Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	if results[0].SrcIP != "192.168.1.1" {
		t.Errorf("SrcIP: got %q, want %q", results[0].SrcIP, "192.168.1.1")
	}
}

func TestJA4H_ProcessPacketNonHTTP(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte{0x16, 0x03, 0x01, 0x00, 0xFF})
	fp := NewJA4H()
	results, err := fp.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for non-HTTP, got %d", len(results))
	}
}

func TestJA4H_Reset(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))

	fp := NewJA4H()
	fp.ProcessPacket(pkt)
	if len(fp.results) != 1 {
		t.Fatalf("expected 1 result before reset, got %d", len(fp.results))
	}
	fp.Reset()
	if len(fp.results) != 0 {
		t.Errorf("expected 0 results after reset, got %d", len(fp.results))
	}
}

func TestJA4H_HTTP10(t *testing.T) {
	raw := "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)
	parts := strings.Split(fp, "_")
	// version should be "10"
	if !strings.HasPrefix(parts[0], "ge10") {
		t.Errorf("expected version 10, got part A: %q", parts[0])
	}
}

func TestJA4H_PseudoHeadersExcluded(t *testing.T) {
	// Pseudo-headers starting with ':' should be excluded from count and hash.
	raw := "GET / HTTP/1.1\r\n:authority: example.com\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")
	// Count should be 2 (Host, Accept), not 3.
	// Part A: ge11nn02...
	if parts[0][6:8] != "02" {
		t.Errorf("header count should be 02, got %q from part A %q", parts[0][6:8], parts[0])
	}

	// Part B hash should only include Host and Accept.
	expectedB := truncHash("Host,Accept")
	if parts[1] != expectedB {
		t.Errorf("Part B: got %q, want %q", parts[1], expectedB)
	}
}
