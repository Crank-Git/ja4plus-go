package ja4plus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/http2/hpack"
)

// buildTCPPacketWithPayload creates a gopacket.Packet containing Ethernet +
// IPv4 + TCP layers with the given payload bytes as TCP application data.
func buildTCPPacketWithPayload(t testing.TB, payload []byte) gopacket.Packet {
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
	_ = tcp.SetNetworkLayerForChecksum(ip)

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

	expectedA := "ge11cr04enus"
	if parts[0] != expectedA {
		t.Errorf("Part A: got %q, want %q", parts[0], expectedA)
	}

	expectedB := truncHash("Host,User-Agent,Accept-Language,Accept")
	if parts[1] != expectedB {
		t.Errorf("Part B: got %q, want %q", parts[1], expectedB)
	}

	expectedC := truncHash("session,theme")
	if parts[2] != expectedC {
		t.Errorf("Part C: got %q, want %q", parts[2], expectedC)
	}

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

	if !strings.HasPrefix(parts[0], "ge11nn") {
		t.Errorf("Part A should start with ge11nn, got %q", parts[0])
	}

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

			gotLang := partA[len(partA)-4:]
			if gotLang != tt.expected {
				t.Errorf("lang code: got %q, want %q (partA=%q)", gotLang, tt.expected, partA)
			}
		})
	}
}

func TestJA4H_HeaderHashUsesOriginalOrder(t *testing.T) {
	raw1 := "GET / HTTP/1.1\r\nAlpha: 1\r\nBeta: 2\r\nGamma: 3\r\n\r\n"
	raw2 := "GET / HTTP/1.1\r\nGamma: 3\r\nAlpha: 1\r\nBeta: 2\r\n\r\n"

	pkt1 := buildTCPPacketWithPayload(t, []byte(raw1))
	pkt2 := buildTCPPacketWithPayload(t, []byte(raw2))

	fp1 := ComputeJA4H(pkt1)
	fp2 := ComputeJA4H(pkt2)

	parts1 := strings.Split(fp1, "_")
	parts2 := strings.Split(fp2, "_")

	if parts1[0] != parts2[0] {
		t.Errorf("Part A should match: %q vs %q", parts1[0], parts2[0])
	}

	if parts1[1] == parts2[1] {
		t.Error("Part B should differ for different header orders")
	}

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
	raw := "GET / HTTP/1.1\r\nCookie: zebra=1; alpha=2; middle=3\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")

	expectedC := truncHash("alpha,middle,zebra")
	if parts[2] != expectedC {
		t.Errorf("Part C: got %q, want %q", parts[2], expectedC)
	}
}

func TestJA4H_CookieValuesSorted(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nCookie: zebra=z; alpha=a; middle=m\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")

	expectedD := truncHash("alpha=a,middle=m,zebra=z")
	if parts[3] != expectedD {
		t.Errorf("Part D: got %q, want %q", parts[3], expectedD)
	}
}

// TestJA4H_FoxIOHTTP1Vector runs JA4H against testdata/foxio/pcap/http1.pcapng
// and asserts the first request's Part A matches the FoxIO expected vector.
// Skipped when the fixture is not present.
func TestJA4H_FoxIOHTTP1Vector(t *testing.T) {
	pcapPath := "testdata/foxio/pcap/http1.pcapng"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skipf("fixture %s not present; skipping FoxIO vector test", pcapPath)
	}

	packets := loadPCAP(t, pcapPath)

	fp := NewJA4H()
	got := ""
	for _, pkt := range packets {
		results, _ := fp.ProcessPacket(pkt)
		if len(results) > 0 {
			got = results[0].Fingerprint
			break
		}
	}
	if got == "" {
		t.Fatal("no JA4H result extracted from http1.pcapng")
	}
	const want = "po11nn050000_530ceba2075f_000000000000_000000000000"
	if got != want {
		t.Errorf("http1.pcapng JA4H: got %q, want %q", got, want)
	}
}

// TestJA4H_NormalizeVersion verifies the FoxIO PR #288 HTTP version mapping:
// HTTP/1.0 -> "10", HTTP/1.1 -> "11", HTTP/2 -> "20", HTTP/3 -> "30".
func TestJA4H_NormalizeVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"HTTP/1.0", "10"},
		{"HTTP/1.1", "11"},
		{"HTTP/2", "20"},
		{"HTTP/3", "30"},
		{"HTTP/2.0", "20"},
		{"HTTP/3.0", "30"},
		{"", "00"},
		{"HTTP/", "00"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := ja4hNormalizeVersion(tt.in)
			if got != tt.want {
				t.Errorf("ja4hNormalizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
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

	// Issue #25 removed the results slice, so the reassembler is the only state that Reset
	// clears. A request that arrives in one packet leaves the reassembler empty, so this
	// test reads the result of the second call instead.
	fp := NewJA4H()

	before, _ := fp.ProcessPacket(pkt)
	if len(before) != 1 {
		t.Fatalf("the HTTP request produced %d results, want 1", len(before))
	}

	fp.Reset()

	after, _ := fp.ProcessPacket(pkt)
	if len(after) != 1 || after[0].Fingerprint != before[0].Fingerprint {
		t.Errorf("the read after Reset produces %v, and the read before it produces %v", after, before)
	}
}

func TestJA4H_HTTP10(t *testing.T) {
	raw := "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)
	parts := strings.Split(fp, "_")
	if !strings.HasPrefix(parts[0], "ge10") {
		t.Errorf("expected version 10, got part A: %q", parts[0])
	}
}

func TestJA4H_StreamReassembly(t *testing.T) {
	// Test that multi-segment HTTP requests are reassembled correctly.
	fp := NewJA4H()

	// Split an HTTP request across two TCP segments.
	// Split mid-request-line so the first segment alone is not parseable.
	fullRequest := "GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"
	part1 := fullRequest[:10] // "GET /path " — incomplete request line
	part2 := fullRequest[10:] // "HTTP/1.1\r\nHost: ..."

	srcIP := net.IP{192, 168, 1, 1}
	dstIP := net.IP{10, 0, 0, 1}

	// Build first segment with seq=1000
	pkt1 := buildTCPPacketWithSeq(t, srcIP, dstIP, 54321, 80, 1000, []byte(part1))
	_, err := fp.ProcessPacket(pkt1)
	if err != nil {
		t.Fatalf("seg1: unexpected error: %v", err)
	}
	// First segment alone is not a valid HTTP request (no headers complete)

	// Build second segment with seq = 1000 + len(part1)
	pkt2 := buildTCPPacketWithSeq(t, srcIP, dstIP, 54321, 80, uint32(1000+len(part1)), []byte(part2))
	results, err := fp.ProcessPacket(pkt2)
	if err != nil {
		t.Fatalf("seg2: unexpected error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected fingerprint after reassembly of 2 segments")
	}
	if results[0].Type != "ja4h" {
		t.Errorf("expected type ja4h, got %s", results[0].Type)
	}
}

// buildTCPPacketWithSeq creates a TCP packet with a specific sequence number.
func buildTCPPacketWithSeq(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		ACK:     true,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestJA4H_PseudoHeadersExcluded(t *testing.T) {
	raw := "GET / HTTP/1.1\r\n:authority: example.com\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	pkt := buildTCPPacketWithPayload(t, []byte(raw))
	fp := ComputeJA4H(pkt)

	parts := strings.Split(fp, "_")
	if parts[0][6:8] != "02" {
		t.Errorf("header count should be 02, got %q from part A %q", parts[0][6:8], parts[0])
	}

	expectedB := truncHash("Host,Accept")
	if parts[1] != expectedB {
		t.Errorf("Part B: got %q, want %q", parts[1], expectedB)
	}
}

// The header block of a request that declares a body of 8 bytes. The gate of #455 reads the
// `Content-Length` value, so the test states one.
const ja4hDeclaredBodyRequest = "POST /upload HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Content-Type: text/plain\r\n" +
	"Content-Length: 8\r\n" +
	"\r\n"

// The body that completes the request above. It holds the 8 bytes the header declares.
const ja4hDeclaredBody = "12345678"

// TestJA4H_ProducesNoValueForARequestWhoseBodyNeverCompletes holds the ruling of #455.
//
// The maintainer ruled on 2026-08-13 that the library holds the value until the payload after
// the header block reaches the byte count that `Content-Length` names. No capture of the
// corpus separates the candidate answers, so this test builds the separating packet.
// `.claude/rules/rulings.md` `## Where a ruling is recorded` states that rule, and the port's
// issue Crank-Git/ja4plus#607 carries the other half.
//
// The test fails when a reader removes the gate, because the library then produces a value
// for a request that no sender completed.
func TestJA4H_ProducesNoValueForARequestWhoseBodyNeverCompletes(t *testing.T) {
	fingerprinter := NewJA4H()

	packet := ja4hSegmentAt(t, 1000, 0, ja4hDeclaredBodyRequest)
	results, err := fingerprinter.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("the header block returned an error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("the request produced %d values before its body, and the ruling states 0: %q",
			len(results), results[0].Fingerprint)
	}

	// One rule governs every path that produces a JA4H value, so the one-shot function
	// declines the same request.
	if value := ComputeJA4H(packet); value != "" {
		t.Fatalf("ComputeJA4H produced %q for a request before its body, and the ruling states \"\"",
			value)
	}
}

// TestJA4H_ProducesTheValueAtThePacketThatCompletesTheBody holds the emission frame of #455.
//
// The library produced the value at the packet that ends the header block, and the reference
// produces it later. `docs/audit/ja4h-deviation-cluster.md`
// `## Cause 2 — the library emits at the frame that ends the header block` measures the
// difference on `http1.pcapng`.
//
// The test fails when the emission frame moves back, because the first segment then carries
// the value.
func TestJA4H_ProducesTheValueAtThePacketThatCompletesTheBody(t *testing.T) {
	fingerprinter := NewJA4H()

	head := ja4hDeclaredBodyRequest + ja4hDeclaredBody[:4]
	tail := ja4hDeclaredBody[4:]

	first, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, head))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("the first segment produced %d values, and the emission frame states 0: %q",
			len(first), first[0].Fingerprint)
	}

	second, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, uint32(1000+len(head)), 1, tail))
	if err != nil {
		t.Fatalf("the second segment returned an error: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("the segment that completes the body produced %d values, and the emission frame states 1",
			len(second))
	}
}

// TestJA4H_ProducesTheValueForARequestThatDeclaresNoBody holds the limit of the gate of #455.
//
// A request that names no `Content-Length` names no byte count, so the header block completes
// it. The test fails when the gate holds such a request, because the library then produces no
// value for a request that every FoxIO implementation answers.
func TestJA4H_ProducesTheValueForARequestThatDeclaresNoBody(t *testing.T) {
	fingerprinter := NewJA4H()

	results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the request returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the request produced %d values, and the reference holds 1", len(results))
	}
}

// TestJA4H_ProducesTheValueForARequestWhoseContentLengthIsNoByteCount holds the second limit
// of the gate of #455.
//
// A `Content-Length` value that is not a byte count names no count, so the header block
// completes the request. That reading keeps a malformed header from holding a value for the
// life of the stream.
func TestJA4H_ProducesTheValueForARequestWhoseContentLengthIsNoByteCount(t *testing.T) {
	fingerprinter := NewJA4H()

	request := "POST /upload HTTP/1.1\r\n" +
		"Host: 192.168.235.136:8089\r\n" +
		"Content-Length: eight\r\n" +
		"\r\n"

	results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, request))
	if err != nil {
		t.Fatalf("the request returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the request produced %d values, and the reading states 1", len(results))
	}
}

// ja4hDeterminismRuns is the number of times the determinism test computes one value.
//
// Go randomizes the iteration order of a map on every range, so one range over a map of
// this many keys reaches a new order on nearly every run. 200 runs make a surviving
// order-dependence improbable. #303 records the measurement that this count holds.
const ja4hDeterminismRuns = 200

// ja4hDeterminismRequest is one HTTP request that carries 12 headers and 12 cookies.
//
// A map of one or two keys hides an order-dependence, because few orders exist. This
// request gives the map enough keys that a range reaches a different order on each run.
// The request ends with `\r\n\r\n`, because `ParseHTTPRequest` returns nil for a header
// block that has not ended.
const ja4hDeterminismRequest = "GET /search?q=one HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"User-Agent: Mozilla/5.0\r\n" +
	"Accept: text/html\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Accept-Encoding: gzip, deflate\r\n" +
	"Referer: https://example.com/\r\n" +
	"Connection: keep-alive\r\n" +
	"Upgrade-Insecure-Requests: 1\r\n" +
	"Sec-Fetch-Dest: document\r\n" +
	"Sec-Fetch-Mode: navigate\r\n" +
	"Cache-Control: max-age=0\r\n" +
	"Cookie: zeta=26; alpha=1; mike=13; bravo=2; november=14; charlie=3; " +
	"oscar=15; delta=4; papa=16; echo=5; quebec=17; foxtrot=6\r\n" +
	"\r\n"

// TestJA4H_ComputesOneValueForOneRequestOnEveryRun holds the determinism of the three
// JA4H values.
//
// `ja4hSortedCookieStrings` ranges the `Cookies` map at `ja4h.go:315`, and the JA4H value
// is an ordered string. A range that reached the output without a sort would make the
// library answer differently for one input on two runs, and a fingerprint that is not
// stable compares against nothing. #303 records the reproduction attempt that found no
// such range on this tree, and this test holds the property that the attempt measured.
func TestJA4H_ComputesOneValueForOneRequestOnEveryRun(t *testing.T) {
	payload := []byte(ja4hDeterminismRequest)

	first := parser.ParseHTTPRequest(payload)
	if first == nil {
		t.Fatal("ParseHTTPRequest returned nil for the determinism request")
	}
	if len(first.Cookies) != 12 {
		t.Fatalf("the request parsed %d cookies, and the test needs 12", len(first.Cookies))
	}

	wantBase := computeJA4HFromRequest(first)
	wantRaw := computeJA4HRaw(first)
	wantRawOriginal := computeJA4HRawOriginalOrder(first)

	// A fresh parse on each run covers the parser as well as the fingerprinter, because
	// `ParseHTTPRequest` fills the two maps that the value reads.
	for run := 2; run <= ja4hDeterminismRuns; run++ {
		req := parser.ParseHTTPRequest(payload)
		if req == nil {
			t.Fatalf("run %d: ParseHTTPRequest returned nil", run)
		}
		if got := computeJA4HFromRequest(req); got != wantBase {
			t.Fatalf("run %d: the JA4H value moved\n run 1: %s\n run %d: %s", run, wantBase, run, got)
		}
		if got := computeJA4HRaw(req); got != wantRaw {
			t.Fatalf("run %d: the JA4H_r value moved\n run 1: %s\n run %d: %s", run, wantRaw, run, got)
		}
		if got := computeJA4HRawOriginalOrder(req); got != wantRawOriginal {
			t.Fatalf("run %d: the JA4H_ro value moved\n run 1: %s\n run %d: %s", run, wantRawOriginal, run, got)
		}
	}
}

// TestJA4H_SortsTheCookiePairListByTheCookieName holds the sort that makes the value
// stable.
//
// The determinism test above passes for a second reason: a sorted list and an unsorted
// list of one element are the same list. This test reads the pair order directly, so it
// fails when the sort goes away even though the cookie count stays at 12.
func TestJA4H_SortsTheCookiePairListByTheCookieName(t *testing.T) {
	req := parser.ParseHTTPRequest([]byte(ja4hDeterminismRequest))
	if req == nil {
		t.Fatal("ParseHTTPRequest returned nil for the determinism request")
	}

	names, pairs := ja4hSortedCookieStrings(req)

	wantNames := "alpha,bravo,charlie,delta,echo,foxtrot,mike,november,oscar,papa,quebec,zeta"
	if names != wantNames {
		t.Errorf("the cookie name list is not sorted\n want: %s\n got:  %s", wantNames, names)
	}

	wantPairs := "alpha=1,bravo=2,charlie=3,delta=4,echo=5,foxtrot=6,mike=13," +
		"november=14,oscar=15,papa=16,quebec=17,zeta=26"
	if pairs != wantPairs {
		t.Errorf("the cookie pair list is not sorted by the name\n want: %s\n got:  %s", wantPairs, pairs)
	}

	// The wire order differs from the sorted order, so a test that reads the sorted order
	// cannot pass by accident.
	if strings.Join(req.CookieNames, ",") == wantNames {
		t.Error("the request carries the cookies in sorted wire order, so the test proves nothing")
	}
}

// ja4hEmptyHeaderListHash is the first 12 characters of the SHA-256 hash of the empty
// string. The maintainer ruled on 2026-08-14 that JA4H part b writes this value for an
// empty header list, and R18 of `docs/specs/foxio/JA4H.md` is the deciding rule. The port
// half of the ruling lives in `Crank-Git/ja4plus#612`, and issue #527 is the reversal path.
const ja4hEmptyHeaderListHash = "e3b0c44298fc"

// ja4hZeroSentinel is the value that R27 of `docs/specs/foxio/JA4H.md` confines to part c
// and to part d.
const ja4hZeroSentinel = "000000000000"

// ja4hEmptyHeaderListRequest holds frame 4 of `testdata/foxio/pcap/gre-erspan-vxlan.pcap`.
// The request carries no header, and its path holds one unencoded space.
const ja4hEmptyHeaderListRequest = "GET /Hello Arkime HTTP/1.0\r\n\r\n"

// ja4hEmptyHeaderListVector is the FoxIO value for that frame.
// `testdata/foxio/wireshark/gre-erspan-vxlan.pcap.json` holds it.
const ja4hEmptyHeaderListVector = "ge10nn000000_e3b0c44298fc_000000000000_000000000000"

// TestJA4HPartBHashesAnEmptyHeaderList holds the ruling of 2026-08-14.
//
// R18 of `docs/specs/foxio/JA4H.md` states
// `Truncated SHA256 hash of Headers, in the order they appear`, and it names no sentinel.
// The Rust reference and the Zeek package write the sentinel, and the image outranks both.
func TestJA4HPartBHashesAnEmptyHeaderList(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte("GET / HTTP/1.0\r\n\r\n"))

	fingerprint := ComputeJA4H(pkt)
	if fingerprint == "" {
		t.Fatal("ComputeJA4H produced no value for a request with no header")
	}

	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		t.Fatalf("ComputeJA4H = %q, and the value holds %d parts rather than 4", fingerprint, len(parts))
	}
	if parts[1] != ja4hEmptyHeaderListHash {
		t.Errorf("part b = %q, want %q", parts[1], ja4hEmptyHeaderListHash)
	}
}

// TestJA4HKeepsTheZeroSentinelInPartCAndPartD holds R27 of `docs/specs/foxio/JA4H.md`.
//
// The ruling of 2026-08-14 moves part b alone. A change that moved part c or part d as
// well would disagree with every FoxIO implementation.
func TestJA4HKeepsTheZeroSentinelInPartCAndPartD(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))

	fingerprint := ComputeJA4H(pkt)
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		t.Fatalf("ComputeJA4H = %q, and the value holds %d parts rather than 4", fingerprint, len(parts))
	}
	if parts[2] != ja4hZeroSentinel {
		t.Errorf("part c = %q, want %q", parts[2], ja4hZeroSentinel)
	}
	if parts[3] != ja4hZeroSentinel {
		t.Errorf("part d = %q, want %q", parts[3], ja4hZeroSentinel)
	}
}

// TestJA4HReadsARequestPathThatHoldsASpace holds rule 5a of issue #527.
//
// `requestLineRe` in `internal/parser/http.go` read a path of non-space characters, so a
// path with one unencoded space reached no value. FoxIO holds a value for the same frame.
func TestJA4HReadsARequestPathThatHoldsASpace(t *testing.T) {
	request := parser.ParseHTTPRequest([]byte(ja4hEmptyHeaderListRequest))
	if request == nil {
		t.Fatal("ParseHTTPRequest read no request from a path that holds a space")
	}
	if want := "/Hello Arkime"; request.Path != want {
		t.Errorf("Path = %q, want %q", request.Path, want)
	}
	if want := "HTTP/1.0"; request.Version != want {
		t.Errorf("Version = %q, want %q", request.Version, want)
	}
}

// TestTheRequestLineReadsNoSecondLine holds the separator rule of `requestLineRe`.
//
// A separator of `\s` reads a line ending, so the match crossed into the second line and
// read a request line that no line of the payload holds. `ja4l.go` reads `IsHTTPRequest` to
// pick a measurement point, so such a match moves a JA4L value. #527 closed the defect on
// 2026-08-14, and the first payload below matched before that day.
func TestTheRequestLineReadsNoSecondLine(t *testing.T) {
	// A payload that starts with none of the nine method prefixes reaches the expression, so
	// both functions answer from it.
	unmatched := []string{
		"SSH-2.0-OpenSSH_9.6\r\n/a HTTP/1.1\r\n\r\n",
		"SSH-2.0-OpenSSH_9.6\r\nsome junk HTTP/1.1\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
	}

	for _, payload := range unmatched {
		if parser.IsHTTPRequest([]byte(payload)) {
			t.Errorf("IsHTTPRequest reads %q as a request", payload)
		}
		if request := parser.ParseHTTPRequest([]byte(payload)); request != nil {
			t.Errorf("ParseHTTPRequest reads %q as the request %+v", payload, request)
		}
	}

	// The path group reads no carriage return and no line feed. A group of any character
	// reads a bare carriage return, and the path then holds the smuggled text.
	//
	// `IsHTTPRequest` answers `true` for each payload below from its nine-prefix fast path,
	// which reads `GET ` and never the expression. #57 built that path, and #527 does not
	// move it. So this test reads `ParseHTTPRequest` alone here, and no fingerprint value
	// follows a payload that reaches no request.
	smuggled := []string{
		"GET /a\rFAKE HTTP/1.1\r\nReal: 1\r\n\r\n",
		"GET /a\r\nFAKE HTTP/1.1\r\n\r\n",
	}

	for _, payload := range smuggled {
		if request := parser.ParseHTTPRequest([]byte(payload)); request != nil {
			t.Errorf("ParseHTTPRequest reads %q as the request %+v", payload, request)
		}
	}
}

// TestTheRequestLineReadsASpaceAndATabAsASeparator holds the separator set of
// `requestLineRe`. RFC 9112 section 3 names one space, and a lenient parser reads a tab.
func TestTheRequestLineReadsASpaceAndATabAsASeparator(t *testing.T) {
	payloads := []string{
		"GET /a HTTP/1.1\r\n\r\n",
		"GET\t/a\tHTTP/1.1\r\n\r\n",
		"GET  /a  HTTP/1.1\r\n\r\n",
		"GET /a HTTP/1.1\n\n",
	}

	for _, payload := range payloads {
		request := parser.ParseHTTPRequest([]byte(payload))
		if request == nil {
			t.Fatalf("ParseHTTPRequest read no request from %q", payload)
		}
		if request.Path != "/a" {
			t.Errorf("Path of %q is %q, want %q", payload, request.Path, "/a")
		}
	}
}

// TestJA4HProducesTheFoxioValueOfTheSpacedPathFrame proves that the two rules of #527
// close one comparison of the corpus together.
func TestJA4HProducesTheFoxioValueOfTheSpacedPathFrame(t *testing.T) {
	pkt := buildTCPPacketWithPayload(t, []byte(ja4hEmptyHeaderListRequest))

	if got := ComputeJA4H(pkt); got != ja4hEmptyHeaderListVector {
		t.Errorf("ComputeJA4H = %q, want %q", got, ja4hEmptyHeaderListVector)
	}
}

// ja4hHashCallSite names one call of a truncated-hash function in the root package.
type ja4hHashCallSite struct {
	file     string
	function string
	callee   string
}

// ja4hHashCallSites names every call of a truncated-hash function in the root package.
//
// The ruling of 2026-08-14 reaches JA4H part b and each of the three JA4X parts, so four
// sites call `parser.TruncatedHashNoSentinel`. Each of the other seven keeps the zero
// sentinel for an empty list, and this table is the record of which seven. A new call site
// fails this test, so a later author must state which rule the new site follows.
//
// #527 built the JA4H half, and #582 built the JA4X half.
var ja4hHashCallSites = []ja4hHashCallSite{
	{"ja4.go", "ja4CipherHash", "TruncatedHash"},
	{"ja4.go", "ja4ExtensionHash", "TruncatedHash"},
	{"ja4.go", "computeJA4OriginalOrder", "TruncatedHash"},
	{"ja4.go", "computeJA4OriginalOrder", "TruncatedHash"},
	{"ja4h.go", "computeJA4HFromRequest", "TruncatedHashNoSentinel"},
	{"ja4h.go", "computeJA4HFromRequest", "TruncatedHash"},
	{"ja4h.go", "computeJA4HFromRequest", "TruncatedHash"},
	{"ja4s.go", "computeJA4SPair", "TruncatedHash"},
	{"ja4x.go", "computeJA4XWithRaw", "TruncatedHashNoSentinel"},
	{"ja4x.go", "computeJA4XWithRaw", "TruncatedHashNoSentinel"},
	{"ja4x.go", "computeJA4XWithRaw", "TruncatedHashNoSentinel"},
}

// TestEveryTruncatedHashCallSiteOfTheRootPackageIsNamed reads the source and compares it
// against `ja4hHashCallSites`.
//
// The test reads the syntax tree rather than a line number, because a later edit above a
// call moves the line and never the enclosing function.
func TestEveryTruncatedHashCallSiteOfTheRootPackageIsNamed(t *testing.T) {
	fileSet := token.NewFileSet()

	var found []ja4hHashCallSite

	for _, path := range productionGoFilesOf(t, ".") {
		file, err := goparser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(function, func(node ast.Node) bool {
				callee := parserHashCallee(node)
				if callee == "" {
					return true
				}
				found = append(found, ja4hHashCallSite{path, function.Name.Name, callee})
				return true
			})
		}
	}

	sortHashCallSites(found)
	want := append([]ja4hHashCallSite(nil), ja4hHashCallSites...)
	sortHashCallSites(want)

	if len(found) != len(want) {
		t.Fatalf("the root package holds %d truncated-hash call sites, and the table names %d:\n%v",
			len(found), len(want), found)
	}
	for i := range found {
		if found[i] != want[i] {
			t.Errorf("call site %d is %v, and the table names %v", i, found[i], want[i])
		}
	}
}

// parserHashCallee returns the name of the `parser` hash function that the node calls.
// It returns an empty string when the node calls no such function.
func parserHashCallee(node ast.Node) string {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return ""
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok || packageName.Name != "parser" {
		return ""
	}
	switch selector.Sel.Name {
	case "TruncatedHash", "TruncatedHashNoSentinel":
		return selector.Sel.Name
	}
	return ""
}

func sortHashCallSites(sites []ja4hHashCallSite) {
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		if sites[i].function != sites[j].function {
			return sites[i].function < sites[j].function
		}
		return sites[i].callee < sites[j].callee
	})
}

// ja4hHTTP2KeyLog returns the KeyLog that names the handshake secret and the application
// secret of one connection.
//
// A TLS 1.3 client writes the Finished message under the handshake traffic key and the
// HTTP/2 request under the application traffic key, so the reader needs both.
func ja4hHTTP2KeyLog(t *testing.T, random, handshake, application []byte) *KeyLog {
	t.Helper()

	lines := parser.TLS13ClientHandshakeSecretLabel + " " + hex.EncodeToString(random) + " " +
		hex.EncodeToString(handshake) + "\n" +
		parser.TLS13ClientApplicationSecretLabel + " " + hex.EncodeToString(random) + " " +
		hex.EncodeToString(application) + "\n"

	keyLog, err := ParseKeyLog(strings.NewReader(lines))
	if err != nil {
		t.Fatalf("ParseKeyLog returned %v", err)
	}

	return keyLog
}

// ja4hHTTP2Block returns the HPACK field block of the name and value pairs.
func ja4hHTTP2Block(t *testing.T, encoder *hpack.Encoder, buffer *bytes.Buffer, fields ...string) []byte {
	t.Helper()

	buffer.Reset()

	for i := 0; i < len(fields); i += 2 {
		if err := encoder.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}); err != nil {
			t.Fatalf("WriteField returned %v", err)
		}
	}

	return append([]byte{}, buffer.Bytes()...)
}

// ja4hHTTP2HeadersFrame returns one HEADERS frame that carries the whole field block.
// RFC 9113 section 4.1 states the 9-octet header, and section 6.2 states END_HEADERS as
// `0x04`.
func ja4hHTTP2HeadersFrame(streamID byte, block []byte) []byte {
	length := len(block)

	frame := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		0x01,
		0x04,
		0x00, 0x00, 0x00, streamID,
	}

	return append(frame, block...)
}

// ja4hHTTP2Fingerprints returns the JA4H fingerprint of each result.
func ja4hHTTP2Fingerprints(results []FingerprintResult) []string {
	var values []string

	for _, result := range results {
		if result.Type == "ja4h" {
			values = append(values, result.Fingerprint)
		}
	}

	return values
}

// ja4hHTTP2Connection returns the packets of one synthetic HTTP/2 request stream, and the
// client random of that connection.
//
// The stream carries the ClientHello in the clear, then one protected handshake record, then
// one protected application record for each element of content. The application records
// number from 0, because RFC 8446 section 5.3 restarts the sequence number at the key
// change.
func ja4hHTTP2Connection(t *testing.T, random, handshake, application []byte, content [][]byte) []gopacket.Packet {
	t.Helper()

	return ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application, content)
}

// ja4hHTTP2ConnectionFrom returns the packets of one synthetic HTTP/2 request stream, from
// the initial sequence number that the caller states.
//
// A second connection of one address pair and port pair starts at an initial sequence number
// of its own. So a test that reuses the four-tuple states that number. #753 records the limit
// that the reuse reaches.
func ja4hHTTP2ConnectionFrom(
	t *testing.T,
	baseSeq uint32,
	random, handshake, application []byte,
	content [][]byte,
) []gopacket.Packet {
	t.Helper()

	handshakeKeys := tls13TestKeys(t, handshake)
	applicationKeys := tls13TestKeys(t, application)

	payloads := [][]byte{
		tls13TestClientHelloRecord(random),
		tls13TestProtectRecord(t, handshakeKeys, []byte{0x14, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00},
			parser.TLSRecordTypeHandshake, 0),
	}

	for index, part := range content {
		payloads = append(payloads, tls13TestProtectRecord(t, applicationKeys, part,
			parser.TLSRecordTypeApplicationData, uint64(index)))
	}

	var packets []gopacket.Packet

	seq := baseSeq

	for _, payload := range payloads {
		packets = append(packets, tls13TestPacket(t, tls13TestClientIP, tls13TestServerIP,
			tls13TestClientPort, tls13TestServerPort, seq, payload))
		seq += uint32(len(payload))
	}

	return packets
}

// TestTheProcessorReadsAnHTTP2RequestOfAProtectedTLS13Record holds the acceptance criterion
// of #529: the library decrypts a protected TLS application record on TCP where the key log
// holds the secret, and it decodes the HPACK header block inside it.
//
// The test states the two raw values in full, because a raw value states the header order
// and the cookie handling that the FoxIO reference decides. A test that stated the hashed
// value alone would pass on a wrong order.
func TestTheProcessorReadsAnHTTP2RequestOfAProtectedTLS13Record(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	first := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/",
		"user-agent", "probe", "accept", "*/*", "accept-language", "en-US", "cookie", "a=1")

	second := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/two",
		"user-agent", "probe", "referer", "https://example.test/")

	preface := append([]byte(parser.HTTP2ClientPreface),
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		preface,
		ja4hHTTP2HeadersFrame(1, first),
		ja4hHTTP2HeadersFrame(3, second),
	})

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	var raw []string

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		for _, result := range results {
			if result.Type != "ja4h" {
				continue
			}

			raw = append(raw, result.RawOriginalOrder)

			if !strings.HasPrefix(result.Fingerprint, strings.SplitN(result.RawOriginalOrder, "_", 2)[0]+"_") {
				t.Errorf("the value %q and the raw value %q state different part a values",
					result.Fingerprint, result.RawOriginalOrder)
			}
		}
	}

	wanted := []string{
		"ge20cn03enus_user-agent,accept,accept-language_a_a=1",
		"ge20nr010000_user-agent_",
	}

	if len(raw) != len(wanted) {
		t.Fatalf("the run produced %d JA4H values %v, and the stream carries %d requests",
			len(raw), raw, len(wanted))
	}

	for index, value := range wanted {
		if raw[index] != value {
			t.Errorf("request %d produced the raw value %q, and the block states %q",
				index+1, raw[index], value)
		}
	}
}

// TestTheProcessorProducesNoHTTP2ValueWithoutAKeyLog states that the decode needs the
// secret. The FoxIO reference reads the plaintext that `tshark` supplies, and this library
// decrypts the record itself.
func TestTheProcessorProducesNoHTTP2ValueWithoutAKeyLog(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/")

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	processor := NewProcessor()

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		if values := ja4hHTTP2Fingerprints(results); len(values) != 0 {
			t.Errorf("packet %d produced %v, and the processor holds no key log", index+1, values)
		}
	}
}

// TestTheProcessorProducesNoHTTP2ValueForASecretThatOpensNoRecord states that a key log of
// another connection produces no value and no panic. A fingerprinter returns a non-fatal
// error, and never a panic.
func TestTheProcessorProducesNoHTTP2ValueForASecretThatOpensNoRecord(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/")

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	wrong := bytes.Repeat([]byte{0x99}, 32)
	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, wrong, wrong)))

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		if values := ja4hHTTP2Fingerprints(results); len(values) != 0 {
			t.Errorf("packet %d produced %v, and the key log names another secret", index+1, values)
		}
	}
}

// TestTheProcessorProducesNoHTTP2ValueForASecretOfTheWrongLength states the decline that
// `DeriveTLS13RecordKeys` holds. The library reads the SHA-256 key schedule of
// TLS_AES_128_GCM_SHA256 alone, and a SHA-384 suite states a 48-byte secret. Issue #492 is
// the reversal path.
func TestTheProcessorProducesNoHTTP2ValueForASecretOfTheWrongLength(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/")

	packets := ja4hHTTP2Connection(t, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	long := bytes.Repeat([]byte{0x88}, 48)
	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, long, long)))

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		if values := ja4hHTTP2Fingerprints(results); len(values) != 0 {
			t.Errorf("packet %d produced %v, and the secret holds 48 bytes", index+1, values)
		}
	}
}

// TestTheHTTP2ReaderRepublishesNoRequestOfAnEarlierPacket states the emission rule. The
// reader reads each byte of the stream once and it holds one HPACK decoder for the
// connection, because the dynamic table of RFC 7541 section 2.3.2 serves the whole
// connection. So the packet that carries a header block is the packet that publishes it.
//
// **#753 replaced the counter that this test once held.** The reader decoded the whole
// stream at each packet until then, and a counter separated a new request from one the
// stream already published.
func TestTheHTTP2ReaderRepublishesNoRequestOfAnEarlierPacket(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	blocks := make([][]byte, 0, 3)
	for _, path := range []string{"/one", "/two", "/three"} {
		blocks = append(blocks, ja4hHTTP2Block(t, encoder, buffer,
			":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", path))
	}

	content := [][]byte{[]byte(parser.HTTP2ClientPreface)}
	for index, block := range blocks {
		content = append(content, ja4hHTTP2HeadersFrame(byte(1+2*index), block))
	}

	packets := ja4hHTTP2Connection(t, random, handshake, application, content)

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	perPacket := make([]int, 0, len(packets))

	for index, packet := range packets {
		results, err := processor.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned %v for packet %d", err, index+1)
		}

		perPacket = append(perPacket, len(ja4hHTTP2Fingerprints(results)))
	}

	// Packet 1 carries the ClientHello, packet 2 the Finished message and packet 3 the
	// preface. Each of the last three carries one HEADERS frame.
	wanted := []int{0, 0, 0, 1, 1, 1}

	if len(perPacket) != len(wanted) {
		t.Fatalf("the run read %d packets, and the connection holds %d", len(perPacket), len(wanted))
	}

	for index, count := range wanted {
		if perPacket[index] != count {
			t.Errorf("packet %d produced %d values, and the stream newly carries %d",
				index+1, perPacket[index], count)
		}
	}
}

// ja4hHTTP2DataFrame returns one DATA frame of the length that the caller states.
//
// RFC 9113 section 6.1 states the DATA type as `0x0`. A client sends a request body in this
// frame, so a long connection carries far more DATA than HEADERS.
func ja4hHTTP2DataFrame(streamID byte, length int) []byte {
	frame := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		0x00,
		0x00,
		0x00, 0x00, 0x00, streamID,
	}

	return append(frame, bytes.Repeat([]byte{0x5a}, length)...)
}

// ja4hHTTP2Run returns the JA4H fingerprint of each packet of one run, in order.
func ja4hHTTP2Run(t *testing.T, processor *Processor, packets []gopacket.Packet) []string {
	t.Helper()

	var values []string

	for index, packet := range packets {
		results, errs := processor.ProcessPacket(packet)
		if len(errs) > 0 {
			t.Fatalf("ProcessPacket returned %v for packet %d", errs, index+1)
		}

		values = append(values, ja4hHTTP2Fingerprints(results)...)
	}

	return values
}

// TestTheProcessorReadsAnHTTP2RequestOfAStreamAbove64Kilobytes holds the byte bound of
// limit 1 of #753.
//
// The reader decoded the whole stream at each packet, so a bound of 65536 bytes held that
// cost. The bound stopped the connection rather than delaying it, and every later request of
// a long connection reached no value.
func TestTheProcessorReadsAnHTTP2RequestOfAStreamAbove64Kilobytes(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/late",
		"user-agent", "probe")

	content := [][]byte{[]byte(parser.HTTP2ClientPreface)}

	// Five records of about 16 kB each carry the stream past 65536 bytes. RFC 8446 section
	// 5.2 bounds one record at 16384 octets of plaintext.
	for range 5 {
		content = append(content, ja4hHTTP2DataFrame(1, 16000))
	}

	content = append(content, ja4hHTTP2HeadersFrame(3, block))

	packets := ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application, content)

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	values := ja4hHTTP2Run(t, processor, packets)

	if len(values) != 1 {
		t.Fatalf("the run produced %d values %v, and the connection carries 1 request past 65536 bytes",
			len(values), values)
	}
}

// TestTheProcessorReadsMoreRequestsThanTheCallBoundOfOneConnection holds the request bound
// of limit 1 of #753.
//
// `http2MaxRequests` bounds the requests one decode returns. The caller counted the requests
// the stream already published, so a decode that stopped at the bound stopped that counter
// too. The connection then reached no later value.
func TestTheProcessorReadsMoreRequestsThanTheCallBoundOfOneConnection(t *testing.T) {
	const total = 300

	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	frames := []byte(parser.HTTP2ClientPreface)

	for index := range total {
		block := ja4hHTTP2Block(t, encoder, buffer,
			":method", "GET", ":authority", "example.test", ":scheme", "https",
			":path", fmt.Sprintf("/r%d", index))
		frames = append(frames, ja4hHTTP2HeadersFrame(1, block)...)
	}

	// The second record carries one PING frame, which RFC 9113 section 6.7 states as type
	// `0x6`. It reaches the reader with the requests that the first record left unread.
	ping := []byte{0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}
	ping = append(ping, bytes.Repeat([]byte{0x00}, 8)...)

	packets := ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application,
		[][]byte{frames, ping})

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	values := ja4hHTTP2Run(t, processor, packets)

	if len(values) != total {
		t.Fatalf("the run produced %d values, and the connection carries %d requests",
			len(values), total)
	}
}

// TestTheProcessorReadsAnHTTP2RequestOfAReorderedConnection states that a segment which
// arrives out of order costs no value.
//
// The decode reads each byte of the stream once, so it holds the sequence number of the
// first byte it has not read. A segment above that number leaves a hole, and the decode waits
// for the segment that fills it. TCP reorders a segment of any connection, so a decode that
// stopped at a hole would stop most connections.
func TestTheProcessorReadsAnHTTP2RequestOfAReorderedConnection(t *testing.T) {
	random := bytes.Repeat([]byte{0x2c}, 32)
	handshake := bytes.Repeat([]byte{0x71}, 32)
	application := bytes.Repeat([]byte{0x35}, 32)

	buffer := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buffer)

	block := ja4hHTTP2Block(t, encoder, buffer,
		":method", "GET", ":authority", "example.test", ":scheme", "https", ":path", "/one",
		"user-agent", "probe")

	packets := ja4hHTTP2ConnectionFrom(t, 1, random, handshake, application, [][]byte{
		[]byte(parser.HTTP2ClientPreface),
		ja4hHTTP2HeadersFrame(1, block),
	})

	// Packet 1 carries the ClientHello and packet 2 the Finished message. The last two arrive
	// in the reverse order, so the HEADERS record reaches the fingerprinter before the preface.
	reordered := []gopacket.Packet{packets[0], packets[1], packets[3], packets[2]}

	processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

	values := ja4hHTTP2Run(t, processor, reordered)

	if len(values) != 1 {
		t.Fatalf("the run produced %d values %v, and the connection carries 1 request",
			len(values), values)
	}
}

// TestTheProcessorReadsASecondHTTP2ConnectionOfOneFourTuple holds limit 2 of #753.
//
// The HTTP/2 path wrote no consumed range, so `segmentCarriesNoNewRequest` removed no entry
// for it. A second connection of one address pair and port pair therefore read the buffer and
// the counter of the first. It produced no value of its own.
//
// A second connection starts at an initial sequence number of its own. That number sits below
// the number of the first connection about half the time. Each case reaches this test.
func TestTheProcessorReadsASecondHTTP2ConnectionOfOneFourTuple(t *testing.T) {
	cases := []struct {
		name   string
		first  uint32
		second uint32
	}{
		{name: "the second connection opens below the first", first: 500000, second: 1000},
		{name: "the second connection opens above the first", first: 1000, second: 4000000},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			random := bytes.Repeat([]byte{0x2c}, 32)
			handshake := bytes.Repeat([]byte{0x71}, 32)
			application := bytes.Repeat([]byte{0x35}, 32)

			buffer := &bytes.Buffer{}
			encoder := hpack.NewEncoder(buffer)

			block := ja4hHTTP2Block(t, encoder, buffer,
				":method", "GET", ":authority", "example.test", ":scheme", "https",
				":path", "/one", "user-agent", "probe")

			content := [][]byte{
				[]byte(parser.HTTP2ClientPreface),
				ja4hHTTP2HeadersFrame(1, block),
			}

			processor := NewProcessor(WithKeyLog(ja4hHTTP2KeyLog(t, random, handshake, application)))

			opening := ja4hHTTP2Run(t, processor,
				ja4hHTTP2ConnectionFrom(t, testCase.first, random, handshake, application, content))
			if len(opening) != 1 {
				t.Fatalf("the first connection produced %d values, and it carries 1 request",
					len(opening))
			}

			// The second connection encodes its own field block, because RFC 7541 section
			// 2.3.2 gives each connection a dynamic table of its own.
			second := &bytes.Buffer{}
			secondBlock := ja4hHTTP2Block(t, hpack.NewEncoder(second), second,
				":method", "GET", ":authority", "example.test", ":scheme", "https",
				":path", "/one", "user-agent", "probe")

			reuse := ja4hHTTP2Run(t, processor, ja4hHTTP2ConnectionFrom(t, testCase.second,
				random, handshake, application, [][]byte{
					[]byte(parser.HTTP2ClientPreface),
					ja4hHTTP2HeadersFrame(1, secondBlock),
				}))

			if len(reuse) != 1 {
				t.Fatalf("the second connection produced %d values, and it carries 1 request",
					len(reuse))
			}

			if reuse[0] != opening[0] {
				t.Errorf("the second connection produced %q, and the first produced %q for the same request",
					reuse[0], opening[0])
			}
		})
	}
}

// A sender ends a header line with the two bytes `\r\n`, or with one line feed.
// `testdata/foxio/pcap/http-empty-useragent.pcap` holds a request that ends each line with
// one line feed, and it splits that request over three TCP segments. FoxIO publishes a
// JA4H value for it, so the reference reads both line endings and it waits for the
// terminating empty line. #286 records the defect that this file holds.
//
// The Python port fixed the same defect in its issue #193.
// `ja4plus/utils/http_utils.py:40` holds the pattern `re.compile(r"\r\n|\n")`, and
// `ja4plus/fingerprinters/ja4h.py:149-151` returns no value until the header block ends.

// The values `testdata/foxio/python/http-empty-useragent.pcap.json` holds for stream 0.
const (
	emptyUserAgentJA4H   = "ge10nn010000_b8bcd45ac095_000000000000_000000000000"
	emptyUserAgentJA4HRO = "ge10nn010000_User-Agent_"
)

// The three TCP segments of the request that `http-empty-useragent.pcap` carries.
// Each line ends with one line feed, and the third segment carries the empty line alone.
const (
	lineFeedRequestLine  = "GET / HTTP/1.0\n"
	lineFeedHeaderLine   = "User-Agent:\n"
	lineFeedBlockEndLine = "\n"
)

// TestJA4H_ReadsAHeaderBlockThatEndsEachLineWithOneLineFeed proves that the parser reads a
// line feed as a line ending.
//
// The parser split the payload on `\r\n` alone, so it read the whole request as one line.
// It found no header, and part a counted `00`.
func TestJA4H_ReadsAHeaderBlockThatEndsEachLineWithOneLineFeed(t *testing.T) {
	raw := lineFeedRequestLine + lineFeedHeaderLine + lineFeedBlockEndLine

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	if results[0].Fingerprint != emptyUserAgentJA4H {
		t.Errorf("the JA4H value is %q, and the FoxIO vector holds %q",
			results[0].Fingerprint, emptyUserAgentJA4H)
	}
	if results[0].RawOriginalOrder != emptyUserAgentJA4HRO {
		t.Errorf("the JA4H_ro value is %q, and the FoxIO vector holds %q",
			results[0].RawOriginalOrder, emptyUserAgentJA4HRO)
	}
}

// TestJA4H_KeepsAHeaderThatCarriesAnEmptyValue proves that a header with no value reaches
// part a and part b.
//
// The reference counts `User-Agent:` as one header, so part a reads `01`.
func TestJA4H_KeepsAHeaderThatCarriesAnEmptyValue(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent:\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11nn020000_Host,User-Agent_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// TestJA4H_ReachesTheReferenceValueOfTheThreeSegmentLineFeedRequest proves that the
// fingerprinter waits for every segment of the header block.
//
// The fingerprinter answered on the first segment, which carries the request line alone.
// That answer counted no header, and it removed the stream before the header arrived.
func TestJA4H_ReachesTheReferenceValueOfTheThreeSegmentLineFeedRequest(t *testing.T) {
	fingerprinter := NewJA4H()
	source := net.IP{192, 168, 1, 1}
	destination := net.IP{10, 0, 0, 1}
	var sequence uint32 = 1000

	segments := []string{lineFeedRequestLine, lineFeedHeaderLine}
	for _, segment := range segments {
		packet := buildTCPPacketWithSeq(t, source, destination, 57722, 9200, sequence, []byte(segment))
		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("ProcessPacket returned an error on segment %q: %v", segment, err)
		}
		if len(results) != 0 {
			t.Fatalf("segment %q produced %d results, and the header block has not ended",
				segment, len(results))
		}
		sequence += uint32(len(segment))
	}

	last := buildTCPPacketWithSeq(t, source, destination, 57722, 9200, sequence, []byte(lineFeedBlockEndLine))
	results, err := fingerprinter.ProcessPacket(last)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the reassembled stream produced %d results, and the test expects 1", len(results))
	}

	if results[0].Fingerprint != emptyUserAgentJA4H {
		t.Errorf("the JA4H value is %q, and the FoxIO vector holds %q",
			results[0].Fingerprint, emptyUserAgentJA4H)
	}
	if results[0].RawOriginalOrder != emptyUserAgentJA4HRO {
		t.Errorf("the JA4H_ro value is %q, and the FoxIO vector holds %q",
			results[0].RawOriginalOrder, emptyUserAgentJA4HRO)
	}
}

// TestJA4H_ProducesNoValueBeforeTheHeaderBlockEnds proves that an unterminated header block
// reaches no value.
//
// A later segment carries a header that changes part a and part b, so an early value is a
// value of a request the sender never sent.
// `ja4plus/fingerprinters/ja4h.py:149-151` of the Python port states the same rule.
func TestJA4H_ProducesNoValueBeforeTheHeaderBlockEnds(t *testing.T) {
	requests := []struct {
		name string
		raw  string
	}{
		{
			name: "the request line arrives alone",
			raw:  "GET /p HTTP/1.1\r\n",
		},
		{
			name: "one header arrives and the empty line does not",
			raw:  "GET /p HTTP/1.1\r\nHost: example.com\r\n",
		},
	}

	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			packet := buildTCPPacketWithPayload(t, []byte(request.raw))
			results, err := NewJA4H().ProcessPacket(packet)
			if err != nil {
				t.Fatalf("ProcessPacket returned an error: %v", err)
			}
			if len(results) != 0 {
				t.Fatalf("ProcessPacket returned %d results, and the test expects 0", len(results))
			}
		})
	}
}

// TestJA4H_ReadsAHeaderBlockThatEndsWithACarriageReturnAndTwoLineFeeds holds the second half
// of the ruling of #298.
//
// **This path passed by coincidence before the ruling, and it passes by design now.** `\n\n`
// is a substring of `\r\n\n`, so the two literals found the terminator one byte late. The
// last header line then carried a trailing carriage return, and the value trim removed it. A
// later change to the value handling would have broken that path silently.
//
// The ruled pattern starts the match at the carriage return, so the header block holds no
// part of the line ending and no trim is load-bearing.
// `TestParseHTTPRequestReadsABlockThatEndsCarriageReturnLineFeedThenLineFeed` of
// `internal/parser` states the offset, and this test states the value.
//
// **Reversal path: #298 and `Crank-Git/ja4plus#614`, together.**
func TestJA4H_ReadsAHeaderBlockThatEndsWithACarriageReturnAndTwoLineFeeds(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11nn010000_Host_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// TestJA4H_ReadsAHeaderBlockThatEndsWithALineFeedAndACarriageReturn holds the ruling of
// #298.
//
// The maintainer ruled the header block terminator on 2026-08-13 UTC, in the port, and
// re-confirmed it on 2026-08-15 UTC. **The terminator is one line ending followed by
// another.** `Crank-Git/ja4plus#614` and `Crank-Git/ja4plus#604` hold the Python half.
//
// This request ends its last header line with one line feed, and it ends the empty line with
// `\r\n`. The terminator is then `\n\r\n`, which neither `\r\n\r\n` nor `\n\n` matches. This
// request reached no JA4H value before the ruling. **No capture of the FoxIO corpus holds a
// mixed terminator**, so this constructed packet is the only thing that separates the two
// candidate answers.
//
// **Reversal path: #298 and `Crank-Git/ja4plus#614`, together.**
func TestJA4H_ReadsAHeaderBlockThatEndsWithALineFeedAndACarriageReturn(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	// The value matches the value of the same request under an unmixed terminator, because
	// the line ending reaches no part of the JA4H value.
	const expectedRaw = "ge11nn010000_Host_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// TestJA4H_DropsAHeaderWithAnEmptyNameFromPartAAndFromPartB proves that one filter serves
// the header count and the header list.
//
// Part a counted a header name that part b dropped, so the count named one more header than
// the hash held. No capture of the corpus reaches the case, so this test builds the
// separating packet. #286 owns the rule, and
// `ja4plus/fingerprinters/ja4h.py:445-449` of the Python port holds the same filter.
func TestJA4H_DropsAHeaderWithAnEmptyNameFromPartAAndFromPartB(t *testing.T) {
	// The second line carries one space before the colon, so the header name trims to the
	// empty string.
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		" : orphan\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	expected := "ge11nn010000_" + truncHash("Host") +
		"_" + truncHash("") + "_" + truncHash("")
	if results[0].Fingerprint != expected {
		t.Errorf("the JA4H value is %q, and the test expects %q", results[0].Fingerprint, expected)
	}

	const expectedRaw = "ge11nn010000_Host_"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("the JA4H_ro value is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}
}

// The port's register row `The JA4H method code for a method outside the nine the Rust
// reference names` holds this reading, and the port decided it at its issue #219 on
// 2026-08-08. The three FoxIO references disagree, so the port follows
// `python/ja4h.py:9`, which reads `method.lower()[:2]` and names no method. The
// maintainer ruled on 2026-08-13 that a row the port's register already holds lands in
// this repository as a reading. FR-parity-47 and FR-parity-48 of
// `docs/specs/features/08-python-parity.md` state the rule.
//
// No vector carries a method outside the nine, so these constructed requests are the
// separating input that `.claude/rules/rulings.md` requires.

// ja4hMethodCode returns the first two characters of part a of the JA4H value.
// It fails the test when the packet produces no JA4H value.
func ja4hMethodCode(t *testing.T, request string) string {
	t.Helper()
	pkt := buildTCPPacketWithPayload(t, []byte(request))
	fp := ComputeJA4H(pkt)
	if fp == "" {
		t.Fatalf("the request %q produced no JA4H value", request)
	}
	partA := strings.Split(fp, "_")[0]
	if len(partA) < 2 {
		t.Fatalf("part a %q holds fewer than two characters", partA)
	}
	return partA[:2]
}

// ja4hWebDAVRequest returns one HTTP request that carries the named method.
func ja4hWebDAVRequest(method string) string {
	return method + " /dav HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"\r\n"
}

func TestJA4HWritesPrForThePropfindMethod(t *testing.T) {
	if got := ja4hMethodCode(t, ja4hWebDAVRequest("PROPFIND")); got != "pr" {
		t.Errorf("PROPFIND writes the method code %q, want %q", got, "pr")
	}
}

func TestJA4HWritesMkForTheMkcolMethod(t *testing.T) {
	if got := ja4hMethodCode(t, ja4hWebDAVRequest("MKCOL")); got != "mk" {
		t.Errorf("MKCOL writes the method code %q, want %q", got, "mk")
	}
}

// TestJA4HWritesTwoLowerCaseCharactersForAnyMethodToken holds the rule that
// FR-parity-47 states. A method that the Wireshark map omits writes a code, and a method
// shorter than two characters writes the whole token.
func TestJA4HWritesTwoLowerCaseCharactersForAnyMethodToken(t *testing.T) {
	cases := []struct {
		method string
		want   string
	}{
		{"PROPFIND", "pr"},
		{"MKCOL", "mk"},
		{"PROPPATCH", "pr"},
		{"REPORT", "re"},
		{"UNLOCK", "un"},
		{"GET", "ge"},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			if got := ja4hMethodCode(t, ja4hWebDAVRequest(c.method)); got != c.want {
				t.Errorf("%s writes the method code %q, want %q", c.method, got, c.want)
			}
		})
	}
}

// The second request of a pipelined pair. It declares no body, so the header block completes
// it under the gate of #455.
//
// The `## Terms` table of `docs/specs/spec.md` holds the row `pipelined pair`, and the round
// of batch #493 added it. `ja4hDeclaredBodyRequest` of `ja4h_test.go` is the first
// request of each pair below, because it declares a body and the pipelined case needs a
// declared body.
const ja4hPipelinedSecondRequest = "GET /second HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Accept: */*\r\n" +
	"\r\n"

// Each test of this file holds the ruling of #463.
//
// **The maintainer ruled this question on 2026-08-14, and the answer is one value.** The
// library produces one JA4H value for a pipelined pair. `ja4h.go` needs no change, because the
// library already produces one value. **Each test below fails when the count moves, and #463 is
// the reversal path.**
//
// **No capture of the corpus reaches a pipelined pair.** A scan of all 38 captures of the
// corpus reports 0 payloads that hold a byte past the first complete request. So
// `.claude/rules/rulings.md` `## Where a ruling is recorded` prescribes a test rather than a
// register entry, and `testdata/deviations.json` holds no entry for this question.
//
// The ruling rests on the four readings below. Each one reads the corpus at the pinned commit
// that `testdata/foxio.pin` holds.
//
//   - The Rust implementation produces one value. `rust/ja4/src/http.rs:22` selects the layer
//     with `pkt.find_proto("http")`, and `rust/ja4/src/pcap.rs:51` states
//     `/// Gets the first protocol with the given name.`
//   - The Python implementation produces one value. `python/ja4.py:405` reads
//     `l = l[0] if isinstance(l, list) else l`, so it keeps the first layer alone.
//   - The Zeek package produces two values. `zeek/scripts/fingerprints/ja4h/main.zeek:145` computes the value in
//     `event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)`, and
//     `zeek/scripts/fingerprints/ja4h/main.zeek:123` clears the state in `event http_request`.
//   - **The count of the Wireshark dissector is unverified.**
//     `wireshark/source/packet-ja4.c:1756` reads `register_postdissector(ja4_handle);`, and no
//     documentation this project reached states how often Wireshark calls a postdissector. **A
//     reversal of this ruling starts at this row**, because the ruling does not rest on it.
//
// **The Zeek count did not decide the question, because it follows from the event rather than
// from a stated rule.** Zeek raises `http_message_done` for each HTTP message. The Zeek
// documentation states `Generated once at the end of parsing an HTTP message.`, and it states
// `A "message" is one top-level HTTP entity, such as a complete request or reply.`
// `docs/specs/foxio/zeek.md` `## The rank of a Zeek value` already records that a Zeek value is
// not a reference value for every method.
// Verified against <https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_HTTP.events.bif.zeek.html>,
// retrieved 2026-08-14 UTC.
//
// **The port needs no change, and it produces one value.**
// `ja4plus/fingerprinters/ja4h.py:167` at the tag `v1.1.0` records the whole buffer as
// consumed. So the two implementations agree today.
//
// **`segmentCarriesNoNewRequest` suppresses no segment of any arrangement below.** The consumed
// range ends at the last byte of the emitting segment, so a later segment starts at
// `consumedEnd` and the guard admits it. **The library produces no second value because it
// reads no byte past the request it parsed.** The body of #463 names the guard as the cause,
// and the measurement names this sentence instead. A later reader who reopens this question
// starts here.
//
// **The candidate repair that the body of #463 names does not work.** That candidate records
// the byte count of the parsed request rather than the byte count of the buffer. A worker
// applied it, measured it and reverted it.
//
//   - It changes no value count of the three arrangements below.
//   - It makes a retransmission of a pipelined segment emit the first value a second time,
//     which reverses the repair of #446.
//   - The two tests of #446 pass under it, so they never caught that duplicate.
//
// `TestJA4H_ProducesNoDuplicateForARetransmissionOfAPipelinedSegment` now holds that guard.

// TestJA4H_ProducesOneValueForASegmentThatHoldsTwoRequests holds the ruling of #463.
//
// The library produces the value of the first request. It reads no byte past that request, so
// the second request reaches no value. **The maintainer ruled that count on 2026-08-14**, and
// #463 is the reversal path.
func TestJA4H_ProducesOneValueForASegmentThatHoldsTwoRequests(t *testing.T) {
	fingerprinter := NewJA4H()

	segment := ja4hDeclaredBodyRequest + ja4hDeclaredBody + ja4hPipelinedSecondRequest
	results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, segment))
	if err != nil {
		t.Fatalf("the segment returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the pipelined segment produced %d values, and the ruling of #463 states 1",
			len(results))
	}
	if results[0].Fingerprint != "po11nn030000_51b2f3543123_000000000000_000000000000" {
		t.Fatalf("the pipelined segment produced %q, and the value of the first request is po11nn030000_51b2f3543123_000000000000_000000000000",
			results[0].Fingerprint)
	}
}

// TestJA4H_ProducesTwoValuesForTwoRequestsInTwoSegments states the limit of the ruling of #463.
//
// **The ruling names one byte range that holds two requests, and it names no separate
// request.** Two requests in two segments are two byte ranges, so each one reaches a value.
// The consumed range ends at the last byte of the emitting segment, so the second segment
// starts at `consumedEnd` and the guard admits it. #463 is the reversal path.
func TestJA4H_ProducesTwoValuesForTwoRequestsInTwoSegments(t *testing.T) {
	fingerprinter := NewJA4H()

	first := ja4hDeclaredBodyRequest + ja4hDeclaredBody
	one, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, first))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the first segment produced %d values, and the reference holds 1", len(one))
	}

	two, err := fingerprinter.ProcessPacket(
		ja4hSegmentAt(t, uint32(1000+len(first)), 1, ja4hPipelinedSecondRequest))
	if err != nil {
		t.Fatalf("the second segment returned an error: %v", err)
	}
	if len(two) != 1 {
		t.Fatalf("the second segment produced %d values, and the reference holds 1", len(two))
	}
}

// TestJA4H_ProducesNoValueForASecondRequestThatTwoSegmentsSplit holds the ruling of #463 on the
// second arrangement.
//
// The emission removes the stream, so the head of the second request leaves the reassembler
// with it. The segment that carries the tail starts with no request line, so
// `parser.IsHTTPRequest` declines it and the second request reaches no value. **One value is
// the ruled count**, and #463 is the reversal path.
func TestJA4H_ProducesNoValueForASecondRequestThatTwoSegmentsSplit(t *testing.T) {
	fingerprinter := NewJA4H()

	first := ja4hDeclaredBodyRequest + ja4hDeclaredBody
	head := ja4hPipelinedSecondRequest[:10]
	tail := ja4hPipelinedSecondRequest[10:]

	one, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, first+head))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the first segment produced %d values, and the ruling of #463 states 1",
			len(one))
	}

	two, err := fingerprinter.ProcessPacket(
		ja4hSegmentAt(t, uint32(1000+len(first)+len(head)), 1, tail))
	if err != nil {
		t.Fatalf("the tail segment returned an error: %v", err)
	}
	if len(two) != 0 {
		t.Fatalf("the tail segment produced %d values, and the ruling of #463 states 0",
			len(two))
	}
}

// TestJA4H_ProducesNoDuplicateForARetransmissionOfAPipelinedSegment holds the repair of #446
// on a pipelined segment.
//
// **This test fails under the candidate repair that #463 names, and that is why it exists.**
// A consumed range that ends at the first request leaves the rest of the segment outside
// itself. The retransmission then reaches the parse path, and it produces the value of the
// first request a second time. A worker of #463 measured that duplicate on 2026-08-14 UTC,
// and pull request #499 records the measurement.
//
// **The ruling of #463 needs no repair, so this test guards a later reversal.** A reader who
// reverses the ruling to two values keeps the consumed range over every byte the emission read.
func TestJA4H_ProducesNoDuplicateForARetransmissionOfAPipelinedSegment(t *testing.T) {
	fingerprinter := NewJA4H()

	segment := ja4hDeclaredBodyRequest + ja4hDeclaredBody + ja4hPipelinedSecondRequest
	one, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, segment))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the first segment produced %d values, and the ruling of #463 states 1",
			len(one))
	}

	repeat, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 1, segment))
	if err != nil {
		t.Fatalf("the retransmission returned an error: %v", err)
	}
	if len(repeat) != 0 {
		t.Fatalf("the retransmission produced %d values, and the repair of #446 states 0: %q",
			len(repeat), repeat[0].Fingerprint)
	}
}

// The FoxIO per-packet vector set publishes `ja4.ja4h_r` on 126 records, and the
// per-stream vector set publishes no `JA4H_r` value. #274 read the per-stream set and left
// `Raw` empty, #290 recorded that the two sets differ, and #310 fills the field.
//
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:603` builds the value as
// `<part a>_<header names>_<sorted cookie names>_<sorted cookie pairs>`, and
// `testdata/foxio/reference/python/ja4h.py:78` builds the same four fields.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:525` sorts the cookie by name,
// and `testdata/foxio/reference/python/ja4h.py:68` sorts it by name too. The two cookie
// fields of the raw sorted form therefore hold the two strings the base value hashes.
//
// The two references disagree on one point, and #285 holds that question. Wireshark writes
// four fields always, and the FoxIO Python reference writes three when the request holds no
// cookie. `Raw` follows `RawOriginalOrder`, which #274 built in the Python shape, so one
// ruling on #285 moves both fields together.

// TestJA4H_RawHoldsTheSortedCookieOrder holds the per-packet vector value verbatim.
//
// The expected value is the `ja4.ja4h_r` value of
// `testdata/foxio/wireshark/http1-with-cookies.pcapng.json`, reproduced verbatim.
func TestJA4H_RawHoldsTheSortedCookieOrder(t *testing.T) {
	raw := "GET /?file=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: text/html\r\n" +
		"Accept-Language: da, en-gb;q=0.8, en;q=0.7\r\n" +
		"Referer: http://example.com/\r\n" +
		"Cookie: yummy_cookie=choco; tasty_cookie=strawberry\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_tasty_cookie,yummy_cookie_tasty_cookie=strawberry,yummy_cookie=choco"
	if results[0].Raw != expectedRaw {
		t.Errorf("Raw is %q, and the FoxIO per-packet vector holds %q", results[0].Raw, expectedRaw)
	}

	// The raw sorted form moves no other field. This assertion fails when the new field
	// changes the wire-order form that #274 built.
	const expectedRawOriginalOrder = "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry"
	if results[0].RawOriginalOrder != expectedRawOriginalOrder {
		t.Errorf("RawOriginalOrder is %q, and it must stay %q",
			results[0].RawOriginalOrder, expectedRawOriginalOrder)
	}

	// The base value hashes the two strings that the raw sorted form writes, so the two
	// forms read one input. This assertion fails when the shared builder changes either.
	expectedBase := "ge11cr04da00_" + truncHash("Host,User-Agent,Accept,Accept-Language") +
		"_" + truncHash("tasty_cookie,yummy_cookie") +
		"_" + truncHash("tasty_cookie=strawberry,yummy_cookie=choco")
	if results[0].Fingerprint != expectedBase {
		t.Errorf("the base JA4H value is %q, and it must stay %q",
			results[0].Fingerprint, expectedBase)
	}
}

// TestJA4H_RawEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie holds the three-field
// shape that `RawOriginalOrder` already carries.
//
// `testdata/foxio/reference/python/ja4h.py:82` appends the two cookie fields under
// `if 'cookie_fields' in x`, so a request with no cookie ends after one underscore.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:603` writes two trailing
// underscores for the same request. **#285 held that reference split, and the maintainer
// ruled it on 2026-08-12. The library keeps the per-stream shape.** This test fails when a
// later ruling reverses the shape, which is the point of it.
//
// `Crank-Git/ja4plus` holds no issue for this question, and the port needs no change. The
// port writes the same three-field shape. `ja4plus/fingerprinters/ja4h.py:532` builds
// `f"{part_a}_{headers_str}_"`. Lines 535 to 538 append the two cookie fields only when the
// request carries a cookie. The docstring at lines 516 to 518 states the same rule.
func TestJA4H_RawEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: t\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expected = "ge11nn020000_Host,User-Agent_"
	if results[0].Raw != expected {
		t.Errorf("Raw is %q, and the test expects %q", results[0].Raw, expected)
	}
	if results[0].RawOriginalOrder != expected {
		t.Errorf("RawOriginalOrder is %q, and it must equal the raw sorted form here, because"+
			" a request with no cookie holds no field that a sort reorders: %q",
			results[0].RawOriginalOrder, expected)
	}
}

// TestJA4H_RawReachesTheReassembledPath proves that the multi-segment path fills the field
// that the single-packet path fills.
//
// The two paths build one result each, and a field that one path fills alone reports a
// value for one capture and no value for another.
func TestJA4H_RawReachesTheReassembledPath(t *testing.T) {
	request := "GET /p HTTP/1.1\r\nHost: example.com\r\nCookie: zeta=1; alpha=2\r\n\r\n"
	// The split falls inside the request line, so the first segment alone parses as no
	// request. `TestJA4H_StreamReassembly` splits at the same point for the same reason.
	head := request[:6]
	tail := request[6:]

	fingerprinter := NewJA4H()
	source := net.IP{192, 168, 1, 1}
	destination := net.IP{10, 0, 0, 1}

	first := buildTCPPacketWithSeq(t, source, destination, 12345, 80, 1000, []byte(head))
	if results, err := fingerprinter.ProcessPacket(first); err != nil || len(results) != 0 {
		t.Fatalf("the first segment produced %d results and error %v", len(results), err)
	}

	second := buildTCPPacketWithSeq(t, source, destination, 12345, 80, 1000+uint32(len(head)), []byte(tail))
	results, err := fingerprinter.ProcessPacket(second)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the reassembled stream produced %d results, and the test expects 1", len(results))
	}

	const expected = "ge11cn010000_Host_alpha,zeta_alpha=2,zeta=1"
	if results[0].Raw != expected {
		t.Errorf("Raw is %q, and the test expects %q", results[0].Raw, expected)
	}
}

// The FoxIO per-stream vector set publishes `JA4H_ro`, and it publishes no `JA4H_r`
// value. `testdata/foxio/reference/python/ja4h.py` builds both keys, and the vector
// writer records only the original-order one. #274 fills `RawOriginalOrder` for that key.
//
// The reference builds the value as `<part a>_<header names>_<cookie names>_<cookie
// pairs>`. A request that carries no cookie ends after the header names and one
// underscore, because `testdata/foxio/reference/python/ja4h.py` appends the two cookie
// fields only when the request holds a cookie.

// TestJA4H_RawOriginalOrderEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie holds the
// three-field shape that 68 of the 89 per-stream vector values carry.
//
// The expected value is the `JA4H_ro` value of
// `testdata/foxio/python/CVE-2018-6794.pcap.json`, reproduced verbatim.
func TestJA4H_RawOriginalOrderEndsAfterTheHeaderNamesWhenTheRequestHoldsNoCookie(t *testing.T) {
	raw := "GET /index.php HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"Accept: text/html\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Accept-Language: ru-RU,ru;q=0.9\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expected = "ge11nn07ruru_Host,Connection,User-Agent,Upgrade-Insecure-Requests,Accept,Accept-Encoding,Accept-Language_"
	if results[0].RawOriginalOrder != expected {
		t.Errorf("RawOriginalOrder is %q, and the FoxIO vector holds %q",
			results[0].RawOriginalOrder, expected)
	}
}

// TestJA4H_RawOriginalOrderHoldsTheCookieWireOrder proves that the raw form keeps the
// wire order of the cookie while the base value sorts it.
//
// The base value hashes the sorted cookie names and the sorted cookie pairs, so a raw
// form that sorted them would carry no information the base value lacks.
func TestJA4H_RawOriginalOrderHoldsTheCookieWireOrder(t *testing.T) {
	raw := "GET /p HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: zeta=1; alpha=2\r\n" +
		"User-Agent: t\r\n" +
		"\r\n"

	packet := buildTCPPacketWithPayload(t, []byte(raw))
	results, err := NewJA4H().ProcessPacket(packet)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ProcessPacket returned %d results, and the test expects 1", len(results))
	}

	const expectedRaw = "ge11cn020000_Host,User-Agent_zeta,alpha_zeta=1,alpha=2"
	if results[0].RawOriginalOrder != expectedRaw {
		t.Errorf("RawOriginalOrder is %q, and the test expects %q",
			results[0].RawOriginalOrder, expectedRaw)
	}

	// The base value sorts the cookie name and the cookie pair, and #274 moves no base
	// value. This assertion fails when the raw form changes the base value.
	expectedBase := "ge11cn020000_" + truncHash("Host,User-Agent") +
		"_" + truncHash("alpha,zeta") + "_" + truncHash("alpha=2,zeta=1")
	if results[0].Fingerprint != expectedBase {
		t.Errorf("the base JA4H value is %q, and it must stay %q",
			results[0].Fingerprint, expectedBase)
	}
}

// TestJA4H_ThePerStreamVectorSetPublishesNoRawKey holds the reading that #274 recorded.
//
// The FoxIO per-stream vector set publishes 89 `JA4H_ro` values and no `JA4H_r` value.
// `ja4plus/fingerprinters/ja4h.py:70` of the Python port states the same rule, and #274
// left `Raw` empty for it.
//
// **The per-packet vector set disagrees, and it publishes 126 `ja4.ja4h_r` values.** #290
// recorded that difference, and #310 fills `Raw` for the per-packet set. This test states
// the per-stream half alone, so it names no rule about the per-packet set.
//
// The test reads the vector files rather than the library, because the claim is about the
// reference and not about this code. A later FoxIO release that publishes the key fails
// this test, and the reader then learns that the per-stream comparison gained a key.
func TestJA4H_ThePerStreamVectorSetPublishesNoRawKey(t *testing.T) {
	// The conformance suite carries a build tag, so this test names the directory itself.
	// `keylog_test.go` and `tunnel_test.go` skip on an absent corpus the same way.
	const streamVectorDir = "testdata/foxio/python"

	if _, statErr := os.Stat(streamVectorDir); statErr != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", streamVectorDir)
	}

	paths, err := filepath.Glob(filepath.Join(streamVectorDir, "*.json"))
	if err != nil {
		t.Fatalf("the glob of %s returned an error: %v", streamVectorDir, err)
	}
	if len(paths) == 0 {
		t.Fatalf("%s holds no vector file", streamVectorDir)
	}

	originalOrderKeys := 0
	rawKeys := 0

	for _, path := range paths {
		content, readErr := os.ReadFile(path) // #nosec G304 -- the path comes from the corpus glob.
		if readErr != nil {
			t.Fatalf("reading %s returned an error: %v", path, readErr)
		}

		var entries []map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal(content, &entries); unmarshalErr != nil {
			t.Fatalf("parsing %s returned an error: %v", path, unmarshalErr)
		}

		for _, entry := range entries {
			if _, held := entry["JA4H_ro"]; held {
				originalOrderKeys++
			}
			if _, held := entry["JA4H_r"]; held {
				rawKeys++
			}
		}
	}

	if originalOrderKeys != 89 {
		t.Errorf("the per-stream set holds %d `JA4H_ro` keys, and #274 measured 89", originalOrderKeys)
	}
	if rawKeys != 0 {
		t.Errorf("the per-stream set holds %d `JA4H_r` keys, and #274 measured 0", rawKeys)
	}
}

// TestJA4H_RawOriginalOrderReachesTheReassembledPath proves that the multi-segment path
// fills the field that the single-packet path fills.
//
// The two paths build one result each, and a field that one path fills alone reports a
// value for one capture and no value for another.
func TestJA4H_RawOriginalOrderReachesTheReassembledPath(t *testing.T) {
	request := "GET /p HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"
	// The split falls inside the request line, so the first segment alone parses as no
	// request. `TestJA4H_StreamReassembly` splits at the same point for the same reason.
	head := request[:6]
	tail := request[6:]

	fingerprinter := NewJA4H()
	source := net.IP{192, 168, 1, 1}
	destination := net.IP{10, 0, 0, 1}

	first := buildTCPPacketWithSeq(t, source, destination, 12345, 80, 1000, []byte(head))
	if results, err := fingerprinter.ProcessPacket(first); err != nil || len(results) != 0 {
		t.Fatalf("the first segment produced %d results and error %v", len(results), err)
	}

	second := buildTCPPacketWithSeq(t, source, destination, 12345, 80, 1000+uint32(len(head)), []byte(tail))
	results, err := fingerprinter.ProcessPacket(second)
	if err != nil {
		t.Fatalf("ProcessPacket returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("the reassembled stream produced %d results, and the test expects 1", len(results))
	}

	const expected = "ge11nn020000_Host,User-Agent_"
	if results[0].RawOriginalOrder != expected {
		t.Errorf("RawOriginalOrder is %q, and the test expects %q",
			results[0].RawOriginalOrder, expected)
	}
}

// The bytes of frame 6 and frame 15 of `CVE-2018-6794.pcap`. The two frames carry the same
// payload on the same four-tuple, and `docs/audit/ja4h-deviation-cluster.md` `## Cause 3`
// records the repeat. `testdata/foxio/wireshark/CVE-2018-6794.pcap.json` publishes a JA4H
// value for frame 6 and for frame 16, and for no other frame of the capture.
const ja4hRepeatedRequest = "GET / HTTP/1.1\r\n" +
	"Host: 192.168.235.136:8089\r\n" +
	"Connection: keep-alive\r\n" +
	"\r\n"

// ja4hSegmentAt builds one TCP segment of the repeat test, at the sequence number and the
// packet timestamp the caller states.
//
// The age pass reads the packet timestamp, so every packet of these tests carries one.
func ja4hSegmentAt(t *testing.T, seq uint32, offsetSeconds int, payload string) gopacket.Packet {
	t.Helper()

	packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
		54321, 8089, seq, []byte(payload))
	packet.Metadata().Timestamp = time.Unix(int64(1500000000+offsetSeconds), 0)
	return packet
}

// TestJA4H_ProducesOneValueForARepeatedTCPSegment holds the repair of #446.
//
// The reassembler drops the stream after each value, so the repeat rebuilt the same request
// and produced a second value. The guard fails when a reader removes it, because the second
// call then returns one result.
func TestJA4H_ProducesOneValueForARepeatedTCPSegment(t *testing.T) {
	fingerprinter := NewJA4H()

	first, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("the first segment produced %d values, and the reference holds 1", len(first))
	}

	repeat, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 1, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the repeated segment returned an error: %v", err)
	}
	if len(repeat) != 0 {
		t.Fatalf("the repeated segment produced %d values, and the reference holds 0: %q",
			len(repeat), repeat[0].Fingerprint)
	}
}

// TestJA4H_ProducesOneValueForARepeatOfAReassembledRequest holds the repair of #446 on the
// path that reads more than one segment.
//
// The consumed range covers the whole buffer, so a repeat of the first segment of a
// reassembled request reaches the guard too.
func TestJA4H_ProducesOneValueForARepeatOfAReassembledRequest(t *testing.T) {
	fingerprinter := NewJA4H()

	head := ja4hRepeatedRequest[:10]
	tail := ja4hRepeatedRequest[10:]

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, head)); err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}

	assembled, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, uint32(1000+len(head)), 1, tail))
	if err != nil {
		t.Fatalf("the second segment returned an error: %v", err)
	}
	if len(assembled) != 1 {
		t.Fatalf("the reassembled request produced %d values, and the reference holds 1",
			len(assembled))
	}

	// The two segments repeat in the order they first arrived, because a repeat of the first
	// segment alone rebuilds no request and reaches no emission.
	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 2, head)); err != nil {
		t.Fatalf("the first repeated segment returned an error: %v", err)
	}

	repeat, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, uint32(1000+len(head)), 3, tail))
	if err != nil {
		t.Fatalf("the second repeated segment returned an error: %v", err)
	}
	if len(repeat) != 0 {
		t.Fatalf("the repeated request produced %d values, and the reference holds 0", len(repeat))
	}
}

// TestJA4H_ReadsASecondRequestOfTheSameStream holds the limit of the guard of #446.
//
// A client that keeps the connection open sends a second request at a higher sequence
// number. That request lies outside the consumed range, and it produces its own value.
func TestJA4H_ReadsASecondRequestOfTheSameStream(t *testing.T) {
	fingerprinter := NewJA4H()

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest)); err != nil {
		t.Fatalf("the first request returned an error: %v", err)
	}

	next := uint32(1000 + len(ja4hRepeatedRequest))
	second, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, next, 1, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the second request returned an error: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("the second request produced %d values, and the reference holds 1", len(second))
	}
}

// TestJA4H_ReadsTheFirstRequestOfAReusedFourTuple holds the second limit of the guard.
//
// A second connection reuses the address pair and the port pair, and it starts at its own
// initial sequence number. That number sits below the stored one about half the time. So a
// guard that reads the end alone loses the first request of the second connection.
// `ja4plus/fingerprinters/ja4h.py:213-220` states the same limit.
func TestJA4H_ReadsTheFirstRequestOfAReusedFourTuple(t *testing.T) {
	fingerprinter := NewJA4H()

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 900000, 0, ja4hRepeatedRequest)); err != nil {
		t.Fatalf("the first connection returned an error: %v", err)
	}

	reused, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 500, 1, ja4hRepeatedRequest))
	if err != nil {
		t.Fatalf("the second connection returned an error: %v", err)
	}
	if len(reused) != 1 {
		t.Fatalf("the second connection produced %d values, and the reference holds 1", len(reused))
	}
}

// TestJA4H_RemovesTheConsumedRangeOfACleanedConnection holds the removal path of #446.
//
// `.claude/rules/concurrency.md` states that a new state map has a removal path in
// `CleanupConnection` and in `Reset`. The repeat produces a value again after each one,
// because the entry that suppresses it is gone.
func TestJA4H_RemovesTheConsumedRangeOfACleanedConnection(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		remove func(*JA4HFingerprinter)
	}{
		{
			name: "CleanupConnection",
			remove: func(f *JA4HFingerprinter) {
				f.CleanupConnection("192.168.235.137", 54321, "192.168.235.136", 8089, "tcp")
			},
		},
		{
			name:   "Reset",
			remove: func(f *JA4HFingerprinter) { f.Reset() },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter := NewJA4H()

			if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest)); err != nil {
				t.Fatalf("the first segment returned an error: %v", err)
			}
			if length := len(fingerprinter.ranges); length != 1 {
				t.Fatalf("the range table holds %d entries, and one segment states 1", length)
			}

			testCase.remove(fingerprinter)

			if length := len(fingerprinter.ranges); length != 0 {
				t.Fatalf("the range table holds %d entries after the removal, and the rule states 0",
					length)
			}
		})
	}
}

// TestJA4H_HoldsTheRangeTableAtTheStreamBound holds the entry bound of #446.
//
// #432 records nine state tables that reach no bound, and this table is not the tenth. The
// insert that reaches the bound removes the entry that received no segment for the longest
// time.
func TestJA4H_HoldsTheRangeTableAtTheStreamBound(t *testing.T) {
	fingerprinter := NewJA4H()

	for index := 0; index < ja4hMaxStreams+50; index++ {
		packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
			uint16(20000+index), 8089, 1000, []byte(ja4hRepeatedRequest))
		packet.Metadata().Timestamp = time.Unix(int64(1500000000+index), 0)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("stream %d returned an error: %v", index, err)
		}
	}

	if length := len(fingerprinter.ranges); length > ja4hMaxStreams {
		t.Fatalf("the range table holds %d entries, and the bound states %d at most",
			length, ja4hMaxStreams)
	}
}

// TestJA4H_ProducesOneValueForARepeatThatTheStreamBoundSeparates holds the second repair of
// #446.
//
// The range table and the reassembler each hold a bound of their own, and the fast path
// fills the range table alone. So the range table can reach its bound while the reassembler
// still holds the buffer of an earlier stream. The entry that leaves therefore takes the
// buffer with it, and the two tables name one set of streams.
func TestJA4H_ProducesOneValueForARepeatThatTheStreamBoundSeparates(t *testing.T) {
	fingerprinter := NewJA4H()

	head := ja4hRepeatedRequest[:10]
	tail := ja4hRepeatedRequest[10:]
	values := 0

	sendToTheSlowStream := func(offsetSeconds int, seq uint32, payload string) {
		t.Helper()

		results, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, seq, offsetSeconds, payload))
		if err != nil {
			t.Fatalf("the slow stream returned an error: %v", err)
		}
		values += len(results)
	}

	sendToTheSlowStream(0, 1000, head)

	// Each of these streams reaches the fast path, so each one writes a range entry and no
	// buffer. The count passes the entry bound, so the entry of the slow stream leaves.
	for index := 0; index < ja4hMaxStreams+10; index++ {
		packet := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
			uint16(30000+index), 8089, 1000, []byte(ja4hRepeatedRequest))
		packet.Metadata().Timestamp = time.Unix(int64(1500000001+index), 0)
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("stream %d returned an error: %v", index, err)
		}
	}

	sendToTheSlowStream(2000, uint32(1000+len(head)), tail)
	sendToTheSlowStream(2001, 1000, head)
	sendToTheSlowStream(2002, uint32(1000+len(head)), tail)

	if values > 1 {
		t.Fatalf("the slow stream produced %d values for one request, and the reference holds 1 at most",
			values)
	}
}

// TestJA4H_RemovesARangeThatReachesTheMaximumAge holds the age bound of #446.
//
// The pass reads the packet timestamp, and never the wall clock. A capture replays faster
// than the wall clock, so a wall clock removes state that the capture still needs.
func TestJA4H_RemovesARangeThatReachesTheMaximumAge(t *testing.T) {
	fingerprinter := NewJA4H()

	if _, err := fingerprinter.ProcessPacket(ja4hSegmentAt(t, 1000, 0, ja4hRepeatedRequest)); err != nil {
		t.Fatalf("the first segment returned an error: %v", err)
	}

	aged := int(ja4hMaxStreamAge/time.Second) + 1
	other := buildTCPPacketWithSeq(t, net.IP{192, 168, 235, 137}, net.IP{192, 168, 235, 136},
		54322, 8089, 1000, []byte(ja4hRepeatedRequest))
	other.Metadata().Timestamp = time.Unix(int64(1500000000+aged), 0)
	if _, err := fingerprinter.ProcessPacket(other); err != nil {
		t.Fatalf("the later segment returned an error: %v", err)
	}

	if _, present := fingerprinter.ranges["192.168.235.137:54321->192.168.235.136:8089"]; present {
		t.Fatal("the range table holds the aged entry, and the age bound states no entry")
	}
}

// This file holds the settled count of #233 against the capture that raised it.
//
// #233 asked whether the library over-emits on `CVE-2018-6794.pcap`, or whether the
// reference reports one value for each distinct request. Neither reading holds. The
// capture carries one HTTP request on each of its two HTTP connections, and it carries
// five TCP retransmissions of each request. So the count of requests is one, and it is
// never four.
//
// Both FoxIO references read the request and decline every retransmission.
// `testdata/foxio/reference/python/ja4.py:589-591` calls `to_ja4h` for a packet whose
// highest layer is `http`, and the tshark HTTP dissector reads no retransmitted segment.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1149` sets `http_req` from an
// `http.request.method` field, and
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:1634` emits the value only when
// that field was present.
//
// #446 built the guard that produces this count, and `segmentCarriesNoNewRequest` in
// `ja4h.go` holds it. The synthetic segments of `ja4h_test.go` prove the
// guard on two packets. This test proves it on the whole capture, where three TCP
// connections interleave and one of the three carries no HTTP request.
//
// A change that re-emits on a retransmission fails this test.

// ja4hRetransmittedCapture is the capture of #233. Frames 8, 9, 15, 26 and 28 repeat frame
// 6, and frames 18, 24, 25, 27 and 29 repeat frame 16.
const ja4hRetransmittedCapture = "CVE-2018-6794.pcap"

// ja4hRetransmittedCaptureValue names the frame that carries each request of the capture,
// and the value the FoxIO vectors publish for it.
//
// `testdata/foxio/python/CVE-2018-6794.pcap.json` holds one entry for stream 0 and one for
// stream 1. `testdata/foxio/wireshark/CVE-2018-6794.pcap.json` attributes a `ja4.ja4h`
// value to frame 6 and to frame 16, and to no other frame.
var ja4hRetransmittedCaptureValue = []struct {
	frame       int
	srcPort     uint16
	fingerprint string
}{
	{frame: 6, srcPort: 53649, fingerprint: "ge11nn07ruru_6cd0fb54989b_000000000000_000000000000"},
	{frame: 16, srcPort: 53656, fingerprint: "ge11nr06ruru_cc6ec9a91856_000000000000_000000000000"},
}

// TestJA4H_ProducesOneValueForEachRequestOfTheRetransmittedCapture holds the reading of
// #233.
//
// The fingerprinter reads every packet of the capture in capture order, and it produces one
// value at each frame that carries a request. A retransmission produces no value.
func TestJA4H_ProducesOneValueForEachRequestOfTheRetransmittedCapture(t *testing.T) {
	capture := filepath.Join(corpusCaptureDir, ja4hRetransmittedCapture)

	if _, err := os.Stat(capture); err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", capture)
	}

	packets := loadPCAP(t, capture)
	if len(packets) == 0 {
		t.Fatalf("%s holds no packet", capture)
	}

	type emission struct {
		frame       int
		srcPort     uint16
		fingerprint string
	}

	var emitted []emission

	fingerprinter := NewJA4H()

	for index, packet := range packets {
		results, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("frame %d returned an error: %v", index+1, err)
		}
		for _, result := range results {
			emitted = append(emitted, emission{
				frame:       index + 1,
				srcPort:     result.SrcPort,
				fingerprint: result.Fingerprint,
			})
		}
	}

	if len(emitted) != len(ja4hRetransmittedCaptureValue) {
		t.Fatalf("the capture produced %d values, and the FoxIO vectors hold %d: %v",
			len(emitted), len(ja4hRetransmittedCaptureValue), emitted)
	}

	for index, want := range ja4hRetransmittedCaptureValue {
		got := emitted[index]
		if got.frame != want.frame {
			t.Errorf("value %d came from frame %d, and the Wireshark vector names frame %d",
				index+1, got.frame, want.frame)
		}
		if got.srcPort != want.srcPort {
			t.Errorf("value %d came from source port %d, and the vector names port %d",
				index+1, got.srcPort, want.srcPort)
		}
		if got.fingerprint != want.fingerprint {
			t.Errorf("value %d reads %q, and the vector holds %q",
				index+1, got.fingerprint, want.fingerprint)
		}
	}
}
