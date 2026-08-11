package ja4plus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// JA4HFingerprinter generates JA4H fingerprints from HTTP request packets.
// It uses TCP stream reassembly to handle multi-segment HTTP requests.
//
// One JA4HFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4HFingerprinter struct {
	results     []FingerprintResult
	reassembler *parser.TCPStreamReassembler
}

// NewJA4H creates a new JA4H HTTP fingerprinter.
func NewJA4H() *JA4HFingerprinter {
	return &JA4HFingerprinter{
		reassembler: parser.NewTCPStreamReassembler(100, 1048576),
	}
}

// ProcessPacket processes a packet and returns JA4H fingerprints if the packet
// contains an HTTP request (possibly reassembled from multiple segments).
func (f *JA4HFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	tcp := parser.GetTCPLayer(packet)
	if tcp == nil {
		return nil, nil
	}

	payload := tcp.Payload
	if len(payload) == 0 {
		return nil, nil
	}

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	// Build stream key from connection tuple (forward direction)
	streamKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

	// Try single-packet parse first (fast path)
	if parser.IsHTTPRequest(payload) {
		req := parser.ParseHTTPRequest(payload)
		if req != nil {
			fingerprint := computeJA4HFromRequest(req)
			if fingerprint != "" {
				result := FingerprintResult{
					Fingerprint: fingerprint,
					Type:        "ja4h",
					SrcIP:       srcIP,
					DstIP:       dstIP,
					SrcPort:     srcPort,
					DstPort:     dstPort,
					Timestamp:   parser.GetPacketTimestamp(packet),
				}
				f.results = append(f.results, result)
				f.reassembler.RemoveStream(streamKey)
				return []FingerprintResult{result}, nil
			}
		}
	}

	// Add to reassembler for multi-segment reassembly
	seq := tcp.Seq
	f.reassembler.AddSegment(streamKey, seq, payload)

	// Try to parse reassembled stream
	assembled := f.reassembler.GetStream(streamKey)
	if assembled == nil || !parser.IsHTTPRequest(assembled) {
		return nil, nil
	}

	req := parser.ParseHTTPRequest(assembled)
	if req == nil {
		return nil, nil
	}

	fingerprint := computeJA4HFromRequest(req)
	if fingerprint == "" {
		return nil, nil
	}

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4h",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Timestamp:   parser.GetPacketTimestamp(packet),
	}
	f.results = append(f.results, result)
	f.reassembler.RemoveStream(streamKey)
	return []FingerprintResult{result}, nil
}

// Reset clears all accumulated results and stream state.
func (f *JA4HFingerprinter) Reset() {
	f.results = nil
	f.reassembler = parser.NewTCPStreamReassembler(100, 1048576)
}

// CleanupConnection removes internal state for the given connection.
// JA4H uses directional arrow keys: srcIP:srcPort->dstIP:dstPort.
func (f *JA4HFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	fwd := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	rev := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
	f.reassembler.RemoveStream(fwd)
	f.reassembler.RemoveStream(rev)
}

// ComputeJA4H extracts the TCP payload from a packet, parses it as an HTTP
// request, and returns the JA4H fingerprint string. Returns "" if the packet
// does not contain an HTTP request.
func ComputeJA4H(packet gopacket.Packet) string {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return ""
	}
	req := parser.ParseHTTPRequest(payload)
	if req == nil {
		return ""
	}
	return computeJA4HFromRequest(req)
}

// ja4hNormalizeVersion converts an HTTP version like "HTTP/1.1", "HTTP/1.0",
// "HTTP/2", or "HTTP/3" into the JA4H 2-char version code ("11", "10", "20", "30").
// Mirrors the FoxIO Wireshark dissector behavior (PR #288): take the part after
// the first "/", lowercase any letters, drop dots, and pad with "0" if the
// resulting string is <= 1 character.
func ja4hNormalizeVersion(v string) string {
	idx := strings.Index(v, "/")
	if idx < 0 || idx == len(v)-1 {
		return "00"
	}
	tail := v[idx+1:]
	var b strings.Builder
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if c == '.' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		b.WriteByte(c)
	}
	out := b.String()
	if len(out) <= 1 {
		out += "0"
	}
	if len(out) > 2 {
		out = out[:2]
	}
	return out
}

// computeJA4HFromRequest builds the JA4H fingerprint from a parsed HTTP request.
//
// Format: {method}{ver}{cookie}{referer}{count}{lang}_{header_hash}_{cookie_name_hash}_{cookie_value_hash}
func computeJA4HFromRequest(req *parser.HTTPRequest) string {
	// Part A components.

	// method: first 2 chars, lowercase.
	method := strings.ToLower(req.Method)
	if len(method) > 2 {
		method = method[:2]
	}

	// version: strip "HTTP/" and dots -> "10", "11", "20", "30" (FoxIO PR #288).
	// Wireshark dissector behavior: lowercase any letters, drop dots; if the
	// resulting string is <= 1 character, append "0" (HTTP/2 -> "20", HTTP/3 -> "30").
	ver := ja4hNormalizeVersion(req.Version)

	// cookie flag.
	cookieFlag := "n"
	if len(req.CookieNames) > 0 {
		cookieFlag = "c"
	}

	// referer flag.
	refererFlag := "n"
	if req.Referer != "" {
		refererFlag = "r"
	}

	// header count: exclude Cookie, Referer, and pseudo-headers (starting with ':').
	headerCount := 0
	for _, h := range req.HeaderNames {
		lower := strings.ToLower(h)
		if lower == "cookie" || lower == "referer" || strings.HasPrefix(h, ":") {
			continue
		}
		headerCount++
	}
	if headerCount > 99 {
		headerCount = 99
	}

	// language: clean and truncate.
	langCode := "0000"
	if req.Language != "" {
		lang := strings.ToLower(req.Language)
		lang = strings.ReplaceAll(lang, "-", "")
		lang = strings.ReplaceAll(lang, ";", ",")
		parts := strings.Split(lang, ",")
		cleaned := parts[0]
		if len(cleaned) > 4 {
			cleaned = cleaned[:4]
		}
		if cleaned != "" {
			langCode = cleaned
			for len(langCode) < 4 {
				langCode += "0"
			}
		}
	}

	partA := fmt.Sprintf("%s%s%s%s%02d%s", method, ver, cookieFlag, refererFlag, headerCount, langCode)

	// Part B: header names in original order, excluding Cookie, Referer, pseudo-headers.
	var filteredHeaders []string
	for _, h := range req.HeaderNames {
		if h == "" || strings.HasPrefix(h, ":") {
			continue
		}
		lower := strings.ToLower(h)
		if lower == "cookie" || lower == "referer" {
			continue
		}
		filteredHeaders = append(filteredHeaders, h)
	}
	headersStr := strings.Join(filteredHeaders, ",")
	partB := parser.TruncatedHash(headersStr)

	// Part C: sorted cookie field names.
	sortedNames := make([]string, len(req.CookieNames))
	copy(sortedNames, req.CookieNames)
	sort.Strings(sortedNames)
	cookieNamesStr := strings.Join(sortedNames, ",")
	partC := parser.TruncatedHash(cookieNamesStr)

	// Part D: sorted cookie name=value pairs.
	type cookiePair struct {
		name  string
		value string
	}
	pairs := make([]cookiePair, 0, len(req.Cookies))
	for k, v := range req.Cookies {
		pairs = append(pairs, cookiePair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].name < pairs[j].name
	})
	pairStrs := make([]string, len(pairs))
	for i, p := range pairs {
		pairStrs[i] = p.name + "=" + p.value
	}
	cookieValuesStr := strings.Join(pairStrs, ",")
	partD := parser.TruncatedHash(cookieValuesStr)

	return fmt.Sprintf("%s_%s_%s_%s", partA, partB, partC, partD)
}
