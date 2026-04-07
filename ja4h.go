package ja4plus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// JA4HFingerprinter generates JA4H fingerprints from HTTP request packets.
type JA4HFingerprinter struct {
	results []FingerprintResult
}

// NewJA4H creates a new JA4H HTTP fingerprinter.
func NewJA4H() *JA4HFingerprinter {
	return &JA4HFingerprinter{}
}

// ProcessPacket processes a packet and returns JA4H fingerprints if the packet
// contains an HTTP request.
func (f *JA4HFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return nil, nil
	}

	if !parser.IsHTTPRequest(payload) {
		return nil, nil
	}

	req := parser.ParseHTTPRequest(payload)
	if req == nil {
		return nil, nil
	}

	fingerprint := computeJA4HFromRequest(req)
	if fingerprint == "" {
		return nil, nil
	}

	srcIP, dstIP, _ := parser.GetIPInfo(packet)
	tcp := parser.GetTCPLayer(packet)

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4h",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		Timestamp:   parser.GetPacketTimestamp(packet),
	}
	if tcp != nil {
		result.SrcPort = uint16(tcp.SrcPort)
		result.DstPort = uint16(tcp.DstPort)
	}

	f.results = append(f.results, result)
	return []FingerprintResult{result}, nil
}

// Reset clears all accumulated results.
func (f *JA4HFingerprinter) Reset() {
	f.results = nil
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

	// version: strip "HTTP/" and dots -> "10", "11", "20", "30".
	ver := strings.Replace(req.Version, "HTTP/", "", 1)
	ver = strings.Replace(ver, ".", "", 1)

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
