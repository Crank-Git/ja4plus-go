package ja4plus

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
)

// JA4HFingerprinter generates JA4H fingerprints from HTTP request packets.
// It uses TCP stream reassembly to handle multi-segment HTTP requests.
//
// One JA4HFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4HFingerprinter struct {
	reassembler *parser.TCPStreamReassembler
	// ranges holds the sequence range of each stream. The reassembler drops a stream after
	// each value, so nothing else records the bytes the fingerprinter already read.
	ranges map[string]*ja4hStreamRange
	// keyLog holds the TLS secrets that the caller supplied, and nil when the caller
	// supplied none. `WithKeyLog` writes it, and the constructor leaves it nil.
	// A fingerprinter without a key log produces no value for an HTTP/2 request, because
	// that request travels inside a protected TLS record.
	keyLog *KeyLog
}

// setKeyLog gives the fingerprinter the TLS secrets that the caller supplied.
//
// `WithKeyLog` calls it, and no exported name of this package reaches it. Epic 10 freezes
// the exported surface, and issue #649 ruled that one option function carries a new
// setting.
// The caller calls it once, before the first packet. A write on a live fingerprinter would
// break the lock-free contract of `.claude/rules/concurrency.md`.
func (f *JA4HFingerprinter) setKeyLog(keyLog *KeyLog) {
	f.keyLog = keyLog
}

// NewJA4H creates a new JA4H HTTP fingerprinter.
func NewJA4H() *JA4HFingerprinter {
	return &JA4HFingerprinter{
		reassembler: parser.NewTCPStreamReassembler(ja4hMaxStreams, ja4hMaxStreamBytes),
		ranges:      make(map[string]*ja4hStreamRange),
	}
}

// ja4hMaxStreams and ja4hMaxStreamBytes bound the reassembler of one fingerprinter.
// A long-running monitor holds one stream for each connection it has seen, so a limit
// keeps the memory bounded.
//
// ja4hMaxStreamBytes bounds the bytes that one stream stores, and #567 added that bound.
// This fingerprinter removes a stream after each value, so a request that completes returns
// the whole bound to the connection. A sender that never completes a request holds one
// stream at the bound until `CleanupConnection`, `Reset` or the stream limit removes it.
const (
	ja4hMaxStreams     = 100
	ja4hMaxStreamBytes = 1048576
)

// ja4hMaxStreamAge is the maximum age of one entry of the range table.
// One entry describes one stream of the reassembler, so the two hold one age.
// `ja4plus/utils/tcp_stream.py:50` sets `DEFAULT_MAX_STREAM_AGE = 600`.
const ja4hMaxStreamAge = 600 * time.Second

// ja4hStreamRange holds the sequence range of one stream.
//
// The reassembler drops the stream after each value, so a repeated segment rebuilds the
// same request and produces a second value. The reference holds one value for one request,
// and this range tells the two apart. Issue #446 records the defect, and
// `ja4plus/fingerprinters/ja4h.py:172-221` holds the same guard.
type ja4hStreamRange struct {
	// bufferStart holds the lowest sequence number of the segments the reassembler holds.
	// `GetStream` reassembles from that number, so the consumed range starts there.
	bufferStart uint32
	// holdsBuffer reports whether bufferStart names a live buffer. A stream that produced a
	// value holds no buffer, because the emission removes it.
	holdsBuffer bool
	// consumedStart and consumedEnd name the sequence range that already produced a value.
	consumedStart uint32
	consumedEnd   uint32
	// holdsConsumed reports whether the stream produced a value.
	holdsConsumed bool
	// lastSeen holds the timestamp of the last segment of the stream. The age pass reads the
	// packet clock, because a capture replays faster than the wall clock.
	lastSeen time.Time
	// http2Emitted counts the HTTP/2 requests of the stream that already produced a value.
	// The protected reader decodes the whole stream at each packet, because the HPACK
	// dynamic table of RFC 7541 section 2.3.2 serves the whole connection. So this counter
	// is what separates a new request from one the stream already published.
	http2Emitted int
}

// ensure fills the reassembler and the range table that the constructor fills.
// A caller who writes `var f JA4HFingerprinter` reaches a nil pointer, and a method call
// on it panics. Every entry point calls this method first.
func (f *JA4HFingerprinter) ensure() {
	if f.reassembler == nil {
		f.reassembler = parser.NewTCPStreamReassembler(ja4hMaxStreams, ja4hMaxStreamBytes)
	}
	if f.ranges == nil {
		f.ranges = make(map[string]*ja4hStreamRange)
	}
}

// ProcessPacket processes a packet and returns JA4H fingerprints if the packet
// contains an HTTP request (possibly reassembled from multiple segments).
// It produces the value at the packet that completes the request, and never at the packet
// that ends the header block. The maintainer ruled that emission frame at #455, and
// `parser.HTTPMessageIsComplete` holds the rule.
func (f *JA4HFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	f.ensure()

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

	// The range table ages against the capture clock, so every packet announces its own
	// timestamp. The table holds ja4hMaxStreams entries at most, so the pass runs on each
	// packet. `ja4plus/fingerprinters/ja4h.py:81` runs the same pass on the same schedule.
	now := parser.GetPacketTimestamp(packet)
	f.evictAgedRanges(now)

	seq := tcp.Seq

	// The guard precedes the two parse paths, because each one produces a value.
	if f.segmentCarriesNoNewRequest(streamKey, seq, len(payload)) {
		return nil, nil
	}

	// Try single-packet parse first (fast path)
	if parser.IsHTTPRequest(payload) {
		req := parser.ParseHTTPRequest(payload)
		// The body gate holds the value until the request completes.
		// A packet that carries a header block and a part of the body therefore reaches the
		// reassembler below.
		if req != nil && parser.HTTPMessageIsComplete(payload, req) {
			fingerprint := computeJA4HFromRequest(req)
			if fingerprint != "" {
				// The two vector sets disagree about the raw sorted form. The per-stream
				// set publishes no `JA4H_r` value, and the per-packet set publishes 126 of
				// them. #310 fills the field for the per-packet set, and #274 holds the
				// per-stream reading.
				result := FingerprintResult{
					Fingerprint:      fingerprint,
					Raw:              computeJA4HRaw(req),
					RawOriginalOrder: computeJA4HRawOriginalOrder(req),
					Type:             "ja4h",
					SrcIP:            srcIP,
					DstIP:            dstIP,
					SrcPort:          srcPort,
					DstPort:          dstPort,
					Timestamp:        parser.GetPacketTimestamp(packet),
				}
				f.reassembler.RemoveStream(streamKey)
				// The fast path reads this packet alone, so its range starts at this
				// sequence number.
				f.rememberTheConsumedRequest(streamKey, seq, len(payload), now)
				return []FingerprintResult{result}, nil
			}
		}
	}

	// Add to reassembler for multi-segment reassembly
	f.recordTheBufferStart(streamKey, seq, now)
	f.reassembler.AddSegment(streamKey, seq, payload)

	// Try to parse reassembled stream
	assembled := f.reassembler.GetStream(streamKey)
	if assembled == nil {
		return nil, nil
	}

	if !parser.IsHTTPRequest(assembled) {
		// An HTTP/2 request carries no request line, so it reaches this branch and never the
		// two parses above. The reader keeps the stream, because the HPACK dynamic table
		// reads every earlier header block of the connection.
		return f.protectedHTTP2Results(streamKey, assembled, FingerprintResult{
			Type:      "ja4h",
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Timestamp: now,
		}), nil
	}

	req := parser.ParseHTTPRequest(assembled)
	if req == nil {
		return nil, nil
	}

	// The stream stays in the reassembler until the request completes, so a later segment of
	// the body reaches this parse with the whole request.
	if !parser.HTTPMessageIsComplete(assembled, req) {
		return nil, nil
	}

	fingerprint := computeJA4HFromRequest(req)
	if fingerprint == "" {
		return nil, nil
	}

	result := FingerprintResult{
		Fingerprint:      fingerprint,
		Raw:              computeJA4HRaw(req),
		RawOriginalOrder: computeJA4HRawOriginalOrder(req),
		Type:             "ja4h",
		SrcIP:            srcIP,
		DstIP:            dstIP,
		SrcPort:          srcPort,
		DstPort:          dstPort,
		Timestamp:        parser.GetPacketTimestamp(packet),
	}
	f.reassembler.RemoveStream(streamKey)
	// The range covers the whole buffer, and not the header block alone. A request that
	// carries a body ends past the header block in its last segment. A range that ends at
	// the header block therefore leaves that segment outside itself.
	// `ja4plus/fingerprinters/ja4h.py:180-183` states the same reason.
	if entry, present := f.ranges[streamKey]; present && entry.holdsBuffer {
		f.rememberTheConsumedRequest(streamKey, entry.bufferStart, len(assembled), now)
	}
	return []FingerprintResult{result}, nil
}

// ja4hMaxProtectedSearchBytes bounds the stream that the protected reader walks.
//
// The reader decrypts the whole stream at each packet, because RFC 8446 section 5.3
// restarts the record sequence number at each key change and no record carries its own
// number. So the cost of one packet grows with the stream, and this bound holds it.
// `ja4xMaxProtectedSearchBytes` in `ja4x.go` holds the same value for the same reason.
//
// The client half of one HTTP/2 connection carries the requests, and it carries no response
// body. `testdata/foxio/pcap/http2-with-cookies.pcapng` reports 20 kB in that direction and
// 1926 kB in the other, measured with `tshark -q -z conv,tcp` on 2026-08-15 UTC. So this
// bound stops the walk of the response direction at once, and it reaches every request of
// that capture.
//
// **A connection whose client half passes this bound reaches no later value, and it reports
// no error.** The reader keeps the whole stream, so the stream of a long connection grows
// past the bound and every later request of that connection is lost. **A delay would need
// an incremental decode**, which needs one HPACK decoder for each connection and therefore a
// table with a bound and a removal path. The tracker holds one issue for this limit, and
// the batch gate writes its number here.
const ja4hMaxProtectedSearchBytes = 65536

// protectedHTTP2Results returns one result for each HTTP/2 request that the protected
// records of one stream newly carry.
//
// It returns nil when the caller supplied no key log, and nil when the key log holds no
// secret for the connection. It allocates no state of its own: the client random comes from
// the ClientHello that the reassembler already holds, and the range table already bounds
// this stream.
//
// **The reader reads the client half of the connection alone.** A key log names each
// connection by the Random field of its ClientHello, and that message travels on the
// request stream. So the response stream parses no ClientHello and this reader declines it,
// which is also the direction that carries no request.
//
// **The stream stays in the reassembler.** The HTTP/1.x path removes a stream after each
// value, and this path cannot: RFC 7541 section 2.3.2 states that the HPACK dynamic table
// serves the whole connection, so a later block reads an entry that an earlier block
// inserted. `ja4hMaxStreamBytes` bounds the stream and `removeRange` removes it.
//
// **This path writes no consumed range, so `segmentCarriesNoNewRequest` removes no entry
// for it.** That removal is what tells a second connection of one address pair and port pair
// from a repeated segment of the first, and an HTTP/2 stream reaches it never. So a second
// connection of one four-tuple reads the buffer of the first, and it produces no value of
// its own. The tracker holds one issue for this limit, and the batch gate writes its
// number here.
func (f *JA4HFingerprinter) protectedHTTP2Results(
	streamKey string,
	data []byte,
	template FingerprintResult,
) []FingerprintResult {
	if f.keyLog == nil || len(data) > ja4hMaxProtectedSearchBytes {
		return nil
	}

	hello, err := parser.ParseClientHello(data)
	if err != nil || hello == nil || len(hello.Random) == 0 {
		return nil
	}

	// The handshake starts at the first protected record of the direction, so the walk skips
	// none. The count it returns is the skip of the application walk, because RFC 8446
	// section 5.3 restarts the sequence number at the key change and no record states it.
	handshakeKeys, err := f.tls13Keys(hello.Random, parser.TLS13ClientHandshakeSecretLabel)
	if err != nil {
		return nil
	}

	_, protected := parser.TLS13ContentOfStream(data, handshakeKeys, 0, parser.TLSRecordTypeHandshake)

	applicationKeys, err := f.tls13Keys(hello.Random, parser.TLS13ClientApplicationSecretLabel)
	if err != nil {
		return nil
	}

	content, _ := parser.TLS13ContentOfStream(data, applicationKeys, protected,
		parser.TLSRecordTypeApplicationData)

	requests := parser.HTTP2Requests(content)

	entry := f.rangeEntry(streamKey, template.Timestamp)
	if len(requests) <= entry.http2Emitted {
		return nil
	}

	fresh := requests[entry.http2Emitted:]
	entry.http2Emitted = len(requests)

	results := make([]FingerprintResult, 0, len(fresh))

	for _, request := range fresh {
		fingerprint := computeJA4HFromRequest(request)
		if fingerprint == "" {
			continue
		}

		result := template
		result.Fingerprint = fingerprint
		result.Raw = computeJA4HRaw(request)
		result.RawOriginalOrder = computeJA4HRawOriginalOrder(request)

		results = append(results, result)
	}

	if len(results) == 0 {
		return nil
	}

	return results
}

// tls13Keys returns the record keys of one traffic secret of the connection.
//
// It returns an error when the key log holds no secret under the label, and an error for a
// secret whose length the library does not read. `DeriveTLS13RecordKeys` states that second
// decline, and the library reads the SHA-256 key schedule of TLS_AES_128_GCM_SHA256 alone.
// A capture outside that suite therefore produces no value and no panic, and issue #492 is
// the reversal path.
func (f *JA4HFingerprinter) tls13Keys(random []byte, label string) (*parser.TLS13RecordKeys, error) {
	secret, err := f.keyLog.Secret(random, label)
	if err != nil {
		return nil, err
	}

	return parser.DeriveTLS13RecordKeys(secret)
}

// ja4hSeqBefore reports whether sequence number a comes before sequence number b.
//
// The two numbers lie within 2**31 of each other, because one stream holds
// ja4hMaxStreamBytes bytes at most. The signed conversion of the difference therefore holds
// across a wrap of the 32-bit sequence number.
// `ja4plus/utils/tcp_stream.py:38` answers the same question. The two answers differ at a
// difference of exactly 2**31, and no caller reaches that difference.
func ja4hSeqBefore(a, b uint32) bool {
	return int32(a-b) < 0
}

// segmentCarriesNoNewRequest reports whether the stream already produced a value for these
// bytes.
//
// It returns true when the segment lies inside the sequence range of a request that already
// produced a value. `ja4plus/fingerprinters/ja4h.py:196-221` states the same rule.
func (f *JA4HFingerprinter) segmentCarriesNoNewRequest(key string, seq uint32, length int) bool {
	entry, present := f.ranges[key]
	if !present || !entry.holdsConsumed {
		return false
	}

	if ja4hSeqBefore(seq, entry.consumedStart) {
		// A second connection reuses the address pair and the port pair, and it starts at its
		// own initial sequence number. That number sits below the stored one about half the
		// time. So a rule that reads the end alone loses the first request of the second
		// connection. A repeated segment carries bytes the request already held, so it starts
		// at or after the request. The buffer of the first connection leaves with the entry,
		// because the second connection numbers its bytes on its own.
		f.removeRange(key)
		return false
	}

	return !ja4hSeqBefore(entry.consumedEnd, seq+uint32(length))
}

// rememberTheConsumedRequest stores the sequence range the stream read to produce its value.
func (f *JA4HFingerprinter) rememberTheConsumedRequest(key string, start uint32, length int, now time.Time) {
	entry := f.rangeEntry(key, now)
	entry.consumedStart = start
	entry.consumedEnd = start + uint32(length)
	entry.holdsConsumed = true
	// The emission removes the stream, so the next segment opens a buffer of its own.
	entry.holdsBuffer = false
}

// recordTheBufferStart stores the lowest sequence number the reassembler holds for the
// stream.
//
// `GetStream` reassembles from the lowest sequence number, and a segment that arrives late
// moves that number down. The consumed range reads this value, so it follows each move.
func (f *JA4HFingerprinter) recordTheBufferStart(key string, seq uint32, now time.Time) {
	entry := f.rangeEntry(key, now)
	if !entry.holdsBuffer || ja4hSeqBefore(seq, entry.bufferStart) {
		entry.bufferStart = seq
		entry.holdsBuffer = true
	}
}

// rangeEntry returns the range entry of the stream, and it creates one when the table holds
// none.
//
// The insert that reaches ja4hMaxStreams removes the entry that received no segment for the
// longest time. One entry describes one stream of the reassembler, so one bound serves the
// two. `ja4plus/fingerprinters/ja4h.py:97-101` reads the reassembler for the same bound.
func (f *JA4HFingerprinter) rangeEntry(key string, now time.Time) *ja4hStreamRange {
	if entry, present := f.ranges[key]; present {
		entry.lastSeen = now
		return entry
	}

	if len(f.ranges) >= ja4hMaxStreams {
		f.removeTheLeastRecentRange()
	}

	entry := &ja4hStreamRange{lastSeen: now}
	f.ranges[key] = entry
	return entry
}

// removeTheLeastRecentRange removes the entry that received no segment for the longest time.
//
// The table holds ja4hMaxStreams entries at most, so the scan reads 100 entries at most.
func (f *JA4HFingerprinter) removeTheLeastRecentRange() {
	oldestKey := ""
	var oldest time.Time
	found := false

	for key, entry := range f.ranges {
		if !found || entry.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = entry.lastSeen
			found = true
		}
	}

	if found {
		f.removeRange(oldestKey)
	}
}

// evictAgedRanges removes each entry that received no segment for ja4hMaxStreamAge.
//
// The clock reads the packet timestamp, and never the wall clock. A capture replays faster
// than the wall clock, so a wall clock removes state that the capture still needs.
//
// The packet carries that timestamp, so a crafted capture controls it, and one timestamp
// decides the age of every stream.
//
// The forged timestamp reaches two cases, and this comment states both.
//
//   - The key of the sender. A segment dated far in the future gives every later segment of
//     that stream a negative age, so this pass removes that entry never.
//   - Every other key. The segment that carries the future timestamp ages the whole table at
//     once, so this pass removes every other stream.
//
// **The maintainer ruled the second case on 2026-08-14, and the library accepts it.** Issue
// #577 holds the ruling and the reversal path. `state_bound.go`, `ja4ssh.go` and `ja4ts.go` hold the same clock, and
// the port holds it at `ja4plus/utils/state_table.py:414` of tag `v1.1.0`.
// `age_clock_ruling_test.go` builds the separating packet.
//
// `removeTheLeastRecentRange` is the bound that holds the memory, because it reads the
// last-seen order and no age. So the loss of the second case is the tracked state, and never
// the memory.
func (f *JA4HFingerprinter) evictAgedRanges(now time.Time) {
	for key, entry := range f.ranges {
		if now.Sub(entry.lastSeen) > ja4hMaxStreamAge {
			f.removeRange(key)
		}
	}
}

// removeRange removes the range entry of the stream, and it removes the buffer of that stream.
//
// The two tables hold a bound of their own, and the fast path writes an entry and no buffer.
// So the range table reaches its bound first, and an entry that leaves alone would leave a
// buffer that no entry describes. `recordTheBufferStart` would then read the later segment as
// the start of that buffer, and the consumed range would miss the bytes below it.
// One removal path therefore serves the two tables.
func (f *JA4HFingerprinter) removeRange(key string) {
	delete(f.ranges, key)
	f.reassembler.RemoveStream(key)
}

// Reset clears the TCP stream reassembler.
// The fingerprinter keeps no result, because ProcessPacket returns each result to the
// caller. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4HFingerprinter) Reset() {
	f.ensure()

	f.reassembler = parser.NewTCPStreamReassembler(ja4hMaxStreams, ja4hMaxStreamBytes)
	f.ranges = make(map[string]*ja4hStreamRange)
}

// CleanupConnection removes internal state for the given connection.
// JA4H uses directional arrow keys: srcIP:srcPort->dstIP:dstPort.
func (f *JA4HFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
	f.ensure()

	fwd := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	rev := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
	f.reassembler.RemoveStream(fwd)
	f.reassembler.RemoveStream(rev)
	delete(f.ranges, fwd)
	delete(f.ranges, rev)
}

// ComputeJA4H extracts the TCP payload from a packet, parses it as an HTTP
// request, and returns the JA4H fingerprint string. Returns "" if the packet
// does not contain an HTTP request.
// It returns "" for a request whose body the packet does not complete, because the ruling of
// #455 states that such a request reaches no value. One rule governs every path that
// produces a JA4H value.
func ComputeJA4H(packet gopacket.Packet) string {
	payload := parser.GetTCPPayload(packet)
	if payload == nil {
		return ""
	}
	req := parser.ParseHTTPRequest(payload)
	if req == nil {
		return ""
	}
	if !parser.HTTPMessageIsComplete(payload, req) {
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

// ja4hPartA builds part a of the JA4H value from a parsed HTTP request.
//
// The base value and the two raw forms share part a, so one function builds it for the
// three. A second copy of this arithmetic would let the forms disagree.
func ja4hPartA(req *parser.HTTPRequest) string {
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

	// The count names the headers that part b hashes, so one filter serves both.
	// A second filter here counted a header with an empty name that part b dropped.
	// #286 records the asymmetry, and `ja4plus/fingerprinters/ja4h.py:419` of the Python
	// port counts the same filtered list.
	headerCount := len(ja4hHeaderNames(req))
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

	return fmt.Sprintf("%s%s%s%s%02d%s", method, ver, cookieFlag, refererFlag, headerCount, langCode)
}

// ja4hHeaderNames returns the header names in wire order, with the original case.
//
// The base value hashes this list and the two raw forms write it, so one function builds
// it for the three.
// It drops the Cookie header, the Referer header and every pseudo-header, because part a
// counts the same set.
func ja4hHeaderNames(req *parser.HTTPRequest) []string {
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
	return filteredHeaders
}

// computeJA4HFromRequest builds the JA4H fingerprint from a parsed HTTP request.
//
// Format: {method}{ver}{cookie}{referer}{count}{lang}_{header_hash}_{cookie_name_hash}_{cookie_value_hash}
func computeJA4HFromRequest(req *parser.HTTPRequest) string {
	partA := ja4hPartA(req)

	// Part B: header names in original order, excluding Cookie, Referer, pseudo-headers.
	//
	// An empty header list hashes to `e3b0c44298fc`, and part b writes no zero sentinel.
	// R18 of `docs/specs/foxio/JA4H.md` names no sentinel, and R27 confines the sentinel to
	// part c and to part d. The maintainer ruled the reference split on 2026-08-14, and
	// issue #527 is the reversal path. The port half is `Crank-Git/ja4plus#612`.
	headersStr := strings.Join(ja4hHeaderNames(req), ",")
	partB := parser.TruncatedHashNoSentinel(headersStr)

	// Part C hashes the sorted cookie names, and part D hashes the sorted cookie pairs.
	cookieNamesStr, cookieValuesStr := ja4hSortedCookieStrings(req)
	partC := parser.TruncatedHash(cookieNamesStr)
	partD := parser.TruncatedHash(cookieValuesStr)

	return fmt.Sprintf("%s_%s_%s_%s", partA, partB, partC, partD)
}

// ja4hSortedCookieStrings returns the sorted cookie name list and the sorted cookie pair
// list of a parsed HTTP request.
//
// The base value hashes both strings and the raw sorted form writes both strings, so one
// function builds them for both. A second copy of this arithmetic would let the two forms
// disagree.
//
// Both lists sort by the cookie name. `testdata/foxio/reference/python/ja4h.py:68` sorts
// the pair list by the name alone, and
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:525` writes the pair list in the
// name order too.
func ja4hSortedCookieStrings(req *parser.HTTPRequest) (string, string) {
	sortedNames := make([]string, len(req.CookieNames))
	copy(sortedNames, req.CookieNames)
	sort.Strings(sortedNames)

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

	return strings.Join(sortedNames, ","), strings.Join(pairStrs, ",")
}

// computeJA4HRawOriginalOrder builds the FoxIO `JA4H_ro` value of a parsed HTTP request.
//
// The form is `<part a>_<header names>_<cookie names>_<cookie pairs>`. Each list holds the
// wire order, which is what separates this value from the base value. The base value
// hashes the sorted cookie name and the sorted cookie pair, so a sorted raw form would
// carry no information the base value lacks.
//
// A request that carries no cookie ends after the header names and one underscore.
// `testdata/foxio/reference/python/ja4h.py` appends the two cookie fields only when the
// request holds a cookie, and 68 of the 89 per-stream vector values carry that shape.
func computeJA4HRawOriginalOrder(req *parser.HTTPRequest) string {
	raw := ja4hRawPrefix(req)

	if len(req.CookieNames) == 0 {
		return raw
	}

	pairs := make([]string, len(req.CookieNames))
	for i, name := range req.CookieNames {
		pairs[i] = name + "=" + req.Cookies[name]
	}

	return raw + strings.Join(req.CookieNames, ",") + "_" + strings.Join(pairs, ",")
}

// ja4hRawPrefix returns the part of a JA4H raw form that the two raw forms share.
//
// The form is `<part a>_<header names>_`. The cookie order is the only thing that
// separates `JA4H_r` from `JA4H_ro`, so one function builds everything before it.
func ja4hRawPrefix(req *parser.HTTPRequest) string {
	return ja4hPartA(req) + "_" + strings.Join(ja4hHeaderNames(req), ",") + "_"
}

// computeJA4HRaw builds the FoxIO `JA4H_r` value of a parsed HTTP request.
//
// The form is `<part a>_<header names>_<sorted cookie names>_<sorted cookie pairs>`. Both
// cookie lists sort by the cookie name, which is what separates this value from
// `JA4H_ro`. The base value hashes the same two strings, so the two forms read one input.
//
// A request that carries no cookie ends after the header names and one underscore.
// `testdata/foxio/reference/python/ja4h.py:82` appends the two cookie fields only when the
// request holds a cookie, and `computeJA4HRawOriginalOrder` ends the same way.
// `testdata/foxio/reference/wireshark/source/packet-ja4.c:603` writes two trailing
// underscores for that request. **#285 holds that reference split, and the maintainer rules
// it.** This function follows `computeJA4HRawOriginalOrder`, so one ruling moves both forms.
func computeJA4HRaw(req *parser.HTTPRequest) string {
	raw := ja4hRawPrefix(req)

	if len(req.CookieNames) == 0 {
		return raw
	}

	names, pairs := ja4hSortedCookieStrings(req)

	return raw + names + "_" + pairs
}
