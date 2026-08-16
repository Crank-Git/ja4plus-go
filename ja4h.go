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
	// http2 holds the incremental decode of a protected HTTP/2 connection, and nil for every
	// other stream. `removeRange` is its removal path, so it leaves with this entry.
	http2 *ja4hHTTP2Decode
}

// ja4hHTTP2Decode holds the decode of one protected HTTP/2 connection.
//
// **The two readers read each byte of the stream once, so the reassembler keeps no byte that
// they already read.** A whole-stream decode costs the whole stream at each packet, and the
// bound that held that cost stopped the connection. #753 records the two limits that this
// type removes.
//
// **The state of one connection is the HPACK dynamic table**, which RFC 7541 section 2.3.2
// gives to the whole connection. `parser.HTTP2Reader` holds it, and
// `http2MaxDynamicTableSize` bounds it.
//
// One entry of the range table holds one decode, so `ja4hMaxStreams` bounds the count and
// `removeRange` is the removal path. `.claude/rules/concurrency.md` states that a new state
// needs both.
type ja4hHTTP2Decode struct {
	// records opens the protected records of the stream. It holds the traffic keys, so the
	// decode needs no later ClientHello.
	records *parser.TLS13StreamReader
	// requests decodes the HTTP/2 frames that the records carry.
	requests *parser.HTTP2Reader
	// nextSeq names the sequence number of the first byte that the readers have not read.
	// The reassembler holds no byte below it, so this number places the buffer of the next
	// packet against the bytes the readers already read.
	nextSeq uint32
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

	// A stream whose HTTP/2 decode is open carries protected records alone, so neither
	// plaintext parse below reads a request of it. Every packet is untrusted input, and a run
	// of ciphertext bytes can otherwise read as a request line.
	protected := f.holdsHTTP2Decode(streamKey)

	// Try single-packet parse first (fast path)
	if !protected && parser.IsHTTPRequest(payload) {
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

	if protected || !parser.IsHTTPRequest(assembled) {
		// An HTTP/2 request carries no request line, so it reaches this branch and never the
		// two parses above. The reader reads each byte of the stream once, because the HPACK
		// dynamic table reads every earlier header block of the connection.
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

// holdsHTTP2Decode reports whether the stream carries a protected HTTP/2 connection that a
// decode already opened.
//
// A live decode reads protected records alone, so the plaintext parse reads no request of
// that stream. Every packet is untrusted input, and a run of ciphertext bytes can otherwise
// read as a request line.
// It creates no entry, because a stream that reaches no decode must leave the table
// untouched.
func (f *JA4HFingerprinter) holdsHTTP2Decode(key string) bool {
	entry, present := f.ranges[key]

	return present && entry.http2 != nil
}

// protectedHTTP2Results returns one result for each HTTP/2 request that the protected
// records of one stream newly carry.
//
// It returns nil when the caller supplied no key log, and nil when the key log holds no
// secret for the connection.
//
// **The reader reads the client half of the connection alone.** A key log names each
// connection by the Random field of its ClientHello, and that message travels on the
// request stream. So the response stream parses no ClientHello and this reader declines it,
// which is also the direction that carries no request.
//
// **The stream leaves the reassembler at each packet, and the decode holds what it still
// needs.** `ja4hHTTP2Decode` holds four things: the traffic keys, the record sequence number,
// the HPACK dynamic table and one incomplete record. So the next packet opens a buffer of its
// own, and the stream of a long connection reaches no bound of the reassembler.
//
// **This path writes the consumed range that `segmentCarriesNoNewRequest` reads.** A repeated
// segment then produces no second value. A second connection of one address pair and port
// pair then removes the entry of the first.
func (f *JA4HFingerprinter) protectedHTTP2Results(
	streamKey string,
	data []byte,
	template FingerprintResult,
) []FingerprintResult {
	if f.keyLog == nil {
		return nil
	}

	entry := f.rangeEntry(streamKey, template.Timestamp)
	buffered := len(data)

	decode, fresh := f.http2Decode(entry, data)
	if decode == nil {
		return nil
	}

	requests := decode.requests.Read(decode.records.Read(fresh))

	// The two readers hold every byte they still need, so the reassembler holds none of them.
	// The consumed range names the bytes that left, and `recordTheBufferStart` opens the next
	// buffer at the segment that follows them.
	if ja4hSeqBefore(decode.nextSeq, entry.bufferStart+uint32(buffered)) {
		decode.nextSeq = entry.bufferStart + uint32(buffered)
	}

	f.reassembler.RemoveStream(streamKey)
	f.rememberTheConsumedStream(entry, entry.bufferStart, buffered)

	results := make([]FingerprintResult, 0, len(requests))

	for _, request := range requests {
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

// http2Decode returns the decode of the stream, and the bytes of the buffer that no reader
// has read.
//
// It returns the decode that the entry holds, where the buffer follows the bytes that decode
// already read. It opens a decode from the ClientHello of the buffer otherwise, and it then
// returns the whole buffer.
// It returns nil where the buffer carries no ClientHello, and nil where the key log holds no
// secret of the connection.
//
// **A buffer that the decode cannot follow opens a decode of its own.** Two cases reach that
// branch. A second connection of one address pair and port pair opens above the bytes the
// first connection read, and a lost segment leaves a gap. The first case then reads the
// ClientHello of the second connection, and the second case reads none and produces no value.
func (f *JA4HFingerprinter) http2Decode(
	entry *ja4hStreamRange,
	data []byte,
) (*ja4hHTTP2Decode, []byte) {
	if entry.http2 != nil && entry.holdsBuffer {
		// The signed conversion holds across a wrap of the 32-bit sequence number, because one
		// buffer holds ja4hMaxStreamBytes bytes at most.
		offset := int(int32(entry.http2.nextSeq - entry.bufferStart))
		if offset >= 0 {
			// A buffer that ends below the first unread byte carries read bytes alone, so the
			// readers receive an empty chunk.
			return entry.http2, data[min(offset, len(data)):]
		}
	}

	decode := f.openHTTP2Decode(data)
	if decode == nil {
		return nil, nil
	}

	// The decode opens at the first byte of the buffer, and the caller then advances the
	// number. A fresh decode holds no number of its own, so this assignment states it once.
	decode.nextSeq = entry.bufferStart
	entry.http2 = decode
	// The consumed range names the bytes of one connection, so a decode of a second connection
	// opens a range of its own.
	entry.holdsConsumed = false

	return decode, data
}

// openHTTP2Decode returns a decode of the connection that the buffer opens.
//
// It returns nil where the buffer carries no ClientHello, and nil where the key log holds no
// secret of that ClientHello.
//
// **The ClientHello is what tells a second connection from a lost segment.** A buffer that
// opens above the bytes an earlier decode read reaches this function, and a TLS 1.3 client
// sends a ClientHello at the start of a connection alone. So a buffer that carries one names
// a second connection, and a buffer that carries none names a hole that a later segment
// fills.
func (f *JA4HFingerprinter) openHTTP2Decode(data []byte) *ja4hHTTP2Decode {
	hello, err := parser.ParseClientHello(data)
	if err != nil || hello == nil || len(hello.Random) == 0 {
		return nil
	}

	handshakeKeys, err := f.tls13Keys(hello.Random, parser.TLS13ClientHandshakeSecretLabel)
	if err != nil {
		return nil
	}

	applicationKeys, err := f.tls13Keys(hello.Random, parser.TLS13ClientApplicationSecretLabel)
	if err != nil {
		return nil
	}

	return &ja4hHTTP2Decode{
		records:  parser.NewTLS13StreamReader(handshakeKeys, applicationKeys),
		requests: parser.NewHTTP2Reader(),
	}
}

// ja4hHTTP2ConsumedWindow bounds the sequence range that one protected HTTP/2 stream holds.
//
// `ja4hSeqBefore` reads the signed difference of two sequence numbers, so it needs the two
// within 2**31 of each other. One connection carries any number of bytes, and this window
// keeps the consumed range inside that distance. A segment that TCP reorders arrives within
// milliseconds of its neighbors, so no reordered segment reaches the far end of this window.
const ja4hHTTP2ConsumedWindow = 1 << 30

// rememberTheConsumedStream advances the consumed range of a protected HTTP/2 stream.
//
// The range opens at the first byte of the connection, and it never moves back. So a segment
// that TCP reorders sits inside the range, and `segmentCarriesNoNewRequest` reads it as a
// repeated segment rather than as a second connection.
// `rememberTheConsumedRequest` names one request instead, because the HTTP/1.x path removes
// the stream at each value and this path removes it at each packet.
func (f *JA4HFingerprinter) rememberTheConsumedStream(entry *ja4hStreamRange, start uint32, length int) {
	end := start + uint32(length)

	if !entry.holdsConsumed {
		entry.consumedStart = start
		entry.consumedEnd = end
		entry.holdsConsumed = true
	} else if ja4hSeqBefore(entry.consumedEnd, end) {
		entry.consumedEnd = end
	}

	if int32(entry.consumedEnd-entry.consumedStart) > ja4hHTTP2ConsumedWindow {
		entry.consumedStart = entry.consumedEnd - ja4hHTTP2ConsumedWindow
	}

	// The emission removes the stream, so the next segment opens a buffer of its own.
	entry.holdsBuffer = false
}

// tls13Keys returns the record keys of one traffic secret of the connection.
//
// It returns an error when the key log holds no secret under the label, and an error for a
// secret whose length the library does not read. `DeriveTLS13RecordKeys` states that second
// decline, and the library reads the SHA-256 key schedule of TLS_AES_128_GCM_SHA256 alone.
// A capture outside that suite therefore produces no value and no panic, and issue #492 is
// the reversal path.
//
// **`protectedCertificates` of `ja4x.go` runs the same two steps inline**, and the two
// sites are not one helper. A reader who changes the key schedule changes both.
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
