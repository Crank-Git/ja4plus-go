package parser

import (
	"errors"
	"fmt"
)

// TLS handshake types.
const (
	TLSRecordTypeHandshake  = 0x16
	TLSHandshakeClientHello = 0x01
	TLSHandshakeServerHello = 0x02
)

// TLS extension type IDs.
const (
	ExtSNI                 = 0x0000
	ExtALPN                = 0x0010
	ExtSignatureAlgorithms = 0x000d
	ExtSupportedVersions   = 0x002b
)

// ClientHello holds parsed fields from a TLS ClientHello message.
type ClientHello struct {
	Version             uint16
	CipherSuites        []uint16
	Extensions          []uint16 // extension type IDs in original order
	SNI                 string   // hostname, or "" if absent/malformed
	HasSNI              bool     // true if SNI extension (0x0000) was present
	ALPNProtocols       []string
	SupportedVersions   []uint16
	SignatureAlgorithms []uint16
	IsQUIC              bool
	IsDTLS              bool
}

// ServerHello holds parsed fields from a TLS ServerHello message.
type ServerHello struct {
	Version           uint16
	CipherSuite       uint16
	Extensions        []uint16
	ALPNProtocol      string
	SupportedVersions []uint16
	IsQUIC            bool
	IsDTLS            bool
}

// IsTLSHandshake returns true if the payload begins with a TLS Handshake record header.
func IsTLSHandshake(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	if payload[0] != TLSRecordTypeHandshake {
		return false
	}
	ht := payload[5]
	return ht == TLSHandshakeClientHello || ht == TLSHandshakeServerHello
}

// handshakeRecordOffset returns the offset of the first handshake record of the payload.
// It returns -1 when the payload holds no handshake record.
//
// A TLS 1.3 client in compatibility mode sends a ChangeCipherSpec record before its second
// client hello. One TCP segment carries both records. A reader that reads only the first
// byte of that segment misses the second hello. Issue #295 records the 40 absent values.
// `testdata/foxio/pcap/tls-handshake.pcapng` packet 125 holds the two records.
//
// The walk steps over a record of any type that is not a handshake record. A peer may send
// a record other than a ChangeCipherSpec record first.
// `ja4plus/utils/tls_utils.py:76-103` walks the same way in the Python port.
//
// Every payload is untrusted input. The walk advances by at least 5 bytes for each record.
// It stops at a length field that passes the end of the payload.
func handshakeRecordOffset(payload []byte) int {
	for pos := 0; pos+5 <= len(payload); {
		if payload[pos] == TLSRecordTypeHandshake {
			return pos
		}

		recordLength := int(payload[pos+3])<<8 | int(payload[pos+4])

		// A step needs the whole record. The walk stops at a length that passes the
		// end of the payload.
		next := pos + 5 + recordLength
		if next > len(payload) {
			return -1
		}

		pos = next
	}

	return -1
}

// ParseClientHello parses a TLS ClientHello from raw TCP payload bytes.
// Returns nil, nil if the payload is not a TLS ClientHello.
// Returns nil, error if it looks like a ClientHello but is truncated/malformed.
//
// It reads the first handshake record of the payload. It steps over each record in front
// of that one. A TLS 1.3 client sends a ChangeCipherSpec record before its second client
// hello. Issue #295 records the values that the first-byte reader missed.
func ParseClientHello(payload []byte) (*ClientHello, error) {
	offset := handshakeRecordOffset(payload)
	if offset < 0 {
		return nil, nil
	}
	payload = payload[offset:]

	if len(payload) < 5 {
		return nil, nil
	}

	recordLength := int(payload[3])<<8 | int(payload[4])

	// recordEnd bounds every later read. A TCP payload can carry more than one TLS
	// record, and a length field of this record must not reach into the next one.
	recordEnd := 5 + recordLength

	if len(payload) < 5+recordLength {
		return nil, errors.New("TLS record truncated")
	}
	if len(payload) < 6 {
		return nil, nil
	}
	if payload[5] != TLSHandshakeClientHello {
		return nil, nil
	}
	if len(payload) < 11 {
		return nil, errors.New("ClientHello truncated: too short for version")
	}

	ch := &ClientHello{
		Version: uint16(payload[9])<<8 | uint16(payload[10]),
	}

	// Skip record header(5) + handshake header(4) + version(2) + random(32)
	pos := 43

	// Session ID
	if pos+1 > len(payload) {
		return nil, errors.New("ClientHello truncated: no session ID length")
	}
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen

	// Cipher suites
	if pos+2 > len(payload) {
		return nil, errors.New("ClientHello truncated: no cipher suites length")
	}
	cipherSuitesLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2

	ciphers := make([]uint16, 0, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen; i += 2 {
		if pos+i+2 > len(payload) {
			break
		}
		c := uint16(payload[pos+i])<<8 | uint16(payload[pos+i+1])
		ciphers = append(ciphers, c)
	}
	ch.CipherSuites = ciphers
	pos += cipherSuitesLen

	// Compression methods
	if pos+1 > len(payload) {
		return ch, nil // partial parse is OK per Python reference
	}
	compressionLen := int(payload[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(payload) {
		return ch, nil
	}
	extensionsLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > recordEnd {
		extensionsEnd = recordEnd
	}

	for pos+4 <= extensionsEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		extDataStart := pos + 4
		extDataEnd := extDataStart + extLen
		if extDataEnd > recordEnd {
			extDataEnd = recordEnd
		}

		ch.Extensions = append(ch.Extensions, extType)
		extData := payload[extDataStart:extDataEnd]

		switch extType {
		case ExtSNI:
			ch.HasSNI = true
			ch.SNI = parseSNI(extData)
		case ExtSupportedVersions:
			ch.SupportedVersions = parseSupportedVersionsClient(extData)
		case ExtALPN:
			ch.ALPNProtocols = parseALPN(extData)
		case ExtSignatureAlgorithms:
			ch.SignatureAlgorithms = parseSignatureAlgorithms(extData)
		}

		pos = extDataStart + extLen
	}

	return ch, nil
}

// ParseServerHello parses a TLS ServerHello from raw TCP payload bytes.
// Returns nil, nil if the payload is not a TLS ServerHello.
func ParseServerHello(payload []byte) (*ServerHello, error) {
	if len(payload) < 5 {
		return nil, nil
	}
	if payload[0] != TLSRecordTypeHandshake {
		return nil, nil
	}

	recordLength := int(payload[3])<<8 | int(payload[4])

	// recordEnd bounds every later read. A TCP payload can carry more than one TLS
	// record, and a length field of this record must not reach into the next one.
	recordEnd := 5 + recordLength

	if len(payload) < 5+recordLength {
		return nil, errors.New("TLS record truncated")
	}
	if len(payload) < 6 {
		return nil, nil
	}
	if payload[5] != TLSHandshakeServerHello {
		return nil, nil
	}
	if len(payload) < 11 {
		return nil, errors.New("ServerHello truncated: too short for version")
	}

	sh := &ServerHello{
		Version: uint16(payload[9])<<8 | uint16(payload[10]),
	}

	// Skip record header(5) + handshake header(4) + version(2) + random(32)
	pos := 43

	// Session ID
	if pos+1 > len(payload) {
		return sh, nil
	}
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen

	// Single cipher suite
	if pos+2 > len(payload) {
		return sh, nil
	}
	sh.CipherSuite = uint16(payload[pos])<<8 | uint16(payload[pos+1])
	pos += 2

	// Compression method (1 byte)
	if pos+1 > len(payload) {
		return sh, nil
	}
	pos += 1

	// Extensions
	if pos+2 > len(payload) {
		return sh, nil
	}
	extensionsLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > recordEnd {
		extensionsEnd = recordEnd
	}

	for pos+4 <= extensionsEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		extDataStart := pos + 4
		extDataEnd := extDataStart + extLen
		if extDataEnd > recordEnd {
			extDataEnd = recordEnd
		}

		sh.Extensions = append(sh.Extensions, extType)
		extData := payload[extDataStart:extDataEnd]

		switch extType {
		case ExtALPN:
			protocols := parseALPN(extData)
			if len(protocols) > 0 {
				sh.ALPNProtocol = protocols[0]
			}
		case ExtSupportedVersions:
			// Server selects ONE version -- 2 bytes directly, no list length byte
			//
			// The guard reads the length of extData, and never extLen. extLen is the
			// length the wire declares, and the clamp above shortens extData to the end
			// of the record. A crafted record makes the two disagree, and #556 records
			// the panic that the declared length produced.
			if len(extData) >= 2 {
				sv := uint16(extData[0])<<8 | uint16(extData[1])
				sh.SupportedVersions = []uint16{sv}
			}
		}

		pos = extDataStart + extLen
	}

	// If supported_versions present and non-GREASE, update version
	if len(sh.SupportedVersions) > 0 {
		for _, v := range sh.SupportedVersions {
			if !IsGreaseValue(v) {
				sh.Version = v
				break
			}
		}
	}

	return sh, nil
}

// TLSVersionString maps a TLS version number to the JA4 version string.
func TLSVersionString(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0200:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ALPNValue returns the two ALPN characters that JA4 and JA4S carry.
//
// It returns `00` when the protocol list is empty, and when the first ALPN value is empty.
// It returns the first byte and the last byte when both bytes fall inside the printable
// ASCII range 0x20-0x7E. It repeats the byte when the first ALPN value holds one
// alphanumeric byte. It returns `99` in every other case.
//
// The FoxIO prose states a different rule, and a measurement contradicts the prose.
// `technical_details/JA4.md:95` states the first and last character of the hexadecimal
// form of the whole first ALPN value. The FoxIO vector `tls-non-ascii-alpn.pcapng` holds
// `99` for the first ALPN value `0xba 0xad`, and `.claude/rules/parity.md` rule 1 states
// that the vector decides. `docs/specs/foxio/JA4.md` R18 and R19 record the split, and
// Reading 5 records the tshark text form that causes it.
//
// The port issues `Crank-Git/ja4plus#127`, `Crank-Git/ja4plus#141` and
// `Crank-Git/ja4plus#162` hold the ruling, and `ja4_alpn_parity_test.go` holds the
// separating packets. Issue #50 adopted the rule here.
//
// Every `%c` below writes a byte of 0x7E or lower, and each guard keeps that true. `%c`
// reads its argument as a code point, so a byte above 0x7F would reach the fingerprint as
// two UTF-8 bytes. A guard that widens past 0x7E must build the string from a byte slice.
func ALPNValue(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}
	first := protocols[0]
	if first == "" {
		return "00"
	}

	firstByte := first[0]
	lastByte := first[len(first)-1]

	// The two FoxIO implementations dispute every one-byte value, so this case keeps the
	// alphanumeric test. `rust/ja4/src/tls.rs:334` writes `0` for the absent last
	// character. `python/ja4.py:276` leaves a one-byte value at one character, because its
	// condition `len(alpn) > 2` is false.
	if len(first) == 1 {
		if alpnIsAlnum(firstByte) {
			return fmt.Sprintf("%c%c", firstByte, firstByte)
		}
		return "99"
	}

	// Both FoxIO implementations pass a printable ASCII byte through, whether or not that
	// byte is alphanumeric. The range stops at 0x7E, because the two implementations agree
	// only inside it.
	if alpnIsPrintableASCII(firstByte) && alpnIsPrintableASCII(lastByte) {
		return fmt.Sprintf("%c%c", firstByte, lastByte)
	}

	return "99"
}

// alpnIsAlnum reports whether b is an ASCII alphanumeric byte:
// 0x30-0x39 ('0'-'9'), 0x41-0x5A ('A'-'Z'), or 0x61-0x7A ('a'-'z').
func alpnIsAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// alpnIsPrintableASCII reports whether b falls inside the printable ASCII range
// 0x20-0x7E. A byte outside that range reaches the two FoxIO implementations as tshark
// text rather than as a byte, and they then disagree.
func alpnIsPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}

// parseSNI extracts the hostname from SNI extension data.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return "" // extension present but can't parse
	}
	// SNI list length (2 bytes)
	pos := 2
	if pos+3 > len(data) {
		return ""
	}
	sniType := data[pos]
	pos++
	hostnameLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if sniType == 0 && pos+hostnameLen <= len(data) {
		hostname := string(data[pos : pos+hostnameLen])
		if hostname != "" {
			return hostname
		}
	}
	return ""
}

// parseSupportedVersionsClient parses the supported_versions extension from a ClientHello.
func parseSupportedVersionsClient(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	pos := 1
	end := 1 + listLen
	if end > len(data) {
		end = len(data)
	}

	var versions []uint16
	for pos+2 <= end {
		v := uint16(data[pos])<<8 | uint16(data[pos+1])
		versions = append(versions, v)
		pos += 2
	}
	return versions
}

// parseALPN parses the ALPN extension data.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	alpnListLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := 2 + alpnListLen
	if end > len(data) {
		end = len(data)
	}

	var protocols []string
	for pos < end {
		if pos+1 > len(data) {
			break
		}
		protoLen := int(data[pos])
		pos++
		if pos+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[pos:pos+protoLen]))
		pos += protoLen
	}
	return protocols
}

// parseSignatureAlgorithms parses the signature_algorithms extension data.
func parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := 2 + listLen
	if end > len(data) {
		end = len(data)
	}

	var algs []uint16
	for pos+2 <= end {
		a := uint16(data[pos])<<8 | uint16(data[pos+1])
		algs = append(algs, a)
		pos += 2
	}
	return algs
}
