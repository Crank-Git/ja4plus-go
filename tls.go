package ja4plus

import (
	"errors"
	"fmt"
)

// TLS handshake types.
const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01
	tlsHandshakeServerHello = 0x02
)

// TLS extension type IDs.
const (
	extSNI                 = 0x0000
	extALPN                = 0x0010
	extSignatureAlgorithms = 0x000d
	extSupportedVersions   = 0x002b
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
}

// IsTLSHandshake returns true if the payload begins with a TLS Handshake record header.
func IsTLSHandshake(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	if payload[0] != tlsRecordTypeHandshake {
		return false
	}
	ht := payload[5]
	return ht == tlsHandshakeClientHello || ht == tlsHandshakeServerHello
}

// ParseClientHello parses a TLS ClientHello from raw TCP payload bytes.
// Returns nil, nil if the payload is not a TLS ClientHello.
// Returns nil, error if it looks like a ClientHello but is truncated/malformed.
func ParseClientHello(payload []byte) (*ClientHello, error) {
	if len(payload) < 5 {
		return nil, nil
	}
	if payload[0] != tlsRecordTypeHandshake {
		return nil, nil
	}

	recordLength := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLength {
		return nil, errors.New("TLS record truncated")
	}
	if len(payload) < 6 {
		return nil, nil
	}
	if payload[5] != tlsHandshakeClientHello {
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
	if extensionsEnd > len(payload) {
		extensionsEnd = len(payload)
	}

	for pos+4 <= extensionsEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		extDataStart := pos + 4
		extDataEnd := extDataStart + extLen
		if extDataEnd > len(payload) {
			extDataEnd = len(payload)
		}

		ch.Extensions = append(ch.Extensions, extType)
		extData := payload[extDataStart:extDataEnd]

		switch extType {
		case extSNI:
			ch.HasSNI = true
			ch.SNI = parseSNI(extData)
		case extSupportedVersions:
			ch.SupportedVersions = parseSupportedVersionsClient(extData)
		case extALPN:
			ch.ALPNProtocols = parseALPN(extData)
		case extSignatureAlgorithms:
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
	if payload[0] != tlsRecordTypeHandshake {
		return nil, nil
	}

	recordLength := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLength {
		return nil, errors.New("TLS record truncated")
	}
	if len(payload) < 6 {
		return nil, nil
	}
	if payload[5] != tlsHandshakeServerHello {
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
	if extensionsEnd > len(payload) {
		extensionsEnd = len(payload)
	}

	for pos+4 <= extensionsEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		extDataStart := pos + 4
		extDataEnd := extDataStart + extLen
		if extDataEnd > len(payload) {
			extDataEnd = len(payload)
		}

		sh.Extensions = append(sh.Extensions, extType)
		extData := payload[extDataStart:extDataEnd]

		switch extType {
		case extALPN:
			protocols := parseALPN(extData)
			if len(protocols) > 0 {
				sh.ALPNProtocol = protocols[0]
			}
		case extSupportedVersions:
			// Server selects ONE version — 2 bytes directly, no list length byte
			if extLen >= 2 {
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

// tlsVersionString maps a TLS version number to the JA4 version string.
// Exported for use by JA4 fingerprinter; not part of the public API contract.
func tlsVersionString(version uint16) string {
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

// alpnValue computes the 2-char ALPN field for JA4 from ALPN protocols.
func alpnValue(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}
	first := protocols[0]
	if first == "" {
		return "00"
	}
	if first[0] > 127 {
		return "99"
	}
	if len(first) == 1 {
		return fmt.Sprintf("%c%c", first[0], first[0])
	}
	return fmt.Sprintf("%c%c", first[0], first[len(first)-1])
}
