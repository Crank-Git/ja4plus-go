package parser

// TLSExtension is a helper type for building TLS extension data in tests.
type TLSExtension struct {
	Typ  uint16
	Data []byte
}

// BuildClientHello constructs a raw TLS ClientHello payload from components.
func BuildClientHello(version uint16, ciphers []uint16, extensions []TLSExtension) []byte {
	// Build inner ClientHello body (after handshake header)
	var body []byte

	// Version (2 bytes)
	body = append(body, byte(version>>8), byte(version))

	// Random (32 bytes of zeros)
	body = append(body, make([]byte, 32)...)

	// Session ID length = 0
	body = append(body, 0x00)

	// Cipher suites
	csLen := len(ciphers) * 2
	body = append(body, byte(csLen>>8), byte(csLen))
	for _, c := range ciphers {
		body = append(body, byte(c>>8), byte(c))
	}

	// Compression methods: 1 method, null
	body = append(body, 0x01, 0x00)

	// Extensions
	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.Typ>>8), byte(ext.Typ))
		extBytes = append(extBytes, byte(len(ext.Data)>>8), byte(len(ext.Data)))
		extBytes = append(extBytes, ext.Data...)
	}
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	// Handshake header: type(1) + length(3)
	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record header: type(1) + version(2) + length(2)
	var record []byte
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// BuildServerHello constructs a raw TLS ServerHello payload.
func BuildServerHello(version uint16, cipher uint16, extensions []TLSExtension) []byte {
	var body []byte

	// Version (2 bytes)
	body = append(body, byte(version>>8), byte(version))

	// Random (32 bytes)
	body = append(body, make([]byte, 32)...)

	// Session ID length = 0
	body = append(body, 0x00)

	// Single cipher suite
	body = append(body, byte(cipher>>8), byte(cipher))

	// Compression method: null
	body = append(body, 0x00)

	// Extensions
	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.Typ>>8), byte(ext.Typ))
		extBytes = append(extBytes, byte(len(ext.Data)>>8), byte(len(ext.Data)))
		extBytes = append(extBytes, ext.Data...)
	}
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	// Handshake header
	var handshake []byte
	handshake = append(handshake, 0x02) // ServerHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record header
	var record []byte
	record = append(record, 0x16)
	record = append(record, 0x03, 0x03)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// MakeSNIExtension creates a TLS SNI extension with the given hostname.
func MakeSNIExtension(hostname string) TLSExtension {
	hBytes := []byte(hostname)
	hLen := len(hBytes)
	totalLen := 1 + 2 + hLen
	var data []byte
	data = append(data, byte((totalLen)>>8), byte(totalLen))
	data = append(data, 0x00)
	data = append(data, byte(hLen>>8), byte(hLen))
	data = append(data, hBytes...)
	return TLSExtension{Typ: ExtSNI, Data: data}
}

// MakeALPNExtension creates a TLS ALPN extension with the given protocols.
func MakeALPNExtension(protocols ...string) TLSExtension {
	var list []byte
	for _, p := range protocols {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	var data []byte
	data = append(data, byte(len(list)>>8), byte(len(list)))
	data = append(data, list...)
	return TLSExtension{Typ: ExtALPN, Data: data}
}

// MakeSupportedVersionsClientExtension creates a client supported_versions extension.
func MakeSupportedVersionsClientExtension(versions ...uint16) TLSExtension {
	listLen := len(versions) * 2
	data := []byte{byte(listLen)}
	for _, v := range versions {
		data = append(data, byte(v>>8), byte(v))
	}
	return TLSExtension{Typ: ExtSupportedVersions, Data: data}
}

// MakeSupportedVersionsServerExtension creates a server supported_versions extension.
func MakeSupportedVersionsServerExtension(version uint16) TLSExtension {
	return TLSExtension{
		Typ:  ExtSupportedVersions,
		Data: []byte{byte(version >> 8), byte(version)},
	}
}

// MakeSignatureAlgorithmsExtension creates a signature_algorithms extension.
func MakeSignatureAlgorithmsExtension(algs ...uint16) TLSExtension {
	listLen := len(algs) * 2
	var data []byte
	data = append(data, byte(listLen>>8), byte(listLen))
	for _, a := range algs {
		data = append(data, byte(a>>8), byte(a))
	}
	return TLSExtension{Typ: ExtSignatureAlgorithms, Data: data}
}
