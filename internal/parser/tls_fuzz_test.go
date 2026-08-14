package parser

import "testing"

// Every fuzz target of this package reads one untrusted payload and discards the result.
// A returned call is the whole proof, because the fuzz engine reports a panic and a hang.
// #45 adds the property assertions of FR-fuzz-14 through FR-fuzz-18 to each target.
//
// `docs/specs/features/06-fuzz-testing.md` states each requirement this file meets.

// FuzzParseClientHelloReadsAnyPayload proves that ParseClientHello returns for any TCP
// payload. FR-fuzz-1 states the requirement.
func FuzzParseClientHelloReadsAnyPayload(f *testing.F) {
	// The parser accepts this seed. It holds a well-formed ClientHello record with the
	// four extensions that a JA4 value reads.
	f.Add(BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, []TLSExtension{
		MakeSNIExtension("example.com"),
		MakeALPNExtension("h2", "http/1.1"),
		MakeSupportedVersionsClientExtension(0x0304, 0x0303),
		MakeSignatureAlgorithmsExtension(0x0403, 0x0804),
	}))

	// The parser rejects each seed below. The first holds no byte. The second states a
	// handshake length that runs past the record.
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0xff, 0xff, 0x03})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseClientHello(payload)
	})
}

// FuzzParseServerHelloReadsAnyPayload proves that ParseServerHello returns for any TCP
// payload. FR-fuzz-2 states the requirement.
func FuzzParseServerHelloReadsAnyPayload(f *testing.F) {
	// The parser accepts this seed.
	f.Add(BuildServerHello(0x0303, 0x1301, []TLSExtension{
		MakeALPNExtension("h2"),
		MakeSupportedVersionsServerExtension(0x0304),
	}))

	// The parser rejects each seed below. The second states a session identifier length
	// that runs past the record.
	f.Add([]byte{})
	f.Add([]byte{
		0x16, 0x03, 0x03, 0x00, 0x0a,
		0x02, 0x00, 0x00, 0x06, 0x03, 0x03, 0xff, 0x00, 0x00, 0x00,
	})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseServerHello(payload)
	})
}
