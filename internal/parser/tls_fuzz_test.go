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

	// The parser rejects each seed below. The first holds no byte. The second holds 10
	// bytes, and the parser reports `ClientHello truncated: too short for version`.
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0xff, 0xff, 0x03})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseClientHello(payload)
	})
}

// FuzzParseServerHelloReadsAnyPayload proves that ParseServerHello returns for any TCP
// payload. FR-fuzz-2 states the requirement.
//
// This target found a real crash on its first 30-second run, and `Crank-Git/ja4plus-go`
// issue 556 holds it. `ParseServerHello` panics on a record that declares a
// supported_versions length of 2 or more and that holds no extension data. So this target
// fails until that issue lands, and the failure is the target doing its work. Never weaken
// the target to make the run pass.
//
// The citation above names the repository, and it writes no bare number.
// `issueCitationHighWaterMark` in `issue_citation_namespace_test.go` holds 543, and this
// repository has allocated more numbers since that measurement. A bare number above the
// mark fails that guard, and this member owns no file that carries the re-measurement.
//
// The seeds below panic for no input, so `go test ./...` replays them and passes.
func FuzzParseServerHelloReadsAnyPayload(f *testing.F) {
	// The parser accepts each seed below. The first is a well-formed record. The second
	// holds 15 bytes, and the parser returns the version it read and no error.
	f.Add(BuildServerHello(0x0303, 0x1301, []TLSExtension{
		MakeALPNExtension("h2"),
		MakeSupportedVersionsServerExtension(0x0304),
	}))
	f.Add([]byte{
		0x16, 0x03, 0x03, 0x00, 0x0a,
		0x02, 0x00, 0x00, 0x06, 0x03, 0x03, 0xff, 0x00, 0x00, 0x00,
	})

	// The parser rejects this seed, because it holds no byte.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseServerHello(payload)
	})
}
