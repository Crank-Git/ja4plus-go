package parser

import (
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/fuzzprop"
)

// Every fuzz target of this package reads one untrusted payload and discards the result.
// A returned call is the whole proof, because the fuzz engine reports a panic and a hang.
//
// Every target calls `ExactInput` and `Check` of `internal/fuzzprop`, and those two calls
// carry FR-fuzz-14 through FR-fuzz-18. The package comment of `internal/fuzzprop` states
// which requirement each one meets, and it states why FR-fuzz-14 needs no code.
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
		input := fuzzprop.ExactInput(payload)

		fuzzprop.Check(t, len(input), func() any {
			hello, err := ParseClientHello(input)

			return []any{hello, err}
		})
	})
}

// FuzzParseServerHelloReadsAnyPayload proves that ParseServerHello returns for any TCP
// payload. FR-fuzz-2 states the requirement.
//
// This target found a real crash on its first 30-second run, and `Crank-Git/ja4plus-go`
// issue 556 holds it. `ParseServerHello` panics on a record that declares a
// supported_versions length of 2 or more and that holds no extension data. Never weaken
// the target to make a run pass.
//
// #556 repaired `internal/parser/tls.go` and merged to `dev` on 2026-08-14, so this target
// passes today. The crashing input is a tracked seed of this target, and it is the worked
// example of FR-fuzz-24.
//
// The citation above names the repository, and it writes no bare number.
// `issueCitationHighWaterMark` in `issue_citation_namespace_test.go` bounds a bare number,
// and the Epic 6 round re-measured that mark.
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
		input := fuzzprop.ExactInput(payload)

		fuzzprop.Check(t, len(input), func() any {
			hello, err := ParseServerHello(input)

			return []any{hello, err}
		})
	})
}
