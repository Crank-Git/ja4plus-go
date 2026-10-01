package ja4plus

import (
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
)

// These tests hold the maintainer ruling of 2026-10-01 UTC on the ALPN characters of JA4
// part a and JA4S part a. Issue #801 holds the ruling and is the reversal path, and
// `Crank-Git/ja4plus#789` holds the port half. A reader who reverses a value below reverses
// it in `Crank-Git/ja4plus` as well.
//
// The ruling follows FoxIO Python and Rust at `16b96d95`. `python/ja4.py:156-157` and
// `rust/ja4/src/tls.rs:635-647` each write `9` for a non-ASCII end. `python/ja4.py:149-158`
// and `zeek/src/ja4.cc:76-81` each write a one-character value twice. The ruling departs
// from Wireshark, which writes `99` at `wireshark/source/packet-ja4.c:1027-1028`, from Zeek,
// which writes the raw byte of a non-ASCII end, and from Rust, which writes `0` for an
// absent last character at `rust/ja4/src/tls.rs:352-353`.

// alpnRulingCases holds one case for each row of the phase 1 table of #801, plus the empty
// value. The same cases reach JA4 and JA4S, because the ruling names both.
var alpnRulingCases = []struct {
	name string
	alpn string
	want string
}{
	{"one alphanumeric byte 68", "\x68", "hh"},
	{"one printable byte 2d that is not alphanumeric", "\x2d", "--"},
	{"a last byte ff of 0x80 or higher", "\x68\xff", "h9"},
	{"a first byte ff of 0x80 or higher", "\xff\x68", "9h"},
	{"the FoxIO vector value ba ad", "\xba\xad", "99"},
	{"an empty first ALPN value", "", "00"},
}

func TestTheJA4ALPNCharactersFollowTheRulingOf801(t *testing.T) {
	for _, testCase := range alpnRulingCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := alpnParityCharacters(t, alpnParityJA4PartA(t, testCase.alpn))
			if got != testCase.want {
				t.Errorf("the JA4 ALPN characters of %q are %q, and the ruling of #801 states %q",
					testCase.alpn, got, testCase.want)
			}
		})
	}
}

func TestTheJA4SALPNCharactersFollowTheRulingOf801(t *testing.T) {
	for _, testCase := range alpnRulingCases {
		t.Run(testCase.name, func(t *testing.T) {
			extensions := []parser.TLSExtension{
				parser.MakeALPNExtension(testCase.alpn),
				parser.MakeSupportedVersionsServerExtension(0x0304),
			}
			payload := parser.BuildServerHello(0x0303, 0x1301, extensions)

			results, err := NewJA4S().ProcessPacket(buildTCPPayloadPacket(t, payload))
			if err != nil {
				t.Fatalf("ProcessPacket returned %v", err)
			}
			if len(results) == 0 {
				t.Fatal("ProcessPacket returned no result")
			}
			partA := strings.Split(results[0].Fingerprint, "_")[0]

			got := alpnParityCharacters(t, partA)
			if got != testCase.want {
				t.Errorf("the JA4S ALPN characters of %q are %q, and the ruling of #801 states %q",
					testCase.alpn, got, testCase.want)
			}
		})
	}
}
