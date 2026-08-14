package parser

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// seedGenerate reports whether this run writes the seed files.
// The environment variable selects the write, so an ordinary test run compares the tracked
// file against the value the test builds. A seed that a later change moves therefore fails
// the ordinary run, and it never drifts from the value this file states.
func seedGenerate() bool { return os.Getenv("JA4PLUS_SEEDGEN") == "1" }

// seedNamed holds each seed path that `seedCorpusFile` reached in this run.
// `seedCorpusHoldsNoOtherFile` reads it. A rename that leaves the old file behind then
// fails the test, so no seed keeps a name that states a behavior it does not hold.
var seedNamed = map[string]bool{}

// seedCorpusHoldsNoOtherFile fails when a target directory holds a file that the test
// names no value for. A file with the `issue-` prefix is a crash that the fuzzer wrote,
// and FR-fuzz-24 keeps it, so this check passes over it.
func seedCorpusHoldsNoOtherFile(t *testing.T) {
	t.Helper()

	root := filepath.Join("testdata", "fuzz")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		// `README.md` sits beside the target directories, and Go reads no seed there.
		if filepath.Dir(path) == root {
			return nil
		}
		if strings.HasPrefix(entry.Name(), "issue-") || seedNamed[path] {
			return nil
		}

		t.Errorf("the seed corpus holds %s, and no test builds it", path)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// seedCorpusFile writes one seed file, or it compares the tracked file against the lines.
// `target` names the fuzz target, and `name` names the file under `testdata/fuzz/<target>/`.
func seedCorpusFile(t *testing.T, target, name string, lines ...string) {
	t.Helper()

	path := filepath.Join("testdata", "fuzz", target, name)
	body := "go test fuzz v1\n" + strings.Join(lines, "\n") + "\n"
	seedNamed[path] = true

	if seedGenerate() {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(body))

		return
	}

	tracked, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the seed corpus holds no %s: %v", path, err)
	}
	if string(tracked) != body {
		t.Fatalf("the tracked seed %s differs from the value this test builds", path)
	}
}

func seedPacket(frame []byte) gopacket.Packet {
	return gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
}

func seedBytes(b []byte) string {
	var sb strings.Builder
	sb.WriteString("[]byte(\"")
	for _, c := range b {
		fmt.Fprintf(&sb, "\\x%02x", c)
	}
	sb.WriteString("\")")

	return sb.String()
}

func seedRead(t *testing.T, target, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", "fuzz", target, name)
	seedNamed[path] = true

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(strings.Split(string(raw), "\n")[1])
	line = strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")")
	value, err := strconv.Unquote(line)
	if err != nil {
		t.Fatal(err)
	}

	return []byte(value)
}

// checkTheReducedSeeds proves that each seed of `scripts/seed-fuzz.sh` reaches the parser,
// so FR-fuzz-20 holds for the derived seeds. The script builds each one from the
// identifiers of a capture, and it copies no byte.
func checkTheReducedSeeds(t *testing.T) {
	t.Helper()

	hello, err := ParseClientHello(seedRead(t,
		"FuzzParseClientHelloReadsAnyPayload", "accepts-the-reduced-client-hello-of-badcurveball"))
	if err != nil {
		t.Fatalf("reduced client hello: %v", err)
	}
	t.Logf("reduced client hello: ciphers=%d extensions=%d SNI=%q ALPN=%v",
		len(hello.CipherSuites), len(hello.Extensions), hello.SNI, hello.ALPNProtocols)

	server, err := ParseServerHello(seedRead(t,
		"FuzzParseServerHelloReadsAnyPayload", "accepts-the-reduced-server-hello-of-badcurveball"))
	if err != nil {
		t.Fatalf("reduced server hello: %v", err)
	}
	t.Logf("reduced server hello: cipher=%04x extensions=%d ALPN=%v",
		server.CipherSuite, len(server.Extensions), server.ALPNProtocol)

	request := ParseHTTPRequest(seedRead(t,
		"FuzzParseHTTPRequestReadsAnyPayload", "accepts-the-reduced-request-of-CVE-2018-6794"))
	if request == nil {
		t.Fatal("reduced request returns nil")
	}
	t.Logf("reduced request: method=%s headers=%v", request.Method, request.HeaderNames)
}

// TestEachTargetOfThisPackageHoldsAnAcceptedSeedAndARejectedSeed builds every seed of
// `testdata/fuzz/`, and it asserts the result of the parser for each one. FR-fuzz-19,
// FR-fuzz-20 and FR-fuzz-21 state the requirements.
//
// `JA4PLUS_SEEDGEN=1` writes the files. Every other run compares the tracked file against
// the value this test builds, so no seed drifts from the statement above it.
func TestEachTargetOfThisPackageHoldsAnAcceptedSeedAndARejectedSeed(t *testing.T) {
	// --- FuzzParseClientHelloReadsAnyPayload
	chAccept := BuildClientHello(0x0303, []uint16{0x1301}, nil)
	if _, err := ParseClientHello(chAccept); err != nil {
		t.Fatalf("client hello accept seed: %v", err)
	}
	seedCorpusFile(t, "FuzzParseClientHelloReadsAnyPayload",
		"accepts-a-client-hello-that-carries-no-extension", seedBytes(chAccept))

	chReject := BuildClientHello(0x0303, []uint16{0x1301}, []TLSExtension{MakeSNIExtension("a.invalid")})
	chReject = append(chReject[:len(chReject)-4], 0x00, 0x00)
	if _, err := ParseClientHello(chReject); err == nil {
		t.Fatal("client hello reject seed reports no error")
	} else {
		t.Logf("client hello reject: %v", err)
	}
	seedCorpusFile(t, "FuzzParseClientHelloReadsAnyPayload",
		"rejects-a-record-that-declares-more-bytes-than-it-holds", seedBytes(chReject))

	// --- FuzzParseServerHelloReadsAnyPayload
	shAccept := BuildServerHello(0x0303, 0x1302, nil)
	if _, err := ParseServerHello(shAccept); err != nil {
		t.Fatalf("server hello accept seed: %v", err)
	}
	seedCorpusFile(t, "FuzzParseServerHelloReadsAnyPayload",
		"accepts-a-server-hello-that-carries-no-extension", seedBytes(shAccept))

	shReject := append([]byte(nil), shAccept[:len(shAccept)-5]...)
	if _, err := ParseServerHello(shReject); err == nil {
		t.Fatal("server hello reject seed reports no error")
	} else {
		t.Logf("server hello reject: %v", err)
	}
	seedCorpusFile(t, "FuzzParseServerHelloReadsAnyPayload",
		"rejects-a-record-that-declares-more-bytes-than-it-holds", seedBytes(shReject))

	// --- FuzzParseHTTPRequestReadsAnyPayload
	httpAccept := []byte("HEAD /a HTTP/1.0\nHost: a.invalid\nAccept: */*\n\n")
	if ParseHTTPRequest(httpAccept) == nil {
		t.Fatal("http accept seed returns nil")
	}
	seedCorpusFile(t, "FuzzParseHTTPRequestReadsAnyPayload",
		"accepts-a-head-request-that-ends-with-two-line-feeds", seedBytes(httpAccept))

	httpReject := []byte("HTTP/1.1 200 OK\r\nServer: a\r\n\r\n")
	if got := ParseHTTPRequest(httpReject); got != nil {
		t.Fatalf("http reject seed returns %+v", got)
	}
	seedCorpusFile(t, "FuzzParseHTTPRequestReadsAnyPayload",
		"rejects-a-response-status-line", seedBytes(httpReject))

	// --- FuzzParseQUICInitialReadsAnyPayload
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	key, iv, hpKey, err := DeriveInitialKeys(dcid, 1)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	inner := BuildClientHello(0x0303, []uint16{0x1301, 0x1302}, []TLSExtension{
		MakeSNIExtension("seed.invalid"),
		MakeALPNExtension("h3"),
		MakeSupportedVersionsClientExtension(0x0304),
		MakeSignatureAlgorithmsExtension(0x0403),
	})
	// The CRYPTO frame carries the handshake message, so the record header is dropped.
	handshake := inner[5:]
	quicAccept := quicInitialPacket(t, key, iv, hpKey, dcid, quicCryptoFrame(handshake))

	hello, err := ParseQUICInitial(quicAccept)
	if err != nil || hello == nil {
		t.Fatalf("quic accept seed: hello=%v err=%v", hello, err)
	}
	t.Logf("quic accept: SNI=%q ALPN=%v", hello.SNI, hello.ALPNProtocols)
	seedCorpusFile(t, "FuzzParseQUICInitialReadsAnyPayload",
		"accepts-a-synthesized-version-1-initial-packet-that-carries-a-client-hello",
		seedBytes(quicAccept))

	quicReject := []byte{0x40, 0x11, 0x22, 0x33, 0x44, 0x55}
	if got, err := ParseQUICInitial(quicReject); got != nil || err != nil {
		t.Fatalf("quic reject seed: %v %v", got, err)
	}
	seedCorpusFile(t, "FuzzParseQUICInitialReadsAnyPayload",
		"rejects-a-short-header-packet", seedBytes(quicReject))

	// --- FuzzParseCryptoFramesReadsAnyPayload
	cryptoAccept := append(quicCryptoFrameAtOffset(0, handshake[:20]),
		quicCryptoFrameAtOffset(20, handshake[20:])...)
	fragments, err := ParseCryptoFrames(cryptoAccept)
	if err != nil || len(fragments) != 2 {
		t.Fatalf("crypto accept seed: %d fragments, err=%v", len(fragments), err)
	}
	seedCorpusFile(t, "FuzzParseCryptoFramesReadsAnyPayload",
		"accepts-two-crypto-frames-that-carry-one-fragmented-client-hello",
		seedBytes(cryptoAccept))

	cryptoReject := []byte{0x06, 0x00, 0x80, 0x00, 0x00, 0x10, 0x01}
	if _, err := ParseCryptoFrames(cryptoReject); err == nil {
		t.Fatal("crypto reject seed reports no error")
	} else {
		t.Logf("crypto reject: %v", err)
	}
	seedCorpusFile(t, "FuzzParseCryptoFramesReadsAnyPayload",
		"rejects-a-crypto-frame-that-ends-before-its-length-field-states",
		seedBytes(cryptoReject))

	// --- FuzzParseSSHPacketReadsAnyPayload
	kexinit := fuzzKEXINITMessage()
	sshAccept := make([]byte, 5, 5+len(kexinit)+4)
	sshAccept[0] = byte((len(kexinit) + 5) >> 24)
	sshAccept[1] = byte((len(kexinit) + 5) >> 16)
	sshAccept[2] = byte((len(kexinit) + 5) >> 8)
	sshAccept[3] = byte(len(kexinit) + 5)
	sshAccept[4] = 4
	sshAccept = append(sshAccept, kexinit...)
	sshAccept = append(sshAccept, 0x00, 0x00, 0x00, 0x00)
	if got := ParseSSHPacket(sshAccept); got == nil {
		t.Fatal("ssh accept seed returns nil")
	} else {
		t.Logf("ssh accept: %+v", got)
	}
	seedCorpusFile(t, "FuzzParseSSHPacketReadsAnyPayload",
		"accepts-a-binary-packet-that-carries-a-kexinit-message", seedBytes(sshAccept))

	sshReject := []byte{0x00, 0x00, 0x00, 0x0c, 0xff, 0x14, 0x00, 0x00}
	if got := ParseSSHPacket(sshReject); got != nil {
		t.Fatalf("ssh reject returns %+v", got)
	}
	seedCorpusFile(t, "FuzzParseSSHPacketReadsAnyPayload",
		"rejects-a-packet-whose-padding-length-passes-the-packet", seedBytes(sshReject))

	// --- FuzzParseKEXINITReadsAnyPayload
	empty := make([]byte, 17)
	empty[0] = 20
	for range 10 {
		empty = append(empty, 0x00, 0x00, 0x00, 0x00)
	}
	empty = append(empty, 0x00, 0x00, 0x00, 0x00, 0x00)
	if got := ParseKEXINIT(empty); got == nil {
		t.Fatal("kexinit accept seed returns nil")
	} else {
		t.Logf("kexinit accept: %+v", got)
	}
	seedCorpusFile(t, "FuzzParseKEXINITReadsAnyPayload",
		"accepts-a-kexinit-message-whose-name-lists-are-empty", seedBytes(empty))

	short := make([]byte, 17)
	short[0] = 20
	for range 5 {
		short = append(short, 0x00, 0x00, 0x00, 0x00)
	}
	short = append(short, 0x00, 0x00, 0x00, 0x08, 0x61)
	if got := ParseKEXINIT(short); got != nil {
		t.Fatalf("kexinit reject returns %+v", got)
	}
	seedCorpusFile(t, "FuzzParseKEXINITReadsAnyPayload",
		"rejects-a-message-that-ends-inside-the-sixth-name-list", seedBytes(short))

	// --- FuzzTCPStreamReassemblerReadsAnySegment
	reassemblerAccept := []byte("SSH-2.0-Go\r\n")
	stream := NewTCPStreamReassembler(fuzzReassemblerMaxStreams, fuzzReassemblerMaxBytes)
	stream.AddSegment("10.0.0.9:443", 2000, reassemblerAccept)
	if len(stream.GetStream("10.0.0.9:443")) == 0 {
		t.Fatal("reassembler accept seed stores no byte")
	}
	seedCorpusFile(t, "FuzzTCPStreamReassemblerReadsAnySegment",
		"accepts-two-segments-that-leave-a-gap",
		"string("+strconv.Quote("10.0.0.9:443")+")",
		"uint32(2000)",
		seedBytes(reassemblerAccept),
		"uint32(2100)",
		seedBytes([]byte("tail")))

	reassemblerReject := bytes.Repeat([]byte{0x41}, 96)
	capped := NewTCPStreamReassembler(fuzzReassemblerMaxStreams, fuzzReassemblerMaxBytes)
	capped.AddSegment("cap", 0, reassemblerReject)
	t.Logf("reassembler reject stores %d bytes of 96", len(capped.GetStream("cap")))
	seedCorpusFile(t, "FuzzTCPStreamReassemblerReadsAnySegment",
		"rejects-the-segment-bytes-that-pass-the-byte-cap",
		"string("+strconv.Quote("cap")+")",
		"uint32(0)",
		seedBytes(reassemblerReject),
		"uint32(96)",
		seedBytes([]byte{0x42}))

	// --- FuzzCheckTunnelReadsAnyFrame
	tunnelAccept := fuzzGREFrame(t, 2)
	if err := CheckTunnel(seedPacket(tunnelAccept)); err != nil {
		t.Fatalf("tunnel accept seed: %v", err)
	}
	seedCorpusFile(t, "FuzzCheckTunnelReadsAnyFrame",
		"accepts-a-frame-that-nests-two-gre-layers", seedBytes(tunnelAccept))

	tunnelReject := fuzzGREFrame(t, MaxTunnelDepth+2)
	if err := CheckTunnel(seedPacket(tunnelReject)); err == nil {
		t.Fatal("tunnel reject seed reports no error")
	} else {
		t.Logf("tunnel reject: %v", err)
	}
	seedCorpusFile(t, "FuzzCheckTunnelReadsAnyFrame",
		"rejects-a-frame-that-nests-six-gre-layers", seedBytes(tunnelReject))

	// --- FuzzReadX509IdentifiersReadsAnyCertificate
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x01}, ed25519.SeedSize))
	template := x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{Country: []string{"US"}, CommonName: "seed.invalid"},
		NotBefore:             time.Unix(1579219200, 0),
		NotAfter:              time.Unix(1610841600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadX509Identifiers(der); !ok {
		t.Fatal("x509 accept seed is not read")
	}
	seedCorpusFile(t, "FuzzReadX509IdentifiersReadsAnyCertificate",
		"accepts-a-certificate-that-carries-no-subject-alternative-name", seedBytes(der))

	x509Reject := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	if _, ok := ReadX509Identifiers(x509Reject); ok {
		t.Fatal("x509 reject seed is read")
	}
	seedCorpusFile(t, "FuzzReadX509IdentifiersReadsAnyCertificate",
		"rejects-a-der-sequence-that-holds-no-certificate", seedBytes(x509Reject))

	t.Run("the reduced seeds of the FoxIO corpus parse", checkTheReducedSeeds)

	seedCorpusHoldsNoOtherFile(t)
}
