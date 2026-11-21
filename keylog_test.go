package ja4plus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket/layers"
)

// keyLogTestRandom is one client random of the tests.
var keyLogTestRandom = bytes.Repeat([]byte{0xab}, 32)

// keyLogTestLine returns one line in the NSS key log format.
func keyLogTestLine(label string, random []byte) string {
	return label + " " + hex.EncodeToString(random) + " " + strings.Repeat("cd", 32) + "\n"
}

// keyLogTestCapture returns one pcapng capture that holds the key log in a
// Decryption Secrets Block.
func keyLogTestCapture(keyLog string) []byte {
	section := make([]byte, 28)
	binary.LittleEndian.PutUint32(section[0:4], 0x0A0D0D0A)
	binary.LittleEndian.PutUint32(section[4:8], 28)
	binary.LittleEndian.PutUint32(section[8:12], 0x1A2B3C4D)
	binary.LittleEndian.PutUint16(section[12:14], 1)
	binary.LittleEndian.PutUint64(section[16:24], 0xFFFFFFFFFFFFFFFF)
	binary.LittleEndian.PutUint32(section[24:28], 28)

	padded := (len(keyLog) + 3) / 4 * 4
	total := 20 + padded
	block := make([]byte, total)
	binary.LittleEndian.PutUint32(block[0:4], 0x0000000A)
	binary.LittleEndian.PutUint32(block[4:8], uint32(total))
	binary.LittleEndian.PutUint32(block[8:12], 0x544C534B)
	binary.LittleEndian.PutUint32(block[12:16], uint32(len(keyLog)))
	copy(block[16:], keyLog)
	binary.LittleEndian.PutUint32(block[total-4:total], uint32(total))

	return append(section, block...)
}

func TestParseKeyLogReadsTheNSSKeyLogFormat(t *testing.T) {
	log := keyLogTestLine("CLIENT_HANDSHAKE_TRAFFIC_SECRET", keyLogTestRandom) +
		keyLogTestLine("SERVER_HANDSHAKE_TRAFFIC_SECRET", keyLogTestRandom)

	keyLog, err := ParseKeyLog(strings.NewReader(log))
	if err != nil {
		t.Fatalf("ParseKeyLog returned %v", err)
	}

	if keyLog.Len() != 2 {
		t.Fatalf("ParseKeyLog returned %d secrets, and the key log holds 2", keyLog.Len())
	}

	secret, err := keyLog.Secret(keyLogTestRandom, "SERVER_HANDSHAKE_TRAFFIC_SECRET")
	if err != nil {
		t.Fatalf("Secret returned %v", err)
	}

	if len(secret) != 32 {
		t.Errorf("Secret returned %d bytes, and the line holds 32", len(secret))
	}
}

func TestReadKeyLogFromCaptureReadsADecryptionSecretsBlock(t *testing.T) {
	capture := keyLogTestCapture(keyLogTestLine("CLIENT_TRAFFIC_SECRET_0", keyLogTestRandom))

	keyLog, err := ReadKeyLogFromCapture(bytes.NewReader(capture))
	if err != nil {
		t.Fatalf("ReadKeyLogFromCapture returned %v", err)
	}

	if keyLog.Len() != 1 {
		t.Fatalf("ReadKeyLogFromCapture returned %d secrets, and the block holds 1", keyLog.Len())
	}

	randoms := keyLog.ClientRandoms()
	if len(randoms) != 1 || !bytes.Equal(randoms[0], keyLogTestRandom) {
		t.Errorf("ClientRandoms returned %x, and the block holds %x", randoms, keyLogTestRandom)
	}
}

func TestSecretReturnsAnErrorForAConnectionTheCaptureDoesNotCarry(t *testing.T) {
	// A Decryption Secrets Block holds a secret for a connection that the capture does
	// not carry. The library ignores the secret.
	keyLog, err := ParseKeyLog(strings.NewReader(keyLogTestLine("EXPORTER_SECRET", keyLogTestRandom)))
	if err != nil {
		t.Fatalf("ParseKeyLog returned %v", err)
	}

	if _, err := keyLog.Secret(bytes.Repeat([]byte{0x11}, 32), "EXPORTER_SECRET"); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Secret returned %v for a client random the key log does not hold", err)
	}

	if _, err := keyLog.Secret(keyLogTestRandom, "SERVER_TRAFFIC_SECRET_0"); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Secret returned %v for a label the key log does not hold", err)
	}
}

func TestSecretReturnsAnErrorFromAKeyLogThatHoldsNothing(t *testing.T) {
	var keyLog *KeyLog

	if _, err := keyLog.Secret(keyLogTestRandom, "EXPORTER_SECRET"); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Secret returned %v from a key log that holds nothing", err)
	}

	if keyLog.Len() != 0 {
		t.Errorf("Len returned %d from a key log that holds nothing", keyLog.Len())
	}
}

func TestDecryptQUICPacketReturnsAnErrorWhenTheCallerSuppliesNoSecret(t *testing.T) {
	// FR-gaps-18 states that the library produces no fingerprint from a secret when the
	// caller supplies none.
	plaintext, err := DecryptQUICPacket(bytes.Repeat([]byte{0x41}, 64), nil, 0)
	if !errors.Is(err, ErrNoSecret) {
		t.Errorf("DecryptQUICPacket returned %v, and the caller supplied no secret", err)
	}

	if plaintext != nil {
		t.Errorf("DecryptQUICPacket returned %x, and the caller supplied no secret", plaintext)
	}
}

// TestDecryptQUICPacketReadsTheHandshakeOfTheCaptureWithSecrets holds FR-gaps-15 and
// FR-gaps-16 on the capture `chrome-cloudflare-quic-with-secrets.pcapng`.
// The capture carries the server handshake secret in a Decryption Secrets Block, and the
// server handshake packets carry the certificate of the connection.
func TestDecryptQUICPacketReadsTheHandshakeOfTheCaptureWithSecrets(t *testing.T) {
	path := filepath.Join(corpusCaptureDir, "chrome-cloudflare-quic-with-secrets.pcapng")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", path)
	}

	keyLog, err := ReadKeyLogFromCapture(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadKeyLogFromCapture returned %v", err)
	}

	randoms := keyLog.ClientRandoms()
	if len(randoms) == 0 {
		t.Fatal("ReadKeyLogFromCapture returned no client random, and the capture holds a Decryption Secrets Block")
	}

	var fragments []parser.CryptoFragment

	for _, random := range randoms {
		secret, err := keyLog.Secret(random, "SERVER_HANDSHAKE_TRAFFIC_SECRET")
		if err != nil {
			continue
		}

		for _, payload := range keyLogTestUDPPayloads(t, path) {
			for _, packet := range keyLogTestLongHeaderPackets(payload) {
				plaintext, err := DecryptQUICPacket(packet, secret, 0)
				if err != nil {
					continue
				}

				found, err := parser.ParseCryptoFrames(plaintext)
				if err != nil && len(found) == 0 {
					continue
				}

				fragments = append(fragments, found...)
			}
		}
	}

	if len(fragments) == 0 {
		t.Fatal("the library read no CRYPTO frame from the server handshake packets of the capture")
	}

	assembled := parser.ReassembleCryptoFrames(fragments)

	// The decrypted CRYPTO stream of the server carries the handshake messages of
	// TLS 1.3, from EncryptedExtensions to Finished. A wrong secret produces no
	// message chain that ends at the last byte.
	types := keyLogTestHandshakeTypes(assembled)
	if len(types) < 2 || types[0] != 0x08 || types[len(types)-1] != 0x14 {
		t.Fatalf("the server handshake holds %d bytes and the message types %#x", len(assembled), types)
	}
}

// keyLogTestHandshakeTypes returns the type of each TLS handshake message.
// One message carries one type byte and a three-byte length.
// It returns the types it read up to the first message that passes the buffer.
func keyLogTestHandshakeTypes(handshake []byte) []byte {
	var types []byte

	for pos := 0; pos+4 <= len(handshake); {
		length := int(handshake[pos+1])<<16 | int(handshake[pos+2])<<8 | int(handshake[pos+3])
		if length == 0 || pos+4+length > len(handshake) {
			return types
		}

		types = append(types, handshake[pos])
		pos += 4 + length
	}

	return types
}

// keyLogTestUDPPayloads returns the UDP payload of every packet of the capture.
func keyLogTestUDPPayloads(t *testing.T, path string) [][]byte {
	t.Helper()

	var payloads [][]byte

	for _, packet := range loadPCAP(t, path) {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		udp, ok := udpLayer.(*layers.UDP)
		if !ok || len(udp.Payload) == 0 {
			continue
		}

		payloads = append(payloads, udp.Payload)
	}

	return payloads
}

// keyLogTestLongHeaderPackets returns each long header packet of one datagram.
// One QUIC datagram carries more than one packet, so the test walks the datagram.
func keyLogTestLongHeaderPackets(datagram []byte) [][]byte {
	var packets [][]byte

	for pos := 0; pos+7 < len(datagram); {
		if datagram[pos]&0x80 == 0 {
			break
		}

		start := pos
		pos += 5

		for range 2 {
			if pos >= len(datagram) {
				return packets
			}

			length := int(datagram[pos])
			pos += 1 + length

			if pos > len(datagram) {
				return packets
			}
		}

		// An Initial packet carries a token, and a Handshake packet carries none.
		if datagram[start]&0x30 == 0x00 {
			tokenLength, next, err := parser.DecodeVarint(datagram, pos)
			if err != nil {
				return packets
			}

			pos = next + int(tokenLength)
			if pos > len(datagram) {
				return packets
			}
		}

		length, next, err := parser.DecodeVarint(datagram, pos)
		if err != nil {
			return packets
		}

		end := next + int(length)
		if end > len(datagram) {
			return packets
		}

		packets = append(packets, datagram[start:end])
		pos = end
	}

	return packets
}

// These two tests hold the FR-gaps-17 amendment of issue #171.
//
// The requirement held one sentence that states two facts. types.go holds eight exported
// names for a key log, and no exported function accepted a KeyLog. A reader who reads the
// first fact alone expects a fingerprint that a secret decrypts. The library produces none.
//
// The maintainer moved the second boundary on 2026-08-15 UTC, and comment 5299963400 of
// issue #649 records the ruling. WithKeyLog is now the one route by which key material
// reaches a Processor, and FR-gaps-17c states that route. Issue #649 is the reversal path,
// and a reversal restores the earlier requirement and this test with it.

// conformanceGapsPath names the page that FR-gaps-17 lives on.
const conformanceGapsPath = "docs/specs/features/05-conformance-gaps.md"

// keyLogNameCount states the count of exported names that FR-gaps-17 through
// FR-gaps-17b name. The page states the same count in prose, so a change to one of them
// without the other fails this test.
const keyLogNameCount = 8

// keyLogCountSentence quotes the prose of the page that states the count above.
// A stale count is the defect this project measures most, so a test holds the sentence.
const keyLogCountSentence = "holds each of the eight exported names"

// TestFRGaps17NamesEveryExportedKeyLogName holds the first fact of the amendment.
// The requirement names an exported name of this package, and never a name the package
// does not hold.
func TestFRGaps17NamesEveryExportedKeyLogName(t *testing.T) {
	named := keyLogNamesOfTheRequirement(t)
	if len(named) != keyLogNameCount {
		t.Fatalf("FR-gaps-17 through FR-gaps-17b name %d exported names, want %d: %v",
			len(named), keyLogNameCount, named)
	}

	// The page wraps a sentence over more than one line, so the reader joins the lines
	// before it looks for the count.
	flat := strings.Join(strings.Fields(conformanceGapsPage(t)), " ")
	if !strings.Contains(flat, keyLogCountSentence) {
		t.Errorf("%s states no sentence that holds %q, so the prose count is stale",
			conformanceGapsPath, keyLogCountSentence)
	}

	held := exportedNamesOfThePackage(t)
	for _, name := range named {
		if !held[name] {
			t.Errorf("FR-gaps-17 names %s and the package exports no such name", name)
		}
	}
}

// keyLogRouteName states the one exported function that accepts a KeyLog.
// The maintainer ruled the route on 2026-08-15 UTC, and issue #649 is the reversal path.
const keyLogRouteName = "WithKeyLog"

// TestWithKeyLogIsTheOneExportedFunctionThatAcceptsAKeyLog holds FR-gaps-17c: key material
// reaches a Processor through one exported name.
// It reads every parameter of every exported function and method of the package, because
// the requirement binds the whole exported surface and not one file.
// Epic 10 (#100) freezes that surface next, so a second route that lands before the freeze
// is a second name the project cannot remove afterward.
func TestWithKeyLogIsTheOneExportedFunctionThatAcceptsAKeyLog(t *testing.T) {
	functions := 0
	routes := 0

	for _, file := range packageSourceFiles(t) {
		parsed, err := goparser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range parsed.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || !ast.IsExported(function.Name.Name) {
				continue
			}

			functions++

			for _, param := range function.Type.Params.List {
				if !strings.Contains(typeExpressionText(param.Type), "KeyLog") {
					continue
				}

				if function.Name.Name == keyLogRouteName {
					routes++

					continue
				}

				t.Errorf("%s of %s accepts a KeyLog, and FR-gaps-17c names %s as the one route",
					function.Name.Name, file, keyLogRouteName)
			}
		}
	}

	if functions == 0 {
		t.Fatal("the package declares no exported function, so this test proves nothing")
	}

	if routes != 1 {
		t.Errorf("%d exported functions named %s accept a KeyLog, want 1", routes, keyLogRouteName)
	}
}

// keyLogNamesOfTheRequirement returns each name that a code span of FR-gaps-17
// through FR-gaps-17b holds, sorted and without a repeat.
func keyLogNamesOfTheRequirement(t *testing.T) []string {
	t.Helper()

	page := conformanceGapsPage(t)
	span := regexp.MustCompile("`([^`]+)`")
	seen := map[string]bool{}
	inside := false

	var names []string

	// The three requirements are consecutive, and FR-gaps-17c ends the block. A
	// requirement wraps over more than one line, so the reader holds the block state and
	// reads no line by its indent.
	for _, line := range strings.Split(page, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "- **FR-gaps-17**") {
			inside = true
		}

		if strings.HasPrefix(trimmed, "- **FR-gaps-17c**") {
			inside = false
		}

		if !inside {
			continue
		}

		for _, match := range span.FindAllStringSubmatch(line, -1) {
			name := match[1]
			if seen[name] {
				continue
			}

			seen[name] = true
			names = append(names, name)
		}
	}

	if !seen["KeyLog"] {
		t.Fatalf("%s holds no FR-gaps-17 block that names KeyLog", conformanceGapsPath)
	}

	sort.Strings(names)

	return names
}

// conformanceGapsPage returns the text of the page that FR-gaps-17 lives on.
func conformanceGapsPage(t *testing.T) string {
	t.Helper()

	page, err := os.ReadFile(conformanceGapsPath)
	if err != nil {
		t.Fatalf("read %s: %v", conformanceGapsPath, err)
	}

	return string(page)
}

// exportedNamesOfThePackage returns every exported name the package declares, and it writes
// a method as `Type.Method`.
func exportedNamesOfThePackage(t *testing.T) map[string]bool {
	t.Helper()

	held := map[string]bool{}

	for _, file := range packageSourceFiles(t) {
		parsed, err := goparser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range parsed.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(node.Name.Name) {
					continue
				}

				if node.Recv == nil {
					held[node.Name.Name] = true

					continue
				}

				held[receiverTypeName(node.Recv)+"."+node.Name.Name] = true
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					addExportedSpecName(held, spec)
				}
			}
		}
	}

	return held
}

// addExportedSpecName adds the exported name of one type, variable or constant declaration.
func addExportedSpecName(held map[string]bool, spec ast.Spec) {
	switch node := spec.(type) {
	case *ast.TypeSpec:
		if ast.IsExported(node.Name.Name) {
			held[node.Name.Name] = true
		}
	case *ast.ValueSpec:
		for _, name := range node.Names {
			if ast.IsExported(name.Name) {
				held[name.Name] = true
			}
		}
	}
}

// packageSourceFiles returns every source file of the package, and no test file.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the source files: %v", err)
	}

	sources := make([]string, 0, len(files))

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		sources = append(sources, file)
	}

	if len(sources) == 0 {
		t.Fatal("the package holds no source file, so this test proves nothing")
	}

	return sources
}

// typeExpressionText returns the source text of a type expression.
// It calls types.ExprString, which reads every expression form the Go grammar states. A
// hand-written reader returns the empty string for the form it does not name, and a
// `func(*KeyLog)` parameter then passes the guard of FR-gaps-17c.
func typeExpressionText(expr ast.Expr) string {
	return types.ExprString(expr)
}
