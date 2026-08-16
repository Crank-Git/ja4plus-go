package ja4plus

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The addresses and the ports of the synthetic TLS 1.3 connection of this file.
const (
	tls13TestClientIP   = "192.0.2.10"
	tls13TestServerIP   = "192.0.2.20"
	tls13TestClientPort = 51000
	tls13TestServerPort = 443
)

// tls13TestKeys returns the write key and the write initialization vector of one traffic
// secret.
//
// The test derives them through the parser, because the parser holds the one derivation of
// RFC 8446 section 7.3 and a second copy would drift from it.
func tls13TestKeys(t *testing.T, secret []byte) *parser.TLS13RecordKeys {
	t.Helper()

	keys, err := parser.DeriveTLS13RecordKeys(secret)
	if err != nil {
		t.Fatalf("DeriveTLS13RecordKeys returned %v", err)
	}

	return keys
}

// tls13TestProtectRecord returns one protected TLS 1.3 record that carries the content.
// RFC 8446 section 5.2 states the record, and section 5.3 states the nonce.
func tls13TestProtectRecord(
	t *testing.T,
	keys *parser.TLS13RecordKeys,
	content []byte,
	innerType byte,
	sequence uint64,
) []byte {
	t.Helper()

	plaintext := append(append([]byte{}, content...), innerType)

	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		t.Fatalf("aes.NewCipher returned %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM returned %v", err)
	}

	length := len(plaintext) + aead.Overhead()
	header := []byte{
		parser.TLSRecordTypeApplicationData,
		0x03, 0x03,
		byte(length >> 8), byte(length),
	}

	nonce := make([]byte, len(keys.IV))
	copy(nonce, keys.IV)

	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(sequence >> (8 * i))
	}

	return aead.Seal(header, nonce, plaintext, header)
}

// tls13TestCertificateMessage returns one TLS 1.3 Certificate handshake message that
// carries the certificates.
//
// RFC 8446 section 4.4.2 states the body: `opaque certificate_request_context<0..2^8-1>;`
// then `CertificateEntry certificate_list<0..2^24-1>;`. One entry holds
// `opaque cert_data<1..2^24-1>` and `Extension extensions<0..2^16-1>`.
func tls13TestCertificateMessage(certs ...[]byte) []byte {
	var list []byte

	for _, cert := range certs {
		list = append(list, byte(len(cert)>>16), byte(len(cert)>>8), byte(len(cert)))
		list = append(list, cert...)
		list = append(list, 0x00, 0x00)
	}

	body := []byte{0x00}
	body = append(body, byte(len(list)>>16), byte(len(list)>>8), byte(len(list)))
	body = append(body, list...)

	message := []byte{
		tlsHandshakeCertificate,
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
	}

	return append(message, body...)
}

// tls13TestClientHelloRecord returns one TLS 1.3 ClientHello record that carries the
// random.
func tls13TestClientHelloRecord(random []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, 0x00, 0x00)

	message := []byte{parser.TLSHandshakeClientHello, 0x00, byte(len(body) >> 8), byte(len(body))}
	message = append(message, body...)

	record := []byte{parser.TLSRecordTypeHandshake, 0x03, 0x01, byte(len(message) >> 8), byte(len(message))}

	return append(record, message...)
}

// tls13TestPacket returns one TCP packet that carries the payload.
func tls13TestPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		PSH:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers returned %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()

	return packet
}

// tls13TestCertificate returns one self-signed certificate in DER form.
func tls13TestCertificate(t *testing.T, name string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"ja4plus"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate returned %v", err)
	}

	return der
}

// tls13TestKeyLog returns the KeyLog that names one secret of one connection.
func tls13TestKeyLog(t *testing.T, label string, random, secret []byte) *KeyLog {
	t.Helper()

	line := label + " " + hex.EncodeToString(random) + " " + hex.EncodeToString(secret) + "\n"

	keyLog, err := ParseKeyLog(strings.NewReader(line))
	if err != nil {
		t.Fatalf("ParseKeyLog returned %v", err)
	}

	return keyLog
}

// tls13TestFingerprints returns the JA4X fingerprint of each result.
func tls13TestFingerprints(results []FingerprintResult) []string {
	var values []string

	for _, result := range results {
		if result.Type == "ja4x" {
			values = append(values, result.Fingerprint)
		}
	}

	return values
}

// TestTheProcessorReadsTheCertificateOfAProtectedTLS13Record holds the acceptance criterion
// of #492: the library reads the Certificate message of a protected TLS 1.3 record on TCP
// where the key log holds the secret.
//
// A TLS 1.3 server writes the Certificate message under the outer content type
// TLSRecordTypeApplicationData, which RFC 8446 section 5.2 states. So the plaintext reader
// of `findCertificatesInStream` walks past it.
func TestTheProcessorReadsTheCertificateOfAProtectedTLS13Record(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")

	want := ComputeJA4XFromDER(certDER)
	if want == "" {
		t.Fatal("ComputeJA4XFromDER read no certificate, and the test built one")
	}

	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	processor := NewProcessor(WithKeyLog(keyLog))

	// The client sends the ClientHello, which names the connection in the key log.
	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	// The server sends one unprotected ServerHello record, one ChangeCipherSpec record and
	// then the protected records. The first protected record is sequence number 0.
	server := []byte{parser.TLSRecordTypeHandshake, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00}
	server = append(server, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	server = append(server, tls13TestProtectRecord(t, keys, []byte{0x08, 0x00, 0x00, 0x00}, parser.TLSRecordTypeHandshake, 0)...)
	server = append(server, tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 1)...)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	values := tls13TestFingerprints(results)
	if len(values) != 1 || values[0] != want {
		t.Fatalf("the processor returned %v, and the record carries %s", values, want)
	}
}

// TestTheProcessorReadsTheCertificateOfEveryProtectedRecordOfAChain holds a chain that one
// Certificate message carries, and a message that spans two records.
func TestTheProcessorReadsTheCertificateOfEveryProtectedRecordOfAChain(t *testing.T) {
	random := bytes.Repeat([]byte{0x2e}, 32)
	secret := bytes.Repeat([]byte{0x77}, 32)

	leaf := tls13TestCertificate(t, "leaf.example")
	issuer := tls13TestCertificate(t, "issuer.example")

	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	processor := NewProcessor(WithKeyLog(keyLog))

	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	// One Certificate message spans two records, because the message is larger than the
	// record the sender writes. RFC 8446 section 5.1 permits that split.
	message := tls13TestCertificateMessage(leaf, issuer)
	half := len(message) / 2

	server := tls13TestProtectRecord(t, keys, message[:half], parser.TLSRecordTypeHandshake, 0)
	server = append(server, tls13TestProtectRecord(t, keys, message[half:], parser.TLSRecordTypeHandshake, 1)...)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	values := tls13TestFingerprints(results)
	want := []string{ComputeJA4XFromDER(leaf), ComputeJA4XFromDER(issuer)}

	if len(values) != len(want) {
		t.Fatalf("the processor returned %v, and the chain carries %v", values, want)
	}

	for i, value := range values {
		if value != want[i] {
			t.Errorf("the processor returned %s at position %d, and the chain carries %s", value, i, want[i])
		}
	}
}

// TestTheProcessorReadsNoProtectedCertificateWithoutAKeyLog holds FR-gaps-18: the library
// produces no fingerprint from a secret when the caller supplies none.
func TestTheProcessorReadsNoProtectedCertificateWithoutAKeyLog(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")
	keys := tls13TestKeys(t, secret)

	processor := NewProcessor()

	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	server := tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 0)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	if values := tls13TestFingerprints(results); len(values) != 0 {
		t.Fatalf("the processor returned %v, and the caller supplied no key log", values)
	}
}

// TestTheProcessorReadsNoProtectedCertificateOfATruncatedRecord holds the bound of every
// length field. Every packet is untrusted input, and a fingerprinter never panics.
func TestTheProcessorReadsNoProtectedCertificateOfATruncatedRecord(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")
	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	record := tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 0)

	for _, length := range []int{1, 4, 5, 6, len(record) / 2, len(record) - 1} {
		processor := NewProcessor(WithKeyLog(keyLog))

		client := tls13TestPacket(t,
			tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
			1, tls13TestClientHelloRecord(random))
		if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
			t.Fatalf("ProcessPacket returned %v", errs)
		}

		results, errs := processor.ProcessPacket(tls13TestPacket(t,
			tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
			1, record[:length]))
		if len(errs) > 0 {
			t.Fatalf("ProcessPacket returned %v at %d bytes", errs, length)
		}

		if values := tls13TestFingerprints(results); len(values) != 0 {
			t.Errorf("the processor returned %v from a record of %d bytes", values, length)
		}
	}
}

// TestCleanupConnectionRemovesTheProtectedStream holds the removal path of the state that
// the protected reader uses. The reader reads the reverse stream of the reassembler, and
// `CleanupConnection` removes both directions.
func TestCleanupConnectionRemovesTheProtectedStream(t *testing.T) {
	random := bytes.Repeat([]byte{0x4d}, 32)
	secret := bytes.Repeat([]byte{0x91}, 32)

	certDER := tls13TestCertificate(t, "protected.example")
	keys := tls13TestKeys(t, secret)
	keyLog := tls13TestKeyLog(t, parser.TLS13ServerHandshakeSecretLabel, random, secret)

	processor := NewProcessor(WithKeyLog(keyLog))

	client := tls13TestPacket(t,
		tls13TestClientIP, tls13TestServerIP, tls13TestClientPort, tls13TestServerPort,
		1, tls13TestClientHelloRecord(random))
	if _, errs := processor.ProcessPacket(client); len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	processor.CleanupConnection(tls13TestClientIP, tls13TestClientPort, tls13TestServerIP, tls13TestServerPort, "tcp")

	server := tls13TestProtectRecord(t, keys, tls13TestCertificateMessage(certDER), parser.TLSRecordTypeHandshake, 0)

	results, errs := processor.ProcessPacket(tls13TestPacket(t,
		tls13TestServerIP, tls13TestClientIP, tls13TestServerPort, tls13TestClientPort,
		1, server))
	if len(errs) > 0 {
		t.Fatalf("ProcessPacket returned %v", errs)
	}

	if values := tls13TestFingerprints(results); len(values) != 0 {
		t.Fatalf("the processor returned %v after CleanupConnection removed the client stream", values)
	}
}

// TestTheProcessorReadsTheProtectedCertificatesOfTheHTTP2Capture holds the yield that #492
// buys on the corpus.
//
// `http2-with-cookies.pcapng` carries a TLS 1.3 connection and the Decryption Secrets
// Blocks of that connection. Frame 10 holds three certificates behind the record
// protection, and `docs/audit/ja4x-deviation-cluster.md`
// `## Cause 2 — the library reads no encrypted TLS 1.3 handshake record` measured the 9
// deviations that the three values close.
//
// The three expected values are the FoxIO vector values, and the register held each one
// under ruling #492 until this issue removed the entry.
func TestTheProcessorReadsTheProtectedCertificatesOfTheHTTP2Capture(t *testing.T) {
	path := filepath.Join(corpusCaptureDir, "http2-with-cookies.pcapng")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s is absent, so run `make corpus` to fetch the FoxIO corpus", path)
	}

	keyLog, err := ReadKeyLogFromCapture(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadKeyLogFromCapture returned %v", err)
	}

	if keyLog.Len() == 0 {
		t.Fatal("the capture holds no Decryption Secrets Block, and the vector set needs one")
	}

	processor := NewProcessor(WithKeyLog(keyLog))

	var values []string

	for _, packet := range loadPCAP(t, path) {
		results, _ := processor.ProcessPacket(packet)
		values = append(values, tls13TestFingerprints(results)...)
	}

	want := []string{
		"a373a9f83c6b_7022c563de38_2e3757343cb0",
		"a373a9f83c6b_a373a9f83c6b_5d71497f7704",
		"7d5dbb3783b4_a373a9f83c6b_2fbee3f04f3b",
	}

	if !slices.Equal(values, want) {
		t.Fatalf("the processor returned %v, and the FoxIO vector holds %v", values, want)
	}
}
