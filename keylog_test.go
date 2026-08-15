package ja4plus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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
