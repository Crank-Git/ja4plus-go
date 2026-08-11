package ja4plus

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/keylog"
	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
)

// Fingerprinter is the interface that all JA4+ fingerprinters implement.
type Fingerprinter interface {
	ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error)
	Reset()
	// CleanupConnection removes internal state associated with a connection
	// identified by the given 5-tuple. Each fingerprinter normalizes the tuple
	// to its own internal key format. This prevents state leaks in long-running
	// monitors. For QUIC-keyed fingerprinters (JA4, JA4S), this also cleans up
	// any DCID-to-tuple mappings.
	CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string)
}

// FingerprintResult holds a single fingerprint and its metadata.
type FingerprintResult struct {
	Fingerprint      string
	Raw              string
	RawOriginalOrder string // JA4_ro: wire-order, no sorting, SNI/ALPN preserved
	Type             string
	SrcIP            string
	DstIP            string
	SrcPort          uint16
	DstPort          uint16
	Timestamp        time.Time
}

// ErrNoSecret reports that no secret is available for the connection.
// A caller who supplies no key log reads this error, and a caller whose key log holds no
// secret for the connection reads it too.
var ErrNoSecret = errors.New("ja4plus: no TLS secret for the connection")

// keyLogMaxBytes bounds the key log the library reads.
// A key log is untrusted input, and one line of it holds about 150 bytes, so this bound
// carries more than one hundred thousand connections.
const keyLogMaxBytes = 16 << 20

// KeyLog holds the TLS secrets of one or more connections, and the client random of the
// connection identifies each one.
//
// A caller builds a KeyLog with ParseKeyLog or with ReadKeyLogFromCapture, and the value
// does not change after that. Any number of goroutines read one KeyLog.
//
// The library reads a secret only when the caller supplies one. It reads no key material
// outside the capture file and outside the reader the caller passes.
type KeyLog struct {
	// secrets maps the client random and the label to one secret. The key holds the
	// client random in hexadecimal, because a byte slice is no map key.
	secrets map[string][]byte
	// randoms holds the client random of each connection, in the order the key log
	// states it first.
	randoms [][]byte
}

// ParseKeyLog returns the KeyLog of a key log in the NSS key log format, which
// `draft-ietf-tls-keylogfile` specifies.
// It ignores a line it cannot read.
// It reads at most 16 megabytes.
func ParseKeyLog(r io.Reader) (*KeyLog, error) {
	if r == nil {
		return &KeyLog{secrets: map[string][]byte{}}, nil
	}

	data, err := io.ReadAll(io.LimitReader(r, keyLogMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("ja4plus: the library cannot read the key log: %w", err)
	}

	return keyLogOfEntries(keylog.Parse(data)), nil
}

// ReadKeyLogFromCapture returns the KeyLog that the Decryption Secrets Blocks of a pcapng
// capture carry.
// It returns an empty KeyLog for a capture that holds no such block.
// It returns an error for a reader that holds no pcapng capture.
// FR-gaps-15 states this requirement, and `gopacket` v1.1.19 discards the block.
func ReadKeyLogFromCapture(r io.Reader) (*KeyLog, error) {
	if r == nil {
		return &KeyLog{secrets: map[string][]byte{}}, nil
	}

	logs, err := keylog.ReadPcapng(r)
	if err != nil {
		return nil, fmt.Errorf("ja4plus: the library cannot read the decryption secrets: %w", err)
	}

	var entries []keylog.Entry
	for _, keyLog := range logs {
		entries = append(entries, keylog.Parse(keyLog)...)
	}

	return keyLogOfEntries(entries), nil
}

// keyLogOfEntries returns the KeyLog of the entries.
// A later entry with one label and one client random replaces an earlier entry, because
// a capture that holds two Decryption Secrets Blocks repeats a secret.
func keyLogOfEntries(entries []keylog.Entry) *KeyLog {
	keyLog := &KeyLog{secrets: make(map[string][]byte, len(entries))}
	seen := make(map[string]bool, len(entries))

	for _, entry := range entries {
		random := hex.EncodeToString(entry.ClientRandom)
		keyLog.secrets[random+" "+entry.Label] = entry.Secret

		if !seen[random] {
			seen[random] = true

			keyLog.randoms = append(keyLog.randoms, entry.ClientRandom)
		}
	}

	return keyLog
}

// Secret returns the secret of one label for the connection that the client random
// identifies.
// It returns ErrNoSecret when the key log holds no such secret. A Decryption Secrets Block
// that holds a secret for a connection the capture does not carry reaches no caller,
// because no packet of the capture states that client random.
func (k *KeyLog) Secret(clientRandom []byte, label string) ([]byte, error) {
	if k == nil || len(k.secrets) == 0 {
		return nil, ErrNoSecret
	}

	secret, ok := k.secrets[hex.EncodeToString(clientRandom)+" "+label]
	if !ok {
		return nil, ErrNoSecret
	}

	out := make([]byte, len(secret))
	copy(out, secret)

	return out, nil
}

// ClientRandoms returns the client random of every connection the key log holds, sorted.
func (k *KeyLog) ClientRandoms() [][]byte {
	if k == nil {
		return nil
	}

	randoms := make([][]byte, 0, len(k.randoms))
	for _, random := range k.randoms {
		out := make([]byte, len(random))
		copy(out, random)

		randoms = append(randoms, out)
	}

	sort.Slice(randoms, func(i, j int) bool {
		return hex.EncodeToString(randoms[i]) < hex.EncodeToString(randoms[j])
	})

	return randoms
}

// Len returns the count of secrets the key log holds.
func (k *KeyLog) Len() int {
	if k == nil {
		return 0
	}

	return len(k.secrets)
}

// DecryptQUICPacket returns the frame bytes of one QUIC packet, which the secret protects.
// The secret is one TLS traffic secret, and KeyLog.Secret returns one.
// connectionIDLength states the Destination Connection ID length of a short header
// packet. A long header packet carries its own lengths, so it ignores that argument.
// It returns ErrNoSecret when the caller supplies no secret, and it produces no
// fingerprint in that case.
// It returns a non-fatal error for a packet it cannot read, and it never panics.
// RFC 9001 Section 5.1 states the key derivation, and Section 5.4.1 states the header
// protection.
func DecryptQUICPacket(payload, secret []byte, connectionIDLength int) ([]byte, error) {
	plaintext, err := parser.DecryptQUICPacketWithSecret(payload, secret, connectionIDLength)
	if errors.Is(err, parser.ErrNoSecret) {
		return nil, ErrNoSecret
	}

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
