// Package keylog reads the TLS secrets that a capture carries.
//
// The package decodes a capture container and a key log, and it reads no packet, so it
// sits outside `internal/parser`. `docs/audit/findings.md` records the same boundary for
// `internal/capture/`.
package keylog

import (
	"encoding/hex"
	"strings"
)

// keyLogRandomLength is the byte count of the Random field of a ClientHello.
// `draft-ietf-tls-keylogfile` writes it as 64 hexadecimal characters.
const keyLogRandomLength = 32

// Entry is one secret of one connection, read from a key log line.
type Entry struct {
	// Label names the secret, for example `SERVER_HANDSHAKE_TRAFFIC_SECRET`.
	Label string
	// ClientRandom holds the Random field of the ClientHello of the connection.
	ClientRandom []byte
	// Secret holds the secret bytes.
	Secret []byte
}

// Parse returns one entry for each line of a key log in the NSS key log
// format, which `draft-ietf-tls-keylogfile` specifies.
// It ignores an empty line and a line whose first character is `#`.
// It ignores a line it cannot read, because a program appends to a key log while it runs
// and the last line of a capture can be partial.
func Parse(data []byte) []Entry {
	var entries []Entry

	for _, line := range strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}

		random, err := hex.DecodeString(fields[1])
		if err != nil || len(random) != keyLogRandomLength {
			continue
		}

		secret, err := hex.DecodeString(fields[2])
		if err != nil || len(secret) == 0 {
			continue
		}

		entries = append(entries, Entry{
			Label:        fields[0],
			ClientRandom: random,
			Secret:       secret,
		})
	}

	return entries
}
