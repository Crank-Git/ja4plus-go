package keylog

import (
	"strings"
	"testing"
)

func TestParseReadsOneLine(t *testing.T) {
	line := "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 32)

	entries := Parse([]byte(line))
	if len(entries) != 1 {
		t.Fatalf("Parse returned %d entries, and the key log holds 1", len(entries))
	}

	if entries[0].Label != "CLIENT_HANDSHAKE_TRAFFIC_SECRET" {
		t.Errorf("Parse returned the label %q", entries[0].Label)
	}

	if len(entries[0].ClientRandom) != 32 {
		t.Errorf("Parse returned a client random of %d bytes, and the line holds 32",
			len(entries[0].ClientRandom))
	}

	if len(entries[0].Secret) != 32 {
		t.Errorf("Parse returned a secret of %d bytes, and the line holds 32",
			len(entries[0].Secret))
	}
}

func TestParseIgnoresACommentAndAnEmptyLine(t *testing.T) {
	random := strings.Repeat("ab", 32)
	secret := strings.Repeat("cd", 32)
	log := "# a comment\r\n\r\nSERVER_TRAFFIC_SECRET_0 " + random + " " + secret + "\r\n"

	entries := Parse([]byte(log))
	if len(entries) != 1 {
		t.Fatalf("Parse returned %d entries, and the key log holds 1", len(entries))
	}

	if entries[0].Label != "SERVER_TRAFFIC_SECRET_0" {
		t.Errorf("Parse returned the label %q", entries[0].Label)
	}
}

func TestParseIgnoresALineItCannotRead(t *testing.T) {
	random := strings.Repeat("ab", 32)
	secret := strings.Repeat("cd", 32)
	log := strings.Join([]string{
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + random + " zz",
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + random[:10] + " " + secret,
		"EXPORTER_SECRET " + random + " " + secret,
	}, "\n")

	entries := Parse([]byte(log))
	if len(entries) != 1 {
		t.Fatalf("Parse returned %d entries, and the key log holds 1 line it can read",
			len(entries))
	}

	if entries[0].Label != "EXPORTER_SECRET" {
		t.Errorf("Parse returned the label %q", entries[0].Label)
	}
}
