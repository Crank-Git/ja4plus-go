package parser

import (
	"encoding/binary"
	"strings"
	"testing"
)

// fuzzSSHNameList returns the SSH name-list encoding of the names: a 4-byte length and
// the bytes of the comma-separated names.
func fuzzSSHNameList(names string) []byte {
	encoded := make([]byte, 4, 4+len(names))
	binary.BigEndian.PutUint32(encoded, uint32(len(names)))

	return append(encoded, names...)
}

// fuzzKEXINITMessage returns one SSH KEXINIT message that ParseKEXINIT accepts.
// The message starts at the message type byte, and it carries the ten name-lists that
// ParseKEXINIT reads.
func fuzzKEXINITMessage() []byte {
	message := make([]byte, 17)
	message[0] = 20

	lists := []string{
		"curve25519-sha256,ecdh-sha2-nistp256",
		"rsa-sha2-512,ssh-ed25519",
		"chacha20-poly1305@openssh.com",
		"chacha20-poly1305@openssh.com",
		"hmac-sha2-256",
		"hmac-sha2-256",
		"none",
		"none",
		"",
		"",
	}
	for _, list := range lists {
		message = append(message, fuzzSSHNameList(list)...)
	}

	// The first key exchange packet flag and the reserved field close the message.
	return append(message, 0x00, 0x00, 0x00, 0x00, 0x00)
}

// FuzzParseSSHPacketReadsAnyPayload proves that ParseSSHPacket returns for any TCP
// payload. FR-fuzz-6 states the requirement.
func FuzzParseSSHPacketReadsAnyPayload(f *testing.F) {
	// The parser accepts each seed below.
	//   - An identification string.
	//   - A binary packet that carries a NEWKEYS message.
	//   - An identification string with no line terminator. The parser reads the four
	//     bytes `SSH-` and it returns a banner, so no line terminator is needed.
	f.Add([]byte("SSH-2.0-OpenSSH_8.9\r\n"))

	newkeys := make([]byte, 26)
	binary.BigEndian.PutUint32(newkeys[0:4], 20)
	newkeys[4] = 4
	newkeys[5] = 21
	f.Add(newkeys)

	f.Add([]byte("SSH-2.0-" + strings.Repeat("A", 300)))

	// The parser rejects each seed below. The first holds no byte. The second states a
	// packet length of 16 megabytes.
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x05, 0x14, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = ParseSSHPacket(payload)
	})
}

// FuzzParseKEXINITReadsAnyPayload proves that ParseKEXINIT returns for any payload that
// starts at the message type byte. FR-fuzz-7 states the requirement.
func FuzzParseKEXINITReadsAnyPayload(f *testing.F) {
	// The parser accepts this seed.
	f.Add(fuzzKEXINITMessage())

	// The parser rejects each seed below. The first holds no byte. The second names a
	// message type that is not KEXINIT. The third states a name-list length that runs
	// past the message.
	f.Add([]byte{})
	f.Add(append([]byte{21}, make([]byte, 32)...))

	truncated := make([]byte, 17)
	truncated[0] = 20
	f.Add(append(truncated, 0xff, 0xff, 0xff, 0xff, 0x61))

	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = ParseKEXINIT(payload)
	})
}
