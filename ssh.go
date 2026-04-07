package ja4plus

import (
	"encoding/binary"
)

// SSHPacketInfo holds parsed SSH packet information.
type SSHPacketInfo struct {
	Type    string // "banner", "kexinit", "data"
	Payload []byte
}

// IsSSHPacket checks if payload looks like SSH traffic.
// SSH packets start with "SSH-" (banner) or have SSH binary packet framing.
func IsSSHPacket(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}

	// Check for SSH banner
	if payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-' {
		return true
	}

	// Check SSH binary packet format:
	// 4 bytes: packet length (big-endian)
	// 1 byte:  padding length
	// Then payload follows
	packetLength := binary.BigEndian.Uint32(payload[:4])

	// Sanity check: length must be reasonable (2..35000) and we need at least 6 bytes
	if packetLength < 2 || packetLength > 35000 || len(payload) < 6 {
		return false
	}

	paddingLength := payload[4]
	// Padding length must be less than packet length
	if paddingLength >= byte(packetLength) {
		return false
	}

	msgType := payload[5]
	// Valid SSH message types: 1-255
	if msgType >= 1 {
		return true
	}

	return false
}

// ParseSSHPacket extracts SSH packet info (type, payload size).
// Returns nil if the payload is not a recognized SSH packet.
func ParseSSHPacket(payload []byte) *SSHPacketInfo {
	if len(payload) < 4 {
		return nil
	}

	// Check for SSH banner
	if payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-' {
		return &SSHPacketInfo{
			Type:    "banner",
			Payload: payload,
		}
	}

	// Try SSH binary packet format
	if len(payload) < 6 {
		return nil
	}

	packetLength := binary.BigEndian.Uint32(payload[:4])
	if packetLength < 2 || packetLength > 35000 {
		return nil
	}

	paddingLength := payload[4]
	if paddingLength >= byte(packetLength) {
		return nil
	}

	msgType := payload[5]

	// SSH_MSG_KEXINIT = 20
	if msgType == 20 {
		return &SSHPacketInfo{
			Type:    "kexinit",
			Payload: payload,
		}
	}

	return &SSHPacketInfo{
		Type:    "data",
		Payload: payload,
	}
}
