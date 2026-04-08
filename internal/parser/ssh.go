package parser

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
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

// KEXINITInfo holds parsed SSH KEXINIT algorithm lists.
// The 10 name-lists are: kex_algorithms, server_host_key_algorithms,
// encryption_c2s, encryption_s2c, mac_c2s, mac_s2c,
// compression_c2s, compression_s2c, languages_c2s, languages_s2c.
type KEXINITInfo struct {
	KexAlgorithms          string // index 0
	ServerHostKeyAlgorithms string // index 1
	EncryptionC2S          string // index 2
	EncryptionS2C          string // index 3
	MACC2S                 string // index 4
	MACS2C                 string // index 5
	CompressionC2S         string // index 6
	CompressionS2C         string // index 7
}

// ParseKEXINIT parses algorithm name-lists from an SSH KEXINIT message.
// The payload must start at the msg_type byte (0x14 = 20).
func ParseKEXINIT(payload []byte) *KEXINITInfo {
	// Need at least msg_type (1) + cookie (16) + some data
	if len(payload) < 17 {
		return nil
	}
	// Verify msg_type is KEXINIT
	if payload[0] != 20 {
		return nil
	}

	pos := 17 // skip msg_type (1) + cookie (16)
	lists := make([]string, 0, 10)

	for i := 0; i < 10; i++ {
		if pos+4 > len(payload) {
			break
		}
		nameListLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4
		if pos+nameListLen > len(payload) {
			break
		}
		lists = append(lists, string(payload[pos:pos+nameListLen]))
		pos += nameListLen
	}

	if len(lists) < 6 {
		return nil
	}

	info := &KEXINITInfo{
		KexAlgorithms:           lists[0],
		ServerHostKeyAlgorithms: lists[1],
		EncryptionC2S:           lists[2],
		EncryptionS2C:           lists[3],
		MACC2S:                  lists[4],
		MACS2C:                  lists[5],
	}
	if len(lists) > 6 {
		info.CompressionC2S = lists[6]
	}
	if len(lists) > 7 {
		info.CompressionS2C = lists[7]
	}
	return info
}

// ComputeHASSH computes the HASSH fingerprint from a KEXINIT.
// For client (isServer=false): MD5(kex;encryption_c2s;mac_c2s;compression_c2s)
// For server (isServer=true): MD5(kex;encryption_s2c;mac_s2c;compression_s2c)
func ComputeHASSH(info *KEXINITInfo, isServer bool) string {
	if info == nil {
		return ""
	}
	var hasshStr string
	if isServer {
		hasshStr = info.KexAlgorithms + ";" + info.EncryptionS2C + ";" + info.MACS2C + ";" + info.CompressionS2C
	} else {
		hasshStr = info.KexAlgorithms + ";" + info.EncryptionC2S + ";" + info.MACC2S + ";" + info.CompressionC2S
	}
	hash := md5.Sum([]byte(hasshStr))
	return fmt.Sprintf("%x", hash)
}

// ParseKEXINITFromPacket is a convenience function that extracts KEXINIT info
// from an SSH binary packet payload (starting from the 4-byte packet length).
func ParseKEXINITFromPacket(data []byte) *KEXINITInfo {
	if len(data) < 6 {
		return nil
	}
	packetLength := binary.BigEndian.Uint32(data[:4])
	if packetLength < 2 || packetLength > 65536 {
		return nil
	}
	if len(data) < 6 {
		return nil
	}
	// data[5] is msg_type
	if data[5] != 20 {
		return nil
	}
	// Pass from msg_type onward
	return ParseKEXINIT(data[5:])
}
