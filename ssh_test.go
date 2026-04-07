package ja4plus

import (
	"encoding/binary"
	"testing"
)

func TestIsSSHPacket_Banner(t *testing.T) {
	payload := []byte("SSH-2.0-OpenSSH_8.9\r\n")
	if !IsSSHPacket(payload) {
		t.Error("expected SSH banner to be detected")
	}
}

func TestIsSSHPacket_NonSSH(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
	if IsSSHPacket(payload) {
		t.Error("expected non-SSH data to not be detected as SSH")
	}
}

func TestIsSSHPacket_Empty(t *testing.T) {
	if IsSSHPacket(nil) {
		t.Error("expected nil payload to return false")
	}
	if IsSSHPacket([]byte{}) {
		t.Error("expected empty payload to return false")
	}
	if IsSSHPacket([]byte{0x01, 0x02}) {
		t.Error("expected short payload to return false")
	}
}

func TestIsSSHPacket_BinaryPacket(t *testing.T) {
	// Build a valid SSH binary packet: length=20, padding=4, msg_type=21 (NEWKEYS)
	buf := make([]byte, 26)
	binary.BigEndian.PutUint32(buf[0:4], 20)
	buf[4] = 4  // padding length
	buf[5] = 21 // msg type (NEWKEYS)
	if !IsSSHPacket(buf) {
		t.Error("expected valid SSH binary packet to be detected")
	}
}

func TestIsSSHPacket_InvalidLength(t *testing.T) {
	// Packet length too large
	buf := make([]byte, 10)
	binary.BigEndian.PutUint32(buf[0:4], 50000)
	buf[4] = 4
	buf[5] = 21
	if IsSSHPacket(buf) {
		t.Error("expected oversized packet length to return false")
	}
}

func TestParseSSHPacket_Banner(t *testing.T) {
	payload := []byte("SSH-2.0-OpenSSH_8.9\r\n")
	info := ParseSSHPacket(payload)
	if info == nil {
		t.Fatal("expected non-nil result for SSH banner")
	}
	if info.Type != "banner" {
		t.Errorf("expected type 'banner', got %q", info.Type)
	}
}

func TestParseSSHPacket_Kexinit(t *testing.T) {
	// Build a KEXINIT binary packet: msg_type=20
	buf := make([]byte, 26)
	binary.BigEndian.PutUint32(buf[0:4], 20)
	buf[4] = 4
	buf[5] = 20 // SSH_MSG_KEXINIT
	info := ParseSSHPacket(buf)
	if info == nil {
		t.Fatal("expected non-nil result for KEXINIT")
	}
	if info.Type != "kexinit" {
		t.Errorf("expected type 'kexinit', got %q", info.Type)
	}
}

func TestParseSSHPacket_Data(t *testing.T) {
	// Build a data packet: msg_type=94 (SSH_MSG_CHANNEL_DATA)
	buf := make([]byte, 26)
	binary.BigEndian.PutUint32(buf[0:4], 20)
	buf[4] = 4
	buf[5] = 94
	info := ParseSSHPacket(buf)
	if info == nil {
		t.Fatal("expected non-nil result for data packet")
	}
	if info.Type != "data" {
		t.Errorf("expected type 'data', got %q", info.Type)
	}
}

func TestParseSSHPacket_Nil(t *testing.T) {
	if ParseSSHPacket(nil) != nil {
		t.Error("expected nil for nil input")
	}
	if ParseSSHPacket([]byte{0x01}) != nil {
		t.Error("expected nil for short input")
	}
}
