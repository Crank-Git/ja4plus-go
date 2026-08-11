package keylog

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// pcapngTestSectionHeader returns one Section Header Block in the byte order.
func pcapngTestSectionHeader(order binary.ByteOrder) []byte {
	block := make([]byte, 28)
	order.PutUint32(block[0:4], 0x0A0D0D0A)
	order.PutUint32(block[4:8], 28)
	order.PutUint32(block[8:12], 0x1A2B3C4D)
	order.PutUint16(block[12:14], 1)
	order.PutUint16(block[14:16], 0)
	order.PutUint64(block[16:24], 0xFFFFFFFFFFFFFFFF)
	order.PutUint32(block[24:28], 28)

	return block
}

// pcapngTestSecretsBlock returns one Decryption Secrets Block that holds the data.
func pcapngTestSecretsBlock(order binary.ByteOrder, secretsType uint32, data []byte) []byte {
	padded := (len(data) + 3) / 4 * 4
	total := 20 + padded
	block := make([]byte, total)
	order.PutUint32(block[0:4], 0x0000000A)
	order.PutUint32(block[4:8], uint32(total))
	order.PutUint32(block[8:12], secretsType)
	order.PutUint32(block[12:16], uint32(len(data)))
	copy(block[16:], data)
	order.PutUint32(block[total-4:total], uint32(total))

	return block
}

func TestReadPcapngReadsOneDecryptionSecretsBlock(t *testing.T) {
	secrets := "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00 11\n"
	capture := append(pcapngTestSectionHeader(binary.LittleEndian),
		pcapngTestSecretsBlock(binary.LittleEndian, 0x544C534B, []byte(secrets))...)

	logs, err := ReadPcapng(bytes.NewReader(capture))
	if err != nil {
		t.Fatalf("ReadPcapng returned %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("ReadPcapng returned %d key logs, and the capture holds 1", len(logs))
	}

	if string(logs[0]) != secrets {
		t.Errorf("ReadPcapng returned %q, and the block holds %q", logs[0], secrets)
	}
}

func TestReadPcapngReadsABigEndianCapture(t *testing.T) {
	secrets := "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00 11\n"
	capture := append(pcapngTestSectionHeader(binary.BigEndian),
		pcapngTestSecretsBlock(binary.BigEndian, 0x544C534B, []byte(secrets))...)

	logs, err := ReadPcapng(bytes.NewReader(capture))
	if err != nil {
		t.Fatalf("ReadPcapng returned %v", err)
	}

	if len(logs) != 1 || string(logs[0]) != secrets {
		t.Fatalf("ReadPcapng returned %q, and the block holds %q", logs, secrets)
	}
}

func TestReadPcapngSkipsASecretsTypeThatIsNotATLSKeyLog(t *testing.T) {
	// 0x57474B4C is the WireGuard Key Log type, which this library does not read.
	capture := append(pcapngTestSectionHeader(binary.LittleEndian),
		pcapngTestSecretsBlock(binary.LittleEndian, 0x57474B4C, []byte("key"))...)

	logs, err := ReadPcapng(bytes.NewReader(capture))
	if err != nil {
		t.Fatalf("ReadPcapng returned %v", err)
	}

	if len(logs) != 0 {
		t.Errorf("ReadPcapng returned %d key logs, and the capture holds none", len(logs))
	}
}

func TestReadPcapngRejectsASecretsLengthPastTheBlock(t *testing.T) {
	block := pcapngTestSecretsBlock(binary.LittleEndian, 0x544C534B, []byte("abcd"))
	binary.LittleEndian.PutUint32(block[12:16], 0xFFFFFF00)
	capture := append(pcapngTestSectionHeader(binary.LittleEndian), block...)

	if _, err := ReadPcapng(bytes.NewReader(capture)); err == nil {
		t.Error("ReadPcapng returned no error, and the secrets length passes the block")
	}
}

func TestReadPcapngRejectsABlockLengthBelowTheHeader(t *testing.T) {
	capture := pcapngTestSectionHeader(binary.LittleEndian)
	block := make([]byte, 12)
	binary.LittleEndian.PutUint32(block[0:4], 0x0000000A)
	binary.LittleEndian.PutUint32(block[4:8], 4)
	capture = append(capture, block...)

	if _, err := ReadPcapng(bytes.NewReader(capture)); err == nil {
		t.Error("ReadPcapng returned no error, and the block length is 4")
	}
}

func TestReadPcapngRejectsACaptureWithNoSectionHeader(t *testing.T) {
	capture := pcapngTestSecretsBlock(binary.LittleEndian, 0x544C534B, []byte("x"))

	if _, err := ReadPcapng(bytes.NewReader(capture)); err == nil {
		t.Error("ReadPcapng returned no error, and the capture starts with no section header")
	}
}

func TestReadPcapngReportsATruncatedBlock(t *testing.T) {
	capture := append(pcapngTestSectionHeader(binary.LittleEndian),
		pcapngTestSecretsBlock(binary.LittleEndian, 0x544C534B, []byte("secret"))...)

	if _, err := ReadPcapng(bytes.NewReader(capture[:len(capture)-6])); err == nil {
		t.Error("ReadPcapng returned no error, and the last block is truncated")
	}
}

func TestReadPcapngReadsAnEmptyReader(t *testing.T) {
	logs, err := ReadPcapng(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("ReadPcapng returned %v", err)
	}

	if len(logs) != 0 {
		t.Errorf("ReadPcapng returned %d key logs, and the reader holds none", len(logs))
	}
}
