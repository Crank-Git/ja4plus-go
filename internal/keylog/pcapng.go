package keylog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The pcapng block types this reader knows.
// The IETF draft `draft-ietf-opsawg-pcapng` states each value.
const (
	// pcapngSectionHeaderType names the Section Header Block. The four bytes read the
	// same in both byte orders, so the byte-order magic that follows decides the order.
	pcapngSectionHeaderType = 0x0A0D0D0A
	// pcapngSecretsType names the Decryption Secrets Block.
	pcapngSecretsType = 0x0000000A
	// pcapngByteOrderMagic holds the value a Section Header Block carries at offset 8.
	pcapngByteOrderMagic = 0x1A2B3C4D
	// pcapngTLSKeyLogType names the Secrets Type of a TLS key log, which the IETF draft
	// writes as `0x544C534B` for the NSS key log format.
	pcapngTLSKeyLogType = 0x544C534B
)

// pcapngBlockHeaderLength counts the block type and the block total length.
const pcapngBlockHeaderLength = 8

// pcapngMinBlockLength is the smallest block: the type, the length and the repeated
// length.
const pcapngMinBlockLength = 12

// pcapngMaxBlockLength bounds one block.
// A capture is untrusted input, and the block length decides one allocation. The largest
// key log of the FoxIO corpus holds 1556 bytes, so 16 megabytes carries every real
// capture.
const pcapngMaxBlockLength = 16 << 20

// ErrNotPcapng reports that the reader does not start with a pcapng Section Header Block.
var ErrNotPcapng = errors.New("keylog: the capture holds no pcapng section header")

// ReadPcapng returns the TLS key log of every Decryption Secrets Block of a pcapng
// capture, in capture order.
// It returns the key logs it read together with any error, so a caller keeps the key logs
// that come before a truncated block.
// It returns ErrNotPcapng when the reader holds another capture format.
// `gopacket` v1.1.19 discards a Decryption Secrets Block, so this reader reads the block.
// The evidence is `pcapgo/ngread.go:504`, where the `default` case of `readPacketHeader`
// discards every block type the switch does not name, and `pcapgo/pcapng.go:35-40`, which
// defines no constant for block type 10.
func ReadPcapng(r io.Reader) ([][]byte, error) {
	var (
		logs   [][]byte
		order  binary.ByteOrder = binary.LittleEndian
		header                  = make([]byte, pcapngBlockHeaderLength)
		first                   = true
	)

	for {
		if _, err := io.ReadFull(r, header); err != nil {
			// A reader that ends on a block boundary holds a whole capture, and an empty
			// reader holds no capture. Neither is a defect.
			if errors.Is(err, io.EOF) {
				return logs, nil
			}

			return logs, fmt.Errorf("keylog: the block header is truncated: %w", err)
		}

		// The four bytes of the Section Header Block type read the same in both byte
		// orders, and every other block type reads in the order of its section.
		blockType := order.Uint32(header[0:4])
		if binary.LittleEndian.Uint32(header[0:4]) == pcapngSectionHeaderType {
			blockType = pcapngSectionHeaderType
		}

		if first && blockType != pcapngSectionHeaderType {
			return logs, ErrNotPcapng
		}

		first = false

		var body []byte

		var err error

		if blockType == pcapngSectionHeaderType {
			order, body, err = pcapngReadSectionHeader(r, header)
		} else {
			body, err = pcapngReadBody(r, order.Uint32(header[4:8]))
		}

		if err != nil {
			return logs, err
		}

		if blockType != pcapngSecretsType {
			continue
		}

		keyLog, err := pcapngKeyLogOfBlock(order, body)
		if err != nil {
			return logs, err
		}

		if keyLog != nil {
			logs = append(logs, keyLog)
		}
	}
}

// pcapngReadSectionHeader returns the byte order of the section and the body of the
// Section Header Block. The byte-order magic follows the block total length, so the reader
// reads it before it reads the length.
func pcapngReadSectionHeader(r io.Reader, header []byte) (binary.ByteOrder, []byte, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, nil, fmt.Errorf("keylog: the section header is truncated: %w", err)
	}

	var order binary.ByteOrder

	switch {
	case binary.LittleEndian.Uint32(magic) == pcapngByteOrderMagic:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(magic) == pcapngByteOrderMagic:
		order = binary.BigEndian
	default:
		return nil, nil, fmt.Errorf("keylog: the section header holds the byte-order magic %x", magic)
	}

	total := order.Uint32(header[4:8])
	if total < pcapngMinBlockLength+4 {
		return nil, nil, fmt.Errorf("keylog: the section header states the length %d", total)
	}

	// The reader already holds the four magic bytes, so the rest of the block follows.
	body, err := pcapngReadBody(r, total-4)
	if err != nil {
		return nil, nil, err
	}

	return order, body, nil
}

// pcapngReadBody returns the body of one block, without the block header and without the
// repeated block total length.
func pcapngReadBody(r io.Reader, total uint32) ([]byte, error) {
	if total < pcapngMinBlockLength || total%4 != 0 {
		return nil, fmt.Errorf("keylog: the block states the length %d", total)
	}

	if total > pcapngMaxBlockLength {
		return nil, fmt.Errorf("keylog: the block states the length %d, and the reader accepts %d",
			total, pcapngMaxBlockLength)
	}

	rest := make([]byte, total-pcapngBlockHeaderLength)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("keylog: the block is truncated: %w", err)
	}

	return rest[:len(rest)-4], nil
}

// pcapngKeyLogOfBlock returns the TLS key log of one Decryption Secrets Block.
// It returns nil for a block that holds secrets of another type.
func pcapngKeyLogOfBlock(order binary.ByteOrder, body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("keylog: the decryption secrets block holds %d bytes", len(body))
	}

	secretsType := order.Uint32(body[0:4])

	length := order.Uint32(body[4:8])
	if uint64(length) > uint64(len(body)-8) {
		return nil, fmt.Errorf("keylog: the decryption secrets block states %d secret bytes, and it holds %d",
			length, len(body)-8)
	}

	if secretsType != pcapngTLSKeyLogType {
		return nil, nil
	}

	keyLog := make([]byte, length)
	copy(keyLog, body[8:8+length])

	return keyLog, nil
}
