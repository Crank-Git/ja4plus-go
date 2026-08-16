package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// TLSRecordTypeApplicationData names the outer content type of every protected TLS 1.3
// record.
//
// RFC 8446 section 5.2 states the rule: `The outer opaque_type field of a TLSCiphertext
// record is always set to the value 23 (application_data) for outward compatibility with
// middleboxes accustomed to parsing previous versions of TLS.` So a TLS 1.3 server writes
// the Certificate message under this type, and never under TLSRecordTypeHandshake.
const TLSRecordTypeApplicationData = 0x17

// The HKDF-Expand-Label labels of the TLS 1.3 record layer.
//
// RFC 8446 section 7.3 states both:
//
//	[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
//	[sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
//
// QUIC renames them, so `DeriveQUICKeys` reads `quic key` and `quic iv` instead. RFC 9001
// section 5.1 states that rename.
const (
	TLS13KeyLabel = "key"
	TLS13IVLabel  = "iv"
)

// The key log labels of the TLS 1.3 secrets.
//
// `draft-ietf-tls-keylogfile` names each one, and `internal/keylog` reads the name from a
// key log line. A caller passes one of these to `KeyLog.Secret` of the root package.
const (
	TLS13ClientHandshakeSecretLabel   = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	TLS13ServerHandshakeSecretLabel   = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	TLS13ClientApplicationSecretLabel = "CLIENT_TRAFFIC_SECRET_0"
	TLS13ServerApplicationSecretLabel = "SERVER_TRAFFIC_SECRET_0"
)

// The three lengths of TLS_AES_128_GCM_SHA256.
//
// RFC 8446 section 7.3 names `key_length` and `iv_length`, and RFC 8446 appendix B.4 names
// the suite. The secret length is the output length of SHA-256.
const (
	tls13SecretLength = 32
	tls13KeyLength    = 16
	tls13IVLength     = 12
)

// tls13RecordHeaderLength is the byte count of the record header that RFC 8446 section 5.2
// states: one content type byte, two version bytes and a two-byte length.
const tls13RecordHeaderLength = 5

// tls13MaxRecordLength bounds the length field of one record.
//
// RFC 8446 section 5.2 states the bound: `The length MUST NOT exceed 2^14 + 256 bytes.`
const tls13MaxRecordLength = 1<<14 + 256

// TLS13RecordKeys holds the write key and the write initialization vector of one TLS 1.3
// traffic secret.
//
// One TLS13RecordKeys value does not change after DeriveTLS13RecordKeys returns it, so any
// number of goroutines read one value. It holds no sequence number, because the sequence
// number belongs to the stream and not to the key.
type TLS13RecordKeys struct {
	// Key holds the [sender]_write_key of RFC 8446 section 7.3.
	Key []byte
	// IV holds the [sender]_write_iv of RFC 8446 section 7.3.
	IV []byte
}

// DeriveTLS13RecordKeys returns the record keys of one TLS 1.3 traffic secret.
//
// RFC 8446 section 7.3 states the two derivations, and this function writes the labels
// TLS13KeyLabel and TLS13IVLabel.
// It returns ErrNoSecret when the caller supplies no secret.
// It returns an error for a secret of another length, because the library reads the
// SHA-256 key schedule of TLS_AES_128_GCM_SHA256 only. A SHA-384 suite states a 48-byte
// secret, and this error names it. A ChaCha20-Poly1305 suite states a 32-byte secret, so
// this function returns keys for it and the record then fails the authentication check.
// Issue #492 is the reversal path of that decline.
func DeriveTLS13RecordKeys(secret []byte) (*TLS13RecordKeys, error) {
	if len(secret) == 0 {
		return nil, ErrNoSecret
	}

	if len(secret) != tls13SecretLength {
		return nil, fmt.Errorf("parser: the secret holds %d bytes, and the library reads %d",
			len(secret), tls13SecretLength)
	}

	key, err := hkdfExpandLabel(secret, TLS13KeyLabel, nil, tls13KeyLength)
	if err != nil {
		return nil, err
	}

	iv, err := hkdfExpandLabel(secret, TLS13IVLabel, nil, tls13IVLength)
	if err != nil {
		return nil, err
	}

	return &TLS13RecordKeys{Key: key, IV: iv}, nil
}

// Open returns the content and the inner content type of one protected TLS 1.3 record.
//
// record starts at the first byte of the record header, and it holds the whole record. A
// longer buffer is allowed, because one stream carries more than one record.
// sequence names the record sequence number of the direction. RFC 8446 section 5.3 states
// that the first record under one traffic key uses the number 0.
// It returns a non-fatal error for a record it cannot read, and it never panics.
//
// The construction follows RFC 8446 section 5.2 and section 5.3. The additional data is
// the record header:
//
//	additional_data = TLSCiphertext.opaque_type ||
//	                  TLSCiphertext.legacy_record_version ||
//	                  TLSCiphertext.length
//
// The nonce takes two steps:
//
//  1. The 64-bit record sequence number is encoded in network byte
//     order and padded to the left with zeros to iv_length.
//
//  2. The padded sequence number is XORed with either the static
//     client_write_iv or server_write_iv (depending on the role).
func (k *TLS13RecordKeys) Open(record []byte, sequence uint64) ([]byte, byte, error) {
	if k == nil {
		return nil, 0, ErrNoSecret
	}

	// Every packet is untrusted input, so the header bound comes before the length field.
	if len(record) < tls13RecordHeaderLength {
		return nil, 0, fmt.Errorf("parser: the record holds %d bytes, and the header needs %d",
			len(record), tls13RecordHeaderLength)
	}

	length := int(record[3])<<8 | int(record[4])
	if length > tls13MaxRecordLength {
		return nil, 0, fmt.Errorf("parser: the record states %d bytes, and RFC 8446 bounds it at %d",
			length, tls13MaxRecordLength)
	}

	end := tls13RecordHeaderLength + length
	if end > len(record) {
		return nil, 0, errors.New("parser: the record length passes the end of the stream")
	}

	block, err := aes.NewCipher(k.Key)
	if err != nil {
		return nil, 0, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}

	nonce := make([]byte, len(k.IV))
	copy(nonce, k.IV)

	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(sequence >> (8 * i))
	}

	header := record[:tls13RecordHeaderLength]

	plaintext, err := aead.Open(nil, nonce, record[tls13RecordHeaderLength:end], header)
	if err != nil {
		return nil, 0, fmt.Errorf("parser: the secret does not open the record: %w", err)
	}

	// RFC 8446 section 5.2 states the inner plaintext as the content, then the type, then
	// a run of zero bytes. So the reader walks back over the padding to find the type.
	last := len(plaintext) - 1
	for last >= 0 && plaintext[last] == 0x00 {
		last--
	}

	if last < 0 {
		return nil, 0, errors.New("parser: the record plaintext holds zero bytes alone")
	}

	return plaintext[:last], plaintext[last], nil
}

// TLS13ContentOfStream returns the content of each protected record of one stream that
// carries the wanted inner content type, and the count of records the keys opened.
//
// The walk reads the stream from the first byte, and it steps over each record by the
// length field of that record. It counts the protected records, because RFC 8446 section
// 5.3 states that the sequence number restarts at 0 at each key change and no record
// carries its own number. An unprotected record carries no sequence number, so the count
// reads the records of type TLSRecordTypeApplicationData alone.
//
// skip names the count of protected records that an earlier traffic key protects. A caller
// that reads the handshake of a stream passes 0, and a caller that reads the application
// data passes the count this function returned for the handshake.
//
// It stops at the first protected record the keys do not open, because the sender changes
// the traffic key after the handshake. It returns the content it read up to that record.
// It reads no record of a stream whose length field passes the end.
func TLS13ContentOfStream(stream []byte, keys *TLS13RecordKeys, skip uint64, innerType byte) ([]byte, uint64) {
	if keys == nil {
		return nil, 0
	}

	var content []byte

	protected := uint64(0)
	opened := uint64(0)

	for pos := 0; pos+tls13RecordHeaderLength <= len(stream); {
		length := int(stream[pos+3])<<8 | int(stream[pos+4])

		next := pos + tls13RecordHeaderLength + length
		if next > len(stream) {
			break
		}

		if stream[pos] != TLSRecordTypeApplicationData {
			pos = next
			continue
		}

		if protected < skip {
			protected++
			pos = next

			continue
		}

		record, found, err := keys.Open(stream[pos:next], protected-skip)
		if err != nil {
			break
		}

		if found == innerType {
			content = append(content, record...)
		}

		protected++
		opened++
		pos = next
	}

	return content, opened
}
