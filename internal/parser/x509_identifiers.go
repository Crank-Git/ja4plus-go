package parser

import "encoding/hex"

// This file reads the three object identifier lists of a certificate, and it parses no
// public key.
//
// `crypto/x509` returns an error for a certificate whose public key names explicit
// elliptic curve parameters, and that error fails the whole certificate parse.
// `docs/audit/ja4x-deviation-cluster.md`
// `## Cause 3 — the Go certificate parser refuses explicit elliptic curve parameters`
// measured the cause, and issue #490 records the repair. JA4X reads the issuer
// identifiers, the subject identifiers and the extension identifiers, so the key blocks
// none of them.
//
// The reader validates no signature and it makes no trust decision. The certificate of
// `badcurveball.pcap` holds the CVE-2020-0601 shape, and a reader of an identifier list
// needs no trust decision.

// Each constant below names one ASN.1 tag byte that a certificate holds.
// X.690 states the low-tag-number form, and RFC 5280 section 4.1 states each field.
const (
	derTagInteger    = 0x02
	derTagOID        = 0x06
	derTagSequence   = 0x30
	derTagSet        = 0x31
	derTagVersion    = 0xa0 // [0] EXPLICIT Version of TBSCertificate.
	derTagExtensions = 0xa3 // [3] EXPLICIT Extensions of TBSCertificate.
)

// derMaxLengthOctets bounds the long form of an ASN.1 length field.
//
// A length above four octets names a certificate larger than any memory this library
// holds, and `ja4xCertificatesInMessage` of `ja4x.go` already bounds one certificate at
// 200000 bytes. The bound also stops a crafted field that would otherwise read far past
// the input.
const derMaxLengthOctets = 4

// X509Identifiers holds the three object identifier lists that JA4X reads.
//
// Each string is the lowercase hexadecimal form of the content octets of one ASN.1 OBJECT
// IDENTIFIER. `testdata/foxio/reference/rust/ja4x/src/lib.rs:66` writes
// `hex::encode(a.attr_type().as_bytes())`, so the reference hexes the same octets.
type X509Identifiers struct {
	// Issuer holds the identifiers of the issuer RDNSequence, in the order the certificate
	// states them.
	Issuer []string
	// Subject holds the identifiers of the subject RDNSequence, in the same order.
	Subject []string
	// Extensions holds the identifier of each extension. It is empty when the certificate
	// carries no extension, because RFC 5280 section 4.1 makes the field optional.
	Extensions []string
}

// ReadX509Identifiers returns the issuer, subject and extension object identifiers of a
// DER-encoded certificate. The second return value is false when the certificate does not
// read.
//
// The reader walks the ASN.1 structure of TBSCertificate, and it skips the public key. So
// it answers true for a certificate that `x509.ParseCertificate` refuses. It validates no
// signature, and it makes no trust decision.
//
// Every packet is untrusted input, so the reader compares each length field with the
// remaining input before it slices.
func ReadX509Identifiers(der []byte) (X509Identifiers, bool) {
	var identifiers X509Identifiers

	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
	certificate, _, ok := derElement(der, derTagSequence)
	if !ok {
		return identifiers, false
	}

	// TBSCertificate is the first field, and it holds every field the reader needs.
	fields, _, ok := derElement(certificate, derTagSequence)
	if !ok {
		return identifiers, false
	}

	// A version 1 certificate omits the version field, so the reader reads the tag first.
	if len(fields) > 0 && fields[0] == derTagVersion {
		if fields, ok = derSkipElement(fields); !ok {
			return identifiers, false
		}
	}

	// serialNumber CertificateSerialNumber ::= INTEGER.
	if _, fields, ok = derElement(fields, derTagInteger); !ok {
		return identifiers, false
	}

	// signature AlgorithmIdentifier.
	if _, fields, ok = derElement(fields, derTagSequence); !ok {
		return identifiers, false
	}

	issuerName, fields, ok := derElement(fields, derTagSequence)
	if !ok {
		return identifiers, false
	}

	// validity Validity.
	if _, fields, ok = derElement(fields, derTagSequence); !ok {
		return identifiers, false
	}

	subjectName, fields, ok := derElement(fields, derTagSequence)
	if !ok {
		return identifiers, false
	}

	// subjectPublicKeyInfo SubjectPublicKeyInfo. The reader skips it, and that skip is the
	// whole repair of #490.
	if _, fields, ok = derElement(fields, derTagSequence); !ok {
		return identifiers, false
	}

	extensionIdentifiers, ok := derIdentifiersInTrailingFields(fields)
	if !ok {
		return identifiers, false
	}

	issuerIdentifiers, ok := derIdentifiersInName(issuerName)
	if !ok {
		return identifiers, false
	}

	subjectIdentifiers, ok := derIdentifiersInName(subjectName)
	if !ok {
		return identifiers, false
	}

	identifiers.Issuer = issuerIdentifiers
	identifiers.Subject = subjectIdentifiers
	identifiers.Extensions = extensionIdentifiers
	return identifiers, true
}

// derIdentifiersInTrailingFields returns the extension identifiers that the fields after
// subjectPublicKeyInfo hold. It returns an empty list when no extensions field is present.
//
// issuerUniqueID, subjectUniqueID and extensions are each optional, and each one carries a
// context tag. So the walk reads the tag of every remaining field.
func derIdentifiersInTrailingFields(fields []byte) ([]string, bool) {
	for len(fields) > 0 {
		if fields[0] == derTagExtensions {
			content, _, ok := derElement(fields, derTagExtensions)
			if !ok {
				return nil, false
			}
			return derIdentifiersInExtensions(content)
		}

		var ok bool
		if fields, ok = derSkipElement(fields); !ok {
			return nil, false
		}
	}
	return nil, true
}

// derIdentifiersInName returns the object identifier of every attribute of one
// RDNSequence, in the order the certificate states them.
//
// Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName, and
// RelativeDistinguishedName ::= SET OF AttributeTypeAndValue. RFC 5280 section 4.1.2.4
// states both. The first field of AttributeTypeAndValue is the identifier.
func derIdentifiersInName(name []byte) ([]string, bool) {
	var identifiers []string

	for rest := name; len(rest) > 0; {
		set, afterSet, ok := derElement(rest, derTagSet)
		if !ok {
			return nil, false
		}
		rest = afterSet

		for attributes := set; len(attributes) > 0; {
			attribute, afterAttribute, ok := derElement(attributes, derTagSequence)
			if !ok {
				return nil, false
			}
			attributes = afterAttribute

			oid, _, ok := derElement(attribute, derTagOID)
			if !ok {
				return nil, false
			}
			identifiers = append(identifiers, hex.EncodeToString(oid))
		}
	}

	return identifiers, true
}

// derIdentifiersInExtensions returns the object identifier of every extension.
//
// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension, and the first field of Extension is
// the identifier. RFC 5280 section 4.1 states both.
func derIdentifiersInExtensions(extensions []byte) ([]string, bool) {
	list, _, ok := derElement(extensions, derTagSequence)
	if !ok {
		return nil, false
	}

	var identifiers []string
	for rest := list; len(rest) > 0; {
		extension, afterExtension, ok := derElement(rest, derTagSequence)
		if !ok {
			return nil, false
		}
		rest = afterExtension

		oid, _, ok := derElement(extension, derTagOID)
		if !ok {
			return nil, false
		}
		identifiers = append(identifiers, hex.EncodeToString(oid))
	}

	return identifiers, true
}

// derElement returns the content octets of the first element of b, and the bytes after
// that element. It returns false when the tag of that element differs from want.
func derElement(b []byte, want byte) (content, rest []byte, ok bool) {
	if len(b) < 2 || b[0] != want {
		return nil, nil, false
	}
	return derAnyElement(b)
}

// derSkipElement returns the bytes after the first element of b. It reads the tag of that
// element and it compares no tag.
func derSkipElement(b []byte) ([]byte, bool) {
	_, rest, ok := derAnyElement(b)
	return rest, ok
}

// derAnyElement returns the content octets of the first element of b, and the bytes after
// that element. It accepts every tag.
//
// The reader refuses the indefinite length form, because DER states one definite length
// for every element. X.690 clause 10.1 states that rule.
func derAnyElement(b []byte) (content, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}

	length := int(b[1])
	offset := 2

	if length&0x80 != 0 {
		octets := length & 0x7f
		if octets == 0 || octets > derMaxLengthOctets || len(b) < offset+octets {
			return nil, nil, false
		}

		length = 0
		for _, octet := range b[offset : offset+octets] {
			length = length<<8 | int(octet)
		}
		offset += octets

		// A four-octet length overflows a 32-bit int, and a negative length would slice
		// backwards.
		if length < 0 {
			return nil, nil, false
		}
	}

	// Every packet is untrusted input, so the length is compared with the remaining input
	// before the slice below reads it.
	if length > len(b)-offset {
		return nil, nil, false
	}
	return b[offset : offset+length], b[offset+length:], true
}
