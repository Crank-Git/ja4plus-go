package ja4plus

import (
	"fmt"
	"net"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
)

// This file holds the evidence of issue #23. The audit checks FR-audit-15 through
// FR-audit-18, and `docs/audit/findings.md` records each finding that these tests reach.
//
// A test whose name starts with `TestTheAuditRecords` states the behavior of a finding
// that stays open. It passes on the code the audit read, and it fails when issue #25
// closes the finding. Issue #25 inverts the assertion in the same commit that closes it.

// auditStateClientIP and auditStateServerIP are the two endpoints of every connection this
// file builds. A fixed address keeps each state table key readable in a failure message.
const (
	auditStateClientIP = "192.168.1.10"
	auditStateServerIP = "10.0.0.5"
)

// auditStateFingerprinters returns every fingerprinter of the processor by name.
// The audit reads each one, because FR-audit-16 names the results slice of every
// fingerprinter and FR-audit-18 names every field that holds state.
// It derives the set from the processor run list, so a new fingerprinter reaches the audit
// with no edit. Issue #148 records the fault a second list produces.
func auditStateFingerprinters(proc *Processor) map[string]Fingerprinter {
	return processorFingerprinters(proc)
}

// auditStateLengths returns the length of every map field and every slice field that the
// fingerprinter reaches, by the path of the field.
// It follows a pointer to a struct, so the map inside the JA4H reassembler is visible.
// It reads an unexported field, because every state field of this package is unexported.
func auditStateLengths(value reflect.Value, path string, lengths map[string]int) {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return
		}

		auditStateLengths(value.Elem(), path, lengths)

		return
	}

	if value.Kind() != reflect.Struct {
		return
	}

	typ := value.Type()

	for index := 0; index < typ.NumField(); index++ {
		field := value.Field(index)
		name := path + "." + typ.Field(index).Name

		switch field.Kind() {
		case reflect.Map, reflect.Slice:
			lengths[name] = field.Len()
		case reflect.Pointer:
			auditStateLengths(field, name, lengths)
		}
	}
}

// auditStateFieldLengths returns the length of every state field of the fingerprinter.
func auditStateFieldLengths(name string, fingerprinter any) map[string]int {
	lengths := map[string]int{}
	auditStateLengths(reflect.ValueOf(fingerprinter), name, lengths)

	return lengths
}

// auditStatePacketSet returns one packet set that gives every fingerprinter state.
// A test of Reset proves nothing about a fingerprinter that holds no state, so each
// fingerprinter needs a packet it reads.
func auditStatePacketSet(t *testing.T) []gopacket.Packet {
	t.Helper()

	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	sshBanner := []byte("SSH-2.0-OpenSSH_9.0\r\n")
	httpRequest := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")

	return []gopacket.Packet{
		// JA4T reads the SYN packet, and JA4L reads the timestamp of it.
		buildTCPPacketWithIPs(t, client, server, 64, 40001, 443, true, false),
		// JA4TS reads the SYN-ACK packet.
		buildTCPPacketWithIPs(t, server, client, 64, 443, 40001, true, true),
		// JA4 reads the TLS client hello.
		buildTCPPacketWithPayload(t, buildClientHelloPayload()),
		// JA4S reads the TLS server hello.
		buildTCPPayloadPacket(t, buildServerHelloPayload(0x1301,
			[]uint16{parser.ExtSupportedVersions}, "")),
		// JA4H reads the HTTP request.
		buildTCPPacketWithSeq(t, client, server, 40002, 80, 1, httpRequest),
		// JA4X reads the TLS certificate record.
		buildTCPPacketWithSeq(t, server, client, 443, 40003, 1,
			buildCertificateRecordPayload(generateSelfSignedCertDER(t))),
		// JA4SSH reads the SSH banner.
		buildSSHPacket(auditStateClientIP, auditStateServerIP, 40004, 22, sshBanner, false),
		// JA4D reads the DHCP message, and JA4D6 reads the DHCPv6 message.
		buildDHCPDiscoverPacket(t),
		buildDHCPv6SolicitPacket(t),
	}
}

// auditStateStatelessTypes names each fingerprinter that holds no state at all.
// Issue #25 removed the results slice, and these three held nothing else. A field that
// returns to one of them needs a removal path, so this list is the reader's warning.
//
// `JA4TSFingerprinter` left this list at issue #56, which gave it the state table
// that part e and the RST value read.
var auditStateStatelessTypes = []string{
	"JA4TFingerprinter", "JA4DFingerprinter", "JA4D6Fingerprinter",
}

// FR-audit-18. Reset clears every field that holds state.
// A monitor that reuses one processor for a second capture reads the state of the first
// one when Reset leaves a field.
func TestReset_ClearsEveryStateFieldOfEveryFingerprinter(t *testing.T) {
	proc := NewProcessor()

	for _, packet := range auditStatePacketSet(t) {
		_, _ = proc.ProcessPacket(packet)
	}

	fingerprinters := auditStateFingerprinters(proc)

	if len(fingerprinters) == 0 {
		t.Fatal("the processor runs no fingerprinter, so this test proves nothing")
	}

	held := 0

	for name, fingerprinter := range fingerprinters {
		fields := auditStateFieldLengths(name, fingerprinter)

		for _, length := range fields {
			held += length
		}

		// A stateless type holds no map field and no slice field, so its removal path is
		// the absence of state. Every other type carries at least one field.
		stateless := slices.Contains(auditStateStatelessTypes, name)

		if stateless && len(fields) != 0 {
			t.Errorf("%s holds the state fields %v, and the record names it stateless", name, fields)
		}

		if !stateless && len(fields) == 0 {
			t.Errorf("%s holds no state field, and the record names it stateful", name)
		}
	}

	if held == 0 {
		t.Fatal("the packet set left no state at all, so this test proves nothing about Reset")
	}

	proc.Reset()

	for name, fingerprinter := range fingerprinters {
		for field, length := range auditStateFieldLengths(name, fingerprinter) {
			if length != 0 {
				t.Errorf("Reset leaves %d entries in %s", length, field)
			}
		}
	}
}

// FR-audit-15 and FR-audit-17. Every state table has a removal path, and
// CleanupConnection reaches it for the connection the caller names.
func TestCleanupConnection_RemovesTheStateTableEntryOfTheNamedConnection(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	// A partial HTTP request stays in the reassembler, because the fast path of
	// JA4H removes a stream it parses in one packet.
	partialRequest := []byte("Host: example.com\r\nAccept: */*\r\n")

	cases := []struct {
		name    string
		state   func(t *testing.T) (Fingerprinter, func() int)
		cleanup func(fingerprinter Fingerprinter)
	}{
		{
			name: "JA4LFingerprinter clears the connections table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4L()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithIPs(t, client, server, 64, 40010, 443, true, false))

				return fingerprinter, func() int { return len(fingerprinter.connections) }
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40010, auditStateServerIP, 443, "tcp")
			},
		},
		{
			name: "JA4SSHFingerprinter clears the connections table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4SSH(0)
				_, _ = fingerprinter.ProcessPacket(buildSSHPacket(auditStateClientIP, auditStateServerIP,
					40011, 22, []byte("SSH-2.0-OpenSSH_9.0\r\n"), false))

				return fingerprinter, func() int { return len(fingerprinter.connections) }
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40011, auditStateServerIP, 22, "tcp")
			},
		},
		{
			name: "JA4HFingerprinter clears the reassembler",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4H()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithSeq(t, client, server, 40012, 80, 1, partialRequest))

				// The reassembler holds its stream table in an unexported field of
				// another package, so the reflect walk reads the count.
				return fingerprinter, func() int {
					return auditStateFieldLengths("JA4HFingerprinter", fingerprinter)["JA4HFingerprinter.reassembler.streams"]
				}
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40012, auditStateServerIP, 80, "tcp")
			},
		},
		{
			name: "JA4XFingerprinter clears the streams table",
			state: func(t *testing.T) (Fingerprinter, func() int) {
				t.Helper()

				fingerprinter := NewJA4X()
				_, _ = fingerprinter.ProcessPacket(
					buildTCPPacketWithSeq(t, server, client, 443, 40013, 1, []byte("not a record")))

				// The reassembler holds its stream table in an unexported field of
				// another package, so the reflect walk reads the count.
				return fingerprinter, func() int {
					return auditStateFieldLengths("JA4XFingerprinter", fingerprinter)["JA4XFingerprinter.reassembler.streams"]
				}
			},
			cleanup: func(fingerprinter Fingerprinter) {
				fingerprinter.CleanupConnection(auditStateClientIP, 40013, auditStateServerIP, 443, "tcp")
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter, count := testCase.state(t)

			if count() == 0 {
				t.Fatal("the packet gave the fingerprinter no state, so this test proves no removal path")
			}

			testCase.cleanup(fingerprinter)

			if got := count(); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries in the state table", got)
			}
		})
	}
}

// F-23-11 is closed. JA4 keys its QUIC state by the tuple of the packet that carried the
// client hello, and CleanupConnection built one direction of that tuple. A caller that
// named the server endpoint first removed no entry. The method now reads both
// directions, which matches the sorted five-tuple that GetShardKey returns.
//
// The test seeds the two maps in the form that ProcessPacket writes, because a synthetic
// QUIC Initial packet reaches no decryption.
func TestJA4CleanupConnectionReadsBothDirectionsOfTheTuple(t *testing.T) {
	const dcid = "8394c8f03e515708"

	seed := func() *JA4Fingerprinter {
		fingerprinter := NewJA4()
		fingerprinter.quicFragments[dcid] = []parser.CryptoFragment{{Offset: 0, Data: []byte{0x01}}}
		fingerprinter.dcidToTuple[dcid] = fmt.Sprintf("%s:%d-%s:%d",
			auditStateClientIP, 40020, auditStateServerIP, 443)

		return fingerprinter
	}

	cases := []struct {
		name    string
		cleanup func(*JA4Fingerprinter)
	}{
		{"the caller names the server endpoint first", func(f *JA4Fingerprinter) {
			f.CleanupConnection(auditStateServerIP, 443, auditStateClientIP, 40020, "udp")
		}},
		{"the caller names the client endpoint first", func(f *JA4Fingerprinter) {
			f.CleanupConnection(auditStateClientIP, 40020, auditStateServerIP, 443, "udp")
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fingerprinter := seed()
			testCase.cleanup(fingerprinter)

			if got := len(fingerprinter.quicFragments); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries in the fragment table", got)
			}

			if got := len(fingerprinter.dcidToTuple); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries in the reverse map", got)
			}
		})
	}
}

// F-23-12 is closed. JA4X keyed the deduplication set by the hash of the certificate.
// CleanupConnection therefore reached no entry of it, and a certificate that two connections
// carried produced one fingerprint. The fingerprinter now holds a stream index of the hashes it
// wrote, and CleanupConnection removes the hashes of the connection the caller names.
// #489 then gave the set key the stream beside the certificate hash.
func TestJA4XCleanupConnectionRemovesTheCertificateHashOfTheConnection(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}
	record := buildCertificateRecordPayload(generateSelfSignedCertDER(t))

	fingerprinter := NewJA4X()

	first, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 40030, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(first) != 1 {
		t.Fatalf("the first connection produced %d results, want 1", len(first))
	}

	fingerprinter.CleanupConnection(auditStateClientIP, 40030, auditStateServerIP, 443, "tcp")

	second, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 40031, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(second) != 1 {
		t.Errorf("the second connection produced %d results, and the closure of F-23-12 produces 1", len(second))
	}

	if got := len(fingerprinter.processedCerts); got != 1 {
		t.Errorf("the deduplication set holds %d entries, and the second connection wrote one", got)
	}

	// A third connection carries the same certificate on a third stream, and it produces
	// one value. #489 keyed the set by the certificate and the stream together, and this
	// assertion read 0 before that change.
	// `TestJA4XProducesOneValueWhenOneStreamRepeatsOneCertificate` of
	// `ja4x_stream_key_test.go` holds the deduplication that one stream still needs.
	third, err := fingerprinter.ProcessPacket(
		buildTCPPacketWithSeq(t, server, client, 443, 40032, 1, record))
	if err != nil {
		t.Fatalf("ProcessPacket returned the error %v", err)
	}

	if len(third) != 1 {
		t.Errorf("a third connection produced %d results, and the closure of #489 produces 1", len(third))
	}
}

// F-23-13 is closed. JA4L built its state table key from the `proto` argument that the
// caller passes, and no doc comment stated the two tokens the fingerprinter writes. A
// caller that passed another spelling removed no entry. `normalizeKey` now writes one
// case for every token, so the write and the removal reach one key.
func TestJA4LCleanupConnectionReadsTheProtocolArgumentInEitherCase(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	for _, proto := range []string{"TCP", "tcp", "Tcp"} {
		t.Run(proto, func(t *testing.T) {
			fingerprinter := NewJA4L()
			_, _ = fingerprinter.ProcessPacket(
				buildTCPPacketWithIPs(t, client, server, 64, 40040, 443, true, false))

			if got := len(fingerprinter.connections); got != 1 {
				t.Fatalf("the SYN packet produced %d connection entries, want 1", got)
			}

			fingerprinter.CleanupConnection(auditStateClientIP, 40040, auditStateServerIP, 443, proto)

			if got := len(fingerprinter.connections); got != 0 {
				t.Errorf("CleanupConnection leaves %d entries for the token %q", got, proto)
			}
		})
	}
}

// F-23-1 through F-23-10 are closed, and the suspected finding S1 named them.
// Every fingerprinter appended each result to a results slice, no exported method read
// that slice, and only Reset cleared it. Issue #25 removed the slice, because
// ProcessPacket already returns each result to the caller.
//
// This test states that no fingerprinter holds a field that grows with the packet count.
func TestNoFingerprinterKeepsAResultAfterProcessPacketReturnsIt(t *testing.T) {
	const connections = 50

	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	proc := NewProcessor()

	produced := 0

	for index := 0; index < connections; index++ {
		port := uint16(41000 + index)

		first, _ := proc.ProcessPacket(buildTCPPacketWithIPs(t, client, server, 64, port, 443, true, false))
		second, _ := proc.ProcessPacket(buildTCPPacketWithIPs(t, server, client, 64, 443, port, true, true))

		produced += len(first) + len(second)
	}

	if produced == 0 {
		t.Fatal("the packet set produced no result, so this test proves nothing about the state")
	}

	for index := 0; index < connections; index++ {
		proc.CleanupConnection(auditStateClientIP, uint16(41000+index), auditStateServerIP, 443, "tcp")
	}

	// A field whose length reaches the connection count is a results slice under another
	// name. Every remaining field is a connection table that CleanupConnection empties.
	for name, fingerprinter := range auditStateFingerprinters(proc) {
		for field, length := range auditStateFieldLengths(name, fingerprinter) {
			if length != 0 {
				t.Errorf("CleanupConnection leaves %d entries in %s, and the fingerprinter keeps no result",
					length, field)
			}
		}
	}
}

// TestNoFingerprinterTypeHoldsAResultsField states the same rule against the type rather
// than against one run. A later change that adds the field back fails here.
func TestNoFingerprinterTypeHoldsAResultsField(t *testing.T) {
	for name, fingerprinter := range auditStateFingerprinters(NewProcessor()) {
		typ := reflect.TypeOf(fingerprinter).Elem()

		if _, held := typ.FieldByName("results"); held {
			t.Errorf("%s holds a results field, and issue #25 removed it under F-23-1 through F-23-10", name)
		}
	}
}

// The suspected finding S3 states that a goroutine which reads the package-level lookup
// state races another goroutine. No code writes that state outside lookupOnce.Do, so the
// race detector reports nothing here.
// The audit records S3 as unconfirmed, and this test holds the measurement.
func TestTheLookupState_ReportsNoRaceWhenGoroutinesReadTheDatabase(t *testing.T) {
	const goroutines = 8

	var group sync.WaitGroup

	sources := make([]string, goroutines)

	for index := 0; index < goroutines; index++ {
		group.Add(1)

		go func(slot int) {
			defer group.Done()

			for round := 0; round < 50; round++ {
				_ = LookupFingerprint("t13d1516h2_8daaf6152771_b186095e22b6")
				sources[slot] = GetDatabaseInfo().Source
			}
		}(index)
	}

	group.Wait()

	for _, source := range sources {
		if source != "embedded" && source != "cache" {
			t.Errorf("GetDatabaseInfo reported the source %q, want embedded or cache", source)
		}
	}
}
