package ja4plus

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
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

// auditStateFingerprinters returns the ten fingerprinters of the processor by name.
// The audit reads each one, because FR-audit-16 names the results slice of every
// fingerprinter and FR-audit-18 names every field that holds state.
func auditStateFingerprinters(proc *Processor) map[string]any {
	return map[string]any{
		"JA4Fingerprinter":    proc.ja4,
		"JA4SFingerprinter":   proc.ja4s,
		"JA4HFingerprinter":   proc.ja4h,
		"JA4TFingerprinter":   proc.ja4t,
		"JA4TSFingerprinter":  proc.ja4ts,
		"JA4LFingerprinter":   proc.ja4l,
		"JA4XFingerprinter":   proc.ja4x,
		"JA4SSHFingerprinter": proc.ja4ssh,
		"JA4DFingerprinter":   proc.ja4d,
		"JA4D6Fingerprinter":  proc.ja4d6,
	}
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

// FR-audit-18. Reset clears every field that holds state.
// A monitor that reuses one processor for a second capture reads the state of the first
// one when Reset leaves a field.
func TestReset_ClearsEveryStateFieldOfEveryFingerprinter(t *testing.T) {
	proc := NewProcessor()

	for _, packet := range auditStatePacketSet(t) {
		_, _ = proc.ProcessPacket(packet)
	}

	fingerprinters := auditStateFingerprinters(proc)

	if len(fingerprinters) != 10 {
		t.Fatalf("the test names %d fingerprinters, want 10", len(fingerprinters))
	}

	for name, fingerprinter := range fingerprinters {
		held := 0
		for _, length := range auditStateFieldLengths(name, fingerprinter) {
			held += length
		}

		if held == 0 {
			t.Errorf("%s holds no state after the packet set, so this test proves nothing about Reset", name)
		}
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

				return fingerprinter, func() int { return len(fingerprinter.streams) }
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

// The audit records F-23-11. JA4 keys its QUIC state by the tuple of the packet that
// carried the client hello, and CleanupConnection builds one direction of the tuple.
// A caller that names the server endpoint first removes no entry.
//
// The test seeds the two maps in the form that ja4.go:60 and ja4.go:65 write, because a
// synthetic QUIC Initial packet reaches no decryption.
//
// Issue #25 closes the finding and inverts the first assertion.
func TestTheAuditRecordsThatJA4CleanupConnectionReadsOneDirectionOfTheTuple(t *testing.T) {
	const dcid = "8394c8f03e515708"

	fingerprinter := NewJA4()
	fingerprinter.quicFragments[dcid] = []parser.CryptoFragment{{Offset: 0, Data: []byte{0x01}}}
	fingerprinter.dcidToTuple[dcid] = fmt.Sprintf("%s:%d-%s:%d",
		auditStateClientIP, 40020, auditStateServerIP, 443)

	fingerprinter.CleanupConnection(auditStateServerIP, 443, auditStateClientIP, 40020, "udp")

	if got := len(fingerprinter.quicFragments); got != 1 {
		t.Errorf("CleanupConnection removed the entry for the server-first tuple, and F-23-11 records that it removes none; the map holds %d entries", got)
	}

	fingerprinter.CleanupConnection(auditStateClientIP, 40020, auditStateServerIP, 443, "udp")

	if got := len(fingerprinter.quicFragments); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries for the client-first tuple", got)
	}

	if got := len(fingerprinter.dcidToTuple); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the reverse map", got)
	}
}

// The audit records F-23-12. JA4X keys the deduplication set by the hash of the
// certificate, and CleanupConnection removes no entry of it. A certificate that two
// connections carry produces one fingerprint.
//
// Issue #25 closes the finding and inverts the second assertion.
func TestTheAuditRecordsThatJA4XCleanupConnectionKeepsTheCertificateHash(t *testing.T) {
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

	if len(second) != 0 {
		t.Errorf("the second connection produced %d results, and F-23-12 records that it produces none", len(second))
	}

	if got := len(fingerprinter.processedCerts); got != 1 {
		t.Errorf("the deduplication set holds %d entries after CleanupConnection, want 1", got)
	}
}

// The audit records F-23-13. JA4L builds its state table key from the `proto` argument
// that the caller passes. No doc comment states the two values the fingerprinter writes,
// so a caller that passes another spelling removes no entry.
//
// Issue #25 closes the finding and inverts the first assertion.
func TestTheAuditRecordsThatJA4LCleanupConnectionMatchesTheProtocolArgument(t *testing.T) {
	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	fingerprinter := NewJA4L()
	_, _ = fingerprinter.ProcessPacket(
		buildTCPPacketWithIPs(t, client, server, 64, 40040, 443, true, false))

	if got := len(fingerprinter.connections); got != 1 {
		t.Fatalf("the SYN packet produced %d connection entries, want 1", got)
	}

	fingerprinter.CleanupConnection(auditStateClientIP, 40040, auditStateServerIP, 443, "TCP")

	if got := len(fingerprinter.connections); got != 1 {
		t.Errorf("CleanupConnection removed the entry for the token TCP, and F-23-13 records that it removes none; the map holds %d entries", got)
	}

	fingerprinter.CleanupConnection(auditStateClientIP, 40040, auditStateServerIP, 443, "tcp")

	if got := len(fingerprinter.connections); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries for the token tcp", got)
	}
}

// The audit records F-23-1 through F-23-10, which the suspected finding S1 names.
// Every fingerprinter appends each result to its results slice, no exported method reads
// that slice, and CleanupConnection removes no element of it.
//
// Issue #25 closes the findings and inverts the two results assertions.
func TestTheAuditRecordsThatCleanupConnectionKeepsEveryResult(t *testing.T) {
	const connections = 50

	client := net.IP{192, 168, 1, 10}
	server := net.IP{10, 0, 0, 5}

	proc := NewProcessor()

	for index := 0; index < connections; index++ {
		port := uint16(41000 + index)

		_, _ = proc.ProcessPacket(buildTCPPacketWithIPs(t, client, server, 64, port, 443, true, false))
		_, _ = proc.ProcessPacket(buildTCPPacketWithIPs(t, server, client, 64, 443, port, true, true))
	}

	for index := 0; index < connections; index++ {
		proc.CleanupConnection(auditStateClientIP, uint16(41000+index), auditStateServerIP, 443, "tcp")
	}

	if got := len(proc.ja4l.connections); got != 0 {
		t.Errorf("CleanupConnection leaves %d entries in the JA4L connections table", got)
	}

	if got := len(proc.ja4t.results); got != connections {
		t.Errorf("the JA4T results slice holds %d results after the cleanup of every connection, and F-23-4 records that it holds %d", got, connections)
	}

	if got := len(proc.ja4ts.results); got != connections {
		t.Errorf("the JA4TS results slice holds %d results after the cleanup of every connection, and F-23-5 records that it holds %d", got, connections)
	}

	if got := len(proc.ja4l.results); got != connections {
		t.Errorf("the JA4L results slice holds %d results after the cleanup of every connection, and F-23-6 records that it holds %d", got, connections)
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
