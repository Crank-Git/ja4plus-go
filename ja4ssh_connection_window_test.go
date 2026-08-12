package ja4plus

import "testing"

// The per-connection flush of issue #216. The maintainer ruled on 2026-08-12 that a second
// method emits the open window of one connection, and that `CleanupConnection` keeps its
// signature.
//
// No conformance vector separates the two candidate answers, because the suite reads each
// capture to its end and it calls no eviction. These tests build the separating sequence
// instead: a connection holds a window open, the caller evicts it, and the test reads the
// emitted value. `.claude/rules/rulings.md` states that such a test records the ruling.
//
// The port carries the same gap. `ja4plus/fingerprinters/ja4ssh.py:530` holds
// `cleanup_connection`, which pops the connection and returns nothing, and
// `ja4plus/fingerprinters/ja4ssh.py:408` holds `_close_window`, which is private. The port
// issue records the reading.
//
// `sshPayloadOfSize` and `sshSeqOfPacket` live in `ja4ssh_window_test.go`, and
// `buildSSHSegment` lives in `ja4ssh_test.go`.

// openOneSSHWindow sends the count of client segments the caller names on one connection,
// and it returns the fingerprinter that holds the open window.
// The window holds 200 packets, so a count below 200 emits nothing.
func openOneSSHWindow(t *testing.T, count int) *JA4SSHFingerprinter {
	t.Helper()

	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for index := 0; index < count; index++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(index, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error at packet %d: %v", index+1, err)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emitted at packet %d, and the window holds 200", index+1)
		}
	}

	return fingerprinter
}

// TestJA4SSHCloseConnectionWindowEmitsTheWindowTheConnectionHoldsOpen holds the ruling of
// issue #216. The eviction reaches the value, and `CleanupConnection` reaches none.
func TestJA4SSHCloseConnectionWindowEmitsTheWindowTheConnectionHoldsOpen(t *testing.T) {
	fingerprinter := openOneSSHWindow(t, 15)

	closed := fingerprinter.CloseConnectionWindow("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")
	if len(closed) != 1 {
		t.Fatalf("the method produced %d values, and the connection holds one open window", len(closed))
	}

	if closed[0].Type != "ja4ssh" {
		t.Errorf("the type is %q, and the method is JA4SSH", closed[0].Type)
	}

	if closed[0].Fingerprint != "c36s0_c15s0_c0s0" {
		t.Errorf("the value is %q, and the open window holds 15 client packets of 36 bytes",
			closed[0].Fingerprint)
	}

	// No packet triggers this emission, so the result reads the endpoints of the connection.
	// `CloseOpenWindows` names the client as the source, and this method agrees with it.
	if closed[0].SrcIP != "192.168.1.100" || closed[0].SrcPort != 54321 {
		t.Errorf("the source is %s:%d, and the client of the connection is 192.168.1.100:54321",
			closed[0].SrcIP, closed[0].SrcPort)
	}

	if closed[0].DstIP != "10.0.0.1" || closed[0].DstPort != 22 {
		t.Errorf("the destination is %s:%d, and the server of the connection is 10.0.0.1:22",
			closed[0].DstIP, closed[0].DstPort)
	}
}

// TestJA4SSHCloseConnectionWindowEvictsTheConnection holds the second half of the ruling.
// The method emits the open window and then deletes the connection, so `CloseOpenWindows`
// reaches nothing after it. Issue #216 states the rule.
func TestJA4SSHCloseConnectionWindowEvictsTheConnection(t *testing.T) {
	fingerprinter := openOneSSHWindow(t, 15)

	if closed := fingerprinter.CloseConnectionWindow(
		"192.168.1.100", 54321, "10.0.0.1", 22, "tcp"); len(closed) != 1 {
		t.Fatalf("the method produced %d values, and the connection holds one open window", len(closed))
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows produced %d values, and the method evicted the connection",
			len(closed))
	}

	if fingerprinter.connections["192.168.1.100:54321-10.0.0.1:22"] != nil {
		t.Error("the state table holds the connection, and the method evicts it")
	}
}

// TestJA4SSHCloseConnectionWindowReadsTheEndpointsInEitherOrder holds the key contract.
// The method names the connection by the same key `CleanupConnection` accepts, and that key
// normalizes the two endpoints. Issue #216 states the rule.
func TestJA4SSHCloseConnectionWindowReadsTheEndpointsInEitherOrder(t *testing.T) {
	fingerprinter := openOneSSHWindow(t, 15)

	// The caller names the server first, and the connection is the same connection.
	closed := fingerprinter.CloseConnectionWindow("10.0.0.1", 22, "192.168.1.100", 54321, "tcp")
	if len(closed) != 1 {
		t.Fatalf("the method produced %d values, and the reversed key names the same connection",
			len(closed))
	}

	if closed[0].SrcIP != "192.168.1.100" || closed[0].SrcPort != 54321 {
		t.Errorf("the source is %s:%d, and the client of the connection is 192.168.1.100:54321",
			closed[0].SrcIP, closed[0].SrcPort)
	}
}

// TestJA4SSHCloseConnectionWindowLeavesEveryOtherConnectionOpen holds the scope of the
// method. It reaches one connection, and `CloseOpenWindows` reaches every connection.
func TestJA4SSHCloseConnectionWindowLeavesEveryOtherConnectionOpen(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for _, port := range []uint16{54321, 54322} {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", port, 22, payload,
				sshSeqOfPacket(0, payload))); err != nil {
			t.Fatalf("the fingerprinter returned an error on the connection of port %d: %v", port, err)
		}
	}

	if closed := fingerprinter.CloseConnectionWindow(
		"192.168.1.100", 54321, "10.0.0.1", 22, "tcp"); len(closed) != 1 {
		t.Fatalf("the method produced %d values, and it reaches one connection", len(closed))
	}

	remaining := fingerprinter.CloseOpenWindows()
	if len(remaining) != 1 {
		t.Fatalf("CloseOpenWindows produced %d values, and one connection stays open", len(remaining))
	}

	if remaining[0].SrcPort != 54322 {
		t.Errorf("the open connection carries the client port %d, and the method evicted port 54321",
			remaining[0].SrcPort)
	}
}

// TestJA4SSHCloseConnectionWindowProducesNoValueForAnUnknownConnection holds the miss case.
// A caller that evicts a connection the fingerprinter never read reaches no value.
func TestJA4SSHCloseConnectionWindowProducesNoValueForAnUnknownConnection(t *testing.T) {
	fingerprinter := openOneSSHWindow(t, 15)

	closed := fingerprinter.CloseConnectionWindow("192.168.1.200", 54321, "10.0.0.1", 22, "tcp")
	if len(closed) != 0 {
		t.Errorf("the method produced %d values, and the fingerprinter read no such connection",
			len(closed))
	}
}

// TestJA4SSHCloseConnectionWindowEvictsAConnectionOfBareACKs holds the empty-window guard.
// A window that holds no SSH packet describes no traffic, so the method emits no value. It
// evicts the connection, because `CleanupConnection` evicts it too.
func TestJA4SSHCloseConnectionWindowEvictsAConnectionOfBareACKs(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	if _, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true)); err != nil {
		t.Fatalf("the fingerprinter returned an error on the bare ACK: %v", err)
	}

	closed := fingerprinter.CloseConnectionWindow("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")
	if len(closed) != 0 {
		t.Errorf("the method produced %d values, and the window holds no SSH packet", len(closed))
	}

	if len(fingerprinter.connections) != 0 {
		t.Errorf("the state table holds %d connections, and the method evicts the connection",
			len(fingerprinter.connections))
	}
}

// TestJA4SSHCloseConnectionWindowReturnsAnEmptySliceOnASecondCall holds the eviction.
// The first call deletes the connection, so the second call names a connection the state
// table no longer holds.
func TestJA4SSHCloseConnectionWindowReturnsAnEmptySliceOnASecondCall(t *testing.T) {
	fingerprinter := openOneSSHWindow(t, 15)

	if first := fingerprinter.CloseConnectionWindow(
		"192.168.1.100", 54321, "10.0.0.1", 22, "tcp"); len(first) != 1 {
		t.Fatalf("the first call produced %d values, and the connection holds one open window",
			len(first))
	}

	second := fingerprinter.CloseConnectionWindow("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")
	if len(second) != 0 {
		t.Errorf("the second call produced %d values, and the first call evicted the connection",
			len(second))
	}
}

// TestAZeroValueJA4SSHFingerprinterClosesNoConnectionWindow holds the zero-value contract.
// A caller who writes `var f JA4SSHFingerprinter` reaches a nil state table.
func TestAZeroValueJA4SSHFingerprinterClosesNoConnectionWindow(t *testing.T) {
	var fingerprinter JA4SSHFingerprinter

	if closed := fingerprinter.CloseConnectionWindow(
		"192.168.1.100", 54321, "10.0.0.1", 22, "tcp"); len(closed) != 0 {
		t.Errorf("the zero value produced %d values, and it read no packet", len(closed))
	}
}

// TestWindowCloserHoldsCloseConnectionWindow holds the placement the maintainer ruled on
// 2026-08-12. The method sits on the second optional interface, beside `CloseOpenWindows`,
// and `Fingerprinter` does not change. Issue #216 records the ruling, and issue #53 records
// the interface.
func TestWindowCloserHoldsCloseConnectionWindow(t *testing.T) {
	var fingerprinter Fingerprinter = openOneSSHWindow(t, 15)

	closer, holds := fingerprinter.(WindowCloser)
	if !holds {
		t.Fatal("JA4SSHFingerprinter implements no WindowCloser, and it holds a window open")
	}

	if closed := closer.CloseConnectionWindow(
		"192.168.1.100", 54321, "10.0.0.1", 22, "tcp"); len(closed) != 1 {
		t.Errorf("the interface call produced %d values, and the connection holds one open window",
			len(closed))
	}
}

// TestAStatelessFingerprinterImplementsNoConnectionWindowCloser holds the type assertion the
// processor makes. A stateless fingerprinter holds no window open, so it implements nothing.
func TestAStatelessFingerprinterImplementsNoConnectionWindowCloser(t *testing.T) {
	var fingerprinter Fingerprinter = NewJA4T()

	if _, holds := fingerprinter.(WindowCloser); holds {
		t.Error("JA4TFingerprinter implements WindowCloser, and it holds no window open")
	}
}

// TestJA4SSHCleanupConnectionEmitsNoValueAfterTheRuling holds the half of the ruling that
// keeps the old contract. `CleanupConnection` deletes the connection and it returns nothing,
// so a caller that only reclaims memory receives no fingerprint it did not ask for. The
// edge-case table of issue #53 states that contract, and issue #216 keeps it.
func TestJA4SSHCleanupConnectionEmitsNoValueAfterTheRuling(t *testing.T) {
	fingerprinter := openOneSSHWindow(t, 15)

	fingerprinter.CleanupConnection("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows produced %d values, and CleanupConnection loses the window",
			len(closed))
	}
}

// TestProcessorCloseConnectionWindowReturnsTheJoinedResults holds the processor path.
// A caller of the processor reaches every fingerprinter that implements WindowCloser, and
// the processor skips every other one. Issue #216 adds the method.
func TestProcessorCloseConnectionWindowReturnsTheJoinedResults(t *testing.T) {
	processor := NewProcessor()
	payload := sshPayloadOfSize(36)

	for index := 0; index < 15; index++ {
		results, errs := processor.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(index, payload)))
		for _, err := range errs {
			t.Logf("the processor reported a non-fatal error at packet %d: %v", index+1, err)
		}

		for _, result := range results {
			if result.Type == "ja4ssh" {
				t.Fatalf("the processor emitted a JA4SSH value at packet %d, and the window holds 200",
					index+1)
			}
		}
	}

	closed := processor.CloseConnectionWindow("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")

	var values int

	for _, result := range closed {
		if result.Type == "ja4ssh" {
			values++
		}
	}

	if values != 1 {
		t.Errorf("the processor produced %d JA4SSH values, and the connection holds one open window",
			values)
	}
}

// TestSyncProcessorCloseConnectionWindowReturnsTheJoinedResults holds FR-concurrency-13.
// Issue #148 requires one SyncProcessor wrapper for every exported Processor method.
func TestSyncProcessorCloseConnectionWindowReturnsTheJoinedResults(t *testing.T) {
	processor := NewSyncProcessor()
	payload := sshPayloadOfSize(36)

	for index := 0; index < 15; index++ {
		if _, errs := processor.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(index, payload))); len(errs) > 0 {
			t.Logf("the processor reported %d non-fatal errors at packet %d", len(errs), index+1)
		}
	}

	closed := processor.CloseConnectionWindow("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")

	var values int

	for _, result := range closed {
		if result.Type == "ja4ssh" {
			values++
		}
	}

	if values != 1 {
		t.Errorf("the processor produced %d JA4SSH values, and the connection holds one open window",
			values)
	}
}
