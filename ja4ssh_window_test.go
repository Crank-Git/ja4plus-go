package ja4plus

import (
	"testing"
)

// The JA4SSH window rules of issue #53. The port holds the rulings in its issues #28, #96,
// #97, #105, #199 and #214, and `docs/specs/features/08-python-parity.md` numbers them
// FR-parity-25 through FR-parity-33.
//
// `buildSSHPacket` lives in `ja4ssh_test.go`. It sets the ACK flag on every packet, so a
// packet with no payload is a bare ACK.

// sshPayloadOfSize returns an SSH data payload of the size the caller names.
// The payload opens with `SSH-2.0-` so that `parser.IsSSHPacket` reads it as SSH data.
// The caller names a size of 8 bytes or more.
func sshPayloadOfSize(size int) []byte {
	payload := make([]byte, size)
	copy(payload, "SSH-2.0-")

	return payload
}

// TestJA4SSHEmitsAtThePacketCountAndHoldsNoUpperCap holds FR-parity-25 and FR-parity-26.
// The port's issue #28 rules the threshold, and `ja4ssh.py:261` reads
// `if total_packets >= self.packet_count`.
func TestJA4SSHEmitsAtThePacketCountAndHoldsNoUpperCap(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for count := 1; count < 200; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, payload, false))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error at packet %d: %v", count, err)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emitted at packet %d, and the window holds 200", count)
		}
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, payload, false))
	if err != nil {
		t.Fatalf("the fingerprinter returned an error at packet 200: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter produced %d values at packet 200, and the window holds 200", len(results))
	}

	if results[0].Fingerprint != "c36s0_c200s0_c0s0" {
		t.Errorf("the value is %q, and the window holds 200 client packets of 36 bytes", results[0].Fingerprint)
	}
}

// TestJA4SSHReadsTheModeOfTheWindowAlone holds FR-parity-27.
// The port's issue #96 rules the mode field, and `ja4ssh.py:439-440` clears the two packet
// lists at every emission.
func TestJA4SSHReadsTheModeOfTheWindowAlone(t *testing.T) {
	fingerprinter := NewJA4SSH(4)

	for count := 0; count < 4; count++ {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false)); err != nil {
			t.Fatalf("the fingerprinter returned an error in the first window: %v", err)
		}
	}

	var second []FingerprintResult

	for count := 0; count < 4; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(100), false))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error in the second window: %v", err)
		}

		second = append(second, results...)
	}

	if len(second) != 1 {
		t.Fatalf("the second window produced %d values, and one window produces one value", len(second))
	}

	if second[0].Fingerprint != "c100s0_c4s0_c0s0" {
		t.Errorf("the value is %q, and the second window holds four client packets of 100 bytes",
			second[0].Fingerprint)
	}
}

// TestJA4SSHProducesNoFingerprintForAWindowOfBareACKs holds FR-parity-28.
// The port's issue #97 rules the empty window, and `ja4ssh.py:423-424` declines it.
// A bare ACK is not an SSH packet, so it does not advance the window.
func TestJA4SSHProducesNoFingerprintForAWindowOfBareACKs(t *testing.T) {
	fingerprinter := NewJA4SSH(3)

	for count := 0; count < 3; count++ {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false)); err != nil {
			t.Fatalf("the fingerprinter returned an error on an SSH packet: %v", err)
		}
	}

	for count := 0; count < 20; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHPacket("10.0.0.1", "192.168.1.100", 22, 54321, nil, true))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error on a bare ACK: %v", err)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emitted on bare ACK %d, and a window of bare ACKs holds no SSH packet",
				count+1)
		}
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows produced %d values, and the open window holds no SSH packet", len(closed))
	}
}

// TestJA4SSHCloseOpenWindowsEmitsTheWindowAConnectionHoldsOpen holds FR-parity-29 and
// FR-parity-33. The port's issues #105, #199 and #214 rule the method, and
// `rust/ja4/src/ssh.rs:45-55` and `zeek/ja4ssh/main.zeek:160-164` both emit the open window.
func TestJA4SSHCloseOpenWindowsEmitsTheWindowAConnectionHoldsOpen(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	for count := 0; count < 15; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error at packet %d: %v", count+1, err)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emitted at packet %d, and the window holds 200", count+1)
		}
	}

	closed := fingerprinter.CloseOpenWindows()
	if len(closed) != 1 {
		t.Fatalf("CloseOpenWindows produced %d values, and one connection holds one open window", len(closed))
	}

	if closed[0].Type != "ja4ssh" {
		t.Errorf("the type is %q, and the method is JA4SSH", closed[0].Type)
	}

	if closed[0].Fingerprint != "c36s0_c15s0_c0s0" {
		t.Errorf("the value is %q, and the open window holds 15 client packets of 36 bytes",
			closed[0].Fingerprint)
	}

	if closed[0].SrcIP != "192.168.1.100" || closed[0].SrcPort != 54321 {
		t.Errorf("the source is %s:%d, and the client of the connection is 192.168.1.100:54321",
			closed[0].SrcIP, closed[0].SrcPort)
	}

	if closed[0].DstIP != "10.0.0.1" || closed[0].DstPort != 22 {
		t.Errorf("the destination is %s:%d, and the server of the connection is 10.0.0.1:22",
			closed[0].DstIP, closed[0].DstPort)
	}
}

// TestJA4SSHCloseOpenWindowsReturnsAnEmptySliceOnASecondCall holds the edge case that the
// issue names. The first call emits the window and clears the counters, so the second call
// reads an empty window. `ja4ssh.py:394-396` states the same rule.
func TestJA4SSHCloseOpenWindowsReturnsAnEmptySliceOnASecondCall(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	for count := 0; count < 15; count++ {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false)); err != nil {
			t.Fatalf("the fingerprinter returned an error at packet %d: %v", count+1, err)
		}
	}

	if first := fingerprinter.CloseOpenWindows(); len(first) != 1 {
		t.Fatalf("the first call produced %d values, and the connection holds one open window", len(first))
	}

	second := fingerprinter.CloseOpenWindows()
	if len(second) != 0 {
		t.Errorf("the second call produced %d values, and the library emits one window once", len(second))
	}
}

// TestJA4SSHLosesTheOpenWindowWhenNoCallerClosesIt holds the edge case that the issue names.
// The method is opt-in, and the library forces no flush.
func TestJA4SSHLosesTheOpenWindowWhenNoCallerClosesIt(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	for count := 0; count < 15; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error at packet %d: %v", count+1, err)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emitted at packet %d, and the caller closed no window", count+1)
		}
	}
}

// TestJA4SSHCloseOpenWindowsReadsTheConnectionsInArrivalOrder holds the publication order.
// A range over a Go map orders nothing, so two runs of one capture would disagree.
// `ja4ssh.py:367-380` reads the same order.
func TestJA4SSHCloseOpenWindowsReadsTheConnectionsInArrivalOrder(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	// The three connections open in this order, and the first client port is the highest of
	// the three. A sort by the connection key would report them in another order.
	ports := []uint16{54323, 54322, 54321}

	for _, port := range ports {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", port, 22, sshPayloadOfSize(36), false)); err != nil {
			t.Fatalf("the fingerprinter returned an error on the connection of port %d: %v", port, err)
		}
	}

	closed := fingerprinter.CloseOpenWindows()
	if len(closed) != len(ports) {
		t.Fatalf("CloseOpenWindows produced %d values, and the capture opened %d connections",
			len(closed), len(ports))
	}

	for index, port := range ports {
		if closed[index].SrcPort != port {
			t.Errorf("value %d carries the client port %d, and the capture opened port %d in that place",
				index+1, closed[index].SrcPort, port)
		}
	}
}

// TestAStatefulFingerprinterImplementsWindowCloser holds the maintainer's ruling of
// 2026-08-11 on FR-parity-30. `CloseOpenWindows` sits on a second optional interface, and a
// caller discovers it with a type assertion.
func TestAStatefulFingerprinterImplementsWindowCloser(t *testing.T) {
	var fingerprinter Fingerprinter = NewJA4SSH(200)

	if _, holds := fingerprinter.(WindowCloser); !holds {
		t.Error("JA4SSHFingerprinter implements no WindowCloser, and it holds a window open")
	}
}

// TestAStatelessFingerprinterImplementsNoWindowCloser holds the maintainer's ruling of
// 2026-08-11 on FR-parity-30. A stateless fingerprinter implements nothing, and `Processor`
// skips it with a type assertion.
func TestAStatelessFingerprinterImplementsNoWindowCloser(t *testing.T) {
	var fingerprinter Fingerprinter = NewJA4T()

	if _, holds := fingerprinter.(WindowCloser); holds {
		t.Error("JA4TFingerprinter implements WindowCloser, and it holds no window open")
	}
}

// TestProcessorCloseOpenWindowsReturnsTheJoinedResults holds FR-parity-31.
func TestProcessorCloseOpenWindowsReturnsTheJoinedResults(t *testing.T) {
	processor := NewProcessor()

	for count := 0; count < 15; count++ {
		results, errs := processor.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false))
		for _, err := range errs {
			t.Logf("the processor reported a non-fatal error at packet %d: %v", count+1, err)
		}

		for _, result := range results {
			if result.Type == "ja4ssh" {
				t.Fatalf("the processor emitted a JA4SSH value at packet %d, and the window holds 200",
					count+1)
			}
		}
	}

	closed := processor.CloseOpenWindows()

	var values int

	for _, result := range closed {
		if result.Type == "ja4ssh" {
			values++
		}
	}

	if values != 1 {
		t.Errorf("the processor produced %d JA4SSH values, and one connection holds one open window", values)
	}
}

// TestSyncProcessorCloseOpenWindowsReturnsTheJoinedResults holds FR-concurrency-13.
// Issue #148 requires one SyncProcessor wrapper for every exported Processor method.
func TestSyncProcessorCloseOpenWindowsReturnsTheJoinedResults(t *testing.T) {
	processor := NewSyncProcessor()

	for count := 0; count < 15; count++ {
		if _, errs := processor.ProcessPacket(
			buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, sshPayloadOfSize(36), false)); len(errs) > 0 {
			t.Logf("the processor reported %d non-fatal errors at packet %d", len(errs), count+1)
		}
	}

	closed := processor.CloseOpenWindows()

	var values int

	for _, result := range closed {
		if result.Type == "ja4ssh" {
			values++
		}
	}

	if values != 1 {
		t.Errorf("the processor produced %d JA4SSH values, and one connection holds one open window", values)
	}
}

// TestAZeroValueJA4SSHFingerprinterClosesNoWindow holds the zero-value contract.
// A caller who writes `var f JA4SSHFingerprinter` reaches a nil map, and a range over a nil
// map reads nothing.
func TestAZeroValueJA4SSHFingerprinterClosesNoWindow(t *testing.T) {
	var fingerprinter JA4SSHFingerprinter

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("the zero value produced %d values, and it read no packet", len(closed))
	}
}
