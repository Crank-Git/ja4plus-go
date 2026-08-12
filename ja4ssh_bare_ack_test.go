package ja4plus

import "testing"

// The part c rules of issue #221. Part c counts the bare ACK of the TCP handshake, which
// arrives before the first SSH packet of the connection.
//
// `wireshark/source/packet-ja4.c:1302` counts a bare ACK on port 22 and it reads no SSH state
// first. `python/ja4ssh.py:112` counts the same packet. The port holds the rule at
// `ja4plus/fingerprinters/ja4ssh.py:176`.
//
// `sshPayloadOfSize` and `sshSeqOfPacket` live in `ja4ssh_window_test.go`. `buildSSHPacket` and
// `buildSSHSegment` live in `ja4ssh_test.go`. Both set the ACK flag alone, so a packet with no
// payload is a bare ACK.
//
// One reading of issue #221 belongs to issue #222, and this comment records it. `ssh-r.pcap`
// stream 1 holds 5 client bare ACKs, at the frames 298, 303, 312, 332 and 340. The reference
// counts the first 4 and it drops frame 340, because frame 335 is a FIN+ACK packet.
// `python/ja4.py:555` tests the two flags and `python/ja4.py:556` calls `finalize_ja4ssh` on
// that frame. `python/ja4.py:377` deletes the stream from the cache, so no later packet reaches
// the value. `wireshark/source/packet-ja4.c:1399` tests the same two flags, and
// `wireshark/source/packet-ja4.c:1401` writes the value.
// Issue #222 closed the window on that FIN+ACK packet, so this library now counts 4.
// Before issue #221 the library counted 4 of the 5 and it dropped frame 298, so part c read
// `c4s5` from the wrong 4 packets.

// TestJA4SSHCountsTheClientBareACKOfTheTCPHandshake holds the client half of
// issue #221. The reference counts the third packet of the handshake, and a state table that
// opens on SSH data alone loses it.
//
// `ssh-r.pcap` stream 0, `ssh-scp-1050.pcap` stream 0 and `ssh2.pcapng` stream 14 each report
// one more client ACK than this library produced before the repair.
func TestJA4SSHCountsTheClientBareACKOfTheTCPHandshake(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	payload := sshPayloadOfSize(36)

	// The handshake ACK travels to port 22, and it opens the connection.
	results, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the handshake ACK", err)
	}

	if len(results) != 0 {
		t.Fatalf("the fingerprinter emits %d values on the handshake ACK, and a bare ACK advances no window", len(results))
	}

	for index := 0; index < 2; index++ {
		results, err = fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 2 SSH packets emits 1", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c1s0" {
		t.Errorf("the fingerprinter produces %q, and part c counts the handshake ACK as `c1s0`", results[0].Fingerprint)
	}
}

// TestJA4SSHCountsTheServerBareACKThatPrecedesTheVersionLine holds the server half of issue
// #221. A bare ACK from TCP port 22 reaches the server count. The count reads no SSH data
// first.
func TestJA4SSHCountsTheServerBareACKThatPrecedesTheVersionLine(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	payload := sshPayloadOfSize(36)

	results, err := fingerprinter.ProcessPacket(
		buildSSHPacket("10.0.0.1", "192.168.1.100", 22, 54321, nil, true))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the server ACK", err)
	}

	if len(results) != 0 {
		t.Fatalf("the fingerprinter emits %d values on the server ACK, and a bare ACK advances no window", len(results))
	}

	for index := 0; index < 2; index++ {
		results, err = fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 2 SSH packets emits 1", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c0s1" {
		t.Errorf("the fingerprinter produces %q, and part c counts the server ACK as `c0s1`", results[0].Fingerprint)
	}
}

// TestJA4SSHOpensNoConnectionForABareACKOffPort22 holds the TCP port test of issue #221.
// `wireshark/source/packet-ja4.c:1303` and `python/ja4ssh.py:113` both read the TCP port. The
// port holds the same test at `ja4plus/fingerprinters/ja4ssh.py:176`.
//
// A bare ACK on every TCP connection would fill the state table with traffic that carries no
// SSH.
func TestJA4SSHOpensNoConnectionForABareACKOffPort22(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	payload := sshPayloadOfSize(36)

	results, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 2222, nil, true))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the ACK off port 22", err)
	}

	if len(results) != 0 {
		t.Fatalf("the fingerprinter emits %d values on one bare ACK", len(results))
	}

	for index := 0; index < 2; index++ {
		results, err = fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 2222, payload, sshSeqOfPacket(index, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 2 SSH packets emits 1", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c0s0" {
		t.Errorf("the fingerprinter produces %q, and an ACK off port 22 opens no connection, so part c reads `c0s0`", results[0].Fingerprint)
	}
}

// TestJA4SSHCountsABareACKOffPort22OnAKnownConnection holds the other half of the TCP port
// test. The reference reads the TCP port only where it opens a connection.
// `ja4plus/fingerprinters/ja4ssh.py:250` counts a bare ACK of a known connection on every TCP
// port.
func TestJA4SSHCountsABareACKOffPort22OnAKnownConnection(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	payload := sshPayloadOfSize(36)

	results, err := fingerprinter.ProcessPacket(buildSSHSegment(
		"192.168.1.100", "10.0.0.1", 54321, 2222, payload, sshSeqOfPacket(0, payload)))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first SSH segment", err)
	}

	if len(results) != 0 {
		t.Fatalf("the fingerprinter emits %d values on 1 SSH packet, and the window holds 2", len(results))
	}

	if _, err = fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 2222, nil, true)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the ACK off port 22", err)
	}

	results, err = fingerprinter.ProcessPacket(buildSSHSegment(
		"192.168.1.100", "10.0.0.1", 54321, 2222, payload, sshSeqOfPacket(1, payload)))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the second SSH segment", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 2 SSH packets emits 1", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c1s0" {
		t.Errorf("the fingerprinter produces %q, and part c counts the ACK of a known connection as `c1s0`", results[0].Fingerprint)
	}
}
