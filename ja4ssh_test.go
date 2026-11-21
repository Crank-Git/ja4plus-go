package ja4plus

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// buildSSHPacket creates a synthetic TCP packet with the given parameters.
// It names the sequence number 1, so a test that sends more than one payload segment in one
// direction calls buildSSHSegment instead.
func buildSSHPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ack bool) gopacket.Packet {
	return buildSSHSegment(srcIP, dstIP, srcPort, dstPort, payload, 1)
}

// buildSSHSegment returns one synthetic TCP packet at the sequence number the caller names.
//
// `parser.SSHMessageTracker` reads the sequence number, because it follows the SSH message
// boundary across two segments. A direction that repeats one sequence number sends one
// segment and then a retransmission of it, and FoxIO counts a retransmission once. A test
// that sends more than one payload segment in one direction therefore names an advancing
// number.
func buildSSHSegment(
	srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, seq uint32,
) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if len(payload) > 0 {
		_ = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	} else {
		_ = gopacket.SerializeLayers(buf, opts, ip, tcp)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

// TestJA4SSH_WindowTrigger holds the emission at the window threshold.
// Issue #53 removed the upper cap that this test read at 10, and
// TestJA4SSHEmitsAtThePacketCountAndHoldsNoUpperCap holds the default window of 200.
func TestJA4SSH_WindowTrigger(t *testing.T) {
	fp := NewJA4SSH(10)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	clientPort := uint16(54321)
	serverPort := uint16(22)

	sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	// Send 9 packets — should NOT trigger yet
	for i := 0; i < 9; i++ {
		results, err := fp.ProcessPacket(buildSSHSegment(clientIP, serverIP, clientPort, serverPort,
			sshPayload, sshSeqOfPacket(i, sshPayload)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) > 0 {
			t.Fatalf("did not expect fingerprint after %d packets", i+1)
		}
	}

	// 10th packet should trigger
	results, err := fp.ProcessPacket(buildSSHSegment(clientIP, serverIP, clientPort, serverPort,
		sshPayload, sshSeqOfPacket(9, sshPayload)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected fingerprint after 10 packets")
	}
	if results[0].Type != "ja4ssh" {
		t.Errorf("expected type ja4ssh, got %s", results[0].Type)
	}
}

func TestJA4SSH_DirectionPort22(t *testing.T) {
	fp := NewJA4SSH(10) // The window holds ten SSH packets.

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	clientPort := uint16(54321)
	serverPort := uint16(22)

	clientPayload := sshPayloadOfSize(36)
	serverPayload := sshPayloadOfSize(100)

	// 5 client packets (size 36 each)
	for i := 0; i < 5; i++ {
		_, _ = fp.ProcessPacket(buildSSHSegment(clientIP, serverIP, clientPort, serverPort,
			clientPayload, sshSeqOfPacket(i, clientPayload)))
	}

	// 5 server packets (size 100 each) — should trigger
	var lastResults []FingerprintResult
	for i := 0; i < 5; i++ {
		results, _ := fp.ProcessPacket(buildSSHSegment(serverIP, clientIP, serverPort, clientPort,
			serverPayload, sshSeqOfPacket(i, serverPayload)))
		if len(results) > 0 {
			lastResults = results
		}
	}

	if len(lastResults) == 0 {
		t.Fatal("expected fingerprint")
	}

	// Fingerprint should reflect client mode=36, server mode=100
	expected := "c36s100_c5s5_c0s0"
	if lastResults[0].Fingerprint != expected {
		t.Errorf("expected fingerprint %q, got %q", expected, lastResults[0].Fingerprint)
	}
}

func TestJA4SSH_ModeCalculation(t *testing.T) {
	// Test that mode returns the most frequent value
	tests := []struct {
		values []int
		want   int
	}{
		{nil, 0},
		{[]int{36}, 36},
		{[]int{36, 36, 100}, 36},
		{[]int{100, 36, 100, 100}, 100},
		{[]int{36, 100, 36, 100, 36}, 36},
	}

	for _, tt := range tests {
		got := mode(tt.values)
		if got != tt.want {
			t.Errorf("mode(%v) = %d, want %d", tt.values, got, tt.want)
		}
	}
}

func TestJA4SSH_Reset(t *testing.T) {
	fp := NewJA4SSH(10)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	// Send some packets
	for i := 0; i < 5; i++ {
		_, _ = fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 22, sshPayload, false))
	}

	fp.Reset()

	// Issue #25 removed the results slice, so the connection table is the only state that
	// Reset clears.
	if len(fp.connections) != 0 {
		t.Error("expected connections to be cleared after reset")
	}
}

// TestJA4SSH_EarlyTrigger holds the emission at a window that the caller names.
// Issue #53 removed the upper cap of 10, so the threshold reads the window alone.
func TestJA4SSH_EarlyTrigger(t *testing.T) {
	fp := NewJA4SSH(5)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	for i := 0; i < 4; i++ {
		results, _ := fp.ProcessPacket(buildSSHSegment(clientIP, serverIP, 54321, 22, sshPayload,
			sshSeqOfPacket(i, sshPayload)))
		if len(results) > 0 {
			t.Fatalf("unexpected trigger at packet %d", i+1)
		}
	}

	results, _ := fp.ProcessPacket(buildSSHSegment(clientIP, serverIP, 54321, 22, sshPayload,
		sshSeqOfPacket(4, sshPayload)))
	if len(results) == 0 {
		t.Fatal("expected fingerprint at packet 5")
	}
}

// TestJA4SSH_ACKCounting holds the two bare ACK fields of the value.
// A bare ACK does not advance the window, so the window holds seven SSH packets.
// Issue #53 removed the bare ACK count from the threshold, and FR-parity-28 states the rule.
func TestJA4SSH_ACKCounting(t *testing.T) {
	fp := NewJA4SSH(7)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	// 5 SSH data packets from client
	for i := 0; i < 5; i++ {
		_, _ = fp.ProcessPacket(buildSSHSegment(clientIP, serverIP, 54321, 22, sshPayload,
			sshSeqOfPacket(i, sshPayload)))
	}

	// 3 pure ACKs from server
	for i := 0; i < 3; i++ {
		_, _ = fp.ProcessPacket(buildSSHPacket(serverIP, clientIP, 22, 54321, nil, true))
	}

	// 2 more SSH data from server — the window reaches seven SSH packets
	serverPayload := []byte("SSH-2.0-ServerSSH\r\n")
	var lastResults []FingerprintResult
	for i := 0; i < 2; i++ {
		results, _ := fp.ProcessPacket(buildSSHSegment(serverIP, clientIP, 22, 54321, serverPayload,
			sshSeqOfPacket(i, serverPayload)))
		if len(results) > 0 {
			lastResults = results
		}
	}

	if len(lastResults) == 0 {
		t.Fatal("expected fingerprint")
	}

	// client: 5 SSH packets, server: 2 SSH packets, client ACKs: 0, server ACKs: 3
	fp_str := lastResults[0].Fingerprint
	// Format: c{cmode}s{smode}_c{cpkts}s{spkts}_c{cacks}s{sacks}
	expected := "c21s19_c5s2_c0s3"
	if fp_str != expected {
		t.Errorf("expected %q, got %q", expected, fp_str)
	}
}

func TestJA4SSH_NonSSHIgnored(t *testing.T) {
	fp := NewJA4SSH(10)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	for i := 0; i < 20; i++ {
		results, _ := fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 80, httpPayload, false))
		if len(results) > 0 {
			t.Fatal("should not generate fingerprint for non-SSH traffic")
		}
	}
}

func TestJA4SSH_ModeTieBreaking(t *testing.T) {
	// FoxIO PR #281: on a frequency tie, mode() must return the LOWEST value
	// (deterministic), regardless of insertion order.
	tests := []struct {
		name string
		in   []int
		want int
	}{
		{"tie_lowest_wins", []int{100, 36, 100, 36}, 36},
		{"tie_lowest_wins_reordered", []int{36, 100, 36, 100}, 36},
		{"three-way-tie", []int{100, 200, 50, 100, 200, 50}, 50},
		{"clear_winner", []int{36, 36, 100}, 36},
		{"single_value", []int{42}, 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mode(tt.in)
			if got != tt.want {
				t.Errorf("mode(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestLookupHASSH(t *testing.T) {
	tests := []struct {
		hassh string
		want  string
	}{
		{"8a8ae540028bf433cd68356c1b9e8d5b", "CyberDuck Version 6.7.1"},
		{"06046964c022c6407d15a27b12a6a4fb", "OpenSSH 7.6"},
		{"d93f46d063c4382b6232a4d77db532b2", "Dropbear 2016.72 (Server)"},
		{"unknown_fingerprint", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.hassh, func(t *testing.T) {
			got := LookupHASSH(tt.hassh)
			if got != tt.want {
				t.Errorf("LookupHASSH(%q) = %q, want %q", tt.hassh, got, tt.want)
			}
		})
	}

	// Also assert the table contains all 10 known entries.
	if len(hasshKnownNames) != 10 {
		t.Errorf("expected 10 known HASSH entries, got %d", len(hasshKnownNames))
	}
}

func TestJA4SSH_InterpretFingerprint(t *testing.T) {
	tests := []struct {
		fingerprint string
		wantNil     bool
		wantType    string
	}{
		{"c36s36_c55s75_c70s0", false, "Interactive SSH Session"},
		{"c100s100_c40s60_c30s70", false, "Reverse SSH Session"},
		{"c36s1400_c10s90_c50s50", false, "SSH File Transfer"},
		{"c1400s36_c90s10_c50s50", false, "SSH File Transfer (Upload)"},
		{"invalid", true, ""},
		{"c36s36_c50s50_c50s50", false, "Unknown"},
	}
	for _, tt := range tests {
		info := InterpretJA4SSH(tt.fingerprint)
		if tt.wantNil {
			if info != nil {
				t.Errorf("InterpretJA4SSH(%q) = %+v, want nil", tt.fingerprint, info)
			}
			continue
		}
		if info == nil {
			t.Errorf("InterpretJA4SSH(%q) = nil, want SessionType=%q", tt.fingerprint, tt.wantType)
			continue
		}
		if info.SessionType != tt.wantType {
			t.Errorf("InterpretJA4SSH(%q).SessionType = %q, want %q", tt.fingerprint, info.SessionType, tt.wantType)
		}
	}
}

func TestJA4SSH_GetHASSHFingerprints(t *testing.T) {
	fp := NewJA4SSH(200)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	clientPort := uint16(54321)
	serverPort := uint16(22)

	// Build a synthetic KEXINIT payload as an SSH binary packet.
	// Format: 4-byte packet_length | 1-byte padding_length | 1-byte msg_type(20) | 16-byte cookie | 10 name-lists
	nameListValues := []string{
		"curve25519-sha256", // kex algorithms
		"ssh-ed25519",       // server host key algorithms
		"aes128-ctr",        // encryption c2s
		"aes128-ctr",        // encryption s2c
		"hmac-sha2-256",     // mac c2s
		"hmac-sha2-256",     // mac s2c
		"none",              // compression c2s
		"none",              // compression s2c
		"",                  // languages c2s
		"",                  // languages s2c
	}

	// Build the KEXINIT message body: msg_type + cookie + name-lists
	var kexBody []byte
	kexBody = append(kexBody, 20)                  // msg_type = SSH_MSG_KEXINIT
	kexBody = append(kexBody, make([]byte, 16)...) // cookie (zeros)
	for _, nl := range nameListValues {
		nlLen := make([]byte, 4)
		nlLen[0] = byte(len(nl) >> 24)
		nlLen[1] = byte(len(nl) >> 16)
		nlLen[2] = byte(len(nl) >> 8)
		nlLen[3] = byte(len(nl))
		kexBody = append(kexBody, nlLen...)
		kexBody = append(kexBody, []byte(nl)...)
	}

	// Wrap in SSH binary packet framing: packet_length (4) + padding_length (1) + body
	paddingLen := byte(4)
	packetLen := uint32(1 + len(kexBody) + int(paddingLen))
	var sshPacket []byte
	pl := make([]byte, 4)
	pl[0] = byte(packetLen >> 24)
	pl[1] = byte(packetLen >> 16)
	pl[2] = byte(packetLen >> 8)
	pl[3] = byte(packetLen)
	sshPacket = append(sshPacket, pl...)
	sshPacket = append(sshPacket, paddingLen)
	sshPacket = append(sshPacket, kexBody...)
	sshPacket = append(sshPacket, make([]byte, int(paddingLen))...) // padding

	// Send the KEXINIT packet
	pkt := buildSSHPacket(clientIP, serverIP, clientPort, serverPort, sshPacket, false)
	_, err := fp.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error processing KEXINIT: %v", err)
	}

	// Send enough additional SSH data packets to trigger a window
	sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")
	for i := 0; i < 10; i++ {
		_, _ = fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, clientPort, serverPort, sshPayload, false))
	}

	results := fp.GetHASSHFingerprints()
	if len(results) == 0 {
		t.Fatal("GetHASSHFingerprints() returned no results")
	}
	found := false
	for _, r := range results {
		if r.Fingerprint != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one HASSH result with a non-empty Fingerprint")
	}
}

// The part c rules of issue #221. Part c counts the bare ACK of the TCP handshake, which
// arrives before the first SSH packet of the connection.
//
// `wireshark/source/packet-ja4.c:1302` counts a bare ACK on port 22 and it reads no SSH state
// first. `python/ja4ssh.py:112` counts the same packet. The port holds the rule at
// `ja4plus/fingerprinters/ja4ssh.py:176`.
//
// `sshPayloadOfSize` and `sshSeqOfPacket` live in `ja4ssh_test.go`. `buildSSHPacket` and
// `buildSSHSegment` live in `ja4ssh_test.go`. Both set the ACK flag alone, so a packet with no
// payload is a bare ACK.
//
// One reading of issue #221 belongs to issue #222, and this comment records it. `ssh-r.pcap`
// stream 1 holds 5 client bare ACKs, at the frames 298, 303, 312, 332 and 340. The reference
// counts the first 4 and it drops frame 340, because frame 335 is a FIN+ACK packet.
// `python/ja4.py:546` tests the two flags and `python/ja4.py:547` calls `finalize_ja4ssh` on
// that frame. `python/ja4.py:368` deletes the stream from the cache, so no later packet reaches
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
// `sshPayloadOfSize` and `sshSeqOfPacket` live in `ja4ssh_test.go`, and
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

// TestConnectionWindowCloserHoldsCloseConnectionWindow holds the placement the maintainer
// ruled on 2026-08-12. The method sits on its own optional interface, and `Fingerprinter`
// does not change. Issue #216 records the method, issue #53 records the optional interface,
// and issue #268 records the split that gives the method an interface of its own.
func TestConnectionWindowCloserHoldsCloseConnectionWindow(t *testing.T) {
	var fingerprinter Fingerprinter = openOneSSHWindow(t, 15)

	closer, holds := fingerprinter.(ConnectionWindowCloser)
	if !holds {
		t.Fatal("JA4SSHFingerprinter implements no ConnectionWindowCloser, and it holds a window open")
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

	if _, holds := fingerprinter.(ConnectionWindowCloser); holds {
		t.Error("JA4TFingerprinter implements ConnectionWindowCloser, and it holds no window open")
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
// A caller of the processor reaches every fingerprinter that implements
// ConnectionWindowCloser, and the processor skips every other one. Issue #216 adds the
// method, and issue #268 gives the method an interface of its own.
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

// The FIN+ACK rules of issue #222. A connection that closes emits the window it holds open,
// and the emission starts a new window.
//
// Three sources state the emission. `wireshark/source/packet-ja4.c:1400` tests the TCP flags
// and `wireshark/source/packet-ja4.c:1402` writes the value. `python/ja4.py:546` tests the two
// flags and `python/ja4.py:547` calls `finalize_ja4ssh`, which `python/ja4.py:361` defines.
// The port emits the window at `ja4plus/fingerprinters/ja4ssh.py:268`.
//
// Two of the three sources clear the counters, and Wireshark clears none of them.
// `python/ja4.py:368` deletes the stream from the cache, so no later packet of the stream
// reads a counter of the emitted window. The port clears the four counters at
// `ja4plus/fingerprinters/ja4ssh.py:439` through `ja4plus/fingerprinters/ja4ssh.py:442`.
// `wireshark/source/packet-ja4.c:1485` clears the counters of a filled window alone, so
// Wireshark writes one value twice on `ssh-r.pcap`, at frame 1850 and at frame 1851. This
// library follows the port, and the maintainer's rule of 2026-08-12 states that order.
//
// The flag test reads the two flags, and it reads no other flag.
// `python/ja4.py:546` and `ja4plus/fingerprinters/ja4ssh.py:268` both test the FIN bit and the
// ACK bit, so a FIN+PSH+ACK packet reaches the emission.
// `wireshark/source/packet-ja4.c:1400` tests `tcp_flags == 0x011` instead, and this library
// follows the port.
//
// `sshPayloadOfSize` and `sshSeqOfPacket` live in `ja4ssh_test.go`. `buildSSHPacket`
// and `buildSSHSegment` live in `ja4ssh_test.go`. Both set the ACK flag alone, so a packet
// with no payload is a bare ACK.

// buildSSHFINACK returns one TCP packet that carries the FIN flag and the ACK flag.
//
// The packet carries no payload, which is the shape of the close of a capture. A FIN+ACK
// packet never reaches the bare ACK counter, because FoxIO counts a bare ACK only where the
// TCP flags equal `0x0010`.
func buildSSHFINACK(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		FIN:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()

	return pkt
}

// buildSSHFINPSHACK returns one TCP packet that carries the FIN flag, the PSH flag, the ACK
// flag and one SSH payload.
//
// `python/ja4.py:546` and `ja4plus/fingerprinters/ja4ssh.py:268` each test the FIN bit and the
// ACK bit, so this packet reaches the emission.
// `wireshark/source/packet-ja4.c:1400` tests `tcp_flags == 0x011`, which this packet fails.
func buildSSHFINPSHACK(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, seq uint32) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		FIN:     true,
		PSH:     true,
		Seq:     seq,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()

	return pkt
}

// ja4sshBareACKPart returns part c of one JA4SSH value, which holds the two bare ACK counts.
func ja4sshBareACKPart(t *testing.T, value string) string {
	t.Helper()

	parts := strings.Split(value, "_")
	if len(parts) != 3 {
		t.Fatalf("the value %q holds %d parts, and a JA4SSH value holds three", value, len(parts))
	}

	return parts[2]
}

// TestJA4SSHEmitsTheOpenWindowOnAFINACKPacket holds the emission of issue #222. A window
// below the threshold reaches ProcessPacket on the packet that closes the connection.
func TestJA4SSHEmitsTheOpenWindowOnAFINACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for index := 0; index < 2; index++ {
		results, err := fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emits %d values on 2 SSH packets, and the window holds 200", len(results))
		}
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 73))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+ACK packet, and the connection holds one window open", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c0s0" {
		t.Errorf("the fingerprinter produces %q, and the open window of 2 client SSH packets reads `c36s0_c2s0_c0s0`", results[0].Fingerprint)
	}

	if results[0].Type != "ja4ssh" {
		t.Errorf("the result names the type %q, and the method is `ja4ssh`", results[0].Type)
	}
}

// TestJA4SSHCountsNoBareACKForTheFINACKPacket holds the flag rule of part c. FoxIO counts a
// bare ACK only where the TCP flags equal `0x0010`, so the packet that closes the connection
// reaches no counter of part c.
func TestJA4SSHCountsNoBareACKForTheFINACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	if _, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the handshake ACK", err)
	}

	for index := 0; index < 2; index++ {
		if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload))); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 73))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+ACK packet, and the connection holds one window open", len(results))
	}

	if produced := ja4sshBareACKPart(t, results[0].Fingerprint); produced != "c1s0" {
		t.Errorf("part c reads %s, and the handshake ACK is the one bare ACK of the window", produced)
	}
}

// TestJA4SSHClearsTheWindowOnAFINACKPacket holds the clear of issue #222. The port clears the
// four counters of the emitted window, so the second FIN+ACK packet of a close reaches an
// empty window and emits nothing.
func TestJA4SSHClearsTheWindowOnAFINACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for index := 0; index < 2; index++ {
		if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
			"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(index, payload))); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SSH segment %d", err, index)
		}
	}

	first, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 73))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first FIN+ACK packet", err)
	}

	if len(first) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the first FIN+ACK packet, and it emits 1", len(first))
	}

	second, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("10.0.0.1", "192.168.1.100", 22, 54321, 1))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the second FIN+ACK packet", err)
	}

	if len(second) != 0 {
		t.Fatalf("the fingerprinter emits %d values on the second FIN+ACK packet %v, and the first one emptied the window",
			len(second), second)
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows returns %d values %v, and the FIN+ACK packet emptied the window",
			len(closed), closed)
	}
}

// TestJA4SSHCountsTheBareACKThatFollowsAFINACKPacketInTheNextWindow holds the reading that
// issue #221 recorded for issue #222. `ssh-r.pcap` stream 1 holds 5 client bare ACKs, and the
// reference counts the first 4. Frame 335 carries a FIN+ACK packet, and frame 340 carries the
// fifth bare ACK, which the new window counts.
//
// The new window holds no SSH packet, so no emission reaches that count.
func TestJA4SSHCountsTheBareACKThatFollowsAFINACKPacketInTheNextWindow(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	if _, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the handshake ACK", err)
	}

	if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
		"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(0, payload))); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SSH segment", err)
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 37))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+ACK packet, and it emits 1", len(results))
	}

	if produced := ja4sshBareACKPart(t, results[0].Fingerprint); produced != "c1s0" {
		t.Errorf("part c reads %s, and the window holds the handshake ACK alone", produced)
	}

	// The bare ACK that follows the close reaches the new window.
	trailing, err := fingerprinter.ProcessPacket(
		buildSSHPacket("192.168.1.100", "10.0.0.1", 54321, 22, nil, true))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the trailing bare ACK", err)
	}

	if len(trailing) != 0 {
		t.Fatalf("the fingerprinter emits %d values %v on the trailing bare ACK, and that window holds no SSH packet",
			len(trailing), trailing)
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows returns %d values %v, and a window of bare ACKs alone emits nothing",
			len(closed), closed)
	}
}

// TestJA4SSHEmitsTheOpenWindowOnAFINPSHACKPacket holds the flag test of issue #222. The test
// reads the FIN bit and the ACK bit alone, so a packet that also carries the PSH flag closes
// the window. The payload of that packet reaches the window first.
func TestJA4SSHEmitsTheOpenWindowOnAFINPSHACKPacket(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	if _, err := fingerprinter.ProcessPacket(buildSSHSegment(
		"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(0, payload))); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SSH segment", err)
	}

	results, err := fingerprinter.ProcessPacket(buildSSHFINPSHACK(
		"192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(1, payload)))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+PSH+ACK packet", err)
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values on the FIN+PSH+ACK packet, and it emits 1", len(results))
	}

	if results[0].Fingerprint != "c36s0_c2s0_c0s0" {
		t.Errorf("the fingerprinter produces %q, and the window counts the payload of the closing packet",
			results[0].Fingerprint)
	}
}

// TestJA4SSHEmitsNoValueOnAFINACKPacketOfAnUnknownConnection holds the state rule. A FIN+ACK
// packet opens no connection, because the counters of a connection the library never read
// hold nothing.
func TestJA4SSHEmitsNoValueOnAFINACKPacketOfAnUnknownConnection(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	results, err := fingerprinter.ProcessPacket(
		buildSSHFINACK("192.168.1.100", "10.0.0.1", 54321, 22, 1))
	if err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the FIN+ACK packet", err)
	}

	if len(results) != 0 {
		t.Fatalf("the fingerprinter emits %d values %v on a FIN+ACK packet of an unknown connection",
			len(results), results)
	}

	if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
		t.Errorf("CloseOpenWindows returns %d values %v, and the FIN+ACK packet opened no connection",
			len(closed), closed)
	}
}

// TestJA4SSHEmitsTheOpenWindowOnAFINACKPacketOfSshRPcap holds FR-gaps-2 for `ssh-r.pcap` and
// JA4SSH. Stream 1 of that capture holds one value, and the FoxIO per-stream vector at
// `testdata/foxio/python/ssh-r.pcap.json` holds `"JA4SSH.1": "c64s64_c6s5_c4s5"`.
//
// The window holds 11 SSH packets, which is below the threshold of 200, so the value reaches
// ProcessPacket on the FIN+ACK packet at frame 335. Part c reads `c4s5`, because the fifth
// client bare ACK arrives at frame 340 and the new window counts it.
//
// Part a reads `c48s21` and the vector holds `c64s64`. Issue #223 records that difference,
// and this issue closes no part of it.
func TestJA4SSHEmitsTheOpenWindowOnAFINACKPacketOfSshRPcap(t *testing.T) {
	run := ja4sshValuesOfCapture(t, "ssh-r.pcap", 46394)

	if len(run.Window) != 1 {
		t.Fatalf("ProcessPacket produced %d JA4SSH values %v, and the FIN+ACK packet emits 1",
			len(run.Window), run.Window)
	}

	if produced := ja4sshBareACKPart(t, run.Window[0]); produced != "c4s5" {
		t.Errorf("part c reads %s, and the FoxIO vector reads c4s5", produced)
	}

	if produced := ja4sshPacketCountPart(t, run.Window[0]); produced != "c6s5" {
		t.Errorf("part b reads %s, and the FoxIO vector reads c6s5", produced)
	}

	if len(run.Closed) != 0 {
		t.Errorf("CloseOpenWindows produced %d JA4SSH values %v, and the FIN+ACK packet emptied the window",
			len(run.Closed), run.Closed)
	}
}

// Step 2 of the JA4SSH client direction, which issue #413 builds.
//
// The maintainer ruled the three-step order on 2026-08-11, in the second comment of #129.
// Step 1 reads port 22, step 2 reads the TCP handshake originator, and step 3 reads the lower
// port. The project manager ruled #346 on 2026-08-13, under the widened delegation of
// `.claude/rules/rulings.md`. That ruling is provisional, and the maintainer confirms it or
// reverses it.
//
// A connection with no port 22 whose SYN sender holds the lower port separates step 2 from
// step 3. Step 3 names the higher port as the client, which transposes the direction of that
// shape. No capture of the corpus reaches it, so each test below builds the packets by hand.
//
// A SYN sender on the higher port separates nothing, because step 3 reaches the same answer.
// No test below builds that shape.

// The two endpoints of the separating shape. The client sends the SYN, and it holds the lower
// port.
const (
	sshStep2ClientIP   = "10.0.0.1"
	sshStep2ClientPort = uint16(2222)
	sshStep2ServerIP   = "10.0.0.2"
	sshStep2ServerPort = uint16(40000)
)

// sshStep2SYN returns the SYN of the separating shape. The client sends it, so the client
// holds the lower port of the connection.
func sshStep2SYN(t *testing.T) gopacket.Packet {
	t.Helper()

	packet := buildTCPPacketWithIPs(
		t,
		net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP),
		64, sshStep2ClientPort, sshStep2ServerPort, true, false)
	packet.Metadata().Timestamp = time.Unix(1700000000, 0)

	return packet
}

// TestJA4SSHNamesTheSYNSenderAsTheClientOnANonStandardPort holds step 2.
//
// The client sends three SSH packets of 36 bytes, and the server sends two of 100 bytes. The
// value therefore names the client mode 36 and the client packet count 3.
// Step 3 alone reads the higher port as the client, so it reports `c100s36_c2s3_c0s0` on the
// same packets. The test fails when a later change removes step 2.
func TestJA4SSHNamesTheSYNSenderAsTheClientOnANonStandardPort(t *testing.T) {
	fingerprinter := NewJA4SSH(5)

	if _, err := fingerprinter.ProcessPacket(sshStep2SYN(t)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	clientPayload := sshPayloadOfSize(36)
	serverPayload := sshPayloadOfSize(100)

	for index := 0; index < 3; index++ {
		packet := buildSSHSegment(
			sshStep2ClientIP, sshStep2ServerIP, sshStep2ClientPort, sshStep2ServerPort,
			clientPayload, sshSeqOfPacket(index, clientPayload))
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for client packet %d", err, index)
		}
	}

	var results []FingerprintResult

	for index := 0; index < 2; index++ {
		packet := buildSSHSegment(
			sshStep2ServerIP, sshStep2ClientIP, sshStep2ServerPort, sshStep2ClientPort,
			serverPayload, sshSeqOfPacket(index, serverPayload))

		emitted, err := fingerprinter.ProcessPacket(packet)
		if err != nil {
			t.Fatalf("the fingerprinter returns the error %v for server packet %d", err, index)
		}

		if len(emitted) > 0 {
			results = emitted
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 5 packets emits 1", len(results))
	}

	const expected = "c36s100_c3s2_c0s0"

	if results[0].Fingerprint != expected {
		t.Errorf("the value is %q, and the SYN sender is the client, so the value is %q",
			results[0].Fingerprint, expected)
	}
}

// TestJA4SSHNamesTheSYNACKReceiverAsTheClientOnANonStandardPort holds the second half of step 2.
//
// A capture that starts after the SYN still holds the SYN+ACK. The server sends that packet,
// so its destination is the client.
func TestJA4SSHNamesTheSYNACKReceiverAsTheClientOnANonStandardPort(t *testing.T) {
	fingerprinter := NewJA4SSH(5)

	synACK := buildTCPPacketWithIPs(
		t,
		net.ParseIP(sshStep2ServerIP), net.ParseIP(sshStep2ClientIP),
		64, sshStep2ServerPort, sshStep2ClientPort, true, true)
	synACK.Metadata().Timestamp = time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(synACK); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN+ACK", err)
	}

	clientPayload := sshPayloadOfSize(36)
	serverPayload := sshPayloadOfSize(100)

	for index := 0; index < 3; index++ {
		packet := buildSSHSegment(
			sshStep2ClientIP, sshStep2ServerIP, sshStep2ClientPort, sshStep2ServerPort,
			clientPayload, sshSeqOfPacket(index, clientPayload))
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for client packet %d", err, index)
		}
	}

	var results []FingerprintResult

	for index := 0; index < 2; index++ {
		packet := buildSSHSegment(
			sshStep2ServerIP, sshStep2ClientIP, sshStep2ServerPort, sshStep2ClientPort,
			serverPayload, sshSeqOfPacket(index, serverPayload))

		emitted, _ := fingerprinter.ProcessPacket(packet)
		if len(emitted) > 0 {
			results = emitted
		}
	}

	if len(results) != 1 {
		t.Fatalf("the fingerprinter emits %d values, and the window of 5 packets emits 1", len(results))
	}

	const expected = "c36s100_c3s2_c0s0"

	if results[0].Fingerprint != expected {
		t.Errorf("the value is %q, and the SYN+ACK receiver is the client, so the value is %q",
			results[0].Fingerprint, expected)
	}
}

// TestJA4SSHCleanupConnectionRemovesTheConnectionThatStep2Named holds the second site.
//
// `sshConnKeyOfEndpoints` holds no packet, and step 2 changes which endpoint is the client. A
// key that misses the connection leaves the entry, which is a leak. The caller names the two
// endpoints in the server-to-client order, and the state table then holds no connection.
func TestJA4SSHCleanupConnectionRemovesTheConnectionThatStep2Named(t *testing.T) {
	fingerprinter := sshStep2FingerprinterOfOneConnection(t)

	fingerprinter.CleanupConnection(
		sshStep2ServerIP, sshStep2ServerPort, sshStep2ClientIP, sshStep2ClientPort, "tcp")

	if len(fingerprinter.connections) != 0 {
		t.Errorf("the state table holds %d connections, and CleanupConnection removes the one connection",
			len(fingerprinter.connections))
	}

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries, and CleanupConnection empties it",
			fingerprinter.order.Len())
	}

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and CleanupConnection removes the entry of the connection",
			len(fingerprinter.handshakes))
	}
}

// TestJA4SSHCloseConnectionWindowReadsTheClientThatStep2Named holds the other reader of
// `sshConnKeyOfEndpoints`. It names the client of the connection as the source of the result.
func TestJA4SSHCloseConnectionWindowReadsTheClientThatStep2Named(t *testing.T) {
	fingerprinter := sshStep2FingerprinterOfOneConnection(t)

	results := fingerprinter.CloseConnectionWindow(
		sshStep2ServerIP, sshStep2ServerPort, sshStep2ClientIP, sshStep2ClientPort, "tcp")

	if len(results) != 1 {
		t.Fatalf("the method returns %d values, and the connection holds one open window", len(results))
	}

	if results[0].SrcIP != sshStep2ClientIP || results[0].SrcPort != sshStep2ClientPort {
		t.Errorf("the result names the source %s:%d, and the client of the connection is %s:%d",
			results[0].SrcIP, results[0].SrcPort, sshStep2ClientIP, sshStep2ClientPort)
	}

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and the method removes the entry of the connection",
			len(fingerprinter.handshakes))
	}
}

// sshStep2FingerprinterOfOneConnection returns a fingerprinter that holds the separating shape
// as one connection. The window holds 200 packets, so the three client packets emit no value.
func sshStep2FingerprinterOfOneConnection(t *testing.T) *JA4SSHFingerprinter {
	t.Helper()

	fingerprinter := NewJA4SSH(200)

	if _, err := fingerprinter.ProcessPacket(sshStep2SYN(t)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	payload := sshPayloadOfSize(36)

	for index := 0; index < 3; index++ {
		packet := buildSSHSegment(
			sshStep2ClientIP, sshStep2ServerIP, sshStep2ClientPort, sshStep2ServerPort,
			payload, sshSeqOfPacket(index, payload))
		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for client packet %d", err, index)
		}
	}

	if len(fingerprinter.connections) != 1 {
		t.Fatalf("the state table holds %d connections, and these packets open 1",
			len(fingerprinter.connections))
	}

	return fingerprinter
}

// TestJA4SSHWritesNoHandshakeEntryForAPairThatHoldsPort22 holds the guard that keeps the corpus
// value. Step 1 decides a connection of port 22, so an entry would hold state that nothing
// reads. Every SSH capture of the corpus holds port 22 on one side.
func TestJA4SSHWritesNoHandshakeEntryForAPairThatHoldsPort22(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	packet := buildTCPPacketWithIPs(
		t, net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP), 64, 54321, 22, true, false)
	packet.Metadata().Timestamp = time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(packet); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and port 22 decides the direction",
			len(fingerprinter.handshakes))
	}
}

// TestJA4SSHHoldsThePortValueOfTheHandshakeEntryBound reads the bound against the port.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface, and no FoxIO
// source addresses a state table.
func TestJA4SSHHoldsThePortValueOfTheHandshakeEntryBound(t *testing.T) {
	if maxSSHHandshakes != 1000 {
		t.Errorf("the handshake entry bound is %d, and `ja4plus/fingerprinters/ja4ssh.py:53` states 1000",
			maxSSHHandshakes)
	}
}

// TestJA4SSHRemovesTheLeastRecentHandshakeAtTheEntryBound drives the handshake table with one
// SYN more than the bound holds. A SYN on a non-standard port carries no SSH data and opens no
// connection, so the handshake table needs a bound of its own.
func TestJA4SSHRemovesTheLeastRecentHandshakeAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	timestamp := time.Unix(1700000000, 0)

	for index := 0; index <= maxSSHHandshakes; index++ {
		packet := buildTCPPacketWithIPs(
			t, net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP),
			64, uint16(2000+index), sshStep2ServerPort, true, false)
		packet.Metadata().Timestamp = timestamp

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SYN %d", err, index)
		}
	}

	if len(fingerprinter.handshakes) != maxSSHHandshakes {
		t.Fatalf("the handshake table holds %d entries, and the entry bound holds %d",
			len(fingerprinter.handshakes), maxSSHHandshakes)
	}

	if fingerprinter.handshakeOrder.Len() != maxSSHHandshakes {
		t.Errorf("the handshake order list holds %d entries, and the table holds %d",
			fingerprinter.handshakeOrder.Len(), maxSSHHandshakes)
	}

	if len(fingerprinter.connections) != 0 {
		t.Errorf("the state table holds %d connections, and a SYN opens none",
			len(fingerprinter.connections))
	}

	first := sshHandshakeKey(sshStep2ClientIP, 2000, sshStep2ServerIP, sshStep2ServerPort)
	if _, held := fingerprinter.handshakes[first]; held {
		t.Errorf("the handshake table holds the first entry, and the entry bound removes the least recent one")
	}
}

// TestJA4SSHRemovesAHandshakeOlderThanTheAgeBound drives the age bound of the handshake table.
// The age pass runs on the eviction interval, so the later packets reach it.
func TestJA4SSHRemovesAHandshakeOlderThanTheAgeBound(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	start := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshStep2SYN(t)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the SYN", err)
	}

	later := start.Add(601 * time.Second)

	for index := 1; index < sshEvictionInterval; index++ {
		packet := buildTCPPacketWithIPs(
			t, net.ParseIP(sshStep2ClientIP), net.ParseIP(sshStep2ServerIP),
			64, 3000, sshStep2ServerPort, true, false)
		packet.Metadata().Timestamp = later

		if _, err := fingerprinter.ProcessPacket(packet); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for SYN %d", err, index)
		}
	}

	aged := sshHandshakeKey(
		sshStep2ClientIP, sshStep2ClientPort, sshStep2ServerIP, sshStep2ServerPort)
	if _, held := fingerprinter.handshakes[aged]; held {
		t.Errorf("the handshake table holds an entry of age 601 seconds, and the age bound is 600 seconds")
	}
}

// TestJA4SSHResetEmptiesTheHandshakeTable holds the removal path that
// `.claude/rules/concurrency.md` states. A new state map reaches CleanupConnection and Reset.
func TestJA4SSHResetEmptiesTheHandshakeTable(t *testing.T) {
	fingerprinter := sshStep2FingerprinterOfOneConnection(t)

	fingerprinter.Reset()

	if len(fingerprinter.handshakes) != 0 {
		t.Errorf("the handshake table holds %d entries, and Reset empties it",
			len(fingerprinter.handshakes))
	}

	if fingerprinter.handshakeOrder.Len() != 0 {
		t.Errorf("the handshake order list holds %d entries, and Reset empties it",
			fingerprinter.handshakeOrder.Len())
	}
}

// TestJA4SSHHandshakeKeyReadsTheTwoDirectionsAsOneKey holds the rule that solves the second
// site. The state-table key encodes the direction, and the handshake key encodes none. A
// caller that holds four endpoint values and no packet therefore reaches the entry the packet
// path wrote.
func TestJA4SSHHandshakeKeyReadsTheTwoDirectionsAsOneKey(t *testing.T) {
	forward := sshHandshakeKey(
		sshStep2ClientIP, sshStep2ClientPort, sshStep2ServerIP, sshStep2ServerPort)
	reverse := sshHandshakeKey(
		sshStep2ServerIP, sshStep2ServerPort, sshStep2ClientIP, sshStep2ClientPort)

	if forward != reverse {
		t.Errorf("the two directions give the keys %q and %q, and one connection holds one key",
			forward, reverse)
	}
}

// The SSH packet count of issue #200. `internal/parser/ssh.go` reads the four-byte length
// field of an SSH record, and a cipher hides that field after the key exchange. The library
// therefore counted almost no SSH packet after the key exchange, and 42 JA4SSH comparisons
// of the conformance suite differed.
//
// Two FoxIO implementations state the counting rule, and the two agree.
//
//   - `testdata/foxio/reference/wireshark/source/packet-ja4.c:1469` counts one packet for
//     each `ssh.direction` field of the frame, which the `tshark` SSH dissector writes.
//   - `testdata/foxio/reference/python/ja4ssh.py:94` reads
//     `has_ssh = ('ssh' in x['protos']) or ('direction' in x) or has_ssh_extras`, so it
//     counts the packet that `tshark` labels `ssh`.
//
// The port holds the same rule at `ja4plus/fingerprinters/ja4ssh.py:247`, and its
// `SSHMessageTracker` follows the SSH message boundary. `parser.SSHMessageTracker` is the
// one-to-one Go form of that tracker.

// ja4sshCaptureDir holds the FoxIO captures that `make corpus` fetches.
const ja4sshCaptureDir = "testdata/foxio/pcap"

// ja4sshPacketCountRun holds the values of one run over one capture.
// `Window` holds the value that ProcessPacket returned at a filled window, and `Closed`
// holds the value that CloseOpenWindows returned at the end of the capture.
type ja4sshPacketCountRun struct {
	Window []string
	Closed []string
}

// ja4sshValuesOfCapture returns the JA4SSH values that one capture produces on one port pair.
// It skips the test when the corpus is absent.
//
// It keeps the two emission paths apart, because a value that only CloseOpenWindows reaches
// tells a streaming caller nothing.
func ja4sshValuesOfCapture(t *testing.T, capture string, clientPort uint16) ja4sshPacketCountRun {
	t.Helper()

	packets := loadPCAP(t, filepath.Join(ja4sshCaptureDir, capture))

	processor := NewProcessor()

	var run ja4sshPacketCountRun

	keep := func(results []FingerprintResult, into *[]string) {
		for _, result := range results {
			if result.Type != "ja4ssh" {
				continue
			}

			if result.SrcPort != clientPort && result.DstPort != clientPort {
				continue
			}

			*into = append(*into, result.Fingerprint)
		}
	}

	for _, packet := range packets {
		// A fingerprinter returns a non-fatal error, and this test reads the JA4SSH values
		// alone.
		results, _ := processor.ProcessPacket(packet)
		keep(results, &run.Window)
	}

	keep(processor.CloseOpenWindows(), &run.Closed)

	return run
}

// TestJA4SSHCountsTheSSHPacketsOfSshPcapng holds FR-gaps-2 for `ssh.pcapng` and JA4SSH.
//
// The FoxIO per-stream vector at `testdata/foxio/python/ssh.pcapng.json` holds
// `"JA4SSH.1": "c36s36_c76s124_c0s0"` for stream 0, and the per-packet vector at
// `testdata/foxio/wireshark/ssh.pcapng.json` holds the same value at frame 200. The two
// counts add to 200, so the window fills and ProcessPacket emits the value.
//
// The capture proves that the repair restores emission at the window. Before the repair the
// library counted 7 SSH packets of the 200, so no window ever filled and CloseOpenWindows
// was the only emission path.
func TestJA4SSHCountsTheSSHPacketsOfSshPcapng(t *testing.T) {
	run := ja4sshValuesOfCapture(t, "ssh.pcapng", 57377)

	if len(run.Window) != 1 {
		t.Fatalf("ProcessPacket produced %d JA4SSH values %v, and the window of 200 fills once",
			len(run.Window), run.Window)
	}

	if run.Window[0] != "c36s36_c76s124_c0s0" {
		t.Errorf("the value is %q, and the FoxIO vector holds \"c36s36_c76s124_c0s0\"", run.Window[0])
	}
}

// TestJA4SSHCountsTheSSHPacketsOfSshRPcap holds FR-gaps-2 for `ssh-r.pcap` and JA4SSH.
//
// The FoxIO per-stream vector at `testdata/foxio/python/ssh-r.pcap.json` holds five values
// for stream 2, whose client port is 46396. Four windows of 200 SSH packets fill, and the
// FIN+ACK packet of the close emits the fifth value. Issue #222 moved that value from
// CloseOpenWindows to ProcessPacket, and part c of it then read `c9s51` and matched the
// vector.
//
// This test reads part b of each value, which holds the two SSH packet counts. Part b is the
// field that issue #200 repairs. Part a and part c of the first value carry two differences
// that this issue does not close, and issue #200 records the reading of each one.
//
//   - Part c of the first window reads `c18s82`, and both vectors hold `c19s82`. The bare ACK
//     of the TCP handshake arrives before the first SSH packet, and the library counts no
//     bare ACK on a connection it has not opened yet.
//   - Part a of the first window reads `c76s76`, and the two FoxIO implementations disagree.
//     The per-packet vector at `testdata/foxio/wireshark/ssh-r.pcap.json` holds `c76s76` at
//     frame 706, and the per-stream vector holds `c64s64` for the same window and the same
//     counts.
func TestJA4SSHCountsTheSSHPacketsOfSshRPcap(t *testing.T) {
	run := ja4sshValuesOfCapture(t, "ssh-r.pcap", 46396)

	// The two SSH packet counts of the five values the FoxIO vector holds.
	counts := []string{"c104s96", "c108s92", "c106s94", "c111s89", "c66s65"}

	if len(run.Window) != len(counts) {
		t.Fatalf("ProcessPacket produced %d JA4SSH values %v, and the FoxIO vector holds %d values",
			len(run.Window), run.Window, len(counts))
	}

	for index, expected := range counts {
		produced := ja4sshPacketCountPart(t, run.Window[index])
		if produced != expected {
			t.Errorf("value %d counts %s SSH packets, and the FoxIO vector counts %s",
				index+1, produced, expected)
		}
	}

	if len(run.Closed) != 0 {
		t.Errorf("CloseOpenWindows produced %d JA4SSH values %v, and the FIN+ACK packet emptied the window",
			len(run.Closed), run.Closed)
	}
}

// ja4sshPacketCountPart returns part b of one JA4SSH value, which holds the two SSH packet
// counts.
func ja4sshPacketCountPart(t *testing.T, value string) string {
	t.Helper()

	parts := strings.Split(value, "_")
	if len(parts) != 3 {
		t.Fatalf("the value %q holds %d parts, and a JA4SSH value holds three", value, len(parts))
	}

	return parts[1]
}

// The state bound of issue #239. `JA4SSHFingerprinter` holds one entry for each connection,
// and the entry count reached no bound before this change.
//
// Issue #221 raised the cost. A bare ACK on TCP port 22 opens an entry, so every completed
// TCP handshake to port 22 opens one. A port scan of that port therefore opens one entry for
// each connection it opens.
//
// The port bounds the same state, and `.claude/rules/parity.md` rule 2 states that the port
// decides the interface where this project shipped nothing. No FoxIO source addresses a state
// table. `ja4plus/utils/state_table.py:52` sets `DEFAULT_MAX_CONNECTIONS = 10000`,
// `ja4plus/utils/state_table.py:58` sets `DEFAULT_MAX_CONNECTION_AGE = 600`, and
// `ja4plus/utils/state_table.py:62` sets `DEFAULT_EVICTION_INTERVAL = 1000`.
// `ja4plus/fingerprinters/ja4ssh.py:122` announces the packet timestamp to the table, so the
// eviction clock reads the capture and never the wall clock.
//
// Each test below drives the bound with packets, and it reads the entry count of the state
// table. A test that reads a constant alone proves no eviction.

// sshBoundClientIP names the client of every connection of these tests.
const sshBoundClientIP = "192.168.1.100"

// sshBoundServerIP names the server of every connection of these tests.
const sshBoundServerIP = "10.0.0.1"

// sshBoundPacketAt returns one bare ACK to TCP port 22 at the timestamp the caller names.
// A bare ACK on that port opens a connection, and it advances no window.
// The client port names the connection, so a caller reaches a new connection with a new port.
func sshBoundPacketAt(clientPort uint16, timestamp time.Time) gopacket.Packet {
	packet := buildSSHPacket(sshBoundClientIP, sshBoundServerIP, clientPort, 22, nil, true)
	packet.Metadata().Timestamp = timestamp
	return packet
}

// sshBoundConnKey returns the state-table key of the connection the client port names.
func sshBoundConnKey(clientPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:22", sshBoundClientIP, clientPort, sshBoundServerIP)
}

// TestJA4SSHHoldsThePortValuesOfTheStateBound reads the three values against the port.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface. A change to one
// of the three values is therefore a parity change.
func TestJA4SSHHoldsThePortValuesOfTheStateBound(t *testing.T) {
	if maxSSHConnections != 10000 {
		t.Errorf("the entry bound is %d, and `ja4plus/utils/state_table.py:52` states 10000", maxSSHConnections)
	}

	if maxSSHConnectionAge != 600*time.Second {
		t.Errorf("the age bound is %v, and `ja4plus/utils/state_table.py:58` states 600 seconds", maxSSHConnectionAge)
	}

	if sshEvictionInterval != 1000 {
		t.Errorf("the eviction interval is %d, and `ja4plus/utils/state_table.py:62` states 1000", sshEvictionInterval)
	}
}

// TestJA4SSHRemovesTheLeastRecentConnectionAtTheEntryBound drives the entry bound with one
// connection more than the bound holds. The state table keeps the bound, and it removes the
// connection that received no packet for the longest time.
func TestJA4SSHRemovesTheLeastRecentConnectionAtTheEntryBound(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	for index := 0; index <= maxSSHConnections; index++ {
		clientPort := uint16(1024 + index)
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(clientPort, timestamp)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for connection %d", err, index)
		}
	}

	if len(fingerprinter.connections) != maxSSHConnections {
		t.Fatalf("the state table holds %d connections, and the entry bound holds %d",
			len(fingerprinter.connections), maxSSHConnections)
	}

	if _, held := fingerprinter.connections[sshBoundConnKey(1024)]; held {
		t.Errorf("the state table holds the first connection, and the entry bound removes the least recent one")
	}

	if _, held := fingerprinter.connections[sshBoundConnKey(uint16(1024+maxSSHConnections))]; !held {
		t.Errorf("the state table holds no last connection, and the packet that crosses the bound opens one")
	}
}

// TestJA4SSHRemovesAConnectionOlderThanTheAgeBound drives the age bound with the packet
// timestamp. The age pass runs on the eviction interval, so the second connection carries the
// packets that reach it.
func TestJA4SSHRemovesAConnectionOlderThanTheAgeBound(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fingerprinter := sshBoundFingerprinterOfTwoConnections(t, start, start.Add(601*time.Second))

	if _, held := fingerprinter.connections[sshBoundConnKey(1024)]; held {
		t.Errorf("the state table holds a connection of age 601 seconds, and the age bound is 600 seconds")
	}

	if len(fingerprinter.connections) != 1 {
		t.Errorf("the state table holds %d connections, and the age pass removes 1 of the 2",
			len(fingerprinter.connections))
	}
}

// TestJA4SSHKeepsAConnectionInsideTheAgeBound holds the other half of the age bound. A
// connection of age 599 seconds stays, so the pass removes no connection inside the bound.
func TestJA4SSHKeepsAConnectionInsideTheAgeBound(t *testing.T) {
	start := time.Unix(1700000000, 0)
	fingerprinter := sshBoundFingerprinterOfTwoConnections(t, start, start.Add(599*time.Second))

	if len(fingerprinter.connections) != 2 {
		t.Errorf("the state table holds %d connections, and the age pass removes no connection inside the bound",
			len(fingerprinter.connections))
	}
}

// sshBoundFingerprinterOfTwoConnections returns a fingerprinter of two connections.
// The first connection reads one packet at the start time. The second connection reads the
// eviction interval of packets at the later time.
// The last packet reaches the age pass, because the fingerprinter runs that pass on the
// eviction interval.
func sshBoundFingerprinterOfTwoConnections(
	t *testing.T, start time.Time, later time.Time,
) *JA4SSHFingerprinter {
	t.Helper()

	fingerprinter := NewJA4SSH(2)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, start)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first connection", err)
	}

	for index := 1; index < sshEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1025, later)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d of the second connection", err, index)
		}
	}

	return fingerprinter
}

// TestJA4SSHCountsANewWindowForAConnectionThatReturnsAfterTheAgeBound states what an eviction
// costs. The age pass precedes the connection of the packet, so it can remove the connection
// that the packet continues. The packet then opens that connection again, and the window
// counts from zero.
// The port counts such a connection as a returned connection, at
// `ja4plus/utils/state_table.py:95`.
func TestJA4SSHCountsANewWindowForAConnectionThatReturnsAfterTheAgeBound(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	start := time.Unix(1700000000, 0)
	later := start.Add(601 * time.Second)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, start)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the first packet", err)
	}

	// The pass runs on the packet that completes the eviction interval, so the second
	// connection carries every packet up to that one.
	for index := 2; index < sshEvictionInterval; index++ {
		if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1025, later)); err != nil {
			t.Fatalf("the fingerprinter returns the error %v for packet %d", err, index)
		}
	}

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, later)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the packet that returns", err)
	}

	conn, held := fingerprinter.connections[sshBoundConnKey(1024)]
	if !held {
		t.Fatalf("the state table holds no connection, and the packet that returns opens one")
	}

	if conn.clientACKs != 1 {
		t.Errorf("the connection counts %d client bare ACKs, and a connection that returns counts 1",
			conn.clientACKs)
	}
}

// TestJA4SSHResetEmptiesTheOrderList holds the removal path of Reset.
// An order list that keeps a removed connection removes the wrong connection at the entry
// bound.
func TestJA4SSHResetEmptiesTheOrderList(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, timestamp)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the connection", err)
	}

	fingerprinter.Reset()

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries after Reset, and the state table holds none",
			fingerprinter.order.Len())
	}
}

// TestJA4SSHCleanupConnectionEmptiesTheOrderList holds the removal path of
// CleanupConnection. It reads the order list, because the state table and the order list name
// one set of connections.
func TestJA4SSHCleanupConnectionEmptiesTheOrderList(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, timestamp)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the connection", err)
	}

	fingerprinter.CleanupConnection(sshBoundClientIP, 1024, sshBoundServerIP, 22, "tcp")

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries after CleanupConnection, and the state table holds none",
			fingerprinter.order.Len())
	}
}

// TestJA4SSHCloseConnectionWindowEmptiesTheOrderList holds the removal path of
// CloseConnectionWindow. That method removes the connection after it emits the open window.
func TestJA4SSHCloseConnectionWindowEmptiesTheOrderList(t *testing.T) {
	fingerprinter := NewJA4SSH(2)
	timestamp := time.Unix(1700000000, 0)

	if _, err := fingerprinter.ProcessPacket(sshBoundPacketAt(1024, timestamp)); err != nil {
		t.Fatalf("the fingerprinter returns the error %v for the connection", err)
	}

	fingerprinter.CloseConnectionWindow(sshBoundClientIP, 1024, sshBoundServerIP, 22, "tcp")

	if fingerprinter.order.Len() != 0 {
		t.Errorf("the order list holds %d entries after CloseConnectionWindow, and the state table holds none",
			fingerprinter.order.Len())
	}
}

// The JA4SSH window rules of issue #53. The port holds the rulings in its issues #28, #96,
// #97, #105, #199 and #214, and `docs/specs/features/08-python-parity.md` numbers them
// FR-parity-25 through FR-parity-33.
//
// `buildSSHPacket` lives in `ja4ssh_test.go`. It sets the ACK flag on every packet, so a
// packet with no payload is a bare ACK.

// sshPayloadOfSize returns one whole SSH binary packet of the size the caller names.
//
// The payload holds the four-byte length field, the padding length and the message code that
// RFC 4253 section 6 states. `parser.IsSSHPacket` therefore reads it as SSH data. It opens
// with no version line, so `parser.SSHMessageTracker` follows no message boundary in the
// direction. The tracker counts every segment of that direction. The caller names a size of 8
// bytes or more.
func sshPayloadOfSize(size int) []byte {
	payload := make([]byte, size)
	binary.BigEndian.PutUint32(payload, uint32(size-4))
	// The padding length stays below the message length, and the message code names
	// SSH_MSG_CHANNEL_DATA.
	payload[4] = 4
	payload[5] = 94

	return payload
}

// sshSeqOfPacket returns the TCP sequence number of one segment of a direction that sends
// segments of one size. The first segment of a direction carries the sequence number 1.
func sshSeqOfPacket(index int, payload []byte) uint32 {
	return uint32(1 + index*len(payload))
}

// TestJA4SSHEmitsAtThePacketCountAndHoldsNoUpperCap holds FR-parity-25 and FR-parity-26.
// The port's issue #28 rules the threshold, and `ja4ssh.py:261` reads
// `if total_packets >= self.packet_count`.
func TestJA4SSHEmitsAtThePacketCountAndHoldsNoUpperCap(t *testing.T) {
	fingerprinter := NewJA4SSH(200)
	payload := sshPayloadOfSize(36)

	for count := 1; count < 200; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(count-1, payload)))
		if err != nil {
			t.Fatalf("the fingerprinter returned an error at packet %d: %v", count, err)
		}

		if len(results) != 0 {
			t.Fatalf("the fingerprinter emitted at packet %d, and the window holds 200", count)
		}
	}

	results, err := fingerprinter.ProcessPacket(
		buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload, sshSeqOfPacket(199, payload)))
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

	first := sshPayloadOfSize(36)

	for count := 0; count < 4; count++ {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, first,
				sshSeqOfPacket(count, first))); err != nil {
			t.Fatalf("the fingerprinter returned an error in the first window: %v", err)
		}
	}

	var second []FingerprintResult

	// The second window continues the sequence space of the direction, so its first segment
	// follows the four segments of the first window.
	larger := sshPayloadOfSize(100)
	base := sshSeqOfPacket(4, first)

	for count := 0; count < 4; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, larger,
				base+uint32(count*len(larger))))
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

	payload := sshPayloadOfSize(36)

	for count := 0; count < 3; count++ {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(count, payload))); err != nil {
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
// `rust/ja4/src/ssh.rs:45-55` and `zeek/scripts/fingerprints/ja4ssh/main.zeek:98-105` both emit the open window.
func TestJA4SSHCloseOpenWindowsEmitsTheWindowAConnectionHoldsOpen(t *testing.T) {
	fingerprinter := NewJA4SSH(200)

	payload := sshPayloadOfSize(36)

	for count := 0; count < 15; count++ {
		results, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(count, payload)))
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

	payload := sshPayloadOfSize(36)

	for count := 0; count < 15; count++ {
		if _, err := fingerprinter.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(count, payload))); err != nil {
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
// The method is opt-in, and the library forces no flush. No other exported method emits the
// open window, so a caller who evicts the connection loses that window.
func TestJA4SSHLosesTheOpenWindowWhenNoCallerClosesIt(t *testing.T) {
	// CleanupConnection evicts the connection, and Reset clears the table. Neither one
	// returns a value, so neither one can flush the window.
	cases := map[string]func(f *JA4SSHFingerprinter){
		"CleanupConnection": func(f *JA4SSHFingerprinter) {
			f.CleanupConnection("192.168.1.100", 54321, "10.0.0.1", 22, "tcp")
		},
		"Reset": func(f *JA4SSHFingerprinter) { f.Reset() },
	}

	for name, evict := range cases {
		t.Run(name, func(t *testing.T) {
			fingerprinter := NewJA4SSH(200)
			payload := sshPayloadOfSize(36)

			for count := 0; count < 15; count++ {
				results, err := fingerprinter.ProcessPacket(
					buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
						sshSeqOfPacket(count, payload)))
				if err != nil {
					t.Fatalf("the fingerprinter returned an error at packet %d: %v", count+1, err)
				}

				if len(results) != 0 {
					t.Fatalf("the fingerprinter emitted at packet %d, and the window holds 200", count+1)
				}
			}

			evict(fingerprinter)

			if closed := fingerprinter.CloseOpenWindows(); len(closed) != 0 {
				t.Errorf("CloseOpenWindows produced %d values after %s, and the window is lost",
					len(closed), name)
			}
		})
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

	payload := sshPayloadOfSize(36)

	for count := 0; count < 15; count++ {
		results, errs := processor.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(count, payload)))
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

	payload := sshPayloadOfSize(36)

	for count := 0; count < 15; count++ {
		if _, errs := processor.ProcessPacket(
			buildSSHSegment("192.168.1.100", "10.0.0.1", 54321, 22, payload,
				sshSeqOfPacket(count, payload))); len(errs) > 0 {
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
