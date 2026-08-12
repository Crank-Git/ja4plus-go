package ja4plus

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildSSHPacket creates a synthetic TCP packet with the given parameters.
func buildSSHPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ack bool) gopacket.Packet {
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
		results, err := fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, clientPort, serverPort, sshPayload, false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) > 0 {
			t.Fatalf("did not expect fingerprint after %d packets", i+1)
		}
	}

	// 10th packet should trigger
	results, err := fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, clientPort, serverPort, sshPayload, false))
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

	clientPayload := make([]byte, 36)
	copy(clientPayload, "SSH-2.0-client")

	serverPayload := make([]byte, 100)
	copy(serverPayload, "SSH-2.0-server")

	// 5 client packets (size 36 each)
	for i := 0; i < 5; i++ {
		_, _ = fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, clientPort, serverPort, clientPayload, false))
	}

	// 5 server packets (size 100 each) — should trigger
	var lastResults []FingerprintResult
	for i := 0; i < 5; i++ {
		results, _ := fp.ProcessPacket(buildSSHPacket(serverIP, clientIP, serverPort, clientPort, serverPayload, false))
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
		results, _ := fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 22, sshPayload, false))
		if len(results) > 0 {
			t.Fatalf("unexpected trigger at packet %d", i+1)
		}
	}

	results, _ := fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 22, sshPayload, false))
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
		_, _ = fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 22, sshPayload, false))
	}

	// 3 pure ACKs from server
	for i := 0; i < 3; i++ {
		_, _ = fp.ProcessPacket(buildSSHPacket(serverIP, clientIP, 22, 54321, nil, true))
	}

	// 2 more SSH data from server — the window reaches seven SSH packets
	serverPayload := []byte("SSH-2.0-ServerSSH\r\n")
	var lastResults []FingerprintResult
	for i := 0; i < 2; i++ {
		results, _ := fp.ProcessPacket(buildSSHPacket(serverIP, clientIP, 22, 54321, serverPayload, false))
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
