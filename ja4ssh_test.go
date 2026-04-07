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
	if ack && len(payload) == 0 {
		// Pure ACK - no payload
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if len(payload) > 0 {
		gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	} else {
		gopacket.SerializeLayers(buf, opts, ip, tcp)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func TestJA4SSH_WindowTrigger(t *testing.T) {
	fp := NewJA4SSH(200) // default window, early trigger at 10

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
	fp := NewJA4SSH(10) // window of 10, early trigger at 10

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
		fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, clientPort, serverPort, clientPayload, false))
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
		fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 22, sshPayload, false))
	}

	fp.Reset()

	if len(fp.connections) != 0 {
		t.Error("expected connections to be cleared after reset")
	}
	if len(fp.results) != 0 {
		t.Error("expected results to be cleared after reset")
	}
}

func TestJA4SSH_EarlyTrigger(t *testing.T) {
	// With packet count=5, early trigger = min(5, 10) = 5
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

func TestJA4SSH_ACKCounting(t *testing.T) {
	fp := NewJA4SSH(10)

	clientIP := "192.168.1.100"
	serverIP := "10.0.0.1"
	sshPayload := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	// 5 SSH data packets from client
	for i := 0; i < 5; i++ {
		fp.ProcessPacket(buildSSHPacket(clientIP, serverIP, 54321, 22, sshPayload, false))
	}

	// 3 pure ACKs from server
	for i := 0; i < 3; i++ {
		fp.ProcessPacket(buildSSHPacket(serverIP, clientIP, 22, 54321, nil, true))
	}

	// 2 more SSH data from server — should hit 10 total
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
