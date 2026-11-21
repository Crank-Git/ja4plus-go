//go:build prerelease

package repocheck

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The four helpers of this file build the packets of the pre-release cases. Each one is a
// verbatim copy of a test helper of package `ja4plus`: `buildTCPPacketWithPayload` of
// `ja4h_test.go`, `buildTCPPacket` and `mssOptionData` of `ja4t_test.go`, and
// `buildClientHelloPayload` of `benchmark_test.go`. A test helper lives in a `_test.go`
// file, and no package imports another package's test files.
//
// `prereleaseExpectedJA4` in `prerelease_install_test.go` states the JA4 value of the frame
// that these bytes build. A change to a copy moves the frame, and the install case then
// fails on the value.

// buildTCPPacketWithPayload creates a gopacket.Packet containing Ethernet +
// IPv4 + TCP layers with the given payload bytes as TCP application data.
func buildTCPPacketWithPayload(t testing.TB, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		ACK:     true,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildTCPPacket(t testing.TB, srcPort, dstPort uint16, syn, ack bool, window uint16, options []layers.TCPOption) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{10, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Window:  window,
		Options: options,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mssOptionData(val uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, val)
	return b
}

// buildClientHelloPayload returns the bytes of one TLS ClientHello record.
// The record carries the four extensions that JA4 reads: SNI, ALPN,
// supported_versions and signature_algorithms.
func buildClientHelloPayload() []byte {
	cipherSuites := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c}

	var extBytes []byte
	appendExt := func(extType uint16, data []byte) {
		extBytes = append(extBytes, byte(extType>>8), byte(extType))
		extBytes = append(extBytes, byte(len(data)>>8), byte(len(data)))
		extBytes = append(extBytes, data...)
	}

	// server_name: list_len(2) + type(1) + host_len(2) + host
	host := []byte("example.com")
	listLen := len(host) + 3
	sni := []byte{byte(listLen >> 8), byte(listLen), 0x00, byte(len(host) >> 8), byte(len(host))}
	sni = append(sni, host...)
	appendExt(parser.ExtSNI, sni)

	// application_layer_protocol_negotiation: list_len(2) + (len(1) + proto)...
	alpn := []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	appendExt(parser.ExtALPN, alpn)

	// supported_versions: list_len(1) + versions
	appendExt(parser.ExtSupportedVersions, []byte{0x04, 0x03, 0x04, 0x03, 0x03})

	// signature_algorithms: list_len(2) + algorithms
	appendExt(parser.ExtSignatureAlgorithms, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04})

	var body []byte
	body = append(body, 0x03, 0x03)          // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len
	cipherLen := len(cipherSuites) * 2
	body = append(body, byte(cipherLen>>8), byte(cipherLen))
	for _, cs := range cipherSuites {
		body = append(body, byte(cs>>8), byte(cs))
	}
	body = append(body, 0x01, 0x00) // compression_methods: len(1) + null
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	handshakeLen := len(body)
	recordLen := handshakeLen + 4

	payload := []byte{0x16, 0x03, 0x01, byte(recordLen >> 8), byte(recordLen)}
	payload = append(payload, 0x01, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	payload = append(payload, body...)
	return payload
}
