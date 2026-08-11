package ja4plus

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildShardKeyUDPPacket builds one IPv4 UDP packet that carries the given payload.
// GetShardKey reads the transport layer, so a shard key test needs a real UDP header.
func buildShardKeyUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

// quicInitialDatagramBytes is the smallest datagram that carries a client Initial
// packet. RFC 9000 section 14.1 states this minimum.
const quicInitialDatagramBytes = 1200

// buildQUICInitialPayload builds one QUIC version 1 Initial packet.
// RFC 9000 section 17.2.2 states the field order that this function writes.
// The packet payload is a filler of zero bytes, because GetShardKey reads no
// byte of the UDP payload.
func buildQUICInitialPayload(dcid, scid []byte) []byte {
	// The two low bits of the first byte hold the packet number length less one.
	out := []byte{0xC3}
	const packetNumberBytes = 4

	out = binary.BigEndian.AppendUint32(out, 0x00000001)
	out = append(out, byte(len(dcid)))
	out = append(out, dcid...)
	out = append(out, byte(len(scid)))
	out = append(out, scid...)
	out = append(out, 0x00) // Token Length, a variable-length integer of value 0.

	// The Length field counts the Packet Number and the Packet Payload.
	// A two-byte variable-length integer carries the 0b01 prefix in its top bits.
	const lengthFieldBytes = 2
	remainder := quicInitialDatagramBytes - len(out) - lengthFieldBytes
	out = binary.BigEndian.AppendUint16(out, uint16(remainder)|0x4000)

	out = binary.BigEndian.AppendUint32(out, 0x00000001) // Packet Number.
	out = append(out, make([]byte, remainder-packetNumberBytes)...)
	return out
}

// buildShardKeyICMPPacket builds one IPv4 packet that carries neither TCP nor UDP.
func buildShardKeyICMPPacket() gopacket.Packet {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP("192.0.2.1"),
		DstIP:    net.ParseIP("198.51.100.1"),
		Protocol: layers.IPProtocolICMPv4,
		Version:  4,
		TTL:      64,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, icmp)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

// FR-concurrency-18. A connection that lands on two shards splits its state.
// A split connection produces a wrong fingerprint, and no check reports the fault.
func TestGetShardKey_ReturnsOneKeyForBothDirectionsOfOneConnection(t *testing.T) {
	proc := NewProcessor()

	cases := []struct {
		name          string
		clientIP      string
		serverIP      string
		clientPort    uint16
		serverPort    uint16
		buildForward  func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet
		buildResponse func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet
	}{
		{
			name:       "TCP over IPv4",
			clientIP:   "192.168.1.1",
			serverIP:   "10.0.0.1",
			clientPort: 54321,
			serverPort: 443,
			buildForward: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildSYNPacket(sIP, dIP, sPort, dPort)
			},
			buildResponse: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildSYNPacket(sIP, dIP, sPort, dPort)
			},
		},
		{
			// The client address sorts after the server address, so this case drives
			// the other branch of the sort.
			name:       "TCP with the client address above the server address",
			clientIP:   "203.0.113.9",
			serverIP:   "198.51.100.4",
			clientPort: 40000,
			serverPort: 80,
			buildForward: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildSYNPacket(sIP, dIP, sPort, dPort)
			},
			buildResponse: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildSYNPacket(sIP, dIP, sPort, dPort)
			},
		},
		{
			// One host talks to itself, so only the port separates the two directions.
			name:       "TCP on one address with two ports",
			clientIP:   "127.0.0.1",
			serverIP:   "127.0.0.1",
			clientPort: 51000,
			serverPort: 8443,
			buildForward: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildSYNPacket(sIP, dIP, sPort, dPort)
			},
			buildResponse: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildSYNPacket(sIP, dIP, sPort, dPort)
			},
		},
		{
			name:       "UDP over IPv4",
			clientIP:   "192.168.1.1",
			serverIP:   "10.0.0.1",
			clientPort: 55000,
			serverPort: 443,
			buildForward: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildShardKeyUDPPacket(sIP, dIP, sPort, dPort, []byte{0x01, 0x02})
			},
			buildResponse: func(sIP, dIP string, sPort, dPort uint16) gopacket.Packet {
				return buildShardKeyUDPPacket(sIP, dIP, sPort, dPort, []byte{0x03, 0x04})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forward := tc.buildForward(tc.clientIP, tc.serverIP, tc.clientPort, tc.serverPort)
			reply := tc.buildResponse(tc.serverIP, tc.clientIP, tc.serverPort, tc.clientPort)

			forwardKey := proc.GetShardKey(forward)
			replyKey := proc.GetShardKey(reply)

			if forwardKey == "" {
				t.Fatal("GetShardKey returned an empty key for the packet")
			}
			if forwardKey != replyKey {
				t.Errorf("GetShardKey returned %q for the packet and %q for the reply", forwardKey, replyKey)
			}
		})
	}
}

// FR-concurrency-19. A QUIC endpoint changes the connection identifier during a
// connection, so a key that reads the identifier moves the connection to a second shard.
func TestGetShardKey_ReturnsOneKeyWhenTheQUICConnectionIdentifierChanges(t *testing.T) {
	proc := NewProcessor()

	const (
		clientIP   = "192.168.1.1"
		serverIP   = "10.0.0.1"
		clientPort = uint16(55001)
		serverPort = uint16(443)
	)

	firstDCID := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	secondDCID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa}
	serverDCID := []byte{0xde, 0xad, 0xbe, 0xef}
	scid := []byte{0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5}

	initial := buildShardKeyUDPPacket(clientIP, serverIP, clientPort, serverPort,
		buildQUICInitialPayload(firstDCID, scid))
	changed := buildShardKeyUDPPacket(clientIP, serverIP, clientPort, serverPort,
		buildQUICInitialPayload(secondDCID, scid))
	reply := buildShardKeyUDPPacket(serverIP, clientIP, serverPort, clientPort,
		buildQUICInitialPayload(serverDCID, scid))

	want := proc.GetShardKey(initial)
	if want == "" {
		t.Fatal("GetShardKey returned an empty key for the QUIC Initial packet")
	}

	if got := proc.GetShardKey(changed); got != want {
		t.Errorf("GetShardKey returned %q after the connection identifier changed, want %q", got, want)
	}
	if got := proc.GetShardKey(reply); got != want {
		t.Errorf("GetShardKey returned %q for the server reply, want %q", got, want)
	}
}

// The feature file states that a packet with no transport layer produces an empty key.
func TestGetShardKey_ReturnsAnEmptyKeyForAPacketWithNoTransportLayer(t *testing.T) {
	proc := NewProcessor()

	if got := proc.GetShardKey(buildShardKeyICMPPacket()); got != "" {
		t.Errorf("GetShardKey returned %q for an ICMP packet, want an empty key", got)
	}

	empty := gopacket.NewPacket(nil, layers.LayerTypeIPv4, gopacket.Default)
	if got := proc.GetShardKey(empty); got != "" {
		t.Errorf("GetShardKey returned %q for a packet with no IP layer, want an empty key", got)
	}
}

// FR-concurrency-16 and FR-concurrency-17. The core stays lock-free, so a shard keeps
// its throughput. A lock on a fingerprinter also gives false safety, because the
// Processor calls nine other fingerprinters that hold none.
func TestFingerprinters_HoldNoLockOnThePerPacketPath(t *testing.T) {
	proc := NewProcessor()

	fingerprinters := map[string]any{
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

	if len(fingerprinters) != 10 {
		t.Fatalf("the test names %d fingerprinters, want 10", len(fingerprinters))
	}

	for name, fp := range fingerprinters {
		for _, path := range findSyncFields(reflect.TypeOf(fp), name, make(map[reflect.Type]bool)) {
			t.Errorf("%s reaches a lock at %s; a fingerprinter holds no lock", name, path)
		}
	}

	for _, path := range findSyncFields(reflect.TypeOf(&Processor{}), "Processor", make(map[reflect.Type]bool)) {
		t.Errorf("Processor reaches a lock at %s; the per-packet path acquires no lock", path)
	}
}

// findSyncFields returns the path of every field that the type reaches whose own
// type comes from the sync package.
// It follows a pointer, a slice, a map and an array, so a lock behind one of them
// does not escape the search.
// The seen map stops the search on a type that holds itself.
func findSyncFields(typ reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if typ == nil || seen[typ] {
		return nil
	}
	seen[typ] = true

	if typ.PkgPath() == "sync" {
		return []string{path}
	}

	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return findSyncFields(typ.Elem(), path+".*", seen)
	case reflect.Struct:
		var found []string
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			found = append(found, findSyncFields(field.Type, path+"."+field.Name, seen)...)
		}
		return found
	default:
		return nil
	}
}
