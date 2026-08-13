package ja4plus

import (
	"fmt"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// DHCP message type to JA4D abbreviation mapping (DHCPv4).
var dhcpMessageMap = map[byte]string{
	1:  "disco", // DHCPDISCOVER
	2:  "offer", // DHCPOFFER
	3:  "reqst", // DHCPREQUEST
	4:  "decln", // DHCPDECLINE
	5:  "dpack", // DHCPACK
	6:  "dpnak", // DHCPNAK
	7:  "relse", // DHCPRELEASE
	8:  "infor", // DHCPINFORM
	9:  "frenw", // DHCPFORCERENEW
	10: "lqery", // DHCPLEASEQUERY
	11: "lunas", // DHCPLEASEUNASSIGNED
	12: "lunkn", // DHCPLEASEUNKNOWN
	13: "lactv", // DHCPLEASEACTIVE
	14: "blklq", // DHCPBULKLEASEQUERY
	15: "lqdon", // DHCPLEASEQUERYDONE
	16: "actlq", // DHCPACTIVELEASEQUERY
	17: "lqsta", // DHCPLEASEQUERYSTATUS
	18: "dhtls", // DHCPTLS
}

// dhcpExcludedOptions are the option codes excluded from the option list section
// (FoxIO PR #267/#270): Pad (0), MessageType (53), Requested IP (50), FQDN (81).
var dhcpExcludedOptions = map[byte]bool{
	0:  true,
	53: true,
	50: true,
	81: true,
}

// JA4DFingerprinter generates JA4D DHCP fingerprints (FoxIO PR #267/#270).
//
// Format: {type:5}{size:4}{ip:1}{fqdn:1}_{options}_{request_list}
//
//   - type: 5-char DHCP message type abbreviation (from option 53)
//   - size: 4-digit Maximum DHCP Message Size (option 57), capped 9999, default "0000"
//   - ip:   'i' if Requested IP Address (option 50) is present, else 'n'
//   - fqdn: 'd' if Client FQDN (option 81) is present, else 'n'
//   - options: dash-joined option type codes in PRESENCE ORDER, excluding
//     Pad (0), MessageType (53), Requested IP (50), FQDN (81). Default "00".
//   - request_list: dash-joined items of the Parameter Request List (option 55)
//     in original order. Default "00".
//
// One JA4DFingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4DFingerprinter struct {
}

// NewJA4D creates a new JA4D fingerprinter.
func NewJA4D() *JA4DFingerprinter {
	return &JA4DFingerprinter{}
}

// ProcessPacket processes a packet and returns JA4D fingerprint results for DHCP messages.
func (f *JA4DFingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	// DHCP runs over UDP ports 67 (server) and 68 (client)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, nil
	}
	// A caller that supplies a custom decoder can register another concrete type under
	// the UDP layer type. A fingerprinter returns a non-fatal error for it.
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("the UDP layer carries the type %T", udpLayer)
	}

	if udp.SrcPort != 67 && udp.SrcPort != 68 && udp.DstPort != 67 && udp.DstPort != 68 {
		return nil, nil
	}

	// Try to parse as DHCPv4
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return nil, nil
	}
	// The DHCPv4 layer type carries the same risk as the UDP layer type above.
	dhcp, ok := dhcpLayer.(*layers.DHCPv4)
	if !ok {
		return nil, fmt.Errorf("the DHCPv4 layer carries the type %T", dhcpLayer)
	}

	var msgType byte
	var msgTypeSet bool
	var maxMsgSize uint16
	var maxMsgSizeSet bool
	var hasRequestIP bool
	var hasFQDN bool
	var optionsInOrder []byte
	var paramList []byte

	for _, opt := range dhcp.Options {
		code := byte(opt.Type)
		// Track presence-order options (excluding 0/53/50/81 per spec).
		if !dhcpExcludedOptions[code] {
			optionsInOrder = append(optionsInOrder, code)
		}

		switch opt.Type {
		case layers.DHCPOptMessageType: // 53
			if len(opt.Data) > 0 {
				msgType = opt.Data[0]
				msgTypeSet = true
			}
		case layers.DHCPOptMaxMessageSize: // 57
			// R2 of `docs/specs/foxio/JA4D.md` gives subfield 2 four characters, so one
			// occurrence decides it. `wireshark/source/packet-ja4.c:1508-1512` appends
			// every occurrence and reaches a part a of fifteen characters, and this
			// project declines that defect. FR-parity-51 states the rule, and the port's
			// register row `Subfield 2 of JA4D when a message repeats option 57` holds the
			// reading. The port decided it as D4 of its issue #231 on 2026-08-08.
			if len(opt.Data) >= 2 && !maxMsgSizeSet {
				maxMsgSize = uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
				maxMsgSizeSet = true
			}
		case layers.DHCPOptRequestIP: // 50
			hasRequestIP = true
		case 81: // Client FQDN
			hasFQDN = true
		case layers.DHCPOptParamsRequest: // 55
			paramList = opt.Data
		}
	}

	if !msgTypeSet {
		return nil, nil
	}

	// type: 5-char abbreviation, or "%05u" for unknown codes.
	msgTypeStr, ok := dhcpMessageMap[msgType]
	if !ok {
		msgTypeStr = fmt.Sprintf("%05d", msgType)
	}

	// size: 4-digit max msg size, capped at 9999, default "0000".
	sizeStr := "0000"
	if maxMsgSizeSet {
		sz := maxMsgSize
		if sz > 9999 {
			sz = 9999
		}
		sizeStr = fmt.Sprintf("%04d", sz)
	}

	ipFlag := "n"
	if hasRequestIP {
		ipFlag = "i"
	}

	fqdnFlag := "n"
	if hasFQDN {
		fqdnFlag = "d"
	}

	sectionA := fmt.Sprintf("%s%s%s%s", msgTypeStr, sizeStr, ipFlag, fqdnFlag)
	sectionB := ja4dFormatList(optionsInOrder)
	sectionC := ja4dFormatList(paramList)

	fingerprint := fmt.Sprintf("%s_%s_%s", sectionA, sectionB, sectionC)

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4d",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     uint16(udp.SrcPort),
		DstPort:     uint16(udp.DstPort),
		Timestamp:   parser.GetPacketTimestamp(packet),
	}

	return []FingerprintResult{result}, nil
}

// Reset clears the state of the fingerprinter.
// JA4D holds no state, so this method changes nothing. It keeps the Fingerprinter
// interface whole. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4DFingerprinter) Reset() {
}

// CleanupConnection is a no-op for JA4D (stateless per-packet fingerprinter).
func (f *JA4DFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
}

// ja4dFormatList formats a slice of byte values as dash-joined decimals.
// Returns "00" for an empty slice.
func ja4dFormatList(values []byte) string {
	if len(values) == 0 {
		return "00"
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// ComputeJA4D is a one-shot function that computes the JA4D fingerprint for a single packet.
func ComputeJA4D(packet gopacket.Packet) string {
	fp := NewJA4D()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
