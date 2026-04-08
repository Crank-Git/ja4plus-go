package ja4plus

import (
	"fmt"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DHCP message type to JA4D abbreviation mapping.
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

// DHCP options to skip in the option list section.
var dhcpSkipOptions = map[byte]bool{
	53:  true, // Message Type (already in section a)
	255: true, // End
	50:  true, // Requested IP Address (indicated by i/n flag)
	81:  true, // Client FQDN (indicated by d/n flag)
}

// JA4DFingerprinter generates JA4D DHCP fingerprints.
//
// Format: {msg_type}{max_msg_size}{request_ip}{fqdn}_{option_list}_{param_list}
//
// Section a: 5-char message type + 4-digit max message size + request IP flag + FQDN flag
// Section b: DHCP options present (hyphen-separated decimal, skipping 53/255/50/81)
// Section c: Parameter Request List contents (option 55, hyphen-separated decimal)
type JA4DFingerprinter struct {
	results []FingerprintResult
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
	udp := udpLayer.(*layers.UDP)

	if udp.SrcPort != 67 && udp.SrcPort != 68 && udp.DstPort != 67 && udp.DstPort != 68 {
		return nil, nil
	}

	// Try to parse as DHCPv4
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return nil, nil
	}
	dhcp := dhcpLayer.(*layers.DHCPv4)

	var msgType byte
	var maxMsgSize uint16
	var hasRequestIP bool
	var hasFQDN bool
	var optionCodes []byte
	var paramList []byte

	for _, opt := range dhcp.Options {
		optionCodes = append(optionCodes, byte(opt.Type))

		switch opt.Type {
		case layers.DHCPOptMessageType: // 53
			if len(opt.Data) > 0 {
				msgType = opt.Data[0]
			}
		case layers.DHCPOptMaxMessageSize: // 57
			if len(opt.Data) >= 2 {
				maxMsgSize = uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
			}
		case layers.DHCPOptRequestIP: // 50
			hasRequestIP = true
		case 81: // Client FQDN
			hasFQDN = true
		case layers.DHCPOptParamsRequest: // 55
			paramList = opt.Data
		}
	}

	if msgType == 0 {
		return nil, nil
	}

	// Section a: msg_type + max_msg_size + request_ip_flag + fqdn_flag
	msgTypeStr, ok := dhcpMessageMap[msgType]
	if !ok {
		msgTypeStr = fmt.Sprintf("%05d", msgType)
	}

	maxMsgSizeVal := maxMsgSize
	if maxMsgSizeVal > 9999 {
		maxMsgSizeVal = 9999
	}

	requestIPFlag := "n"
	if hasRequestIP {
		requestIPFlag = "i"
	}

	fqdnFlag := "n"
	if hasFQDN {
		fqdnFlag = "d"
	}

	sectionA := fmt.Sprintf("%s%04d%s%s", msgTypeStr, maxMsgSizeVal, requestIPFlag, fqdnFlag)

	// Section b: option list (hyphen-separated, skip 53/255/50/81)
	sectionB := ja4dBuildOptionList(optionCodes, dhcpSkipOptions)

	// Section c: parameter request list (hyphen-separated)
	sectionC := ja4dBuildParamList(paramList)

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

	f.results = append(f.results, result)
	return []FingerprintResult{result}, nil
}

// Reset clears accumulated results.
func (f *JA4DFingerprinter) Reset() {
	f.results = nil
}

// CleanupConnection is a no-op for JA4D (stateless per-packet fingerprinter).
func (f *JA4DFingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
}

// ja4dBuildOptionList formats DHCP option codes as hyphen-separated decimals,
// skipping options in the skip set.
func ja4dBuildOptionList(options []byte, skip map[byte]bool) string {
	if len(options) == 0 {
		return "00"
	}

	var parts []string
	for _, opt := range options {
		if skip[opt] {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d", opt))
	}

	if len(parts) == 0 {
		return "00"
	}
	return strings.Join(parts, "-")
}

// ja4dBuildParamList formats the Parameter Request List (option 55) as hyphen-separated decimals.
func ja4dBuildParamList(params []byte) string {
	if len(params) == 0 {
		return "00"
	}

	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, "-")
}

// ComputeJA4D is a convenience function that computes the JA4D fingerprint for a single packet.
func ComputeJA4D(packet gopacket.Packet) string {
	fp := NewJA4D()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
