package ja4plus

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DHCPv6 message type to JA4D6 abbreviation mapping (RFC 8415 + extensions).
var dhcpv6MessageMap = map[byte]string{
	1:  "solct", // SOLICIT
	2:  "advrt", // ADVERTISE
	3:  "reqst", // REQUEST
	4:  "confm", // CONFIRM
	5:  "renew", // RENEW
	6:  "rebnd", // REBIND
	7:  "reply", // REPLY
	8:  "relse", // RELEASE
	9:  "decln", // DECLINE
	10: "recon", // RECONFIGURE
	11: "inreq", // INFORMATION-REQUEST
	12: "rlayf", // RELAY-FORW
	13: "rlayr", // RELAY-REPL
	14: "query", // LEASEQUERY
	15: "qrply", // LEASEQUERY-REPLY
	16: "qdone", // LEASEQUERY-DONE
	17: "qdata", // LEASEQUERY-DATA
	18: "rereq", // RECONFIGURE-REQUEST
	19: "rrply", // RECONFIGURE-REPLY
	20: "v4qry", // DHCPV4-QUERY
	21: "v4res", // DHCPV4-RESPONSE
	22: "acqry", // ACTIVELEASEQUERY
	23: "sttls", // STARTTLS
	24: "bdudp", // BNDUPD
	25: "brply", // BNDREPLY
	26: "poreq", // POOLREQ
	27: "pores", // POOLRESP
	28: "urqst", // UPDREQ
	29: "ureqa", // UPDREQALL
	30: "udone", // UPDDONE
	31: "conne", // CONNECT
	32: "connr", // CONNECTREPLY
	33: "dconn", // DISCONNECT
	34: "state", // STATE
	35: "conta", // CONTACT
	36: "arinf", // ARINFO
	37: "arrep", // ARREPLY
}

// JA4D6Fingerprinter generates JA4D6 DHCPv6 fingerprints.
//
// Format: {type:5}{size:4}{ip:1}{fqdn:1}_{options}_{request_list}
//
//   - type: 5-char DHCPv6 message type abbreviation
//   - size: 4-digit length of the DUID inside option 1 (Client Identifier),
//     capped 9999, default "0000" if no option 1.
//   - ip:   'i' if IATA option (option 4) present, else 'n'
//   - fqdn: 'd' if Client FQDN (option 39) present, else 'n'
//   - options: dash-joined option type codes in PRESENCE ORDER (no exclusions),
//     including nested sub-options. Default "00".
//   - request_list: dash-joined items of the Option Request option (option 6, ORO).
//     Default "00".
//
// One JA4D6Fingerprinter serves one goroutine. It holds state that no lock guards.
// Give each goroutine its own instance, or share one SyncProcessor.
type JA4D6Fingerprinter struct {
	results []FingerprintResult
}

// NewJA4D6 creates a new JA4D6 DHCPv6 fingerprinter.
func NewJA4D6() *JA4D6Fingerprinter {
	return &JA4D6Fingerprinter{}
}

// ProcessPacket processes a packet and returns JA4D6 fingerprint results for DHCPv6 messages.
func (f *JA4D6Fingerprinter) ProcessPacket(packet gopacket.Packet) ([]FingerprintResult, error) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, nil
	}
	udp := udpLayer.(*layers.UDP)

	// DHCPv6 ports: 546 (client) and 547 (server)
	if udp.SrcPort != 546 && udp.SrcPort != 547 && udp.DstPort != 546 && udp.DstPort != 547 {
		return nil, nil
	}

	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcpLayer == nil {
		return nil, nil
	}
	dhcp := dhcpLayer.(*layers.DHCPv6)

	// Walk options recursively to collect type codes in presence order.
	optionsInOrder := walkDHCPv6Options(dhcp.Options)

	// Find option 1 (Client Identifier) for size, option 4 (IATA) for ip,
	// option 39 (Client FQDN) for fqdn, option 6 (ORO) for request list.
	var sizeStr = "0000"
	var hasIATA, hasFQDN bool
	var paramList []uint16

	for _, opt := range dhcp.Options {
		switch opt.Code {
		case layers.DHCPv6OptClientID: // 1
			if sizeStr == "0000" { // first occurrence
				duidLen := len(opt.Data)
				if duidLen > 9999 {
					duidLen = 9999
				}
				sizeStr = fmt.Sprintf("%04d", duidLen)
			}
		case layers.DHCPv6OptIATA: // 4
			hasIATA = true
		case layers.DHCPv6OptClientFQDN: // 39
			hasFQDN = true
		case layers.DHCPv6OptOro: // 6 — Option Request Option
			// Option data is a sequence of 2-byte option codes.
			d := opt.Data
			for i := 0; i+1 < len(d); i += 2 {
				paramList = append(paramList, binary.BigEndian.Uint16(d[i:i+2]))
			}
		}
	}

	msgTypeStr, ok := dhcpv6MessageMap[byte(dhcp.MsgType)]
	if !ok {
		msgTypeStr = fmt.Sprintf("%05d", dhcp.MsgType)
	}

	ipFlag := "n"
	if hasIATA {
		ipFlag = "i"
	}

	fqdnFlag := "n"
	if hasFQDN {
		fqdnFlag = "d"
	}

	sectionA := fmt.Sprintf("%s%s%s%s", msgTypeStr, sizeStr, ipFlag, fqdnFlag)
	sectionB := ja4d6FormatU16List(optionsInOrder)
	sectionC := ja4d6FormatU16List(paramList)

	fingerprint := fmt.Sprintf("%s_%s_%s", sectionA, sectionB, sectionC)

	srcIP, dstIP, _, _ := parser.GetIPInfo(packet)

	result := FingerprintResult{
		Fingerprint: fingerprint,
		Type:        "ja4d6",
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
func (f *JA4D6Fingerprinter) Reset() {
	f.results = nil
}

// CleanupConnection is a no-op for JA4D6 (stateless per-packet fingerprinter).
func (f *JA4D6Fingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
}

// walkDHCPv6Options walks DHCPv6 options recursively, returning the codes in
// presence order including nested sub-options inside container options like
// IA_NA, IA_TA, IA_PD, IAAddr, and IAPrefix.
func walkDHCPv6Options(opts []layers.DHCPv6Option) []uint16 {
	var out []uint16
	for _, o := range opts {
		out = append(out, uint16(o.Code))
		out = append(out, parseDHCPv6SubOpts(o.Code, o.Data)...)
	}
	return out
}

// parseDHCPv6SubOpts extracts nested option codes from container options that
// carry sub-options after a fixed-size header. Returns codes in wire order.
func parseDHCPv6SubOpts(parent layers.DHCPv6Opt, data []byte) []uint16 {
	// Per RFC 8415:
	//   IA_NA (3): IAID(4) + T1(4) + T2(4) + options
	//   IA_TA (4): IAID(4) + options
	//   IAAddr (5): address(16) + preferred(4) + valid(4) + options
	//   IA_PD (25): IAID(4) + T1(4) + T2(4) + options
	//   IAPrefix (26): preferred(4) + valid(4) + prefix-length(1) + prefix(16) + options
	var offset int
	switch parent {
	case layers.DHCPv6OptIANA: // 3
		offset = 12
	case layers.DHCPv6OptIATA: // 4
		offset = 4
	case layers.DHCPv6OptIAAddr: // 5
		offset = 24
	case layers.DHCPv6OptIAPD: // 25
		offset = 12
	case layers.DHCPv6OptIAPrefix: // 26
		offset = 25
	default:
		return nil
	}
	if offset > len(data) {
		return nil
	}
	rest := data[offset:]
	var out []uint16
	for len(rest) >= 4 {
		code := binary.BigEndian.Uint16(rest[0:2])
		l := int(binary.BigEndian.Uint16(rest[2:4]))
		if 4+l > len(rest) {
			break
		}
		out = append(out, code)
		out = append(out, parseDHCPv6SubOpts(layers.DHCPv6Opt(code), rest[4:4+l])...)
		rest = rest[4+l:]
	}
	return out
}

// ja4d6FormatU16List formats a slice of uint16 as dash-joined decimals.
// Returns "00" for an empty slice.
func ja4d6FormatU16List(values []uint16) string {
	if len(values) == 0 {
		return "00"
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// ComputeJA4D6 is a convenience function that computes the JA4D6 fingerprint for a single packet.
func ComputeJA4D6(packet gopacket.Packet) string {
	fp := NewJA4D6()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
