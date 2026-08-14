package ja4plus

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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

// maxDHCPv6NestingDepth bounds the walk of the DHCPv6 options.
//
// A crafted message nests one container inside another without a limit, so an unbounded
// descent exhausts the stack. The walk enters this many containers at most. The port
// states the same bound at `ja4plus/fingerprinters/ja4d6.py:115`, at tag `v1.1.0`.
const maxDHCPv6NestingDepth = 32

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
	// A caller that supplies a custom decoder can register another concrete type under
	// the UDP layer type. A fingerprinter returns a non-fatal error for it.
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("the UDP layer carries the type %T", udpLayer)
	}

	// DHCPv6 ports: 546 (client) and 547 (server)
	if udp.SrcPort != 546 && udp.SrcPort != 547 && udp.DstPort != 546 && udp.DstPort != 547 {
		return nil, nil
	}

	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcpLayer == nil {
		return nil, nil
	}
	// The DHCPv6 layer type carries the same risk as the UDP layer type above.
	dhcp, ok := dhcpLayer.(*layers.DHCPv6)
	if !ok {
		return nil, fmt.Errorf("the DHCPv6 layer carries the type %T", dhcpLayer)
	}

	// One walk collects every input, so each one reaches an option of an inner message.
	inputs := walkDHCPv6Options(dhcp.Options)
	optionsInOrder := inputs.optionsInOrder
	paramList := inputs.requestList

	duidLen := inputs.duidLen
	if duidLen > 9999 {
		duidLen = 9999
	}
	sizeStr := fmt.Sprintf("%04d", duidLen)
	hasIATA := inputs.hasIATA
	hasFQDN := inputs.hasFQDN

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

	return []FingerprintResult{result}, nil
}

// Reset clears the state of the fingerprinter.
// JA4D6 holds no state, so this method changes nothing. It keeps the Fingerprinter
// interface whole. Issue #25 removed the results slice, which grew without a bound.
func (f *JA4D6Fingerprinter) Reset() {
}

// CleanupConnection is a no-op for JA4D6 (stateless per-packet fingerprinter).
func (f *JA4D6Fingerprinter) CleanupConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) {
}

// ja4d6Inputs holds the six inputs that one walk of the DHCPv6 options collects.
type ja4d6Inputs struct {
	optionsInOrder []uint16
	requestList    []uint16
	duidLen        int
	hasDUID        bool
	hasIATA        bool
	hasFQDN        bool
}

// walkDHCPv6Options returns the six JA4D6 inputs that the DHCPv6 options carry.
//
// The walk reads a nested option of a container, and it reads an option of the inner
// message that option 9, Relay Message, carries. R19 and R20 of
// `docs/specs/foxio/JA4D6.md` record that the Wireshark dissector reads every
// `dhcpv6.option.type` field of the dissection tree, whatever nests it.
func walkDHCPv6Options(opts []layers.DHCPv6Option) *ja4d6Inputs {
	inputs := &ja4d6Inputs{}
	for _, o := range opts {
		inputs.optionsInOrder = append(inputs.optionsInOrder, uint16(o.Code))
		inputs.readDHCPv6Option(o.Code, o.Data)
		inputs.descendDHCPv6Option(o.Code, o.Data, 1)
	}
	return inputs
}

// readDHCPv6Option reads one DHCPv6 option into the four subfield inputs.
// An option code outside the four contributes no input.
func (in *ja4d6Inputs) readDHCPv6Option(code layers.DHCPv6Opt, data []byte) {
	switch code {
	case layers.DHCPv6OptClientID: // 1
		// R13 of `docs/specs/foxio/JA4D6.md`: the dissector reads the length while the
		// subfield is still empty, so the first client DUID of the walk decides it.
		if !in.hasDUID {
			in.duidLen = len(data)
			in.hasDUID = true
		}
	case layers.DHCPv6OptIATA: // 4
		in.hasIATA = true
	case layers.DHCPv6OptClientFQDN: // 39
		in.hasFQDN = true
	case layers.DHCPv6OptOro: // 6 — Option Request Option
		// The option data holds a sequence of two-byte option codes, big-endian.
		for i := 0; i+1 < len(data); i += 2 {
			in.requestList = append(in.requestList, binary.BigEndian.Uint16(data[i:i+2]))
		}
	}
}

// descendDHCPv6Option walks the options that one container option carries.
// An option that carries no nested option contributes no input.
func (in *ja4d6Inputs) descendDHCPv6Option(code layers.DHCPv6Opt, data []byte, depth int) {
	// Per RFC 8415:
	//   IA_NA (3): IAID(4) + T1(4) + T2(4) + options
	//   IA_TA (4): IAID(4) + options
	//   IAAddr (5): address(16) + preferred(4) + valid(4) + options
	//   IA_PD (25): IAID(4) + T1(4) + T2(4) + options
	//   IAPrefix (26): preferred(4) + valid(4) + prefix-length(1) + prefix(16) + options
	var offset int
	switch code {
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
	case layers.DHCPv6OptRelayMessage: // 9
		// Option 9 carries a whole DHCPv6 message rather than a fixed header and
		// sub-options, so the header of that message states the offset.
		offset = dhcpv6OptionsOffset(data)
	default:
		return
	}
	if offset > len(data) {
		return
	}
	in.walkDHCPv6RawOptions(data[offset:], depth)
}

// dhcpv6OptionsOffset returns the offset of the first option of one DHCPv6 message.
//
// RFC 8415 section 8 gives an ordinary message a four-byte header, and section 9 gives
// RELAY-FORW and RELAY-REPL a 34-byte header. A message shorter than the ordinary header
// reports that header, so the caller reads no option of it.
func dhcpv6OptionsOffset(message []byte) int {
	const relayHeaderLen = 34
	const messageHeaderLen = 4
	if len(message) == 0 {
		return messageHeaderLen
	}
	if message[0] == 12 || message[0] == 13 {
		return relayHeaderLen
	}
	return messageHeaderLen
}

// walkDHCPv6RawOptions reads every DHCPv6 option of the wire form into the inputs.
// A container below maxDHCPv6NestingDepth contributes no input.
func (in *ja4d6Inputs) walkDHCPv6RawOptions(rest []byte, depth int) {
	if depth > maxDHCPv6NestingDepth {
		return
	}
	for len(rest) >= 4 {
		code := binary.BigEndian.Uint16(rest[0:2])
		l := int(binary.BigEndian.Uint16(rest[2:4]))
		if 4+l > len(rest) {
			break
		}
		data := rest[4 : 4+l]
		in.optionsInOrder = append(in.optionsInOrder, code)
		in.readDHCPv6Option(layers.DHCPv6Opt(code), data)
		in.descendDHCPv6Option(layers.DHCPv6Opt(code), data, depth+1)
		rest = rest[4+l:]
	}
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

// ComputeJA4D6 is a one-shot function that computes the JA4D6 fingerprint for a single packet.
func ComputeJA4D6(packet gopacket.Packet) string {
	fp := NewJA4D6()
	results, _ := fp.ProcessPacket(packet)
	if len(results) > 0 {
		return results[0].Fingerprint
	}
	return ""
}
