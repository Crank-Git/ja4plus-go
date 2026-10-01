package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/scan"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The cases below port `tests/test_ja4tscan_command.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. No case sends a packet or opens a socket. Each case either stops before the
// network opens, or it passes the fake network below in place of the link.

var (
	scanTestTarget  = netip.MustParseAddr("192.0.2.10")
	scanTestSecond  = netip.MustParseAddr("192.0.2.11")
	scanTestScanner = netip.MustParseAddr("198.51.100.1")
)

var (
	wantIptablesRules = []string{
		"iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
		"iptables -t filter -A INPUT -p icmp -j ACCEPT",
		"iptables -t filter -A INPUT -i lo -j ACCEPT",
		"iptables -t filter -A INPUT -j DROP",
	}
	wantIptablesRemovals = []string{
		"iptables -t filter -D INPUT -j DROP",
		"iptables -t filter -D INPUT -i lo -j ACCEPT",
		"iptables -t filter -D INPUT -p icmp -j ACCEPT",
		"iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
	}
	wantPFRules = []string{
		"pass out all",
		"pass in quick inet proto icmp all",
		"pass in quick on lo0 all",
		"block drop in all",
	}
)

type scanFrame struct {
	at    time.Time
	frame []byte
}

// scanFakeNetwork answers each SYN with SYN-ACK frames at the offsets of its target. Its
// clock moves only when the scanner waits.
type scanFakeNetwork struct {
	t          *testing.T
	now        time.Time
	offsets    map[netip.Addr][]time.Duration
	port       uint16
	sent       []netip.Addr
	queue      []scanFrame
	closed     bool
	onSend     func()
	sendErr    func(netip.Addr) error
	receiveErr func() error
}

func newScanFakeNetwork(t *testing.T, offsets map[netip.Addr][]time.Duration) *scanFakeNetwork {
	return &scanFakeNetwork{t: t, now: time.Unix(1_000_000, 0), offsets: offsets, port: 80}
}

func (n *scanFakeNetwork) clock() time.Time { return n.now }

func (n *scanFakeNetwork) Send(target netip.Addr, srcPort uint16, sequence uint32) (netip.Addr, bool, error) {
	if n.sendErr != nil {
		if err := n.sendErr(target); err != nil {
			return netip.Addr{}, false, err
		}
	}

	if n.onSend != nil {
		n.onSend()
	}

	n.sent = append(n.sent, target)

	for _, offset := range n.offsets[target] {
		n.queue = append(n.queue, scanFrame{at: n.now.Add(offset), frame: n.synAck(target, srcPort, sequence)})
	}

	return scanTestScanner, true, nil
}

func (n *scanFakeNetwork) synAck(target netip.Addr, srcPort uint16, sequence uint32) []byte {
	n.t.Helper()

	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: target.AsSlice(), DstIP: scanTestScanner.AsSlice()}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(n.port), DstPort: layers.TCPPort(srcPort), Seq: 5000, Ack: sequence + 1,
		SYN: true, ACK: true, Window: 64240,
		Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}},
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		n.t.Fatalf("set the checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	ethernet := &layers.Ethernet{SrcMAC: make([]byte, 6), DstMAC: make([]byte, 6), EthernetType: layers.EthernetTypeIPv4}

	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp); err != nil {
		n.t.Fatalf("serialize the SYN-ACK: %v", err)
	}

	return buffer.Bytes()
}

func (n *scanFakeNetwork) Receive(timeout time.Duration) ([]byte, time.Time, bool, error) {
	if n.receiveErr != nil {
		if err := n.receiveErr(); err != nil {
			return nil, time.Time{}, false, err
		}
	}

	earliest := -1
	for index, frame := range n.queue {
		if earliest < 0 || frame.at.Before(n.queue[earliest].at) {
			earliest = index
		}
	}

	if earliest >= 0 && !n.queue[earliest].at.After(n.now.Add(timeout)) {
		next := n.queue[earliest]
		n.queue = append(n.queue[:earliest], n.queue[earliest+1:]...)

		if next.at.After(n.now) {
			n.now = next.at
		}

		return next.frame, next.at, true, nil
	}

	n.now = n.now.Add(timeout)

	return nil, time.Time{}, false, nil
}

func (n *scanFakeNetwork) Close() error {
	n.closed = true
	return nil
}

type scanRunResult struct {
	code   int
	stdout string
	stderr string
	// stderrAtFirstSend holds standard error when the first SYN leaves.
	stderrAtFirstSend string
	opened            bool
}

// runFakeScan runs the scan command over the network, on the platform that goos names.
func runFakeScan(t *testing.T, network *scanFakeNetwork, goos string, args ...string) scanRunResult {
	t.Helper()

	var stdout, stderr bytes.Buffer

	result := scanRunResult{}
	first := true

	if network != nil {
		network.onSend = func() {
			if first {
				result.stderrAtFirstSend = stderr.String()
				first = false
			}
		}
	}

	env := scanEnvironment{
		stdout: &stdout,
		stderr: &stderr,
		goos:   goos,
		openNetwork: func(port uint16, _ netip.Addr, _ func(string)) (scan.Network, error) {
			result.opened = true
			if network == nil {
				t.Error("the case opened the network")
				return nil, errors.New("the case opens no network")
			}
			network.port = port
			return network, nil
		},
		clock: time.Now,
		rand:  rand.New(rand.NewPCG(3, 3)),
	}

	if network != nil {
		env.clock = network.clock
	}

	result.code = runScanCommand(args, env)
	result.stdout = stdout.String()
	result.stderr = stderr.String()

	return result
}

func TestTheUsageNamesEveryOptionOfTheInterface(t *testing.T) {
	for _, option := range []string{"--port", "--rate", "--retransmit", "--format", "--output", "--force"} {
		if !strings.Contains(scanUsage, option) {
			t.Errorf("the usage names no option %s", option)
		}
	}
}

func TestTheDefaultsAreTheFoxIODefaults(t *testing.T) {
	options, err := parseScanArgs([]string{"192.0.2.10"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}

	if options.port != 80 || options.rate != 10 || !options.retransmit || options.format != "table" {
		t.Errorf("the defaults are %+v", options)
	}
}

func TestAnOptionValueOutsideItsRangeIsRefusedBeforeTheNetworkOpens(t *testing.T) {
	cases := [][]string{
		{"--port", "0"}, {"--port", "65536"}, {"--port", "http"},
		{"--rate", "0"}, {"--rate", "-1"}, {"--rate", "nan"}, {"--rate", "fast"}, {"--rate", "inf"},
		{"--retransmit", "maybe"}, {"--format", "xml"}, {"--port"}, {"--unknown"},
	}

	for _, option := range cases {
		run := runFakeScan(t, nil, "linux", append([]string{scanTestTarget.String()}, option...)...)
		if run.code != 1 || run.opened || !strings.Contains(run.stderr, option[0]) {
			t.Errorf("%v: exit %d, opened %v, stderr %q", option, run.code, run.opened, run.stderr)
		}
	}
}

func TestAnIPv6TargetExitsWithStatus1AndSendsNothing(t *testing.T) {
	run := runFakeScan(t, nil, "linux", "2001:db8::1")

	if run.code != 1 || run.opened || run.stdout != "" || !strings.Contains(run.stderr, "IPv4 alone") {
		t.Errorf("exit %d, opened %v, stdout %q, stderr %q", run.code, run.opened, run.stdout, run.stderr)
	}
}

func TestAFileLineThatIsNoIPv4AddressExitsWithStatus1AndSendsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1\n192.0.2.300\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := runFakeScan(t, nil, "linux", path)
	if run.code != 1 || run.opened || !strings.Contains(run.stderr, "line 2") || !strings.Contains(run.stderr, "192.0.2.300") {
		t.Errorf("exit %d, opened %v, stderr %q", run.code, run.opened, run.stderr)
	}
}

func TestAnEmptyTargetFileExitsWithStatus1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := runFakeScan(t, nil, "linux", path)
	if run.code != 1 || run.opened || !strings.Contains(run.stderr, "names no address") {
		t.Errorf("exit %d, opened %v, stderr %q", run.code, run.opened, run.stderr)
	}
}

func TestNoRawSocketPrivilegeExitsWithStatus1AndSendsNothing(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES} {
		var stdout, stderr bytes.Buffer

		code := runScanCommand([]string{scanTestTarget.String()}, scanEnvironment{
			stdout: &stdout, stderr: &stderr, goos: "linux", clock: time.Now,
			openNetwork: func(uint16, netip.Addr, func(string)) (scan.Network, error) {
				return nil, &os.SyscallError{Syscall: "socket", Err: errno}
			},
		})

		if code != 1 || !strings.Contains(stderr.String(), "privilege to open a raw socket") ||
			!strings.Contains(stderr.String(), "CAP_NET_RAW") || strings.Contains(stderr.String(), "iptables") {
			t.Errorf("%v: exit %d, stderr %q", errno, code, stderr.String())
		}
	}
}

func TestAnotherSocketFailureExitsWithStatus1(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runScanCommand([]string{scanTestTarget.String()}, scanEnvironment{
		stdout: &stdout, stderr: &stderr, goos: "linux", clock: time.Now,
		openNetwork: func(uint16, netip.Addr, func(string)) (scan.Network, error) {
			return nil, &os.SyscallError{Syscall: "socket", Err: syscall.ENODEV}
		},
	})

	if code != 1 || !strings.Contains(stderr.String(), "could not open a raw socket") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

// The maintainer ruled on 2026-10-01 in #796 that a macOS build without the `libpcap` build
// tag stops with one line on standard error that names the tag. The link returns that line.
func TestABuildWithNoLinkBackendStopsWithOneLine(t *testing.T) {
	var stdout, stderr bytes.Buffer

	line := "capture: the scan needs the libpcap build tag on darwin. Build the program with the command go build -tags libpcap ./cmd/ja4plus."
	code := runScanCommand([]string{scanTestTarget.String()}, scanEnvironment{
		stdout: &stdout, stderr: &stderr, goos: "darwin", clock: time.Now,
		openNetwork: func(uint16, netip.Addr, func(string)) (scan.Network, error) {
			return nil, errors.New(line)
		},
	})

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if code != 1 || len(lines) != 1 || !strings.Contains(lines[0], "libpcap build tag") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestLinuxWritesTheFourIptablesRulesBeforeTheFirstSYN(t *testing.T) {
	run := runFakeScan(t, newScanFakeNetwork(t, nil), "linux", scanTestTarget.String())

	before := strings.Split(run.stderrAtFirstSend, "\n")
	for _, rule := range wantIptablesRules {
		if !containsLine(before, rule) {
			t.Errorf("standard error holds no line %q before the first SYN", rule)
		}
	}
}

func TestLinuxWritesTheFourRemovalCommands(t *testing.T) {
	run := runFakeScan(t, newScanFakeNetwork(t, nil), "linux", scanTestTarget.String())

	for _, rule := range wantIptablesRemovals {
		if !containsLine(strings.Split(run.stderr, "\n"), rule) {
			t.Errorf("standard error holds no line %q", rule)
		}
	}
}

func TestMacOSWritesTheFourPFRulesBeforeTheFirstSYN(t *testing.T) {
	run := runFakeScan(t, newScanFakeNetwork(t, nil), "darwin", scanTestTarget.String())

	before := strings.Split(run.stderrAtFirstSend, "\n")
	for _, rule := range wantPFRules {
		if !containsLine(before, rule) {
			t.Errorf("standard error holds no line %q before the first SYN", rule)
		}
	}

	if strings.Contains(run.stderr, "iptables") {
		t.Error("the macOS run names iptables")
	}
}

func TestTheModeWithoutRetransmissionsWritesNoFirewallRule(t *testing.T) {
	run := runFakeScan(t, newScanFakeNetwork(t, nil), "linux", scanTestTarget.String(), "--retransmit", "no")

	if strings.Contains(run.stderr, "iptables") || strings.Contains(run.stderr, "pass out all") {
		t.Errorf("standard error holds a rule: %q", run.stderr)
	}
}

func TestTheRulesReachStandardErrorAndNeverStandardOutput(t *testing.T) {
	run := runFakeScan(t, newScanFakeNetwork(t, nil), "linux", scanTestTarget.String(), "--format", "table")

	if strings.Contains(run.stdout, "iptables") {
		t.Errorf("standard output holds a rule: %q", run.stdout)
	}
}

func TestTheJSONObjectHoldsTheTypeJA4TScan(t *testing.T) {
	network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond, 1100 * time.Millisecond}})
	run := runFakeScan(t, network, "linux", scanTestTarget.String(), "--format", "json")

	lines := strings.Split(strings.TrimSpace(run.stdout), "\n")
	if run.code != 0 || len(lines) != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q", run.code, run.stdout, run.stderr)
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("the line %q is no JSON object: %v", lines[0], err)
	}

	want := map[string]any{
		"type": "ja4tscan", "fingerprint": "64240_2_1460_00_1",
		"src_ip": scanTestTarget.String(), "src_port": float64(80), "dst_ip": scanTestScanner.String(),
	}
	for key, value := range want {
		if record[key] != value {
			t.Errorf("the field %s holds %v, want %v", key, record[key], value)
		}
	}

	for _, key := range []string{"dst_port", "timestamp"} {
		if _, held := record[key]; !held {
			t.Errorf("the object holds no field %s", key)
		}
	}
}

func TestATargetThatSendsOneSynAckWritesOneWarningLine(t *testing.T) {
	network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond}})
	run := runFakeScan(t, network, "linux", scanTestTarget.String())

	var warnings []string
	for _, line := range strings.Split(run.stderr, "\n") {
		if strings.HasPrefix(line, "Warning:") {
			warnings = append(warnings, line)
		}
	}

	if len(warnings) != 1 || !strings.Contains(warnings[0], scanTestTarget.String()) {
		t.Errorf("the warnings are %q", warnings)
	}
}

func TestTheModeWithoutRetransmissionsWritesNoWarningLine(t *testing.T) {
	network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond}})
	run := runFakeScan(t, network, "linux", scanTestTarget.String(), "--retransmit", "no", "--format", "json")

	if strings.Contains(run.stderr, "Warning:") || len(strings.Split(strings.TrimSpace(run.stdout), "\n")) != 1 {
		t.Errorf("stdout %q, stderr %q", run.stdout, run.stderr)
	}
}

func TestTheCSVFormatWritesAHeaderAndOneRow(t *testing.T) {
	network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond, 1100 * time.Millisecond}})
	run := runFakeScan(t, network, "linux", scanTestTarget.String(), "--format", "csv")

	lines := strings.Split(strings.TrimSpace(run.stdout), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "ja4tscan") {
		t.Errorf("the CSV output is %q", run.stdout)
	}
}

func TestAnOutputFileThatExistsIsRefusedBeforeTheNetworkOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := runFakeScan(t, nil, "linux", scanTestTarget.String(), "--output", path)

	content, _ := os.ReadFile(path)
	if run.code != 1 || run.opened || string(content) != "keep" || !strings.Contains(run.stderr, "--force") {
		t.Errorf("exit %d, opened %v, file %q, stderr %q", run.code, run.opened, content, run.stderr)
	}
}

func TestForceReplacesAnOutputFileThatExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond}})
	run := runFakeScan(t, network, "linux", scanTestTarget.String(), "--output", path, "--force", "--format", "json", "--retransmit", "no")

	content, _ := os.ReadFile(path)
	if run.code != 0 || !strings.Contains(string(content), "ja4tscan") || run.stdout != "" {
		t.Errorf("exit %d, file %q, stdout %q, stderr %q", run.code, content, run.stdout, run.stderr)
	}
}

func TestASocketFailureDuringTheScanExitsWithStatus1AndKeepsTheResults(t *testing.T) {
	for _, on := range []string{"send", "receive"} {
		network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond}})
		start := network.now
		failure := errors.New("network is down")

		switch on {
		case "send":
			network.sendErr = func(target netip.Addr) error {
				if target == scanTestSecond {
					return failure
				}
				return nil
			}
		case "receive":
			network.receiveErr = func() error {
				if network.now.Sub(start) >= 10*time.Second {
					return failure
				}
				return nil
			}
		}

		run := runFakeScan(t, network, "linux", scanTestTarget.String()+"/31", "--retransmit", "no", "--rate", "0.1", "--format", "json")

		stderrLines := strings.Split(strings.TrimSpace(run.stderr), "\n")
		if run.code != 1 || len(stderrLines) != 1 || !strings.HasPrefix(stderrLines[0], "Error: ") || !strings.Contains(stderrLines[0], "network is down") {
			t.Errorf("%s: exit %d, stderr %q", on, run.code, run.stderr)
		}

		if !strings.Contains(run.stdout, scanTestTarget.String()) || !network.closed {
			t.Errorf("%s: stdout %q, closed %v", on, run.stdout, network.closed)
		}
	}
}

func TestTheScanSendsOneSYNToEachTargetOfANetwork(t *testing.T) {
	network := newScanFakeNetwork(t, nil)
	run := runFakeScan(t, network, "linux", "203.0.113.0/30", "--retransmit", "no", "--rate", "1000")

	if run.code != 0 || len(network.sent) != 4 {
		t.Errorf("exit %d, sent %v, stderr %q", run.code, network.sent, run.stderr)
	}
}

func TestAnInterruptWritesTheResultOfEachTargetThatAnswered(t *testing.T) {
	network := newScanFakeNetwork(t, map[netip.Addr][]time.Duration{scanTestTarget: {100 * time.Millisecond, 1100 * time.Millisecond}})
	start := network.now

	var stdout, stderr bytes.Buffer

	code := runScanCommand([]string{scanTestTarget.String(), "--format", "json"}, scanEnvironment{
		stdout: &stdout, stderr: &stderr, goos: "linux", clock: network.clock, rand: rand.New(rand.NewPCG(3, 3)),
		openNetwork: func(uint16, netip.Addr, func(string)) (scan.Network, error) { return network, nil },
		stopped:     func() bool { return network.now.Sub(start) >= 2*time.Second },
	})

	if code != scanExitInterrupted || !strings.Contains(stdout.String(), `"fingerprint":"64240_2_1460_00_1"`) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}

	return false
}
