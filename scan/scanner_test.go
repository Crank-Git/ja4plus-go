package scan

import (
	"errors"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The cases below port `tests/test_ja4tscan_scanner.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. The port's `docs/specs/features/12-active-scan.md` states each requirement that
// a case names.

var testTarget = netip.MustParseAddr("192.0.2.10")

type scanRun struct {
	results  []Result
	warnings []string
	scanner  *Scanner
	err      error
}

type scanOptions struct {
	retransmit bool
	rate       float64
	port       uint16
}

func defaultScanOptions() scanOptions {
	return scanOptions{retransmit: true, rate: 10, port: 80}
}

func newTestScanner(t *testing.T, network *fakeNetwork, options scanOptions, run *scanRun) *Scanner {
	t.Helper()

	scanner, err := NewScanner(Config{
		Port:       options.port,
		Rate:       options.rate,
		Retransmit: options.retransmit,
		Network:    network,
		Clock:      network.clock,
		OnResult:   func(result Result) { run.results = append(run.results, result) },
		OnWarning:  func(line string) { run.warnings = append(run.warnings, line) },
		Rand:       rand.New(rand.NewPCG(7, 7)),
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	return scanner
}

func runScan(t *testing.T, network *fakeNetwork, targets []netip.Addr, options scanOptions) scanRun {
	t.Helper()

	var run scanRun

	run.scanner = newTestScanner(t, network, options, &run)
	run.err = run.scanner.Run(slices.Values(targets))

	return run
}

func values(results []Result) []string {
	out := make([]string, 0, len(results))
	for _, result := range results {
		out = append(out, result.Value)
	}

	return out
}

func oneTarget(s script) map[netip.Addr]script {
	return map[netip.Addr]script{testTarget: s}
}

func TestATargetThatSendsOneSynAckReceivesOneSend(t *testing.T) {
	network := newFakeNetwork(t, oneTarget(synAckScript(0.05)), 80)
	runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions())

	if len(network.sent) != 1 {
		t.Errorf("the scanner sent %d SYN packets, want 1", len(network.sent))
	}
}

func TestATargetThatRetransmitsReceivesOneSend(t *testing.T) {
	network := newFakeNetwork(t, oneTarget(synAckScript(0.05, 1.05, 3.05)), 80)
	runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions())

	if len(network.sent) != 1 || network.sent[0].target != testTarget {
		t.Errorf("the scanner sent %v, want one SYN to %v", network.sent, testTarget)
	}
}

func TestTheScannerSendsToEachNamedTargetOnceAndToNoOtherAddress(t *testing.T) {
	targets := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"),
	}
	network := newFakeNetwork(t, nil, 80)
	runScan(t, network, append(targets, targets[0]), defaultScanOptions())

	var got []netip.Addr
	for _, syn := range network.sent {
		got = append(got, syn.target)
	}

	if !slices.Equal(got, targets) {
		t.Errorf("the scanner sent to %v, want %v", got, targets)
	}
}

func TestASynAckAndFourRetransmissionsWriteOneResult(t *testing.T) {
	network := newFakeNetwork(t, oneTarget(synAckScript(0.1, 1.1, 3.1, 7.1, 15.1)), 80)
	run := runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions())

	if got := values(run.results); !slices.Equal(got, []string{"64240_2_1460_00_1-2-4-8"}) {
		t.Errorf("the results are %v", got)
	}

	if len(run.warnings) != 0 {
		t.Errorf("the scan warns %v", run.warnings)
	}
}

func TestTheResultNamesTheTargetAsTheSourceAndTheScannerAsTheDestination(t *testing.T) {
	network := newFakeNetwork(t, oneTarget(synAckScript(0.1)), 443)
	options := defaultScanOptions()
	options.port = 443
	run := runScan(t, network, []netip.Addr{testTarget}, options)

	if len(run.results) != 1 {
		t.Fatalf("the scan wrote %d results, want 1", len(run.results))
	}

	result := run.results[0]
	if result.Target != testTarget || result.TargetPort != 443 {
		t.Errorf("the source is %v:%d", result.Target, result.TargetPort)
	}

	if result.Scanner != fakeScannerIP || result.ScannerPort != network.sent[0].srcPort {
		t.Errorf("the destination is %v:%d", result.Scanner, result.ScannerPort)
	}
}

func TestTheResultTimeIsTheReceiveTimeOfTheLastResponse(t *testing.T) {
	network := newFakeNetwork(t, oneTarget(synAckScript(0.1, 1.1, 3.1)), 80)
	start := network.now
	run := runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions())

	if want := start.Add(seconds(3.1)); !run.results[0].Time.Equal(want) {
		t.Errorf("the result time is %v, want %v", run.results[0].Time, want)
	}
}

func TestATargetThatSendsNoResponseWritesNoResult(t *testing.T) {
	run := runScan(t, newFakeNetwork(t, nil, 80), []netip.Addr{testTarget}, defaultScanOptions())

	if len(run.results) != 0 || len(run.warnings) != 0 {
		t.Errorf("the scan wrote %v and warned %v", run.results, run.warnings)
	}
}

func TestAFirstResponseThatCarriesRSTWritesTheResetValue(t *testing.T) {
	s := flagScript([]float64{0.1}, "R")
	run := runScan(t, newFakeNetwork(t, oneTarget(s), 80), []netip.Addr{testTarget}, defaultScanOptions())

	if got := values(run.results); !slices.Equal(got, []string{ResetValue}) || len(run.warnings) != 0 {
		t.Errorf("the results are %v and the warnings are %v", got, run.warnings)
	}
}

func TestARSTACKWithAWindowOf512WritesTheResetValue(t *testing.T) {
	s := flagScript([]float64{0.1}, "RA")
	s.window = 512
	run := runScan(t, newFakeNetwork(t, oneTarget(s), 80), []netip.Addr{testTarget}, defaultScanOptions())

	if got := values(run.results); !slices.Equal(got, []string{ResetValue}) {
		t.Errorf("the results are %v", got)
	}
}

func TestASynAckThenARSTWritesTheRSTDelay(t *testing.T) {
	s := flagScript([]float64{0.1, 1.1, 7.1}, "SA", "SA", "R")
	run := runScan(t, newFakeNetwork(t, oneTarget(s), 80), []netip.Addr{testTarget}, defaultScanOptions())

	if got := values(run.results); !slices.Equal(got, []string{"64240_2_1460_00_1-R6"}) || len(run.warnings) != 0 {
		t.Errorf("the results are %v and the warnings are %v", got, run.warnings)
	}
}

func TestAnICMPMessageThatAnswersTheSYNWritesNoResult(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	quoted := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 198, 51, 100, 1, 192, 0, 2, 10, 0xc3, 0x50, 0, 80}
	network.push(network.now.Add(100*time.Millisecond), serializeFrame(t,
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: testTarget.AsSlice(), DstIP: fakeScannerIP.AsSlice()},
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}, gopacket.Payload(quoted)))

	run := runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions())
	if len(run.results) != 0 || len(run.warnings) != 0 {
		t.Errorf("the scan wrote %v and warned %v", run.results, run.warnings)
	}
}

func TestEveryTruncationOfAResponseRaisesNothingAndWritesNothing(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	frame := network.responseFrame(testTarget, 50000, 0, synAckScript(0), "SA")

	for end := range len(frame) {
		network.push(network.now.Add(time.Duration(end)*time.Millisecond), frame[:end])
	}

	if run := runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions()); len(run.results) != 0 {
		t.Errorf("the scan wrote %v", run.results)
	}
}

func TestTheAcknowledgmentRule(t *testing.T) {
	cases := []struct {
		name     string
		script   script
		expected []string
	}{
		{"a SYN-ACK that acknowledges another sequence number writes nothing",
			script{offsets: []time.Duration{seconds(0.1)}, flags: []string{"SA"}, ackDelta: 2}, nil},
		{"a SYN-ACK that acknowledges the sequence number itself writes nothing",
			script{offsets: []time.Duration{seconds(0.1)}, flags: []string{"SA"}, ackDelta: 0}, nil},
		{"a RST that acknowledges the sequence number itself is a response",
			script{offsets: []time.Duration{seconds(0.1)}, flags: []string{"R"}, ackDelta: 0}, []string{ResetValue}},
		{"a response from another port writes nothing",
			script{offsets: []time.Duration{seconds(0.1)}, flags: []string{"SA"}, ackDelta: 1, srcPort: 81}, nil},
	}

	for _, c := range cases {
		run := runScan(t, newFakeNetwork(t, oneTarget(c.script), 80), []netip.Addr{testTarget}, defaultScanOptions())
		if got := values(run.results); !slices.Equal(got, c.expected) {
			t.Errorf("%s: the results are %v, want %v", c.name, got, c.expected)
		}
	}
}

func TestAResponseFromAnAddressTheScanNeverNamedWritesNothing(t *testing.T) {
	stranger := netip.MustParseAddr("192.0.2.99")
	network := newFakeNetwork(t, map[netip.Addr]script{stranger: synAckScript(0.1)}, 80)
	_, _, _ = network.Send(stranger, 50000, 1)

	if run := runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions()); len(run.results) != 0 {
		t.Errorf("the scan wrote %v", run.results)
	}
}

// A matching acknowledgment number alone makes no response, because a target sets it. The
// scanner reads a SYN-ACK, or a RST with or without ACK, and FR-active-scan-15 of the port
// states the rule.
func TestTheFlagRule(t *testing.T) {
	cases := []struct {
		name   string
		script script
	}{
		{"a segment with ACK alone and a matching acknowledgment writes nothing", flagScript([]float64{0.1}, "A")},
		{"a segment with ACK and PSH that carries data writes nothing", func() script {
			s := flagScript([]float64{0.1}, "PA")
			s.payload = []byte("HTTP/1.1 200 OK\r\n")
			return s
		}()},
	}

	for _, c := range cases {
		run := runScan(t, newFakeNetwork(t, oneTarget(c.script), 80), []netip.Addr{testTarget}, defaultScanOptions())
		if len(run.results) != 0 {
			t.Errorf("%s: the scan wrote %v", c.name, values(run.results))
		}
	}
}

func TestASegmentWithACKAloneAfterASynAckAddsNoDelay(t *testing.T) {
	alone := runScan(t, newFakeNetwork(t, oneTarget(synAckScript(0.1)), 80), []netip.Addr{testTarget}, defaultScanOptions())
	mixed := runScan(t, newFakeNetwork(t, oneTarget(flagScript([]float64{0.1, 1.1, 2.1}, "SA", "A", "PA")), 80),
		[]netip.Addr{testTarget}, defaultScanOptions())

	if !slices.Equal(values(mixed.results), values(alone.results)) {
		t.Errorf("the results are %v, want %v", values(mixed.results), values(alone.results))
	}
}

func TestOneSynAckAndNoLaterResponseWritesOneWarningLine(t *testing.T) {
	run := runScan(t, newFakeNetwork(t, oneTarget(synAckScript(0.1)), 80), []netip.Addr{testTarget}, defaultScanOptions())

	if got := values(run.results); !slices.Equal(got, []string{"64240_2_1460_00"}) {
		t.Errorf("the results are %v", got)
	}

	if len(run.warnings) != 1 || !strings.Contains(run.warnings[0], testTarget.String()) || strings.Contains(run.warnings[0], "\n") {
		t.Errorf("the warnings are %q, want one line that names the target", run.warnings)
	}
}

func TestTheModeWithoutRetransmissionsWritesNoWarning(t *testing.T) {
	options := defaultScanOptions()
	options.retransmit = false
	run := runScan(t, newFakeNetwork(t, oneTarget(synAckScript(0.1)), 80), []netip.Addr{testTarget}, options)

	if len(run.results) != 1 || len(run.warnings) != 0 {
		t.Errorf("the scan wrote %v and warned %v", run.results, run.warnings)
	}
}

func TestTheScannerWaits120SecondsAfterTheLastSYN(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	start := network.now
	runScan(t, network, []netip.Addr{testTarget}, defaultScanOptions())

	if RetransmitWait != 120*time.Second || !network.now.Equal(start.Add(RetransmitWait)) {
		t.Errorf("the scan ended %v after the SYN, want 120s", network.now.Sub(start))
	}
}

func TestTheModeWithoutRetransmissionsWaits8SecondsAfterTheLastSYN(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	start := network.now
	options := defaultScanOptions()
	options.retransmit = false
	runScan(t, network, []netip.Addr{testTarget}, options)

	if NoRetransmitWait != 8*time.Second || !network.now.Equal(start.Add(NoRetransmitWait)) {
		t.Errorf("the scan ended %v after the SYN, want 8s", network.now.Sub(start))
	}
}

func TestAResponseAfterTheWaitChangesNothing(t *testing.T) {
	run := runScan(t, newFakeNetwork(t, oneTarget(synAckScript(0.1, 121)), 80), []netip.Addr{testTarget}, defaultScanOptions())

	if got := values(run.results); !slices.Equal(got, []string{"64240_2_1460_00"}) {
		t.Errorf("the results are %v", got)
	}
}

func TestTheModeWithoutRetransmissionsReadsTheFirstResponseAlone(t *testing.T) {
	options := defaultScanOptions()
	options.retransmit = false
	run := runScan(t, newFakeNetwork(t, oneTarget(synAckScript(0.1, 1.1, 3.1)), 80), []netip.Addr{testTarget}, options)

	if got := values(run.results); !slices.Equal(got, []string{"64240_2_1460_00"}) {
		t.Errorf("the results are %v", got)
	}
}

func TestTheRateSetsTheSYNCountForEachSecond(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	start := network.now

	var offsets []time.Duration
	network.onSend = func(netip.Addr) { offsets = append(offsets, network.now.Sub(start)) }

	options := defaultScanOptions()
	options.rate = 4
	runScan(t, network, []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"),
	}, options)

	want := []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond}
	if !slices.Equal(offsets, want) {
		t.Errorf("the SYN packets left at %v, want %v", offsets, want)
	}
}

func TestTheStateTableHoldsAtMost10000TargetsUnder20000Targets(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	options := defaultScanOptions()
	options.rate = 1_000_000

	var run scanRun

	scanner := newTestScanner(t, network, options, &run)

	largest := 0
	network.onSend = func(netip.Addr) { largest = max(largest, scanner.table.Len()) }

	targets := make([]netip.Addr, 0, 20000)
	for index := range 20000 {
		targets = append(targets, netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)}))
	}

	if err := scanner.Run(slices.Values(targets)); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if MaxTargets != 10000 || len(network.sent) != 20000 || largest != MaxTargets-1 || scanner.table.Len() != 0 {
		t.Errorf("the table held at most %d targets and %d at the end, for %d SYN packets",
			largest, scanner.table.Len(), len(network.sent))
	}
}

func TestATargetLeavesTheTableWhenItsWaitEnds(t *testing.T) {
	run := runScan(t, newFakeNetwork(t, oneTarget(synAckScript(0.1)), 80), []netip.Addr{testTarget}, defaultScanOptions())

	if run.scanner.table.Len() != 0 || len(run.scanner.probes) != 0 {
		t.Errorf("the table holds %d targets after the scan", run.scanner.table.Len())
	}
}

func TestAFloodingTargetHoldsABoundedResponseList(t *testing.T) {
	offsets := make([]float64, 500)
	for index := range offsets {
		offsets[index] = 0.1 + float64(index)*0.001
	}

	network := newFakeNetwork(t, oneTarget(synAckScript(offsets...)), 80)

	var run scanRun

	scanner := newTestScanner(t, network, defaultScanOptions(), &run)

	if err := scanner.start(testTarget); err != nil {
		t.Fatalf("start: %v", err)
	}

	if err := scanner.receiveUntil(network.now.Add(5 * time.Second)); err != nil {
		t.Fatalf("receiveUntil: %v", err)
	}

	held := len(scanner.probes[testTarget].Value.(*probe).responses)

	scanner.Flush()

	if held != 11 || strings.Count(run.results[0].Value, "-") != 9 {
		t.Errorf("the target held %d responses and wrote %q", held, run.results[0].Value)
	}
}

func TestFlushWritesTheResultOfEveryTargetTheTableHolds(t *testing.T) {
	network := newFakeNetwork(t, oneTarget(synAckScript(0.1, 1.1)), 80)

	var run scanRun

	scanner := newTestScanner(t, network, defaultScanOptions(), &run)

	if err := scanner.start(testTarget); err != nil {
		t.Fatalf("start: %v", err)
	}

	if err := scanner.receiveUntil(network.now.Add(2 * time.Second)); err != nil {
		t.Fatalf("receiveUntil: %v", err)
	}

	scanner.Flush()

	if got := values(run.results); !slices.Equal(got, []string{"64240_2_1460_00_1"}) || scanner.table.Len() != 0 {
		t.Errorf("the results are %v, and the table holds %d targets", got, scanner.table.Len())
	}
}

func TestASocketErrorStopsTheScanAndKeepsTheResultsAlreadyWritten(t *testing.T) {
	second := netip.MustParseAddr("192.0.2.11")
	failure := errors.New("network is down")

	for _, on := range []string{"send", "receive"} {
		network := newFakeNetwork(t, oneTarget(synAckScript(0.1)), 80)
		start := network.now

		switch on {
		case "send":
			network.sendErr = func(target netip.Addr) error {
				if target == second {
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

		options := defaultScanOptions()
		options.retransmit = false
		options.rate = 0.1
		run := runScan(t, network, []netip.Addr{testTarget, second}, options)

		if !errors.Is(run.err, failure) {
			t.Errorf("%s: Run returns %v, want the socket error", on, run.err)
		}

		if len(run.results) != 1 || run.results[0].Target != testTarget {
			t.Errorf("%s: the results are %v, want the result of the first target", on, run.results)
		}
	}
}

func TestNewScannerRefusesAConfigurationItCannotRun(t *testing.T) {
	network := newFakeNetwork(t, nil, 80)
	cases := map[string]Config{
		"a zero port":      {Port: 0, Rate: 10, Network: network},
		"a zero rate":      {Port: 80, Rate: 0, Network: network},
		"a NaN rate":       {Port: 80, Rate: nanRate(), Network: network},
		"no network":       {Port: 80, Rate: 10},
		"a negative rate":  {Port: 80, Rate: -1, Network: network},
		"an infinite rate": {Port: 80, Rate: math.Inf(1), Network: network},
		// One SYN in 1e10 seconds is an interval of 1e19 nanoseconds, and a time.Duration
		// holds at most about 9.2e18.
		"a rate whose interval overflows a Duration": {Port: 80, Rate: 1e-10, Network: network},
	}

	for name, config := range cases {
		if _, err := NewScanner(config); err == nil {
			t.Errorf("NewScanner accepts %s", name)
		}
	}
}

func nanRate() float64 {
	zero := 0.0
	return zero / zero
}

func TestOneIPv4AddressIsOneTarget(t *testing.T) {
	assertTargets(t, "192.0.2.7", []string{"192.0.2.7"})
}

func TestAnIPv4NetworkNamesEveryAddressItHolds(t *testing.T) {
	assertTargets(t, "203.0.113.0/30", []string{"203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.3"})
	assertTargets(t, "203.0.113.5/30", []string{"203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7"})
}

func TestAFileNamesOneAddressOnEachLine(t *testing.T) {
	path := writeTargets(t, "192.0.2.1\n\n192.0.2.2\n 192.0.2.1 \n")
	assertTargets(t, path, []string{"192.0.2.1", "192.0.2.2"})
}

func TestAFileLineThatIsNoIPv4AddressNamesTheLine(t *testing.T) {
	path := writeTargets(t, "192.0.2.1\nnot-an-address\n")

	_, err := ParseTargets(path)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "not-an-address") {
		t.Errorf("ParseTargets returns %v, want an error that names line 2 and its text", err)
	}
}

func TestAnIPv6TargetStatesThatTheScannerReadsIPv4Alone(t *testing.T) {
	for _, text := range []string{"2001:db8::1", "2001:db8::/64", "::ffff:192.0.2.1", writeTargets(t, "2001:db8::1\n")} {
		if _, err := ParseTargets(text); err == nil || !strings.Contains(err.Error(), "IPv4 alone") {
			t.Errorf("ParseTargets(%q) returns %v, want an error that names IPv4 alone", text, err)
		}
	}
}

func TestATargetThatIsNoAddressNoNetworkAndNoFileIsRefused(t *testing.T) {
	_, err := ParseTargets(filepath.Join(t.TempDir(), "absent.txt"))
	if err == nil || !strings.Contains(err.Error(), "no IPv4 address") {
		t.Errorf("ParseTargets returns %v, want an error that names no IPv4 address", err)
	}
}

func writeTargets(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write the target file: %v", err)
	}

	return path
}

func assertTargets(t *testing.T, text string, want []string) {
	t.Helper()

	targets, err := ParseTargets(text)
	if err != nil {
		t.Fatalf("ParseTargets(%q): %v", text, err)
	}

	var got []string
	for target := range targets {
		got = append(got, target.String())
	}

	if !slices.Equal(got, want) {
		t.Errorf("ParseTargets(%q) = %v, want %v", text, got, want)
	}
}

var (
	wantLinuxRules = []string{
		"iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
		"iptables -t filter -A INPUT -p icmp -j ACCEPT",
		"iptables -t filter -A INPUT -i lo -j ACCEPT",
		"iptables -t filter -A INPUT -j DROP",
	}
	wantLinuxRemovals = []string{
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

func TestLinuxStatesTheFourFoxIORulesAndTheFourRemovals(t *testing.T) {
	lines := strings.Split(FirewallRules("linux"), "\n")

	for _, rule := range append(slices.Clone(wantLinuxRules), wantLinuxRemovals...) {
		if !slices.Contains(lines, rule) {
			t.Errorf("the Linux rules hold no line %q", rule)
		}
	}

	if slices.Index(lines, wantLinuxRules[3]) > slices.Index(lines, wantLinuxRemovals[0]) {
		t.Error("a removal precedes the last rule")
	}
}

func TestMacOSStatesTheFourPFRules(t *testing.T) {
	text := FirewallRules("darwin")
	lines := strings.Split(text, "\n")

	for _, rule := range wantPFRules {
		if !slices.Contains(lines, rule) {
			t.Errorf("the macOS rules hold no line %q", rule)
		}
	}

	if strings.Contains(text, "iptables") {
		t.Error("the macOS rules name iptables")
	}
}

func TestTheRuleTextStatesThatTheScannerChangesNoFirewallState(t *testing.T) {
	if !strings.Contains(FirewallRules("linux"), "changes no firewall state") {
		t.Error("the rule text does not state that the scanner changes no firewall state")
	}
}
