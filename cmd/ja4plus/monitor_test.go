package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The monitor loop of issue #80. Every test of this file drives the loop with a stub
// capture handle, because a live interface needs a privilege that no test holds.
//
// FR-capture-16 through FR-capture-23 of `docs/specs/features/13-live-capture.md` state
// the work. Each test names the requirement it reads.

// monitorTestClientIP names the client of every connection of these tests.
const monitorTestClientIP = "192.168.1.100"

// monitorTestServerIP names the server of every connection of these tests.
const monitorTestServerIP = "10.0.0.1"

// stubCaptureHandle returns canned packets to the monitor loop, and it then returns the
// error the caller names.
//
// The stub satisfies `capture.Handle`, so the loop under test is the loop that a live
// interface drives. #77 wrote the same compile-time check in `capture_test.go`.
type stubCaptureHandle struct {
	// packets holds the bytes the handle returns, in order.
	packets [][]byte
	// infos holds the capture information of each packet of `packets`.
	infos []gopacket.CaptureInfo
	// end is the error the handle returns after the last packet.
	end error
	// index counts the packets the handle returned.
	index int
	// beforeRead runs before each read, so a test sets the stop request between two
	// packets.
	beforeRead func(index int)
}

func (h *stubCaptureHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if h.beforeRead != nil {
		h.beforeRead(h.index)
	}

	if h.index >= len(h.packets) {
		return nil, gopacket.CaptureInfo{}, h.end
	}

	data := h.packets[h.index]
	info := h.infos[h.index]
	h.index++

	return data, info, nil
}

func (h *stubCaptureHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

func (h *stubCaptureHandle) Close() error { return nil }

// newStubCaptureHandle returns a handle that serves the packets and then reports the end
// of the stream.
func newStubCaptureHandle(packets [][]byte) *stubCaptureHandle {
	infos := make([]gopacket.CaptureInfo, 0, len(packets))
	timestamp := time.Unix(1700000000, 0).UTC()

	for _, data := range packets {
		infos = append(infos, gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: len(data),
			Length:        len(data),
		})
	}

	return &stubCaptureHandle{packets: packets, infos: infos, end: io.EOF}
}

// buildTCPPacketBytes returns the bytes of one Ethernet frame that carries one TCP
// segment.
//
// The frame carries the TCP options that JA4T reads, so a SYN of this builder produces a
// fingerprint on the first packet.
func buildTCPPacketBytes(t *testing.T, srcIP string, dstIP string, srcPort uint16, dstPort uint16, syn bool, payload []byte) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    parseTestIP(t, srcIP),
		DstIP:    parseTestIP(t, dstIP),
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     !syn,
		Seq:     1,
		Window:  64240,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x07}},
		},
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("the builder sets no network layer for the checksum: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("the builder serializes no packet: %v", err)
	}

	return buffer.Bytes()
}

// parseTestIP returns the address that the text names, and it fails the test for text
// that names no address.
func parseTestIP(t *testing.T, text string) []byte {
	t.Helper()

	address := net.ParseIP(text)
	if address == nil {
		t.Fatalf("the text %q names no address", text)
	}

	return address.To4()
}

// newTestMonitor returns one monitor that writes to the two builders, and it returns the
// two builders.
func newTestMonitor(t *testing.T, options watchOptions, clock func() time.Time) (*monitor, *strings.Builder, *strings.Builder) {
	t.Helper()

	out := &strings.Builder{}
	errOut := &strings.Builder{}

	return newMonitor(options, &stopRequest{}, out, errOut, clock), out, errOut
}

// steadyClock returns a clock that reports one time, so a test that reads no age holds
// every connection.
func steadyClock() func() time.Time {
	instant := time.Unix(1700000000, 0).UTC()
	return func() time.Time { return instant }
}

// TestTheMonitorPrintsAFingerprintForEachPacketItReads reads FR-capture-1 and the first
// acceptance criterion of issue #80. A SYN carries the TCP options that JA4T reads, so
// one packet produces one fingerprint.
func TestTheMonitorPrintsAFingerprintForEachPacketItReads(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})

	instance, out, _ := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if !strings.Contains(out.String(), "ja4t") {
		t.Errorf("standard output holds no JA4T fingerprint: %q", out.String())
	}

	if !strings.Contains(out.String(), monitorTestClientIP+":54120") {
		t.Errorf("standard output names no source endpoint: %q", out.String())
	}
}

// TestTheMonitorStopsAfterThePacketThatFollowsTheStopRequest reads FR-capture-17. The
// loop reads the stop request after each packet, so it finishes the packet it holds.
// The edge-case table of `docs/specs/features/13-live-capture.md` states that no packet
// is half-processed.
func TestTheMonitorStopsAfterThePacketThatFollowsTheStopRequest(t *testing.T) {
	first := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	second := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54121, 443, true, nil)
	third := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54122, 443, true, nil)

	handle := newStubCaptureHandle([][]byte{first, second, third})

	instance, out, _ := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	// The stop request arrives while the monitor holds the second packet, so the monitor
	// reads that packet and then stops.
	handle.beforeRead = func(index int) {
		if index == 1 {
			instance.stop.request()
		}
	}

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if handle.index != 2 {
		t.Errorf("the monitor read %d packets, and it stops after the second one", handle.index)
	}

	if !strings.Contains(out.String(), ":54121") {
		t.Errorf("standard output holds no fingerprint of the second packet: %q", out.String())
	}

	if strings.Contains(out.String(), ":54122") {
		t.Errorf("standard output holds a fingerprint of the third packet: %q", out.String())
	}
}

// TestTheMonitorReportsTheReadFailureOfTheInterface reads the edge-case table of
// `docs/specs/features/13-live-capture.md`. The interface is removed, so the read fails.
// The monitor writes one message and the command exits with status 1.
func TestTheMonitorReportsTheReadFailureOfTheInterface(t *testing.T) {
	handle := newStubCaptureHandle(nil)
	handle.end = errors.New("the interface is removed")

	instance, _, _ := newTestMonitor(t, watchOptions{iface: "eth0"}, steadyClock())

	err := instance.run(handle)
	if err == nil {
		t.Fatal("the monitor returns no error for a failed read")
	}

	if !strings.Contains(err.Error(), "eth0") {
		t.Errorf("the error %q names no interface", err)
	}
}

// TestTheMonitorClosesTheOpenWindowsAfterTheStopRequest reads FR-capture-20. A JA4SSH
// window that reached no threshold holds open, and no packet emits it. The monitor calls
// `Processor.CloseOpenWindows` after the stop request, and it prints the results.
func TestTheMonitorClosesTheOpenWindowsAfterTheStopRequest(t *testing.T) {
	// The payload holds one SSH binary packet: a four-byte length, one padding length and
	// the rest. `parser.IsSSHPacket` reads that shape, and a packet of zero bytes is no
	// SSH packet.
	payload := make([]byte, 36)
	binary.BigEndian.PutUint32(payload[:4], 32)
	payload[4] = 6
	// The message type byte must be 1 or more, and 20 names SSH_MSG_KEXINIT.
	payload[5] = 20

	packets := make([][]byte, 0, 8)

	for index := 0; index < 4; index++ {
		packets = append(packets, buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54144, 22, false, payload))
		packets = append(packets, buildTCPPacketBytes(t, monitorTestServerIP, monitorTestClientIP, 22, 54144, false, payload))
	}

	handle := newStubCaptureHandle(packets)

	instance, out, errOut := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	// The stop request arrives after the last packet, so the run reaches the close of the
	// open windows.
	handle.beforeRead = func(index int) {
		if index == len(packets) {
			instance.stop.request()
		}
	}

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if !strings.Contains(out.String(), "ja4ssh") {
		t.Errorf("standard output holds no open JA4SSH window: %q", out.String())
	}

	if !strings.Contains(errOut.String(), "closing open windows") {
		t.Errorf("standard error names no close of the open windows: %q", errOut.String())
	}
}

// TestTheMonitorRecordsTheTimeEachConnectionLastSentAPacket reads FR-capture-21.
func TestTheMonitorRecordsTheTimeEachConnectionLastSentAPacket(t *testing.T) {
	first := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	second := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54121, 443, true, nil)

	handle := newStubCaptureHandle([][]byte{first, second})

	instance, _, _ := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if instance.table.len() != 2 {
		t.Errorf("the connection table holds %d connections, and the capture names 2", instance.table.len())
	}
}

// TestTheConnectionTableHoldsBothDirectionsOfOneConnectionInOneEntry reads FR-capture-21.
// `Processor.CleanupConnection` accepts the two endpoints in either order, so one entry
// removes the state of both directions.
func TestTheConnectionTableHoldsBothDirectionsOfOneConnectionInOneEntry(t *testing.T) {
	client := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	server := buildTCPPacketBytes(t, monitorTestServerIP, monitorTestClientIP, 443, 54120, false, nil)

	handle := newStubCaptureHandle([][]byte{client, server})

	instance, _, _ := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if instance.table.len() != 1 {
		t.Errorf("the connection table holds %d entries, and the two directions name 1", instance.table.len())
	}
}

// TestTheConnectionTableEvictsAConnectionThatSentNoPacketForTheIdleTimeout reads
// FR-capture-22. The test drives the timeout with a clock rather than a constant, because
// a test that reads a constant proves no eviction.
func TestTheConnectionTableEvictsAConnectionThatSentNoPacketForTheIdleTimeout(t *testing.T) {
	var evicted []connectionKey

	table := newConnectionTable(maxMonitorConnections, monitorIdleTimeout, func(key connectionKey) {
		evicted = append(evicted, key)
	})

	start := time.Unix(1700000000, 0).UTC()
	key := connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 54120, dstIP: monitorTestServerIP, dstPort: 443}

	table.observe(key, start)

	// The connection reaches the timeout exactly, so the table holds it. An eviction here
	// would remove a connection one instant before the requirement states.
	table.evictIdle(start.Add(monitorIdleTimeout))

	if table.len() != 1 {
		t.Fatalf("the table evicted the connection at the timeout, and it holds it until the timeout passes")
	}

	table.evictIdle(start.Add(monitorIdleTimeout + time.Nanosecond))

	if table.len() != 0 {
		t.Errorf("the table holds %d connections past the idle timeout", table.len())
	}

	if len(evicted) != 1 || evicted[0] != key {
		t.Errorf("the table reports the evictions %v, and it evicts the one connection", evicted)
	}
}

// TestTheConnectionTableRefreshesAConnectionThatKeepsSending reads FR-capture-22. A
// connection that sends a packet inside the timeout survives the pass.
func TestTheConnectionTableRefreshesAConnectionThatKeepsSending(t *testing.T) {
	table := newConnectionTable(maxMonitorConnections, monitorIdleTimeout, func(connectionKey) {})

	start := time.Unix(1700000000, 0).UTC()
	key := connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 54120, dstIP: monitorTestServerIP, dstPort: 443}

	table.observe(key, start)
	table.observe(key, start.Add(monitorIdleTimeout))
	table.evictIdle(start.Add(monitorIdleTimeout + time.Second))

	if table.len() != 1 {
		t.Errorf("the table evicted a connection that sent a packet inside the timeout")
	}
}

// TestTheConnectionTableRemovesTheOldestEntryAtTheMaximumEntryCount reads FR-capture-23.
// The test drives the bound with one connection more than the bound holds.
func TestTheConnectionTableRemovesTheOldestEntryAtTheMaximumEntryCount(t *testing.T) {
	var evicted []connectionKey

	bound := 8
	table := newConnectionTable(bound, monitorIdleTimeout, func(key connectionKey) {
		evicted = append(evicted, key)
	})

	start := time.Unix(1700000000, 0).UTC()

	for index := 0; index < bound; index++ {
		table.observe(connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: uint16(1024 + index), dstIP: monitorTestServerIP, dstPort: 443}, start.Add(time.Duration(index)*time.Second))
	}

	// The table holds the bound and no eviction ran, so the bound removes nothing before
	// the insert that reaches it.
	if table.len() != bound {
		t.Fatalf("the table holds %d connections, and the bound is %d", table.len(), bound)
	}

	if len(evicted) != 0 {
		t.Fatalf("the table evicted %d connections below the bound", len(evicted))
	}

	oldest := connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 1024, dstIP: monitorTestServerIP, dstPort: 443}

	table.observe(connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 9000, dstIP: monitorTestServerIP, dstPort: 443}, start.Add(time.Hour))

	if table.len() != bound {
		t.Errorf("the table holds %d connections past the bound of %d", table.len(), bound)
	}

	if len(evicted) != 1 || evicted[0] != oldest {
		t.Errorf("the table reports the evictions %v, and the bound removes the oldest entry %v", evicted, oldest)
	}
}

// TestTheConnectionTableRemovesTheLeastRecentEntryAndNeverTheFirstInsert reads
// FR-capture-23. The requirement names the oldest entry, which is the entry that sent no
// packet for the longest time and never the entry that arrived first.
func TestTheConnectionTableRemovesTheLeastRecentEntryAndNeverTheFirstInsert(t *testing.T) {
	var evicted []connectionKey

	table := newConnectionTable(2, monitorIdleTimeout, func(key connectionKey) {
		evicted = append(evicted, key)
	})

	start := time.Unix(1700000000, 0).UTC()
	first := connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 1024, dstIP: monitorTestServerIP, dstPort: 443}
	second := connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 1025, dstIP: monitorTestServerIP, dstPort: 443}
	third := connectionKey{proto: "tcp", srcIP: monitorTestClientIP, srcPort: 1026, dstIP: monitorTestServerIP, dstPort: 443}

	table.observe(first, start)
	table.observe(second, start.Add(time.Second))
	// The first connection sends again, so the second one is now the least recent.
	table.observe(first, start.Add(2*time.Second))
	table.observe(third, start.Add(3*time.Second))

	if len(evicted) != 1 || evicted[0] != second {
		t.Errorf("the table reports the evictions %v, and the least recent entry is %v", evicted, second)
	}
}

// TestTheMonitorTableHoldsTheValuesTheRequirementsState reads FR-capture-22 and
// FR-capture-23 against the port. `.claude/rules/parity.md` rule 2 states that the port
// decides the interface where this project shipped nothing.
func TestTheMonitorTableHoldsTheValuesTheRequirementsState(t *testing.T) {
	if monitorIdleTimeout != 5*time.Minute {
		t.Errorf("the idle timeout is %v, and FR-capture-22 states 5 minutes", monitorIdleTimeout)
	}

	if maxMonitorConnections != 10000 {
		t.Errorf("the entry bound is %d, and `ja4plus/watch.py:83` states 10000", maxMonitorConnections)
	}
}

// TestTheMonitorEvictsAnIdleConnectionFromTheProcessor reads FR-capture-22. The monitor
// calls `Processor.CleanupConnection` for the connection the table evicts.
func TestTheMonitorEvictsAnIdleConnectionFromTheProcessor(t *testing.T) {
	first := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	second := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54121, 443, true, nil)

	handle := newStubCaptureHandle([][]byte{first, second})

	instant := time.Unix(1700000000, 0).UTC()
	reads := 0
	clock := func() time.Time {
		reads++
		// The second packet arrives past the idle timeout, so the pass evicts the
		// connection of the first packet.
		return instant.Add(time.Duration(reads-1) * (monitorIdleTimeout + time.Minute))
	}

	instance, _, _ := newTestMonitor(t, watchOptions{iface: "lo"}, clock)

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if instance.table.len() != 1 {
		t.Errorf("the table holds %d connections, and the pass evicts the idle one", instance.table.len())
	}
}

// TestTheStopHandlerSetsTheStopRequestOnTheFirstSignal reads FR-capture-18.
func TestTheStopHandlerSetsTheStopRequestOnTheFirstSignal(t *testing.T) {
	signals := make(chan os.Signal, 2)
	stop := &stopRequest{}

	var reset bool
	var raised []os.Signal
	var exited []int

	signals <- os.Interrupt

	watchStopHandler(signals, stop, func() { reset = true }, func(sig os.Signal) error {
		raised = append(raised, sig)
		return nil
	}, func(status int) { exited = append(exited, status) })

	if !stop.isRequested() {
		t.Error("the handler set no stop request for the first signal")
	}

	if !reset {
		t.Error("the handler restored no default disposition, so a second signal exits never")
	}

	if len(raised) != 0 {
		t.Errorf("the handler raised the signals %v, and one signal raises none", raised)
	}

	if len(exited) != 0 {
		t.Errorf("the handler exited with the statuses %v, and one signal exits never", exited)
	}
}

// TestTheStopHandlerRaisesASecondSignalThatArrivedBeforeTheReset reads FR-capture-19. The
// edge-case table of `docs/specs/features/13-live-capture.md` states that two signals
// that arrive quickly exit at once.
func TestTheStopHandlerRaisesASecondSignalThatArrivedBeforeTheReset(t *testing.T) {
	signals := make(chan os.Signal, 2)
	stop := &stopRequest{}

	var raised []os.Signal
	var exited []int

	signals <- os.Interrupt
	signals <- syscall.SIGTERM

	watchStopHandler(signals, stop, func() {}, func(sig os.Signal) error {
		raised = append(raised, sig)
		return nil
	}, func(status int) { exited = append(exited, status) })

	if len(raised) != 1 || raised[0] != syscall.SIGTERM {
		t.Errorf("the handler raised the signals %v, and it raises the second signal", raised)
	}

	if len(exited) != 0 {
		t.Errorf("the handler exited with the statuses %v, and it raises the signal instead", exited)
	}
}

// TestTheStopHandlerExitsWhenThePlatformRaisesNoSignal reads FR-capture-19. The
// requirement states the exit, and it states no mechanism.
func TestTheStopHandlerExitsWhenThePlatformRaisesNoSignal(t *testing.T) {
	signals := make(chan os.Signal, 2)
	stop := &stopRequest{}

	var exited []int

	signals <- os.Interrupt
	signals <- os.Interrupt

	watchStopHandler(signals, stop, func() {}, func(os.Signal) error {
		return errors.New("this platform raises no signal")
	}, func(status int) { exited = append(exited, status) })

	if len(exited) != 1 || exited[0] != watchSecondSignalStatus {
		t.Errorf("the handler exited with the statuses %v, and the second signal exits with %d", exited, watchSecondSignalStatus)
	}
}

// TestTheStopRequestCarriesTheFlagBetweenTwoGoroutines reads FR-capture-18 under the race
// detector. The signal handler runs on one goroutine and the monitor loop runs on
// another, so the flag crosses a goroutine boundary.
func TestTheStopRequestCarriesTheFlagBetweenTwoGoroutines(t *testing.T) {
	stop := &stopRequest{}

	var group sync.WaitGroup
	group.Add(1)

	go func() {
		defer group.Done()
		stop.request()
	}()

	for !stop.isRequested() {
		time.Sleep(time.Millisecond)
	}

	group.Wait()
}

// TestTheTerminationSignalsNameSIGINTAndSIGTERM reads FR-capture-18.
func TestTheTerminationSignalsNameSIGINTAndSIGTERM(t *testing.T) {
	signals := terminationSignals()

	if len(signals) != 2 {
		t.Fatalf("the monitor handles %d signals, and FR-capture-18 names 2", len(signals))
	}

	if signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Errorf("the monitor handles the signals %v, and FR-capture-18 names SIGINT and SIGTERM", signals)
	}
}

// TestTheMonitorWritesOneJSONObjectForEachFingerprint reads FR-capture-5. A stream has no
// end until the operator stops it, so the monitor writes one object per line rather than
// the one array that the capture-file command writes.
func TestTheMonitorWritesOneJSONObjectForEachFingerprint(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})

	instance, out, _ := newTestMonitor(t, watchOptions{iface: "lo", outputJSON: true}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	line := strings.TrimSpace(out.String())
	if !strings.HasPrefix(line, "{") {
		t.Errorf("the JSON output opens with %q, and the monitor writes one object per line", line)
	}

	var record jsonResult
	if err := json.Unmarshal([]byte(strings.Split(line, "\n")[0]), &record); err != nil {
		t.Fatalf("the first line holds no JSON object: %v", err)
	}

	if record.Type == "" {
		t.Error("the JSON object names no method")
	}
}

// TestTheMonitorWritesTheCSVHeaderBeforeTheFirstFingerprint reads FR-capture-5.
func TestTheMonitorWritesTheCSVHeaderBeforeTheFirstFingerprint(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})

	instance, out, _ := newTestMonitor(t, watchOptions{iface: "lo", outputCSV: true}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if lines[0] != "type,src_ip,src_port,dst_ip,dst_port,fingerprint,timestamp" {
		t.Errorf("the first CSV line is %q, and the header names each column", lines[0])
	}

	if len(lines) < 2 {
		t.Error("the CSV output holds no fingerprint row")
	}
}

// TestTheMonitorAppliesTheTypeFilter reads FR-capture-4.
func TestTheMonitorAppliesTheTypeFilter(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})

	instance, out, _ := newTestMonitor(t, watchOptions{iface: "lo", types: map[string]bool{"ja4h": true}}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if strings.Contains(out.String(), "ja4t") {
		t.Errorf("standard output holds a JA4T fingerprint that the filter declines: %q", out.String())
	}
}

// TestTheMonitorCountsEveryPacketAndEveryFingerprint reads the seam that #81 attaches to.
// FR-capture-29 reports the packet count and FR-capture-30 reports the fingerprint count.
func TestTheMonitorCountsEveryPacketAndEveryFingerprint(t *testing.T) {
	first := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	second := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54121, 443, true, nil)

	handle := newStubCaptureHandle([][]byte{first, second})

	instance, _, _ := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if instance.counters.packets.Load() != 2 {
		t.Errorf("the monitor counted %d packets, and the handle served 2", instance.counters.packets.Load())
	}

	if instance.counters.fingerprints.Load() == 0 {
		t.Error("the monitor counted no fingerprint, and two SYN packets produce one each")
	}

	if instance.counters.connections.Load() != 2 {
		t.Errorf("the monitor published %d connections, and the table holds 2", instance.counters.connections.Load())
	}
}

// TestTheMonitorCountersCrossAGoroutineBoundary reads the seam that #81 attaches to. The
// statistics goroutine of #81 reads these counters while the loop writes them, and the
// race detector fails a read that takes no atomic.
func TestTheMonitorCountersCrossAGoroutineBoundary(t *testing.T) {
	counters := &monitorCounters{}

	var group sync.WaitGroup
	group.Add(2)

	go func() {
		defer group.Done()
		for index := 0; index < 1000; index++ {
			counters.packets.Add(1)
			counters.connections.Store(uint64(index))
		}
	}()

	go func() {
		defer group.Done()
		for index := 0; index < 1000; index++ {
			_ = counters.packets.Load()
			_ = counters.connections.Load()
		}
	}()

	group.Wait()

	if counters.packets.Load() != 1000 {
		t.Errorf("the counter holds %d packets, and the writer added 1000", counters.packets.Load())
	}
}
