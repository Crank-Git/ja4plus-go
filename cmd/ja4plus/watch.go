package main

import (
	"container/list"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	ja4plus "github.com/Crank-Git/ja4plus-go"
	"github.com/Crank-Git/ja4plus-go/internal/capture"
	"github.com/Crank-Git/ja4plus-go/internal/parser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// defaultStatsInterval holds the seconds between two statistics lines.
// FR-capture-8 states the default.
const defaultStatsInterval = 60 * time.Second

// watchUsage states the option list of the watch command.
// The parser returns it with each refusal, because the operator repairs the command line.
const watchUsage = "Usage: ja4plus watch --interface <name> [--bpf <filter>] [--json|--csv] " +
	"[--types ja4,ja4t] [--lookup] [--stats-interval <seconds>]"

// watchOptions holds every option of the watch command.
//
// The monitor reads each field, and the statistics line of #81 reads `statsInterval`.
// `newMonitor` takes the whole struct, so #81 needs no new parameter.
type watchOptions struct {
	// iface names the interface the monitor reads. FR-capture-2 states the option.
	iface string
	// filter holds the capture filter of the `--bpf` option. FR-capture-3 states it.
	filter string
	// types holds the method tokens that `--types` names. A nil map admits every method,
	// and `admitsResult` states that rule.
	types map[string]bool
	// outputJSON reports whether the operator names the JSON format.
	outputJSON bool
	// outputCSV reports whether the operator names the CSV format.
	outputCSV bool
	// lookup reports whether each fingerprint carries the application of the database.
	lookup bool
	// statsInterval holds the seconds between two statistics lines. A value of 0 writes one
	// line at exit, and FR-capture-9 states that rule.
	statsInterval time.Duration
}

// captureOpener opens a capture handle for the options it takes.
//
// `runWatch` passes `capture.Open`. A test passes a function that opens no interface,
// because a live interface needs a privilege that no test holds.
type captureOpener func(capture.Options) (capture.Handle, error)

// runWatch reads packets from one live interface. FR-capture-1 states the command.
// It returns an error when one option is wrong, and it opens no interface for that command
// line. FR-capture-37 states that order.
// It returns the error of the capture backend when the host opens no handle.
func runWatch(args []string) error {
	return runWatchWithOpener(args, capture.Open)
}

// runWatchWithOpener reads packets from the interface that the opener opens.
//
// It parses every option before it calls the opener, and FR-capture-37 states that order.
// A test passes an opener that counts its calls, because the order of two steps is a fact
// that no message text states.
func runWatchWithOpener(args []string, open captureOpener) error {
	options, err := parseWatchArgs(args)
	if err != nil {
		return err
	}

	return watchInterface(options, open)
}

// parseWatchArgs returns the options that the arguments name.
// It returns an error in three cases.
//   - An option carries no value.
//   - A value names nothing the command accepts.
//   - The arguments name no interface.
func parseWatchArgs(args []string) (watchOptions, error) {
	options := watchOptions{statsInterval: defaultStatsInterval}

	// The parser reads a value from the next argument, as `runAnalyze` does. The two
	// commands then take one option in one form.
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interface":
			value, err := watchOptionValue(args, &i)
			if err != nil {
				return watchOptions{}, err
			}
			options.iface = value
		case "--bpf":
			value, err := watchOptionValue(args, &i)
			if err != nil {
				return watchOptions{}, err
			}
			options.filter = value
		case "--types":
			value, err := watchOptionValue(args, &i)
			if err != nil {
				return watchOptions{}, err
			}
			filter, err := parseTypes(value)
			if err != nil {
				return watchOptions{}, err
			}
			options.types = filter
		case "--stats-interval":
			value, err := watchOptionValue(args, &i)
			if err != nil {
				return watchOptions{}, err
			}
			interval, err := parseStatsInterval(value)
			if err != nil {
				return watchOptions{}, err
			}
			options.statsInterval = interval
		case "--json":
			options.outputJSON = true
		case "--csv":
			options.outputCSV = true
		case "--lookup":
			options.lookup = true
		default:
			return watchOptions{}, fmt.Errorf("unknown option: %s\n%s", args[i], watchUsage)
		}
	}

	if options.iface == "" {
		return watchOptions{}, fmt.Errorf("watch names no interface. --interface takes the name of one interface\n%s", watchUsage)
	}

	return options, nil
}

// watchOptionValue returns the value that follows the option at the index, and it advances
// the index past that value.
// It returns an error when the option carries no value.
func watchOptionValue(args []string, index *int) (string, error) {
	option := args[*index]
	*index++

	if *index >= len(args) {
		return "", fmt.Errorf("%s requires a value\n%s", option, watchUsage)
	}

	return args[*index], nil
}

// parseStatsInterval returns the statistics interval that the value names.
// It returns an error when the value holds no number, and when the number is below zero.
// A negative interval names no schedule, so the command refuses it rather than reading it
// as the default.
func parseStatsInterval(value string) (time.Duration, error) {
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("--stats-interval takes a count of seconds, and it reads %q", value)
	}

	if seconds < 0 {
		return 0, fmt.Errorf("--stats-interval takes a count of seconds that is 0 or more, and it reads %q", value)
	}

	return time.Duration(seconds) * time.Second, nil
}

// watchCaptureOptions returns the capture options that the command options name.
func watchCaptureOptions(options watchOptions) capture.Options {
	return capture.Options{Interface: options.iface, Filter: options.filter}
}

// watchInterface opens one capture handle and runs the monitor on it.
// It returns the error of the capture backend when the host opens no handle.
// It closes the handle before it returns.
//
// The command prints the error that `internal/capture` returns, and it writes no second
// sentence of its own. `CLAUDE.md` `## Conventions` states that the library writes nothing
// to standard output and nothing to standard error, so this call site completes
// FR-capture-26. `main` writes the error to standard error and exits with status 1.
func watchInterface(options watchOptions, open captureOpener) error {
	handle, err := open(watchCaptureOptions(options))
	if err != nil {
		// FR-capture-35 names the capability that the host needs, and FR-capture-36 names
		// `CAP_NET_RAW` on Linux. `capture.PermissionDenied` reads the error chain of the
		// backend, so this branch reads no message text.
		if capture.PermissionDenied(err) {
			return fmt.Errorf("%s: %w", watchPermissionMessage(runtime.GOOS, options.iface), err)
		}

		// The message of the backend reaches the operator unchanged for every other failure.
		return err
	}

	// FR-capture-14 holds one handle for the whole run, and the monitor opens it once.
	defer func() { _ = handle.Close() }()

	return runMonitor(handle, options)
}

// watchPermissionMessage returns the message that the command writes when the host refuses
// the capture handle. FR-capture-35 states the message, and it names the capability that
// the host needs.
//
// The platforms get three messages, because the repair differs. Linux states a capability,
// and FR-capture-36 names `CAP_NET_RAW`. macOS states no capability, and `bpf(4)` names
// the device that libpcap opens. Every other platform reads one sentence that names the
// platform, as `unsupportedMessage` of `internal/capture/unsupported.go` does.
//
// The Linux text follows `docs/specs/mockups/03-watch-output.html`, which names the
// capability and the `setcap` command. `$(which ja4plus)` writes the path of the program
// that the operator runs, so the operator copies the command without an edit.
func watchPermissionMessage(goos string, iface string) string {
	switch goos {
	case "linux":
		return fmt.Sprintf(
			"the monitor needs CAP_NET_RAW to open interface %s on this host. "+
				"Run the command with sudo. "+
				"The command sudo setcap cap_net_raw+ep $(which ja4plus) grants the capability instead",
			iface)
	case "darwin":
		return fmt.Sprintf(
			"the monitor needs read access to a /dev/bpf device to open interface %s on this host. "+
				"Run the command with sudo", iface)
	default:
		return fmt.Sprintf(
			"the monitor needs the privilege of a packet capture to open interface %s on %s. "+
				"Run the command with sudo", iface, goos)
	}
}

// runMonitor reads packets from the handle until a termination signal stops the run.
//
// It returns the error of the capture backend when a read fails, which the edge-case
// table of `docs/specs/features/13-live-capture.md` names for an interface that the host
// removes. It returns nil for a run that a termination signal stopped, so the exit status
// of that run is 0.
// It installs one handler for each termination signal, and it removes no handler, because
// the process ends when this function returns.
func runMonitor(handle capture.Handle, options watchOptions) error {
	return newMonitor(options, installWatchStopHandler(), os.Stdout, os.Stderr, time.Now).run(handle)
}

// The monitor loop, the signals and the connection table. Issue #80 builds them, and
// FR-capture-16 through FR-capture-23 state the work.
//
// One goroutine owns the `Processor`, the capture handle and the connection table. That
// goroutine is the loop of `monitor.run`, and no other goroutine reaches any of the three.
// So the packet path takes no lock, and FR-capture-16 states that requirement.
// `.claude/rules/concurrency.md` `## The contract` states the model.
//
// The signal handler runs on a second goroutine, and it reaches the `Processor` never. It
// sets one flag that the loop reads after each packet.

// terminationSignals returns the signals that set the stop request.
// FR-capture-18 names SIGINT and SIGTERM.
// The function returns a new slice on each call, so no caller changes what a later caller
// reads.
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// watchSecondSignalStatus is the exit status of a run that a second termination signal
// ends on a platform that sends no signal to itself.
// That run loses the open windows of FR-capture-20, so the status reports a failure. No
// requirement states this number, and issue #80 is the reversal path.
const watchSecondSignalStatus = 1

// stopRequest holds the flag that a termination signal sets and that the monitor loop
// reads.
//
// The signal handler writes the flag on one goroutine and the loop reads it on another,
// so the flag is an atomic value. FR-capture-16 bars a lock on the packet path, and an
// atomic read costs no lock.
type stopRequest struct {
	requested atomic.Bool
}

// request sets the stop request, and it returns.
// The handler does the least work a handler can do. A handler that ended the process
// would truncate the line the monitor is writing, and it would lose the open windows that
// FR-capture-20 prints.
func (s *stopRequest) request() {
	s.requested.Store(true)
}

// isRequested reports whether a termination signal arrived.
func (s *stopRequest) isRequested() bool {
	return s.requested.Load()
}

// installWatchStopHandler returns the stop request that a termination signal sets, and it
// starts the goroutine that reads the signals.
func installWatchStopHandler() *stopRequest {
	stop := &stopRequest{}

	// The buffer holds two signals. The handler reads the first one, and it then drains a
	// second one that arrived before the reset. `os/signal` states that Notify never
	// blocks on the send, so a smaller buffer drops the second signal.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, terminationSignals()...)

	go watchStopHandler(
		signals,
		stop,
		func() { signal.Reset(terminationSignals()...) },
		raiseSignal,
		os.Exit,
	)

	return stop
}

// watchStopHandler reads the termination signals of the channel, and it stops the run.
//
// The first signal sets the stop request and restores the default disposition of each
// termination signal. A second signal then reaches the kernel default, which ends the
// process at once. FR-capture-19 states that requirement, and the edge-case table of
// `docs/specs/features/13-live-capture.md` states that the run loses the open windows.
//
// `os/signal` states both halves of that mechanism. `Notify` "disables the default
// behavior for a given set of asynchronous signals and instead delivers them over one or
// more registered channels", and `Reset` "will restore the system default behavior for
// the signal". The package also states the default behavior: "A SIGHUP, SIGINT, or
// SIGTERM signal causes the program to exit."
// Verified against: <https://pkg.go.dev/os/signal>, read from `go doc os/signal` at
// go1.26.5 on 2026-08-14.
//
// A second signal that arrives before the reset lands in the channel buffer, and the
// reset then ends the delivery of it. The drain reads that signal and raises it again, so
// the window between the two calls loses no second signal.
func watchStopHandler(
	signals <-chan os.Signal,
	stop *stopRequest,
	reset func(),
	raise func(os.Signal) error,
	exit func(int),
) {
	<-signals

	stop.request()
	reset()

	select {
	case second := <-signals:
		if err := raise(second); err != nil {
			// A platform that raises no signal still ends the run at once, because
			// FR-capture-19 states the exit and it states no mechanism.
			exit(watchSecondSignalStatus)
		}
	default:
	}
}

// raiseSignal sends the signal to this process again.
// It returns an error on a platform that sends no such signal to itself. Windows is that
// platform, and FR-capture-25 reports that the monitor is unsupported there.
func raiseSignal(sig os.Signal) error {
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}

	return process.Signal(sig)
}

// maxMonitorConnections is the maximum count of connections the table holds.
// The insert that reaches this count removes the connection that sent no packet for the
// longest time. FR-capture-23 states the bound.
// `.claude/rules/parity.md` rule 2 states that the port decides the interface where this
// project shipped nothing, and no FoxIO source addresses a state table.
// `ja4plus/watch.py:83` of the port sets `DEFAULT_MAX_CONNECTIONS = 10000`.
const maxMonitorConnections = 10000

// monitorIdleTimeout is the time a connection may send no packet before the monitor
// evicts it. FR-capture-22 states 5 minutes, and `ja4plus/watch.py:89` of the port sets
// `DEFAULT_CONNECTION_TIMEOUT = 300.0`.
const monitorIdleTimeout = 5 * time.Minute

// connectionKey names one connection of the monitor table.
//
// The monitor sorts the two endpoints, so a packet and its reply reach one entry.
// `Processor.CleanupConnection` accepts the two endpoints in either order, and
// `Processor.GetShardKey` sorts the same pair for the same reason.
type connectionKey struct {
	// proto names the transport protocol, in the spelling that `GetShardKey` writes.
	proto string
	// srcIP holds the lower address of the sorted pair.
	srcIP string
	// srcPort holds the port of the lower address.
	srcPort uint16
	// dstIP holds the higher address of the sorted pair.
	dstIP string
	// dstPort holds the port of the higher address.
	dstPort uint16
}

// connectionRecord holds one entry of the connection table.
type connectionRecord struct {
	// key names the connection.
	key connectionKey
	// lastSeen holds the time the connection last sent a packet. FR-capture-21 states
	// that record.
	lastSeen time.Time
}

// connectionTable records the time each connection last sent a packet.
//
// FR-capture-21 states the record, FR-capture-22 states the idle timeout, and
// FR-capture-23 states the entry bound.
//
// One goroutine owns one table, and the table takes no lock. The monitor loop is that
// goroutine. `.claude/rules/concurrency.md` `## The contract` states the same model for
// `Processor`.
//
// The list holds the least recently seen connection at the front. The monitor reads one
// clock for every packet and that clock never goes backwards, so the list order follows
// the last-seen time exactly. An idle pass therefore stops at the first connection that
// is not idle.
type connectionTable struct {
	// entries maps each connection to its element of the order list.
	entries map[connectionKey]*list.Element
	// order holds one element for each entry, least recently seen first.
	order *list.List
	// evict runs for each connection the table removes. The monitor passes the call that
	// reaches `Processor.CleanupConnection`.
	evict func(connectionKey)
	// idle holds the time a connection may send no packet before the table evicts it.
	idle time.Duration
	// bound holds the maximum count of entries.
	bound int
}

// newConnectionTable returns an empty table that holds the bound and the idle timeout.
// It calls the eviction function for each connection it removes, on either bound.
func newConnectionTable(bound int, idle time.Duration, evict func(connectionKey)) *connectionTable {
	return &connectionTable{
		entries: make(map[connectionKey]*list.Element),
		order:   list.New(),
		evict:   evict,
		idle:    idle,
		bound:   bound,
	}
}

// observe records that the connection sent a packet at the time the caller names.
// It refreshes a connection the table already holds, and it moves that connection to the
// back of the order list.
// It removes the connection that sent no packet for the longest time when the insert
// reaches the entry bound. FR-capture-23 states that removal.
func (t *connectionTable) observe(key connectionKey, now time.Time) {
	if element, held := t.entries[key]; held {
		if record, ok := element.Value.(*connectionRecord); ok {
			record.lastSeen = now
		}

		t.order.MoveToBack(element)

		return
	}

	for len(t.entries) >= t.bound {
		front := t.order.Front()
		if front == nil {
			break
		}

		t.remove(front)
	}

	t.entries[key] = t.order.PushBack(&connectionRecord{key: key, lastSeen: now})
}

// evictIdle removes every connection that sent no packet for the idle timeout.
// FR-capture-22 states the removal, and the default timeout is 5 minutes.
//
// The pass stops at the first connection that is not idle, so it costs the count it
// removes rather than the count the table holds. The monitor reads one clock for every
// packet, so the order list follows the last-seen time and no later element is older.
// A pass this cheap runs on every packet, which needs no eviction interval.
func (t *connectionTable) evictIdle(now time.Time) {
	for {
		front := t.order.Front()
		if front == nil {
			return
		}

		record, ok := front.Value.(*connectionRecord)
		if !ok {
			t.order.Remove(front)
			continue
		}

		if now.Sub(record.lastSeen) <= t.idle {
			return
		}

		t.remove(front)
	}
}

// remove drops one entry of the table, and it calls the eviction function for it.
//
// It is the one removal path of the table. `.claude/rules/concurrency.md` states that a
// state map holds a removal path, and one path keeps the map and the list in step.
func (t *connectionTable) remove(element *list.Element) {
	t.order.Remove(element)

	record, ok := element.Value.(*connectionRecord)
	if !ok {
		return
	}

	delete(t.entries, record.key)
	t.evict(record.key)
}

// len returns the count of connections the table holds.
// The statistics line of #81 reports this count, and FR-capture-32 states that field.
func (t *connectionTable) len() int {
	return len(t.entries)
}

// monitorConnectionKey returns the key of the connection the packet names.
//
// It returns false for a packet that carries neither TCP nor UDP, because the processor
// holds no per-connection state for such a packet.
// It reads the grouping address pair, which is the pair that `Processor.GetShardKey`
// reads. A mirror sends both directions of one session from one outer pair, and the
// grouping pair separates the two connections.
//
// **This function and `Processor.GetShardKey` in `processor.go` hold one grouping rule in
// two copies, and they differ in the return shape alone.** Each one reads
// `parser.GetGroupingIPInfo`, each one takes the same TCP branch and the same UDP branch,
// and each one applies the sort below. This function returns a `connectionKey`, and
// `GetShardKey` returns a formatted string.
//
// **A change to the grouping rule changes both, and a change to one alone splits them.**
// `GetShardKey` is exported and `.claude/rules/concurrency.md` names it, so the exported
// rule decides and this function follows it. The Epic 13 cross-member review found the
// pair, and issue #614 holds the reading. **The round wrote this comment and it moved no
// code**, because a shared helper changes the exported package and the freeze of #100
// reaches that surface.
// Every packet is untrusted input, so this function reads the decoded layers and it
// slices no byte of its own.
func monitorConnectionKey(packet gopacket.Packet) (connectionKey, bool) {
	srcIP, dstIP, ok := parser.GetGroupingIPInfo(packet)
	if !ok || srcIP == "" {
		return connectionKey{}, false
	}

	var srcPort, dstPort uint16

	var proto string

	if tcp := parser.GetTCPLayer(packet); tcp != nil {
		srcPort, dstPort, proto = uint16(tcp.SrcPort), uint16(tcp.DstPort), "tcp"
	} else if udp := parser.GetUDPLayer(packet); udp != nil {
		srcPort, dstPort, proto = uint16(udp.SrcPort), uint16(udp.DstPort), "udp"
	} else {
		return connectionKey{}, false
	}

	// The sort gives both directions of one connection one entry, so one eviction removes
	// the state of the whole connection.
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return connectionKey{proto: proto, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}, true
}

// monitorCounters holds the counts that the statistics line of #81 reports.
//
// The monitor loop writes each field and the statistics goroutine of #81 reads it, so
// each field is an atomic value. FR-capture-16 bars a lock on the packet path, and an
// atomic store costs no lock. **This struct is the seam of #81**: that goroutine reads
// these three counters, and it reaches the `Processor` and the connection table never.
type monitorCounters struct {
	// packets counts the packets the monitor read. FR-capture-29 reports it.
	packets atomic.Uint64
	// fingerprints counts the results the processor returned. FR-capture-30 reports it.
	fingerprints atomic.Uint64
	// connections holds the entry count of the connection table. FR-capture-32 reports it.
	connections atomic.Uint64
	// drops holds the count of packets the capture backend dropped, and it holds
	// `dropCountUnknown` when the backend reports no count. FR-capture-31 reports it, and
	// the goroutine that owns the capture handle writes it.
	drops atomic.Uint64
}

// monitor holds the state of one watch run.
//
// One goroutine owns the monitor, and that goroutine owns the `Processor`, the capture
// handle and the connection table. FR-capture-16 states that ownership, and the monitor
// therefore needs no `SyncProcessor`.
type monitor struct {
	// processor fingerprints each packet. The monitor owns it, and no other goroutine
	// reaches it.
	processor *ja4plus.Processor
	// table records the time each connection last sent a packet.
	table *connectionTable
	// stop holds the flag that a termination signal sets.
	stop *stopRequest
	// counters holds the counts that #81 reports.
	counters *monitorCounters
	// now reads the clock of the monitor. A test passes a clock of its own.
	// The statistics goroutine reads this clock too, so a test passes a clock that two
	// goroutines call.
	now func() time.Time
	// startedAt holds the time the run started. FR-capture-28 reports the time since it.
	startedAt time.Time
	// lastDropSample holds the time the loop last read the drop count of the handle.
	lastDropSample time.Time
	// results writes each fingerprint to standard output.
	results resultWriter
	// errOut takes the diagnostic output. FR-capture-7 sends the statistics line there,
	// and the stop message joins it.
	errOut io.Writer
	// options holds the option set of the command line.
	options watchOptions
	// packetFails counts the packets that carried a record no fingerprinter read.
	packetFails int
}

// newMonitor returns a monitor that writes fingerprints to the output writer and
// diagnostics to the error writer.
//
// The clock is the clock of the monitor rather than the timestamp of the packet. A live
// capture reads a host clock for both, so the two agree on every ordinary packet. They
// separate on a packet whose timestamp the capture cannot trust: an age pass that read a
// packet timestamp far in the future would evict the whole table from one packet. Issue
// #577 records that property in four offline sites, and it awaits a ruling. **This table
// is new, so it takes the clock that reaches no such packet.** The offline path of
// `runAnalyze` keeps the packet timestamp, because a capture file replays faster than
// real time and a host clock would evict every connection of it.
// The clock also gives the eviction pass its early exit. The `time` package states that
// `the Time returned by time.Now contains both a wall clock reading and a monotonic clock
// reading`, and that `later time-measuring operations, specifically comparisons and
// subtractions, use the monotonic clock reading`. So the clock of the pass never goes
// backwards, and the order list follows the age even when the wall clock of the host
// moves.
// Verified against: <https://pkg.go.dev/time>, read from `go doc time` at go1.26.5 on
// 2026-08-14.
func newMonitor(
	options watchOptions,
	stop *stopRequest,
	out io.Writer,
	errOut io.Writer,
	now func() time.Time,
) *monitor {
	started := now()

	instance := &monitor{
		processor:      ja4plus.NewProcessor(),
		stop:           stop,
		counters:       &monitorCounters{},
		now:            now,
		startedAt:      started,
		lastDropSample: started,
		results:        newResultWriter(out, options),
		errOut:         errOut,
		options:        options,
	}

	instance.table = newConnectionTable(maxMonitorConnections, monitorIdleTimeout, instance.dropConnection)

	return instance
}

// dropConnection removes the per-connection state of every fingerprinter for one evicted
// connection. FR-capture-22 names `CleanupConnection`.
//
// `Processor.CloseConnectionWindow` would emit the window that the evicted connection
// holds open, and FR-capture-22 names it never. So an idle connection loses its open
// window, and issue #216 records the ruling that keeps `CleanupConnection` silent.
func (m *monitor) dropConnection(key connectionKey) {
	m.processor.CleanupConnection(key.srcIP, key.srcPort, key.dstIP, key.dstPort, key.proto)
}

// run reads packets from the handle until a termination signal stops the run, and it
// writes the statistics line.
//
// It returns the error of a failed read, and the edge-case table of
// `docs/specs/features/13-live-capture.md` names one message and exit status 1 for it.
// It returns nil when the stop request stops the run, and when the handle reports the end
// of the stream.
// It closes no handle, because `watchInterface` opened it and closes it.
//
// The statistics goroutine returns before this method writes the open windows, so the two
// goroutines write the error writer in order and take no lock. `statistics.go` states that
// design.
func (m *monitor) run(handle capture.Handle) error {
	// The first sample gives the first statistics line a count, because the loop samples
	// again only after `dropSampleInterval`.
	m.sampleDropCount(handle)

	stopStatistics := m.startStatisticsWriter()

	err := m.readPackets(handle)

	stopStatistics()
	m.sampleDropCount(handle)

	if err == nil {
		err = m.close()
	}

	// FR-capture-9 writes one statistics line at exit, and a statistics interval of 0
	// writes that line alone. The line follows the open windows, as the user flow of
	// `docs/specs/features/13-live-capture.md` states.
	// A run that a failed read ended writes the line too, because the line reports the
	// counts of the run and never the result of it.
	if statsErr := m.writeStatisticsLine(); statsErr != nil && err == nil {
		err = statsErr
	}

	return err
}

// readPackets reads packets from the handle until a termination signal stops the run.
//
// It returns the error of a failed read, and it returns nil for a run that the stop
// request stopped. It writes no statistics line, because `run` owns that line.
//
// **A read blocks until the interface delivers a packet.** Both capture backends block,
// because #78 passed `pcap.BlockForever` deliberately so that the two behave the same.
// So the loop reads the stop request after each packet, which FR-capture-17 states, and
// an interface that carries no traffic reaches that read never. The second signal of
// FR-capture-19 is the exit of that run.
func (m *monitor) readPackets(handle capture.Handle) error {
	linkType := handle.LinkType()

	if err := m.results.header(); err != nil {
		return err
	}

	for {
		data, info, err := handle.ReadPacketData()

		// The handle reports the end of the stream with io.EOF. A live interface reports
		// it never, and a test handle reports it after the last canned packet.
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			// A failed read emits no open window, and it loses the last window of every
			// connection. FR-capture-20 names the stop request, and this path holds no
			// stop request. The edge-case table of
			// `docs/specs/features/13-live-capture.md` names one message and exit status 1
			// for the interface that the host removes, and it names no emission.
			// `runAnalyze` returns on a failed read the same way, so one rule covers the
			// two commands: **a capture that fails emits nothing that a reader would take
			// for a complete result.**
			// The flush still runs, so a writer that holds a row in a buffer writes it.
			if flushErr := m.results.flush(); flushErr != nil {
				return flushErr
			}

			return fmt.Errorf("read %s: %w", m.options.iface, err)
		}

		if err := m.handlePacket(data, info, linkType); err != nil {
			return err
		}

		// A read of the drop count costs one system call, so the loop bounds the rate of
		// it. FR-capture-31 reports the count, and this loop owns the handle that holds it.
		if now := m.now(); now.Sub(m.lastDropSample) >= dropSampleInterval {
			m.lastDropSample = now

			m.sampleDropCount(handle)
		}

		// FR-capture-17 reads the stop request after the packet, so the monitor finishes
		// the packet it holds and no packet is half-processed.
		if m.stop.isRequested() {
			break
		}
	}

	return nil
}

// handlePacket reads one packet: it records the connection, evicts what either bound
// removes, and then fingerprints the packet.
//
// The record precedes the eviction pass, so the pass never evicts the connection of the
// packet that just arrived.
func (m *monitor) handlePacket(data []byte, info gopacket.CaptureInfo, linkType layers.LinkType) error {
	packet := gopacket.NewPacket(data, linkType, gopacket.Default)
	packet.Metadata().Timestamp = info.Timestamp
	packet.Metadata().CaptureLength = info.CaptureLength
	packet.Metadata().Length = info.Length

	m.counters.packets.Add(1)

	now := m.now()

	if key, held := monitorConnectionKey(packet); held {
		m.table.observe(key, now)
	}

	m.table.evictIdle(now)
	m.counters.connections.Store(uint64(m.table.len()))

	results, errs := m.processor.ProcessPacket(packet)
	m.packetFails += len(errs)

	return m.writeResults(results)
}

// writeResults writes each result the type filter admits, and it counts every result.
// FR-capture-30 counts the results the processor returned, so the count precedes the
// filter.
func (m *monitor) writeResults(results []ja4plus.FingerprintResult) error {
	for _, result := range results {
		m.counters.fingerprints.Add(1)

		if !admitsResult(m.options.types, result) {
			continue
		}

		if err := m.results.write(result); err != nil {
			return err
		}
	}

	return nil
}

// close ends the run: it prints the open windows and the note of the failed records.
//
// FR-capture-20 calls `Processor.CloseOpenWindows` after the stop request, because no
// packet emits the last window of a connection. A run that the second signal of
// FR-capture-19 ends reaches this method never, and it loses those windows.
func (m *monitor) close() error {
	if m.stop.isRequested() {
		if _, err := fmt.Fprintln(m.errOut, "ja4plus: stopping, closing open windows"); err != nil {
			return err
		}
	}

	if err := m.writeResults(m.processor.CloseOpenWindows()); err != nil {
		return err
	}

	// A fingerprinter returns a non-fatal error for a record it cannot read. One line for
	// the whole run reaches standard error, so standard output holds the fingerprints
	// alone. `runAnalyze` writes the same note for the same reason.
	if m.packetFails > 0 {
		if _, err := fmt.Fprintf(m.errOut, "note: %d packets carried a record that no fingerprinter read\n", m.packetFails); err != nil {
			return err
		}
	}

	return m.results.flush()
}

// resultWriter writes one fingerprint to standard output, in the format the options name.
// FR-capture-5 states that the format options match the capture-file command.
type resultWriter interface {
	// header writes whatever the format writes before the first fingerprint.
	header() error
	// write writes one fingerprint, and it reaches the reader of a running monitor.
	write(result ja4plus.FingerprintResult) error
	// flush writes whatever the format holds in a buffer.
	flush() error
}

// newResultWriter returns the writer of the format that the options name.
func newResultWriter(out io.Writer, options watchOptions) resultWriter {
	switch {
	case options.outputJSON:
		return &jsonResultWriter{out: out, lookup: options.lookup}
	case options.outputCSV:
		return &csvResultWriter{writer: csv.NewWriter(out), lookup: options.lookup}
	default:
		return &textResultWriter{out: out, lookup: options.lookup}
	}
}

// monitorApplication returns the application that the database holds for the fingerprint,
// and an empty string for a fingerprint the database does not hold.
func monitorApplication(fingerprint string, lookup bool) string {
	if !lookup {
		return ""
	}

	if record := ja4plus.LookupFingerprint(fingerprint); record != nil {
		return record.Application
	}

	return ""
}

// monitorTypeWidth is the column width of the method name of one text line.
// The widest token of `methodTokens` is `ja4ssh`, which holds six characters.
const monitorTypeWidth = 6

// textResultWriter writes one aligned line for each fingerprint.
//
// The writer pads the method column to a fixed width. `runAnalyze` aligns its table with
// a `tabwriter`, which reads every row before it writes the first one. A monitor writes
// each line as the packet arrives, so it holds no row back.
type textResultWriter struct {
	out    io.Writer
	lookup bool
}

func (w *textResultWriter) header() error { return nil }

func (w *textResultWriter) write(result ja4plus.FingerprintResult) error {
	source := fmt.Sprintf("%s:%d", result.SrcIP, result.SrcPort)
	destination := fmt.Sprintf("%s:%d", result.DstIP, result.DstPort)

	if !w.lookup {
		_, err := fmt.Fprintf(w.out, "%-*s  %s -> %s  %s\n",
			monitorTypeWidth, result.Type, source, destination, result.Fingerprint)

		return err
	}

	_, err := fmt.Fprintf(w.out, "%-*s  %s -> %s  %s  %s\n",
		monitorTypeWidth, result.Type, source, destination, result.Fingerprint,
		monitorApplication(result.Fingerprint, w.lookup))

	return err
}

func (w *textResultWriter) flush() error { return nil }

// jsonResultWriter writes one JSON object for each fingerprint, on one line.
//
// `runAnalyze` writes one array, because a capture file ends and the array closes. A
// monitor has no end until the operator stops it, so an array would reach the reader at
// exit alone. One object per line reaches the reader of a running monitor.
type jsonResultWriter struct {
	out    io.Writer
	lookup bool
}

func (w *jsonResultWriter) header() error { return nil }

func (w *jsonResultWriter) write(result ja4plus.FingerprintResult) error {
	record := jsonResult{
		Type:        result.Type,
		SrcIP:       result.SrcIP,
		SrcPort:     result.SrcPort,
		DstIP:       result.DstIP,
		DstPort:     result.DstPort,
		Fingerprint: result.Fingerprint,
		Timestamp:   result.Timestamp.Format(time.RFC3339),
		Application: monitorApplication(result.Fingerprint, w.lookup),
	}

	// The encoder writes one newline after each value, so each object holds one line.
	return json.NewEncoder(w.out).Encode(record)
}

func (w *jsonResultWriter) flush() error { return nil }

// csvResultWriter writes the header and then one row for each fingerprint.
//
// The writer flushes each row, because the reader of a running monitor reads a row that
// sits in a buffer never.
type csvResultWriter struct {
	writer *csv.Writer
	lookup bool
}

func (w *csvResultWriter) header() error {
	header := []string{"type", "src_ip", "src_port", "dst_ip", "dst_port", "fingerprint", "timestamp"}
	if w.lookup {
		header = append(header, "application")
	}

	if err := w.writer.Write(header); err != nil {
		return err
	}

	w.writer.Flush()

	return w.writer.Error()
}

func (w *csvResultWriter) write(result ja4plus.FingerprintResult) error {
	row := []string{
		result.Type,
		result.SrcIP,
		strconv.FormatUint(uint64(result.SrcPort), 10),
		result.DstIP,
		strconv.FormatUint(uint64(result.DstPort), 10),
		result.Fingerprint,
		result.Timestamp.Format(time.RFC3339),
	}

	if w.lookup {
		row = append(row, monitorApplication(result.Fingerprint, w.lookup))
	}

	if err := w.writer.Write(row); err != nil {
		return err
	}

	w.writer.Flush()

	return w.writer.Error()
}

func (w *csvResultWriter) flush() error {
	w.writer.Flush()

	return w.writer.Error()
}
