package main

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/Crank-Git/ja4plus-go/internal/capture"
	"github.com/Crank-Git/ja4plus-go/scan"
)

// scanUsage names every option of the scan command. Each name and each default comes from
// the FoxIO wrapper, through `ja4plus/scan/command.py` of `Crank-Git/ja4plus` at tag
// `v1.3.0`. Parity rule 2 makes the port the reference for this interface.
const scanUsage = "Usage: ja4plus scan <target> [--port <port>] [--rate <syn/s>] [--retransmit yes|no] " +
	"[--format table|json|csv] [--output <file>] [--force]"

// scanMethodType is the `type` value of a scan result. FR-active-scan-17 of the port names it.
const scanMethodType = "ja4tscan"

// The defaults of the FoxIO wrapper. S16 of the port's `docs/specs/foxio/JA4TScan.md` at
// tag `v1.3.0` records them.
const (
	scanDefaultPort = 80
	scanDefaultRate = 10.0
)

// scanExitInterrupted is the exit status after a signal stops the scan. A shell reports
// 128 plus the signal number for a program that SIGINT ends.
const scanExitInterrupted = 130

// scanStopCheckInterval bounds one receive, so a stop request ends the wait within this
// time. It matches the read deadline of the monitor.
const scanStopCheckInterval = 250 * time.Millisecond

// errScanInterrupted reports that the operator stopped the scan.
var errScanInterrupted = errors.New("the operator stopped the scan")

// scanOptions holds every option of the scan command.
type scanOptions struct {
	target     string
	port       uint16
	rate       float64
	retransmit bool
	format     string
	output     string
	force      bool
}

// scanEnvironment holds what the scan command reads from the host. `runScan` passes the
// host, and a test passes a fake network, so no test opens a socket.
type scanEnvironment struct {
	stdout      io.Writer
	stderr      io.Writer
	goos        string
	openNetwork func(port uint16, first netip.Addr, warn func(string)) (scan.Network, error)
	clock       func() time.Time
	rand        *rand.Rand
	// stopped reports whether the operator asked the scan to stop. Nil never stops.
	stopped func() bool
}

// runScan runs the scan command on the network of this host, and it exits the process.
func runScan(args []string) {
	os.Exit(runScanWithStopHandler(args, installWatchStopHandler, scanEnvironment{
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		goos:        runtime.GOOS,
		openNetwork: scan.OpenNetwork,
		clock:       time.Now,
	}))
}

// runScanWithStopHandler runs the scan command under the stop handler that install
// returns, and it returns the exit status.
//
// The scan uses the stop handler of the monitor. The first signal stops the send loop, and
// a second signal reaches the default disposition and ends the process at once. The release
// runs before the return, so no registration outlives the scan.
func runScanWithStopHandler(args []string, install func() (*stopRequest, func()), env scanEnvironment) int {
	stop, release := install()
	defer release()

	env.stopped = stop.isRequested

	return runScanCommand(args, env)
}

// parseScanArgs returns the options of the command line. It returns an error that names the
// option for a value outside the range of that option.
func parseScanArgs(args []string) (scanOptions, error) {
	options := scanOptions{port: scanDefaultPort, rate: scanDefaultRate, retransmit: true, format: "table"}

	for index := 0; index < len(args); index++ {
		argument := args[index]

		switch argument {
		case "--force":
			options.force = true

			continue
		case "--port", "--rate", "--retransmit", "--format", "--output":
		default:
			if options.target != "" || (len(argument) > 0 && argument[0] == '-') {
				return options, fmt.Errorf("unknown option: %s\n%s", argument, scanUsage)
			}

			options.target = argument

			continue
		}

		index++
		if index >= len(args) {
			return options, fmt.Errorf("%s requires a value\n%s", argument, scanUsage)
		}

		if err := options.set(argument, args[index]); err != nil {
			return options, err
		}
	}

	if options.target == "" {
		return options, fmt.Errorf("missing target argument\n%s", scanUsage)
	}

	return options, nil
}

// set stores the value of one option that takes a value.
func (o *scanOptions) set(option, value string) error {
	switch option {
	case "--port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("--port takes a port from 1 to 65535, and %q is none", value)
		}

		o.port = uint16(port)
	case "--rate":
		rate, err := strconv.ParseFloat(value, 64)
		if err != nil || !(rate > 0) || math.IsInf(rate, 0) {
			return fmt.Errorf("--rate takes a finite number above zero, and %q is none", value)
		}

		// A rate below about 1.1e-10 gives an interval that a time.Duration cannot hold, and
		// the conversion then gives a wrong interval. The port checks no such bound, because
		// a Python float holds the interval.
		if float64(time.Second)/rate >= math.MaxInt64 {
			return fmt.Errorf("--rate %q gives an interval between two SYNs above %v, and the scan holds no longer interval",
				value, time.Duration(math.MaxInt64))
		}

		o.rate = rate
	case "--retransmit":
		if value != "yes" && value != "no" {
			return fmt.Errorf("--retransmit takes yes or no, and %q is neither", value)
		}

		o.retransmit = value == "yes"
	case "--format":
		if value != "table" && value != "json" && value != "csv" {
			return fmt.Errorf("--format takes table, json or csv, and %q is none", value)
		}

		o.format = value
	case "--output":
		o.output = value
	}

	return nil
}

// runScanCommand runs the scan command and returns the exit status.
//
// The command reads every target and opens the network before it writes the firewall rules.
// So an unreadable target or a refused privilege stops the scan before the first SYN. The
// command changes no firewall state: it writes the rules, and the operator applies them.
func runScanCommand(args []string, env scanEnvironment) int {
	fail := func(format string, values ...any) int {
		_, _ = fmt.Fprintf(env.stderr, format+"\n", values...)
		return 1
	}

	options, err := parseScanArgs(args)
	if err != nil {
		return fail("error: %v", err)
	}

	targets, err := scan.ParseTargets(options.target)
	if err != nil {
		return fail("Error: %v. The scan sent nothing.", err)
	}

	next, stopTargets := iter.Pull(targets)
	defer stopTargets()

	first, held := next()
	if !held {
		return fail("Error: the target %q names no address. The scan sent nothing.", options.target)
	}

	out, closeOutput, err := openScanOutput(options, env.stdout)
	if err != nil {
		return fail("Error: %v. The scan sent nothing.", err)
	}
	defer closeOutput()

	warn := func(line string) { _, _ = fmt.Fprintln(env.stderr, line) }

	network, err := env.openNetwork(options.port, first, warn)
	if err != nil {
		return fail("%s", scanOpenMessage(err, options.target))
	}
	defer func() { _ = network.Close() }()

	// FR-active-scan-8 of the port writes the rules before the first SYN. The mode without
	// retransmissions reads the first response alone, so a kernel RST changes no value there
	// and the mode writes no rule.
	if options.retransmit {
		_, _ = fmt.Fprintln(env.stderr, scan.FirewallRules(env.goos))
	}

	return scanTargets(options, env, network, out, first, next)
}

// scanTargets runs the scanner over the targets and writes each result to the output.
func scanTargets(options scanOptions, env scanEnvironment, network scan.Network, out io.Writer,
	first netip.Addr, next func() (netip.Addr, bool),
) int {
	// The scan takes no lookup option, so the writer receives no identifier.
	writer := newResultWriter(out, watchOptions{outputJSON: options.format == "json", outputCSV: options.format == "csv"}, nil)
	if err := writer.header(); err != nil {
		_, _ = fmt.Fprintf(env.stderr, "Error: the result stream takes no header: %v\n", err)
		return 1
	}

	var writeErr error

	scanner, err := scan.NewScanner(scan.Config{
		Port:       options.port,
		Rate:       options.rate,
		Retransmit: options.retransmit,
		Network:    stoppableNetwork{Network: network, stopped: env.stopped},
		Clock:      env.clock,
		OnResult: func(result scan.Result) {
			if writeErr == nil {
				writeErr = writer.write(scanFingerprintResult(result))
			}
		},
		OnWarning: func(line string) { _, _ = fmt.Fprintln(env.stderr, line) },
		Rand:      env.rand,
	})
	if err != nil {
		_, _ = fmt.Fprintf(env.stderr, "Error: %v\n", err)
		return 1
	}

	runErr := scanner.Run(func(yield func(netip.Addr) bool) {
		for target, held := first, true; held; target, held = next() {
			if !yield(target) {
				return
			}
		}
	})

	if errors.Is(runErr, errScanInterrupted) {
		// The operator stopped the wait, so each target writes what it already sent.
		scanner.Flush()
	}

	if err := writer.flush(); err != nil && writeErr == nil {
		writeErr = err
	}

	switch {
	case errors.Is(runErr, errScanInterrupted):
		return scanExitInterrupted
	case runErr != nil:
		// A downed interface or a full send buffer fails a socket call. Every result written
		// before the failure stays in the result stream.
		_, _ = fmt.Fprintf(env.stderr, "Error: the scan stopped: %v\n", runErr)
		return 1
	case writeErr != nil:
		_, _ = fmt.Fprintf(env.stderr, "Error: the result stream takes no result: %v\n", writeErr)
		return 1
	}

	return 0
}

// scanFingerprintResult returns the output record of one scan result. The target sent the
// responses that the value reads, so the target is the source.
func scanFingerprintResult(result scan.Result) ja4plus.FingerprintResult {
	return ja4plus.FingerprintResult{
		Fingerprint: result.Value,
		Type:        scanMethodType,
		SrcIP:       result.Target.String(),
		SrcPort:     result.TargetPort,
		DstIP:       result.Scanner.String(),
		DstPort:     result.ScannerPort,
		Timestamp:   result.Time.UTC(),
	}
}

// scanOpenMessage returns the message for a network that did not open.
func scanOpenMessage(err error, target string) string {
	if capture.PermissionDenied(err) {
		return "Error: ja4plus scan has no privilege to open a raw socket.\n" +
			"Linux grants the privilege through the CAP_NET_RAW capability.\n" +
			"macOS grants the privilege through write access to the /dev/bpf* devices.\n" +
			"Try: sudo ja4plus scan " + target + "\n" +
			"The socket layer reported: " + err.Error()
	}

	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		return "Error: ja4plus scan could not open a raw socket: " + err.Error()
	}

	return "Error: " + err.Error()
}

// openScanOutput returns the result stream. A file that exists stays untouched unless the
// operator names `--force`.
func openScanOutput(options scanOptions, stdout io.Writer) (io.Writer, func(), error) {
	if options.output == "" {
		return stdout, func() {}, nil
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if options.force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	file, err := os.OpenFile(options.output, flags, 0o644)
	if errors.Is(err, os.ErrExist) {
		return nil, nil, fmt.Errorf("the output file %s exists, and --force replaces it", options.output)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("open the output file: %w", err)
	}

	return file, func() { _ = file.Close() }, nil
}

// stoppableNetwork returns errScanInterrupted from a send or a receive once the operator
// asks the scan to stop. The scanner then returns, and the command writes each result it
// holds.
//
// The send also reads the stop request. A scanner that falls behind its send schedule calls
// no receive between two SYNs, so a check in the receive alone lets the whole target list go
// out after the stop request.
type stoppableNetwork struct {
	scan.Network
	stopped func() bool
}

func (n stoppableNetwork) Send(target netip.Addr, srcPort uint16, sequence uint32) (netip.Addr, bool, error) {
	if n.stopped != nil && n.stopped() {
		return netip.Addr{}, false, errScanInterrupted
	}

	return n.Network.Send(target, srcPort, sequence)
}

func (n stoppableNetwork) Receive(timeout time.Duration) ([]byte, time.Time, bool, error) {
	if n.stopped != nil && n.stopped() {
		return nil, time.Time{}, false, errScanInterrupted
	}

	// The scanner waits up to 120 seconds in one call, so each call waits a short slice of
	// it and the next call reads the stop request again.
	return n.Network.Receive(min(timeout, scanStopCheckInterval))
}
