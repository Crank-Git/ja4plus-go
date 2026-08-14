package main

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/capture"
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
// The monitor of #80 reads each field, and the statistics line of #81 reads
// `statsInterval`. This slice parses the options and opens the handle, and it runs no
// monitor loop.
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
	options, err := parseWatchArgs(args)
	if err != nil {
		return err
	}

	return watchInterface(options, capture.Open)
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
		// Seam for #82. The privilege failure of FR-capture-35 and FR-capture-36 reads this
		// error and names the capability the host needs. The message of the backend reaches
		// the operator unchanged until then.
		return err
	}

	// FR-capture-14 holds one handle for the whole run, and the monitor opens it once.
	defer func() { _ = handle.Close() }()

	return runMonitor(handle, options)
}

// runMonitor returns an error, and it reads no packet from the handle.
//
// TODO(#80): Build the loop, the signal handler and the connection table here.
// FR-capture-16 through FR-capture-23 state the work. Both capture backends block until a
// packet arrives, because the libpcap backend passes `pcap.BlockForever` deliberately. So
// an idle interface blocks the read of the loop on every platform, and the statistics line
// of #81 needs a second goroutine that reads the statistics interval of the options.
func runMonitor(_ capture.Handle, _ watchOptions) error {
	return errors.New("watch: the monitor reads no packet yet. Issue #80 builds the monitor loop")
}
