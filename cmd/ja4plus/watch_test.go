package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/capture"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// stubHandle is a capture handle that opens nothing. A test that reaches the monitor needs
// a handle, and no test of this file holds the privilege that a live interface needs.
type stubHandle struct {
	closed bool
}

func (s *stubHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, errors.New("stub: the handle delivers no packet")
}

func (s *stubHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (s *stubHandle) Close() error {
	s.closed = true
	return nil
}

func TestParseWatchArgsReadsEveryOption(t *testing.T) {
	options, err := parseWatchArgs([]string{
		"--interface", "eth0",
		"--bpf", "tcp port 443",
		"--types", "ja4,ja4s",
		"--json",
		"--csv",
		"--lookup",
		"--stats-interval", "5",
	})
	if err != nil {
		t.Fatalf("parseWatchArgs returns %v", err)
	}

	if options.iface != "eth0" {
		t.Errorf("the interface is %q, and the option names eth0", options.iface)
	}
	if options.filter != "tcp port 443" {
		t.Errorf("the filter is %q, and the option names tcp port 443", options.filter)
	}
	if !options.types["ja4"] || !options.types["ja4s"] {
		t.Errorf("the type filter is %v, and the option names ja4 and ja4s", options.types)
	}
	if !options.outputJSON {
		t.Error("the JSON option is false, and the arguments hold --json")
	}
	if !options.outputCSV {
		t.Error("the CSV option is false, and the arguments hold --csv")
	}
	if !options.lookup {
		t.Error("the lookup option is false, and the arguments hold --lookup")
	}
	if options.statsInterval != 5*time.Second {
		t.Errorf("the statistics interval is %s, and the option names 5 seconds", options.statsInterval)
	}
}

func TestParseWatchArgsDefaultsTheStatisticsIntervalToSixtySeconds(t *testing.T) {
	options, err := parseWatchArgs([]string{"--interface", "eth0"})
	if err != nil {
		t.Fatalf("parseWatchArgs returns %v", err)
	}

	if options.statsInterval != 60*time.Second {
		t.Errorf("the statistics interval is %s, and FR-capture-8 states 60 seconds", options.statsInterval)
	}
}

func TestParseWatchArgsAdmitsNoTypesOptionAsANilFilter(t *testing.T) {
	options, err := parseWatchArgs([]string{"--interface", "eth0"})
	if err != nil {
		t.Fatalf("parseWatchArgs returns %v", err)
	}

	// A nil filter admits every result, and `admitsResult` states that rule.
	if options.types != nil {
		t.Errorf("the type filter is %v, and the arguments hold no --types option", options.types)
	}
}

func TestParseWatchArgsKeepsAStatisticsIntervalOfZero(t *testing.T) {
	options, err := parseWatchArgs([]string{"--interface", "eth0", "--stats-interval", "0"})
	if err != nil {
		t.Fatalf("parseWatchArgs returns %v", err)
	}

	// FR-capture-9 writes one statistics line at exit for this value, so the parser keeps
	// the zero and never reads it as an absent option.
	if options.statsInterval != 0 {
		t.Errorf("the statistics interval is %s, and the option names 0 seconds", options.statsInterval)
	}
}

func TestParseWatchArgsRefusesANegativeStatisticsInterval(t *testing.T) {
	_, err := parseWatchArgs([]string{"--interface", "eth0", "--stats-interval", "-1"})
	if err == nil {
		t.Fatal("parseWatchArgs returns no error for a negative statistics interval")
	}
	if !strings.Contains(err.Error(), "--stats-interval") {
		t.Errorf("the error is %q, and it names no option", err)
	}
}

func TestParseWatchArgsRefusesAStatisticsIntervalThatHoldsNoNumber(t *testing.T) {
	_, err := parseWatchArgs([]string{"--interface", "eth0", "--stats-interval", "often"})
	if err == nil {
		t.Fatal("parseWatchArgs returns no error for a statistics interval that holds no number")
	}
	if !strings.Contains(err.Error(), "often") {
		t.Errorf("the error is %q, and it holds no value the user wrote", err)
	}
}

func TestParseWatchArgsRefusesAnUnknownOption(t *testing.T) {
	_, err := parseWatchArgs([]string{"--interface", "eth0", "--promiscuous"})
	if err == nil {
		t.Fatal("parseWatchArgs returns no error for an unknown option")
	}
	if !strings.Contains(err.Error(), "--promiscuous") {
		t.Errorf("the error is %q, and it names no option", err)
	}
}

func TestParseWatchArgsRefusesArgumentsThatNameNoInterface(t *testing.T) {
	_, err := parseWatchArgs([]string{"--json"})
	if err == nil {
		t.Fatal("parseWatchArgs returns no error for arguments that name no interface")
	}
	if !strings.Contains(err.Error(), "--interface") {
		t.Errorf("the error is %q, and it names no option", err)
	}
}

func TestParseWatchArgsRefusesAnOptionThatCarriesNoValue(t *testing.T) {
	for _, option := range []string{"--interface", "--bpf", "--types", "--stats-interval"} {
		t.Run(option, func(t *testing.T) {
			_, err := parseWatchArgs([]string{"--interface", "eth0", option})
			if err == nil {
				t.Fatalf("parseWatchArgs returns no error for %s without a value", option)
			}
			if !strings.Contains(err.Error(), option) {
				t.Errorf("the error is %q, and it names no option", err)
			}
		})
	}
}

func TestParseWatchArgsRefusesATypeTokenThatNamesNoMethod(t *testing.T) {
	_, err := parseWatchArgs([]string{"--interface", "eth0", "--types", "ja4,ja5"})
	if err == nil {
		t.Fatal("parseWatchArgs returns no error for a token that names no method")
	}
	if !strings.Contains(err.Error(), "ja5") {
		t.Errorf("the error is %q, and it names no token", err)
	}
}

func TestWatchCaptureOptionsCarriesTheInterfaceAndTheFilter(t *testing.T) {
	options := watchCaptureOptions(watchOptions{iface: "eth0", filter: "tcp port 443"})

	if options.Interface != "eth0" {
		t.Errorf("the interface is %q, and the command names eth0", options.Interface)
	}
	if options.Filter != "tcp port 443" {
		t.Errorf("the filter is %q, and the command names tcp port 443", options.Filter)
	}
}

func TestWatchInterfaceReturnsTheErrorOfTheCaptureBackendUnchanged(t *testing.T) {
	// The message is the one that `compileFilter` of `internal/capture/pcapgo_linux.go`
	// returns under the ruling of #564. The command prints what the backend returns, and it
	// writes no second sentence about the capture filter.
	refusal := errors.New(`capture: the pure-Go backend applies no capture filter, and it declines the filter "tcp port 443". ` +
		"Build with the libpcap build tag to apply a capture filter: go build -tags libpcap ./cmd/ja4plus")

	err := watchInterface(watchOptions{iface: "eth0", filter: "tcp port 443"},
		func(capture.Options) (capture.Handle, error) { return nil, refusal })

	if !errors.Is(err, refusal) {
		t.Fatalf("watchInterface returns %v, and the backend returns the refusal", err)
	}
	// The comparison reads the whole text. `errors.Is` holds for a wrapped error too, so it
	// passes for a command that prepends a second sentence about the capture filter.
	if err.Error() != refusal.Error() {
		t.Errorf("watchInterface returns %q, and the backend returns %q", err, refusal)
	}
}

func TestWatchInterfaceClosesTheHandleThatItOpens(t *testing.T) {
	handle := &stubHandle{}

	// The monitor loop of #80 is not built, so this call returns the error of the seam. The
	// handle closes on every path, because a live run holds one handle for the whole run.
	_ = watchInterface(watchOptions{iface: "eth0"},
		func(capture.Options) (capture.Handle, error) { return handle, nil })

	if !handle.closed {
		t.Error("watchInterface leaves the handle open")
	}
}

func TestRunWatchRefusesAnOptionBeforeItOpensAnInterface(t *testing.T) {
	// FR-capture-37 states that the command opens no interface until it has parsed every
	// option.
	err := runWatch([]string{"--interface", "eth0", "--types", "ja5"})
	if err == nil {
		t.Fatal("runWatch returns no error for a token that names no method")
	}
	if !strings.Contains(err.Error(), "ja5") {
		t.Errorf("the error is %q, and it names no token", err)
	}
	// Every error of `internal/capture` opens with `capture: `, so an error without that
	// prefix reports that the command reached no capture backend.
	if strings.Contains(err.Error(), "capture: ") {
		t.Errorf("the error is %q, and the command opened an interface for arguments it refuses", err)
	}
}

// buildProgram returns the path of the program that this package builds.
// The build carries no build tag, so the binary holds the backend that the platform selects
// for a default build.
func buildProgram(t *testing.T) string {
	t.Helper()

	binary := filepath.Join(t.TempDir(), "ja4plus")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the program: %v\n%s", err, output)
	}

	return binary
}

func TestTheWatchCommandWritesTheCaptureFailureToStandardErrorAndExitsNonZero(t *testing.T) {
	binary := buildProgram(t)

	// The name below reaches no host. On a platform that selects no backend the command
	// reports the platform, and it opens nothing.
	command := exec.Command(binary, "watch", "--interface", "ja4plus-no-such-interface")
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()

	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("the command exits with %v, and FR-capture-26 states a non-zero status", err)
	}
	if exitError.ExitCode() != 1 {
		t.Errorf("the exit status is %d, and the program reports a failure with 1", exitError.ExitCode())
	}
	if stdout.String() != "" {
		t.Errorf("standard output holds %q, and FR-capture-26 sends the message to standard error", stdout.String())
	}
	if !strings.Contains(stderr.String(), "capture:") {
		t.Errorf("standard error holds %q, and it carries no message of the capture package", stderr.String())
	}

	if runtime.GOOS == "darwin" {
		expected := "capture: the monitor needs the libpcap build tag on darwin. " +
			"Build the program with the command go build -tags libpcap ./cmd/ja4plus."
		if !strings.Contains(stderr.String(), expected) {
			t.Errorf("standard error holds %q, and FR-capture-24 states the message %q", stderr.String(), expected)
		}
	}
}

func TestTheUsageNamesTheWatchCommandOnStandardError(t *testing.T) {
	binary := buildProgram(t)

	command := exec.Command(binary, "--help")
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("the command exits with %v, and --help reports success", err)
	}

	if !strings.Contains(stderr.String(), "ja4plus watch") {
		t.Errorf("the usage holds %q, and it names no watch command", stderr.String())
	}
	for _, option := range []string{"--interface", "--bpf", "--stats-interval"} {
		if !strings.Contains(stderr.String(), option) {
			t.Errorf("the usage names no %s option", option)
		}
	}
}
