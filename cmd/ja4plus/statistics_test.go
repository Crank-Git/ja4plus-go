package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The statistics line of issue #81. FR-capture-28 through FR-capture-33 of
// `docs/specs/features/13-live-capture.md` state the work, and each test names the
// requirement it reads.
//
// No test of this file opens a live interface, because a live interface needs a privilege
// that no test holds. Each test drives the monitor with a stub capture handle.

// statisticsLinePrefix opens every statistics line, and a test finds the line with it.
const statisticsLinePrefix = "ja4plus: uptime="

// countStatisticsLines returns the count of statistics lines that the text holds.
func countStatisticsLines(text string) int {
	return strings.Count(text, statisticsLinePrefix)
}

// TestTheStatisticsLineHoldsEveryFieldOfTheRequirements reads FR-capture-28 through
// FR-capture-32, and acceptance criterion 8 of issue #81. The field order and each field
// name come from `docs/specs/mockups/03-watch-output.html`.
func TestTheStatisticsLineHoldsEveryFieldOfTheRequirements(t *testing.T) {
	line := statisticsLine(60*time.Second, 18422, 214, 0, 57)

	expected := "ja4plus: uptime=60s packets=18422 fingerprints=214 dropped=0 connections=57"
	if line != expected {
		t.Errorf("the statistics line is %q, and the mockup states %q", line, expected)
	}
}

// TestTheStatisticsLineReportsTheUptimeInWholeSeconds reads FR-capture-28.
func TestTheStatisticsLineReportsTheUptimeInWholeSeconds(t *testing.T) {
	line := statisticsLine(1900*time.Millisecond, 0, 0, 0, 0)

	if !strings.Contains(line, "uptime=1s") {
		t.Errorf("the statistics line is %q, and 1900 milliseconds hold 1 whole second", line)
	}
}

// TestTheStatisticsLineWritesUnknownForADropCountTheBackendDoesNotReport reads
// FR-capture-33.
func TestTheStatisticsLineWritesUnknownForADropCountTheBackendDoesNotReport(t *testing.T) {
	line := statisticsLine(time.Second, 10, 2, dropCountUnknown, 3)

	if !strings.Contains(line, "dropped=unknown") {
		t.Errorf("the statistics line is %q, and FR-capture-33 writes unknown", line)
	}
}

// TestTheMonitorWritesTheStatisticsLineToStandardError reads FR-capture-7. The line is
// diagnostic output, so a redirect of standard output holds the fingerprints alone.
func TestTheMonitorWritesTheStatisticsLineToStandardError(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})

	instance, out, errOut := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if countStatisticsLines(errOut.String()) != 1 {
		t.Errorf("standard error holds %q, and the run writes one statistics line", errOut.String())
	}
	if strings.Contains(out.String(), statisticsLinePrefix) {
		t.Errorf("standard output holds %q, and FR-capture-7 sends the line to standard error", out.String())
	}
}

// TestTheMonitorWritesOneStatisticsLineForAZeroInterval reads FR-capture-9. A statistics
// interval of 0 writes one line at exit, and it writes no other line.
func TestTheMonitorWritesOneStatisticsLineForAZeroInterval(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})

	instance, _, errOut := newTestMonitor(t, watchOptions{iface: "lo", statsInterval: 0}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if countStatisticsLines(errOut.String()) != 1 {
		t.Errorf("standard error holds %q, and FR-capture-9 writes one line at exit", errOut.String())
	}
}

// TestTheStatisticsWriterWritesOneLineForEachTick reads FR-capture-8. The test drives the
// writer with a channel of its own, so it holds no real clock.
func TestTheStatisticsWriterWritesOneLineForEachTick(t *testing.T) {
	instance, _, errOut := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	ticks := make(chan time.Time)
	done := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		instance.writeStatisticsLines(ticks, done)
	}()

	ticks <- time.Unix(1700000060, 0).UTC()
	ticks <- time.Unix(1700000120, 0).UTC()

	close(done)
	<-finished

	if countStatisticsLines(errOut.String()) != 2 {
		t.Errorf("standard error holds %q, and the writer took two ticks", errOut.String())
	}
}

// TestTheStatisticsWriterReturnsWhenTheDoneChannelCloses reads the resource rule of
// `.claude/rules/concurrency.md`. A goroutine that no channel stops outlives the run.
func TestTheStatisticsWriterReturnsWhenTheDoneChannelCloses(t *testing.T) {
	instance, _, _ := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	done := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		instance.writeStatisticsLines(nil, done)
	}()

	close(done)

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the statistics writer runs after the done channel closes")
	}
}

// TestTheMonitorReportsTheDropCountOfTheCaptureHandle reads FR-capture-31.
func TestTheMonitorReportsTheDropCountOfTheCaptureHandle(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})
	handle.drops = 12
	handle.dropsHeld = true

	instance, _, errOut := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if !strings.Contains(errOut.String(), "dropped=12") {
		t.Errorf("standard error holds %q, and the handle reports 12 drops", errOut.String())
	}
}

// TestTheMonitorReportsUnknownWhenTheHandleReportsNoDropCount reads FR-capture-33.
func TestTheMonitorReportsUnknownWhenTheHandleReportsNoDropCount(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})
	handle.dropsHeld = false

	instance, _, errOut := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if !strings.Contains(errOut.String(), "dropped=unknown") {
		t.Errorf("standard error holds %q, and the handle reports no drop count", errOut.String())
	}
}

// TestTheStatisticsLineReportsTheCountsOfTheRun reads FR-capture-29, FR-capture-30 and
// FR-capture-32. Two SYN packets of two connections produce two entries and one
// fingerprint for each packet.
func TestTheStatisticsLineReportsTheCountsOfTheRun(t *testing.T) {
	first := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	second := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54121, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{first, second})

	instance, _, errOut := newTestMonitor(t, watchOptions{iface: "lo"}, steadyClock())

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	for _, field := range []string{"packets=2", "fingerprints=2", "connections=2"} {
		if !strings.Contains(errOut.String(), field) {
			t.Errorf("standard error holds %q, and it names no %s", errOut.String(), field)
		}
	}
}

// countingWriter counts the writes it takes, and it holds the text of each one.
//
// The statistics goroutine and the monitor loop each write the error writer of one run, at
// two times that no test controls. So this writer takes a lock, and a test reads the count
// through an atomic value.
type countingWriter struct {
	mutex sync.Mutex
	text  strings.Builder
	// writes counts the writes, and a test reads it while the writer takes one.
	writes atomic.Uint64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.writes.Add(1)

	return w.text.Write(data)
}

// String returns the text of every write. The caller reads it after every writer stopped.
func (w *countingWriter) String() string {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	return w.text.String()
}

// TestTheStatisticsGoroutineReadsTheCountersWhileTheLoopWritesThem reads FR-capture-16 and
// the seam of issue #80. The race detector reads this test, so `go test -race ./...`
// reports a data race between the two goroutines.
//
// The loop holds each packet until the statistics goroutine wrote three lines, so the two
// goroutines run at one time and the overlap needs no timing luck.
func TestTheStatisticsGoroutineReadsTheCountersWhileTheLoopWritesThem(t *testing.T) {
	const lines = 3

	packets := make([][]byte, 0, 20)
	for index := range 20 {
		packets = append(packets,
			buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, uint16(50000+index), 443, true, nil))
	}

	handle := newStubCaptureHandle(packets)
	handle.drops = 3
	handle.dropsHeld = true

	errOut := &countingWriter{}
	instance := newMonitor(
		watchOptions{iface: "lo", statsInterval: time.Millisecond},
		&stopRequest{}, &strings.Builder{}, errOut, steadyClock())

	deadline := time.Now().Add(30 * time.Second)
	handle.beforeRead = func(int) {
		// The loop waits for the statistics goroutine, so each read of the counters happens
		// while the loop writes them.
		for errOut.writes.Load() < lines && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if countStatisticsLines(errOut.String()) < lines {
		t.Errorf("standard error holds %q, and the statistics goroutine writes each tick", errOut.String())
	}
}
