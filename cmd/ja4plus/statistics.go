package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Crank-Git/ja4plus-go/internal/capture"
)

// The statistics line of issue #81. FR-capture-28 through FR-capture-34 of
// `docs/specs/features/13-live-capture.md` state the work.
//
// **A second goroutine writes the line, and a measurement states the reason.** The packet
// loop wakes at each packet and at each read deadline, and `readDeadline` of
// `internal/capture` states that deadline. Neither event follows the statistics interval,
// so a line that the packet loop writes reports an interval that the traffic decides. An
// idle interface is when an operator most needs the line, and the second goroutine holds the
// line to the interval that FR-capture-8 states.
//
// **A read blocked forever until 2026-08-15**, and this comment stated that block as the
// reason. #77 found that `pcapgo.EthernetHandle` exposes no read deadline, and #78 passed
// `pcap.BlockForever` so that the two backends behaved the same. **Issue #610 gave each read
// a deadline**, so the packet loop now wakes on an idle interface. The line still needs the
// second goroutine, for the reason above.
//
// **That goroutine reads the counters of `monitorCounters` through their atomic methods,
// and it reaches the `Processor`, the connection table and the capture handle never.**
// `.claude/rules/concurrency.md` `## The contract` states the ownership model that keeps
// the packet path lock-free, and #80 built the seam this file reads.

// dropCountUnknown marks a drop count that the capture backend does not report.
// FR-capture-33 writes `unknown` for it.
//
// The counter holds one atomic value rather than a count beside a flag, so the writer of
// the line reads the count and its validity in one load. Two atomic fields would let one
// line pair the count of one sample with the validity of the next one.
// No interface delivers 18446744073709551615 dropped packets, so no true count reaches
// this value.
const dropCountUnknown = ^uint64(0)

// dropCountUnknownText is the field value that FR-capture-33 states.
const dropCountUnknownText = "unknown"

// dropSampleInterval is the shortest time between two reads of the drop count.
//
// Each read costs one system call, and the goroutine that owns the handle makes it. A read
// for every packet would cost one system call for every packet, and FR-capture-16 keeps
// the packet path cheap. The statistics line reports whole seconds, so a sample each second
// reaches the finest resolution that any line reports.
const dropSampleInterval = time.Second

// statisticsLine returns the line that reports the counts of one run.
//
// `docs/specs/mockups/03-watch-output.html` states the field order and each field name.
// FR-capture-28 through FR-capture-32 state the five fields.
func statisticsLine(uptime time.Duration, packets uint64, fingerprints uint64, drops uint64, connections uint64) string {
	dropped := dropCountUnknownText
	if drops != dropCountUnknown {
		dropped = strconv.FormatUint(drops, 10)
	}

	// FR-capture-28 reports whole seconds, and the division truncates. So a run of 1900
	// milliseconds reports 1.
	return fmt.Sprintf("ja4plus: uptime=%ds packets=%d fingerprints=%d dropped=%s connections=%d",
		uptime/time.Second, packets, fingerprints, dropped, connections)
}

// sampleDropCount reads the drop count of the handle, and it publishes that count for the
// statistics goroutine. FR-capture-31 reports the count.
//
// The goroutine that owns the handle calls this method, because the doc comment of
// `capture.Handle` gives one handle to one goroutine. The pure-Go backend accumulates a
// delta that the kernel resets at each read, so a second caller would take a count that
// the line then loses.
func (m *monitor) sampleDropCount(handle capture.Handle) {
	drops, held := handle.DropCount()
	if !held {
		m.counters.drops.Store(dropCountUnknown)

		return
	}

	m.counters.drops.Store(drops)
}

// writeStatisticsLine writes one statistics line to the error writer.
// FR-capture-7 sends the line to standard error, so a redirect of standard output holds
// the fingerprints alone.
// It returns the error of the writer.
func (m *monitor) writeStatisticsLine() error {
	_, err := fmt.Fprintln(m.errOut, statisticsLine(
		m.now().Sub(m.startedAt),
		m.counters.packets.Load(),
		m.counters.fingerprints.Load(),
		m.counters.drops.Load(),
		m.counters.connections.Load(),
	))

	return err
}

// writeStatisticsLines writes one statistics line for each tick, and it returns when the
// done channel closes.
//
// The caller closes the done channel and then waits for this function to return. So no
// line reaches the error writer after the monitor writes its own diagnostics there, and
// the two goroutines share one writer without a lock.
// A nil tick channel blocks forever, which is the schedule that a statistics interval of 0
// names.
func (m *monitor) writeStatisticsLines(ticks <-chan time.Time, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-ticks:
			// A failed write of a diagnostic line reports nowhere, because the error writer
			// is the one place the monitor reports a failure.
			_ = m.writeStatisticsLine()
		}
	}
}

// startStatisticsWriter starts the goroutine that writes the statistics line, and it
// returns the function that stops that goroutine.
//
// The stop function waits for the goroutine to return, so the caller writes to the error
// writer after that call and never before it.
// A statistics interval of 0 starts a goroutine that no tick reaches. FR-capture-9 writes
// one line at exit for that value, and `run` writes that line.
func (m *monitor) startStatisticsWriter() func() {
	var ticks <-chan time.Time

	var ticker *time.Ticker

	if m.options.statsInterval > 0 {
		ticker = time.NewTicker(m.options.statsInterval)
		ticks = ticker.C
	}

	done := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		defer close(finished)

		m.writeStatisticsLines(ticks, done)
	}()

	return func() {
		if ticker != nil {
			ticker.Stop()
		}

		close(done)
		<-finished
	}
}
