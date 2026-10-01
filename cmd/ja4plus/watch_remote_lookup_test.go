package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Crank-Git/ja4plus-go"
)

// These tests hold the repair of the batch #807 gate. A remote lookup runs on the packet
// path of `watch`, so a slow lookup service stops the capture loop. Issue #804 is the
// reversal path. No test of this file reaches the network: each one passes a fake remote
// lookup to `newMonitor`.

// blockingRemote is a remote lookup that answers only when its context ends.
//
// The release channel also ends a call, so a test that fails leaves no goroutine blocked
// after the test returns.
type blockingRemote struct {
	// entered receives one value at the start of each call.
	entered chan string
	// release ends every call that the context has not ended.
	release chan struct{}
}

func newBlockingRemote(t *testing.T) *blockingRemote {
	t.Helper()

	remote := &blockingRemote{entered: make(chan string, 16), release: make(chan struct{})}
	t.Cleanup(func() { close(remote.release) })

	return remote
}

func (b *blockingRemote) lookup(ctx context.Context, fingerprint string) (*ja4plus.LookupResult, error) {
	b.entered <- fingerprint

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
		return nil, nil
	}
}

// runMonitorAsync runs the monitor on a second goroutine, and it returns a channel that
// receives the result of the run.
func runMonitorAsync(instance *monitor, handle *stubCaptureHandle) <-chan error {
	done := make(chan error, 1)

	go func() { done <- instance.run(handle) }()

	return done
}

func TestAWatchLookupEndsAtTheWatchDeadlineWhenTheServiceNeverAnswers(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})
	remote := newBlockingRemote(t)

	instance := newMonitor(watchOptions{iface: "lo", lookupRemote: true}, &stopRequest{},
		&strings.Builder{}, &strings.Builder{}, steadyClock(), remote.lookup)

	// The watch deadline is 2 seconds, and the margin of 1 second absorbs a slow test host.
	const bound = 3 * time.Second

	started := time.Now()

	select {
	case err := <-runMonitorAsync(instance, handle):
		if err != nil {
			t.Fatalf("the monitor returns the error %v", err)
		}
	case <-time.After(bound):
		t.Fatalf("the monitor is still blocked on the remote lookup after %v", bound)
	}

	if len(remote.entered) == 0 {
		t.Fatal("the monitor sent no remote request, so this test measures nothing")
	}

	if elapsed := time.Since(started); elapsed < time.Second {
		t.Errorf("the monitor returned after %v, before the 2 second deadline could end the lookup", elapsed)
	}
}

func TestAStopRequestCancelsAWatchLookupInFlight(t *testing.T) {
	packet := buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54120, 443, true, nil)
	handle := newStubCaptureHandle([][]byte{packet})
	remote := newBlockingRemote(t)
	stop := &stopRequest{}

	instance := newMonitor(watchOptions{iface: "lo", lookupRemote: true}, stop,
		&strings.Builder{}, &strings.Builder{}, steadyClock(), remote.lookup)

	done := runMonitorAsync(instance, handle)

	select {
	case <-remote.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the monitor sent no remote request")
	}

	// The bound sits far below the 2 second deadline, so only the stop request can end the
	// lookup inside it.
	const bound = 500 * time.Millisecond

	stop.request()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the monitor returns the error %v", err)
		}
	case <-time.After(bound):
		t.Fatalf("the monitor is still blocked on the remote lookup %v after the stop request", bound)
	}
}

// stopAwareRemote records each remote request, and whether the stop request had arrived
// when the request started.
type stopAwareRemote struct {
	stop *stopRequest

	mutex     sync.Mutex
	afterStop []string
}

func (s *stopAwareRemote) lookup(_ context.Context, fingerprint string) (*ja4plus.LookupResult, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.stop.isRequested() {
		s.afterStop = append(s.afterStop, fingerprint)
	}

	return nil, nil
}

func TestTheStopFlushSendsNoRemoteRequest(t *testing.T) {
	payload := monitorTestSSHPayload()
	packets := make([][]byte, 0, 8)

	for range 4 {
		packets = append(packets, buildTCPPacketBytes(t, monitorTestClientIP, monitorTestServerIP, 54144, 22, false, payload))
		packets = append(packets, buildTCPPacketBytes(t, monitorTestServerIP, monitorTestClientIP, 22, 54144, false, payload))
	}

	handle := newStubCaptureHandle(packets)
	stop := &stopRequest{}
	remote := &stopAwareRemote{stop: stop}
	out := &strings.Builder{}

	instance := newMonitor(watchOptions{iface: "lo", lookupRemote: true}, stop,
		out, &strings.Builder{}, steadyClock(), remote.lookup)

	// The stop request arrives after the last packet, so the close of the open windows
	// writes the JA4SSH windows after it.
	handle.beforeRead = func(index int) {
		if index == len(packets) {
			stop.request()
		}
	}

	if err := instance.run(handle); err != nil {
		t.Fatalf("the monitor returns the error %v", err)
	}

	if !strings.Contains(out.String(), "ja4ssh") {
		t.Fatalf("standard output holds no open JA4SSH window, so this test measures nothing: %q", out.String())
	}

	if len(remote.afterStop) != 0 {
		t.Errorf("the stop flush sent %d remote requests: %q", len(remote.afterStop), remote.afterStop)
	}
}
