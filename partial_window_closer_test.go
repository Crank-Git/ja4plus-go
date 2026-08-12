package ja4plus

import (
	"testing"

	"github.com/google/gopacket"
)

// openWindowOnlyFingerprinter implements Fingerprinter and CloseOpenWindows alone.
// A caller of `v0.3.0` writes this shape, because `v0.3.0` exports one window method.
// Issue #268 records the ruling that keeps such a type reachable.
type openWindowOnlyFingerprinter struct {
	closed int
}

func (f *openWindowOnlyFingerprinter) ProcessPacket(gopacket.Packet) ([]FingerprintResult, error) {
	return nil, nil
}

func (f *openWindowOnlyFingerprinter) Reset() {}

func (f *openWindowOnlyFingerprinter) CleanupConnection(string, uint16, string, uint16, string) {}

func (f *openWindowOnlyFingerprinter) CloseOpenWindows() []FingerprintResult {
	f.closed++

	return []FingerprintResult{{Type: "open-window-only"}}
}

// connectionWindowOnlyFingerprinter implements Fingerprinter and CloseConnectionWindow
// alone. Issue #268 records the ruling that keeps such a type reachable.
type connectionWindowOnlyFingerprinter struct {
	closed int
}

func (f *connectionWindowOnlyFingerprinter) ProcessPacket(gopacket.Packet) ([]FingerprintResult, error) {
	return nil, nil
}

func (f *connectionWindowOnlyFingerprinter) Reset() {}

func (f *connectionWindowOnlyFingerprinter) CleanupConnection(string, uint16, string, uint16, string) {
}

func (f *connectionWindowOnlyFingerprinter) CloseConnectionWindow(
	string, uint16, string, uint16, string,
) []FingerprintResult {
	f.closed++

	return []FingerprintResult{{Type: "connection-window-only"}}
}

// TestATypeThatImplementsCloseOpenWindowsAloneImplementsWindowCloser holds the ruling of
// 2026-08-12 on issue #268. A two-method interface skips such a type at both call sites, so
// the type loses a capability that `v0.3.0` already delivers.
func TestATypeThatImplementsCloseOpenWindowsAloneImplementsWindowCloser(t *testing.T) {
	var fingerprinter Fingerprinter = &openWindowOnlyFingerprinter{}

	if _, holds := fingerprinter.(WindowCloser); !holds {
		t.Error("a type that implements CloseOpenWindows alone implements no WindowCloser, and the processor skips it")
	}
}

// TestATypeThatImplementsCloseConnectionWindowAloneImplementsConnectionWindowCloser holds
// the second half of the ruling of 2026-08-12 on issue #268.
func TestATypeThatImplementsCloseConnectionWindowAloneImplementsConnectionWindowCloser(t *testing.T) {
	var fingerprinter Fingerprinter = &connectionWindowOnlyFingerprinter{}

	if _, holds := fingerprinter.(ConnectionWindowCloser); !holds {
		t.Error("a type that implements CloseConnectionWindow alone implements no ConnectionWindowCloser, and the processor skips it")
	}
}

// TestTheOpenWindowDispatchReachesATypeThatImplementsThatMethodAlone runs the dispatch of
// `Processor.CloseOpenWindows` over a fingerprinter that implements CloseOpenWindows alone.
// Issue #268 records the measurement this test holds: such a type compiled as a
// Fingerprinter, and the two-method assertion read false, so the dispatch skipped it.
func TestTheOpenWindowDispatchReachesATypeThatImplementsThatMethodAlone(t *testing.T) {
	partial := &openWindowOnlyFingerprinter{}

	results := closeOpenWindows([]Fingerprinter{NewJA4T(), partial})

	if partial.closed != 1 {
		t.Fatalf("the dispatch called CloseOpenWindows %d times, and the list holds one implementer",
			partial.closed)
	}

	if len(results) != 1 || results[0].Type != "open-window-only" {
		t.Errorf("the dispatch returned %d values, and one implementer returned one value", len(results))
	}
}

// TestTheConnectionWindowDispatchReachesATypeThatImplementsThatMethodAlone runs the dispatch
// of `Processor.CloseConnectionWindow` over a fingerprinter that implements
// CloseConnectionWindow alone. Issue #268 records the ruling this test holds.
func TestTheConnectionWindowDispatchReachesATypeThatImplementsThatMethodAlone(t *testing.T) {
	partial := &connectionWindowOnlyFingerprinter{}

	results := closeConnectionWindow(
		[]Fingerprinter{NewJA4T(), partial}, "192.168.1.100", 54321, "10.0.0.1", 22, "tcp")

	if partial.closed != 1 {
		t.Fatalf("the dispatch called CloseConnectionWindow %d times, and the list holds one implementer",
			partial.closed)
	}

	if len(results) != 1 || results[0].Type != "connection-window-only" {
		t.Errorf("the dispatch returned %d values, and one implementer returned one value", len(results))
	}
}

// TestEachWindowDispatchSkipsTheOtherCapability holds the per-capability assertion of the
// ruling of 2026-08-12 on issue #268. A combined assertion reintroduces the defect the
// ruling repairs, and it makes each of these two calls reach nothing.
func TestEachWindowDispatchSkipsTheOtherCapability(t *testing.T) {
	openOnly := &openWindowOnlyFingerprinter{}
	connectionOnly := &connectionWindowOnlyFingerprinter{}

	if results := closeOpenWindows([]Fingerprinter{connectionOnly}); len(results) != 0 {
		t.Errorf("the open-window dispatch returned %d values, and the type implements no CloseOpenWindows",
			len(results))
	}

	if results := closeConnectionWindow(
		[]Fingerprinter{openOnly}, "192.168.1.100", 54321, "10.0.0.1", 22, "tcp"); len(results) != 0 {
		t.Errorf("the connection-window dispatch returned %d values, and the type implements no CloseConnectionWindow",
			len(results))
	}
}
