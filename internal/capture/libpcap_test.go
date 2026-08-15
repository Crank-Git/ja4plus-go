//go:build libpcap

package capture

import (
	"errors"
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// pcapHandle satisfies Handle, and the libpcap build selects it.
var _ Handle = (*pcapHandle)(nil)

func TestOpenNamesTheInterfaceThatTheHostDoesNotHold(t *testing.T) {
	// The `## Edge cases & failures` table of `docs/specs/features/13-live-capture.md`
	// states one message that names the interface. This test names an interface that no
	// host holds, so it opens nothing and it needs no privilege.
	const name = "an-interface-that-no-host-holds"

	handle, err := Open(Options{Interface: name})
	if err == nil {
		if handle != nil {
			_ = handle.Close()
		}
		t.Fatalf("Open returned no error for the interface %s", name)
	}
	if handle != nil {
		t.Errorf("Open returned the handle %v beside the error", handle)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("the error %q names no interface", err)
	}
	if !strings.HasPrefix(err.Error(), "capture: ") {
		t.Errorf("the error %q holds no `capture: ` prefix", err)
	}
}

func TestTheFilterErrorHoldsTheFilterTextAndTheParserError(t *testing.T) {
	// The `## Edge cases & failures` table asks for the filter text and the parser error.
	// The operator repairs the expression, so the message carries the expression back.
	const filter = "this is not a filter expression"
	parserError := errors.New("syntax error")

	err := filterError(filter, parserError)

	if !strings.Contains(err.Error(), filter) {
		t.Errorf("the error %q holds no filter text", err)
	}
	if !strings.Contains(err.Error(), parserError.Error()) {
		t.Errorf("the error %q holds no parser error", err)
	}
	if !strings.HasPrefix(err.Error(), "capture: ") {
		t.Errorf("the error %q holds no `capture: ` prefix", err)
	}
	if !errors.Is(err, parserError) {
		t.Errorf("the error %q wraps no parser error", err)
	}
}

func TestTheLibpcapBackendReportsTheReadDeadlineAsATimeout(t *testing.T) {
	// Issue #610 states that a read deadline is no failure of the capture. libpcap reports
	// the deadline as `pcap.NextErrorTimeoutExpired`, and the monitor reads the stop request
	// at `ErrReadTimeout`.
	err := readError(pcap.NextErrorTimeoutExpired)

	if !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("the backend returns the error %v for the read deadline of libpcap", err)
	}
}

func TestTheLibpcapBackendReportsAFailedReadAsAFailure(t *testing.T) {
	// A failure that is no deadline keeps the message that the edge-case table of
	// `docs/specs/features/13-live-capture.md` states for a removed interface.
	cause := errors.New("the interface is removed")

	err := readError(cause)

	if errors.Is(err, ErrReadTimeout) {
		t.Errorf("the backend reports the failure %v as a read deadline", cause)
	}
	if !errors.Is(err, cause) {
		t.Errorf("the error %q wraps no cause", err)
	}
	if !strings.HasPrefix(err.Error(), "capture: ") {
		t.Errorf("the error %q holds no `capture: ` prefix", err)
	}
}

func TestTheLibpcapBuildCompilesACaptureFilterExpression(t *testing.T) {
	// FR-capture-15 sends `--bpf` to this build, and the maintainer ruled that on
	// 2026-08-14 in #564. `pcap.CompileBPFFilter` opens a dead handle, so it parses the
	// expression and it needs no privilege and no interface.
	program, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snapshotLength, "tcp port 443")
	if err != nil {
		t.Fatalf("libpcap compiles no program for a valid filter: %v", err)
	}
	if len(program) == 0 {
		t.Error("libpcap returned an empty program for a valid filter")
	}
}

func TestTheLibpcapBuildDeclinesAFilterExpressionThatItCannotParse(t *testing.T) {
	// A parser that accepts every string reports no defect to the operator. This test
	// proves that the tagged build links a parser rather than a stub.
	if _, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snapshotLength, "this is not a filter expression"); err == nil {
		t.Error("libpcap compiled a program for an expression that holds no filter")
	}
}
