package capture

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

// interfaceThatNoHostHolds names an interface that reaches no host. Every test that reads
// the interface branch of `openError` uses it.
const interfaceThatNoHostHolds = "an-interface-that-no-host-holds"

func TestPermissionDeniedReadsAnErrorThatWrapsEPERM(t *testing.T) {
	err := fmt.Errorf("capture: the host opens no interface eth0: %w", syscall.EPERM)

	if !PermissionDenied(err) {
		t.Errorf("PermissionDenied reads %v as no permission failure, and the chain holds EPERM", err)
	}
}

func TestPermissionDeniedReadsAnErrorThatWrapsEACCES(t *testing.T) {
	err := fmt.Errorf("capture: the host opens no interface eth0: %w", syscall.EACCES)

	if !PermissionDenied(err) {
		t.Errorf("PermissionDenied reads %v as no permission failure, and the chain holds EACCES", err)
	}
}

func TestPermissionDeniedReadsNoErrorOfAnotherKind(t *testing.T) {
	err := fmt.Errorf("capture: the host opens no interface eth0: %w", syscall.ENODEV)

	if PermissionDenied(err) {
		t.Errorf("PermissionDenied reads %v as a permission failure, and the chain holds ENODEV", err)
	}
}

func TestPermissionDeniedReadsNoMessageText(t *testing.T) {
	// FR-capture-35 reports the capability that the host names, and a host states that
	// answer as an errno. The text of a capture failure comes from a C library and from the
	// locale of the host, so a match on the text reports a failure that no host stated.
	err := errors.New("capture: the host opens no interface eth0: permission denied")

	if PermissionDenied(err) {
		t.Errorf("PermissionDenied reads %v as a permission failure, and the chain holds no errno", err)
	}
}

func TestPermissionDeniedReadsNoNilError(t *testing.T) {
	if PermissionDenied(nil) {
		t.Error("PermissionDenied reads a nil error as a permission failure")
	}
}

func TestOpenErrorNamesThePackageAndTheInterface(t *testing.T) {
	err := openError(interfaceThatNoHostHolds, errors.New("couldn't query interface"))

	if !strings.HasPrefix(err.Error(), "capture: ") {
		t.Errorf("the error %q holds no `capture: ` prefix", err)
	}
	if !strings.Contains(err.Error(), interfaceThatNoHostHolds) {
		t.Errorf("the error %q names no interface", err)
	}
}

func TestOpenErrorCarriesTheCauseOfTheBackendInTheChain(t *testing.T) {
	cause := errors.New("couldn't open packet socket")

	err := openError(interfaceThatNoHostHolds, cause)

	if !errors.Is(err, cause) {
		t.Errorf("the error %q carries the cause of the backend never", err)
	}
	if !strings.Contains(err.Error(), cause.Error()) {
		t.Errorf("the error %q holds the text of the cause never", err)
	}
}

func TestOpenErrorReportsNoPermissionFailureForAnInterfaceThatNoHostHolds(t *testing.T) {
	// The edge-case table of `docs/specs/features/13-live-capture.md` states one message
	// that names the interface for this case. A host that refuses a capture handle refuses
	// it for every interface, so the probe of `captureRefusal` would report a permission
	// failure for a name that names nothing. `openError` reads the interface first.
	err := openError(interfaceThatNoHostHolds, errors.New("couldn't query interface"))

	if PermissionDenied(err) {
		t.Errorf("the error %q reports a permission failure, and the host holds no interface of that name", err)
	}
}

func TestCaptureRefusalReturnsAnErrnoOrNothing(t *testing.T) {
	// The probe answers one of two ways on every platform. It returns nil when the host
	// opens a capture device, and it returns the errno of the host when the host refuses
	// one. A privileged run and an unprivileged run therefore both pass, and the test reads
	// the shape that `PermissionDenied` needs.
	refusal := captureRefusal()
	if refusal == nil {
		return
	}

	if !PermissionDenied(refusal) {
		t.Errorf("captureRefusal returns %v, and PermissionDenied reads no permission failure in it", refusal)
	}
}
