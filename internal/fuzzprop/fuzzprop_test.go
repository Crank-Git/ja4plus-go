package fuzzprop

import (
	"strings"
	"testing"
	"time"
)

// recordingReporter records each failure that check reports. A property that no test has
// seen fail is a property that nobody has verified, and a real `*testing.T` cannot record a
// failure without failing the run.
type recordingReporter struct {
	failures []string
}

func (r *recordingReporter) Helper() {}

func (r *recordingReporter) Errorf(format string, args ...any) {
	r.failures = append(r.failures, format)
	_ = args
}

// slowCall returns a call that returns one fixed value after the named delay.
func slowCall(delay time.Duration) func() any {
	return func() any {
		time.Sleep(delay)

		return 1
	}
}

func TestTheTimeBoundFiresForAnInputAtTheSizeBound(t *testing.T) {
	reported := &recordingReporter{}

	check(reported, MaxInputBytes, slowCall(MaxCallDuration+100*time.Millisecond))

	if len(reported.failures) != 1 {
		t.Fatalf("check reported %d failures, and FR-fuzz-16 states 1: %v", len(reported.failures), reported.failures)
	}
	if !strings.Contains(reported.failures[0], "FR-fuzz-16") {
		t.Errorf("check reported %q, and the failure names no requirement", reported.failures[0])
	}
}

func TestTheTimeBoundFiresForNoInputAboveTheSizeBound(t *testing.T) {
	reported := &recordingReporter{}

	check(reported, MaxInputBytes+1, slowCall(MaxCallDuration+100*time.Millisecond))

	if len(reported.failures) != 0 {
		t.Errorf("check reported %v, and FR-fuzz-16 bounds no input above %d bytes",
			reported.failures, MaxInputBytes)
	}
}

func TestTheTimeBoundFiresForNoFastCall(t *testing.T) {
	reported := &recordingReporter{}

	check(reported, 1024, slowCall(0))

	if len(reported.failures) != 0 {
		t.Errorf("check reported %v for a call that returns at once", reported.failures)
	}
}

func TestTheAllocationBoundFiresAboveTheByteCount(t *testing.T) {
	reported := &recordingReporter{}

	check(reported, 8, func() any {
		// The call allocates one block above MaxAllocBytes, and it reads the length so that
		// the compiler keeps the allocation.
		block := make([]byte, MaxAllocBytes+(1<<20))

		return len(block)
	})

	if len(reported.failures) != 1 {
		t.Fatalf("check reported %d failures, and FR-fuzz-17 states 1: %v", len(reported.failures), reported.failures)
	}
	if !strings.Contains(reported.failures[0], "FR-fuzz-17") {
		t.Errorf("check reported %q, and the failure names no requirement", reported.failures[0])
	}
}

func TestTheAllocationBoundFiresForNoSmallCall(t *testing.T) {
	reported := &recordingReporter{}

	check(reported, 8, func() any {
		block := make([]byte, 1024)

		return len(block)
	})

	if len(reported.failures) != 0 {
		t.Errorf("check reported %v for a call that allocates 1024 bytes", reported.failures)
	}
}

func TestTheDeterminismAssertionFiresOnATwoValueResult(t *testing.T) {
	reported := &recordingReporter{}
	counter := 0

	check(reported, 8, func() any {
		counter++

		return counter
	})

	if len(reported.failures) != 1 {
		t.Fatalf("check reported %d failures, and FR-fuzz-18 states 1: %v", len(reported.failures), reported.failures)
	}
	if !strings.Contains(reported.failures[0], "the second call returned") {
		t.Errorf("check reported %q, and the failure names no second call", reported.failures[0])
	}
}

func TestTheDeterminismAssertionFiresForNoRepeatedResult(t *testing.T) {
	reported := &recordingReporter{}

	check(reported, 8, func() any {
		return []any{"ja4", error(nil)}
	})

	if len(reported.failures) != 0 {
		t.Errorf("check reported %v for a call that returns one value two times", reported.failures)
	}
}

func TestExactInputRemovesTheCapacityPastTheLength(t *testing.T) {
	raw := make([]byte, 5, 8)
	copy(raw, "abcde")

	exact := ExactInput(raw)

	if cap(exact) != len(exact) {
		t.Errorf("ExactInput returned len=%d cap=%d, and FR-fuzz-15 needs one number",
			len(exact), cap(exact))
	}
	if string(exact) != "abcde" {
		t.Errorf("ExactInput returned %q, and the input holds %q", exact, raw)
	}
}

func TestExactInputTurnsAReadPastTheEndIntoAPanic(t *testing.T) {
	raw := make([]byte, 5, 8)

	// The same read returns 6 bytes before the copy, and the parser then reads a byte that
	// no input carries. FR-fuzz-15 names that read.
	if beyond := raw[:6]; len(beyond) != 6 {
		t.Fatalf("the read past the end returned %d bytes, and the capacity holds 6", len(beyond))
	}

	defer func() {
		recovered, ok := recover().(error)
		if !ok {
			t.Errorf("the read past the end raised no runtime error")

			return
		}
		if !strings.Contains(recovered.Error(), "slice bounds out of range") {
			t.Errorf("the read past the end raised %v, and the runtime states a slice bound",
				recovered)
		}
	}()

	_ = ExactInput(raw)[:6]
	t.Errorf("the read past the end of the copy raised no panic")
}

func TestExactInputReturnsNilForNil(t *testing.T) {
	if ExactInput(nil) != nil {
		t.Errorf("ExactInput returned a slice for a nil input")
	}
}
