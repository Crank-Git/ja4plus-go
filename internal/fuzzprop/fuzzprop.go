// Package fuzzprop holds the properties that every fuzz target of this
// repository runs.
//
// `docs/specs/features/06-fuzz-testing.md` states FR-fuzz-14 through FR-fuzz-18. This
// package carries one implementation of them, because 13 targets live in two packages and
// 13 copies of one property drift apart.
//
// This package holds no fuzz target and no test of the library. A target calls
// `ExactInput` and `Check`, and it reads no field of the result.
//
// # FR-fuzz-14 needs no code, and this package adds none
//
// FR-fuzz-14 states that a target fails when the code under test panics. The Go test
// runner already does this on both paths, so a wrapper here would add nothing and would
// remove the stack trace that names the panic.
//
//   - `go test ./...` replays each seed input as one subtest. `tRunner` in
//     `testing/testing.go` recovers the panic, calls `t.Fail` at `testing/testing.go:1955`,
//     flushes the log, and panics again at `testing/testing.go:1974`. The process then
//     prints the stack. A measured run reported
//     `panic: the deliberate panic of the FR-fuzz-14 proof [recovered, repanicked]`.
//     `fRunner` in `testing/fuzz.go:641` covers a panic of the fuzz test body itself, and
//     `doPanic` at `testing/fuzz.go:684` ends that path the same way.
//   - `go test -fuzz` runs each input in a worker process. That process dies on a panic,
//     and the coordinator reports `fuzzing process hung or terminated unexpectedly` at
//     `internal/fuzz/worker.go:145`. It then writes the input to the seed corpus.
//
// A recover-and-fail wrapper is worse than the default. It stops the runtime before the
// runtime prints the stack, so the crash report names the wrapper and not the parser.
// Read at go1.26.5.
//
// # FR-fuzz-15 is subsumed for one read, and `ExactInput` closes the second
//
// FR-fuzz-15 states that a target fails when the code under test reads past the end of its
// input. A Go index expression and a Go slice expression each report the same defect two
// different ways, and FR-fuzz-14 catches one of the two.
//
//   - `input[i]` for an `i` at or above the length panics with `index out of range`. The
//     runtime raises it, and FR-fuzz-14 fails the target. This read needs no mechanism.
//   - `input[:n]` for an `n` above the length and at or below the capacity panics for
//     nothing. It returns the bytes that follow the input in memory, and the parser then
//     reads a value that no input carries.
//
// The second read is reachable, because the fuzz engine hands the target a slice whose
// capacity is above its length. `mutateBytes` writes into a scratch slice at
// `internal/fuzz/mutator.go:112`, and `internal/fuzz/mutator.go:113` assigns that scratch
// slice to the value the target receives. `internal/fuzz/mutator.go:107` is the assignment
// that gives that scratch slice a capacity of `maxPerVal` bytes, and
// `internal/fuzz/mutator.go:106` is the test above it. `internal/fuzz/mutator.go:56` computes
// `maxPerVal` from the whole byte budget. Each line was measured at go1.26.5 on 2026-08-14.
//
// One measured seed replay reported `len=5 cap=8` at go1.26.5. A seed replay reaches no
// mutator. So that measurement proves one thing: the engine hands the target a slice whose
// capacity is above its length. It proves nothing about the four lines above. The conclusion
// holds under either path.
//
// `ExactInput` returns a copy whose capacity equals its length, so a read of the second
// kind panics and FR-fuzz-14 reports it. That is the whole mechanism FR-fuzz-15 needs.
//
// # FR-fuzz-17 reads `runtime/metrics`, and neither candidate of the plan fits
//
// The plan of issue 45 of `Crank-Git/ja4plus-go` names two candidates for the allocation
// bound. This package takes a third one, and each sentence below states a measurement or a
// documented property.
//
//   - `testing.AllocsPerRun` counts allocations, and FR-fuzz-17 bounds bytes. It also runs
//     the function more than one time and it disables the garbage collector, so it changes
//     the run that the target measures.
//   - `runtime.ReadMemStats` reports the bytes, and it costs too much for a per-input
//     check. One call measured 24736 ns on an Apple M4 at go1.26.5. Two calls for each
//     input therefore spend about 50 microseconds of every execution.
//   - `runtime/metrics.Read` over one sample reports the same bytes, and one call measured
//     230.7 ns on the same machine and the same toolchain. That is 107 times cheaper, and
//     the fuzz engine runs about 620000 executions each second on this machine.
//
// `/gc/heap/allocs:bytes` is cumulative, so the difference of two reads is the count of
// bytes that one call allocated.
package fuzzprop

import (
	"reflect"
	"runtime/metrics"
	"testing"
	"time"
)

// MaxInputBytes states the input size that the time bound of FR-fuzz-16 reaches. A larger
// input carries no time bound, because FR-fuzz-16 states one for 64 KB and under.
const MaxInputBytes = 64 << 10

// MaxCallDuration states the time bound of FR-fuzz-16.
const MaxCallDuration = time.Second

// MaxAllocBytes states the allocation bound of FR-fuzz-17.
const MaxAllocBytes = 64 << 20

// allocsMetric names the cumulative count of heap bytes that the application allocates.
// `runtime/metrics` documents it as `Cumulative sum of memory allocated to the heap by the
// application.`
const allocsMetric = "/gc/heap/allocs:bytes"

// ExactInput returns a copy of input whose capacity equals its length.
//
// It meets FR-fuzz-15. The package comment states which read it catches, and it states why
// the fuzz engine makes that read reachable. It returns nil for a nil input, so a caller
// that separates nil from empty keeps that separation.
func ExactInput(input []byte) []byte {
	if input == nil {
		return nil
	}

	exact := make([]byte, len(input))
	copy(exact, input)

	return exact
}

// Check runs call two times over one fuzz input and asserts FR-fuzz-16, FR-fuzz-17 and
// FR-fuzz-18.
//
// inputBytes states the size of the input that the target passes to the code under test.
// The time bound applies at or below MaxInputBytes, and it does not apply above it.
//
// call returns the whole result of the code under test. A caller that reads two values
// returns them in one `[]any`, because `reflect.DeepEqual` compares that slice element by
// element. A caller that reads no value returns nil, and the determinism property then
// holds without a comparison.
//
// Check fails the test, and it never panics for a result of any shape.
func Check(t *testing.T, inputBytes int, call func() any) {
	t.Helper()

	check(t, inputBytes, call)
}

// reporter is the part of `*testing.T` that check writes to.
//
// `testing.TB` holds an unexported method, so no type outside `testing` implements it.
// `fuzzprop_test.go` passes a recorder that counts each failure, and each property is then
// proved to fire in a run that passes.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// check holds the properties of Check. Check states what each one means.
func check(t reporter, inputBytes int, call func() any) {
	t.Helper()

	sample := []metrics.Sample{{Name: allocsMetric}}

	metrics.Read(sample)
	allocsBefore := sample[0].Value.Uint64()

	start := time.Now()
	first := call()
	firstElapsed := time.Since(start)

	metrics.Read(sample)
	allocsAfter := sample[0].Value.Uint64()

	start = time.Now()
	second := call()
	secondElapsed := time.Since(start)

	// FR-fuzz-16. The lower of two measurements is the better estimate of the cost of the
	// call, because a scheduler delay adds time and it never removes time. This machine
	// runs 10 fuzz workers at once, so one measurement reports the load of the machine as
	// often as it reports the cost of the parser. A parser that needs more than one second
	// needs it on both calls, so the lower measurement still reports that parser.
	elapsed := min(firstElapsed, secondElapsed)
	if inputBytes <= MaxInputBytes && elapsed > MaxCallDuration {
		t.Errorf("the call returned in %v for an input of %d bytes, and FR-fuzz-16 bounds it at %v",
			elapsed, inputBytes, MaxCallDuration)
	}

	// FR-fuzz-17. `runtime/metrics` reports a cumulative count, so the difference of two
	// reads is the count of bytes that the first call allocated.
	if allocated := allocsAfter - allocsBefore; allocated > MaxAllocBytes {
		t.Errorf("the call allocated %d bytes for an input of %d bytes, and FR-fuzz-17 bounds it at %d",
			allocated, inputBytes, MaxAllocBytes)
	}

	// FR-fuzz-18.
	if !reflect.DeepEqual(first, second) {
		t.Errorf("the second call returned %#v, and the first call returned %#v", second, first)
	}
}
