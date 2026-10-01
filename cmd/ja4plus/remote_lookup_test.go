package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Crank-Git/ja4plus-go"
)

// These tests hold the rule of #804. The maintainer ruled on 2026-10-01 UTC that this
// program reads `JA4PLUS_DB_LOOKUP` with the semantics of the port at tag `v1.3.0`.
// `ja4plus/cli.py:490` of `Crank-Git/ja4plus` at that tag holds the rule, and issue #804 is
// the reversal path. No test of this file reaches the network: each one passes a remote
// lookup function that answers from memory.

// unknownFingerprint is a fingerprint that the mapping table holds no entry for.
const unknownFingerprint = "zz_unknown_fingerprint_zz"

// knownFingerprint is a fingerprint that the embedded mapping table holds an entry for.
// `lookup_test.go` of the root package reads the same value.
const knownFingerprint = "t13d1516h2_8daaf6152771_02713d6af862"

// environment returns a getenv function that reads the map alone, so a test never reads the
// environment of the process that runs it.
func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// fakeRemote counts each request and answers with the application it holds.
type fakeRemote struct {
	calls       []string
	application string
	err         error
}

func (f *fakeRemote) lookup(_ context.Context, fingerprint string) (*ja4plus.LookupResult, error) {
	f.calls = append(f.calls, fingerprint)
	if f.err != nil {
		return nil, f.err
	}

	if f.application == "" {
		return nil, nil
	}

	return &ja4plus.LookupResult{Application: f.application}, nil
}

func TestTheVariableAlonePermitsTheRemoteLookup(t *testing.T) {
	if !remoteLookupPermitted(false, environment(map[string]string{remoteLookupVariable: "1"})) {
		t.Errorf("%s=1 permits no remote lookup", remoteLookupVariable)
	}
}

func TestTheOptionAlonePermitsTheRemoteLookup(t *testing.T) {
	if !remoteLookupPermitted(true, environment(nil)) {
		t.Error("--lookup-remote permits no remote lookup")
	}
}

func TestNoOptionAndNoVariablePermitNoRemoteLookup(t *testing.T) {
	if remoteLookupPermitted(false, environment(nil)) {
		t.Error("a run that names no option and sets no variable permits the remote lookup")
	}
}

// TestTheVariablePermitsTheRemoteLookupWithTheValue1Alone holds the one spelling that the port
// reads. `ja4plus/cli.py:509` at `v1.3.0` compares the value with `"1"`, so `true` and `yes`
// permit nothing.
func TestTheVariablePermitsTheRemoteLookupWithTheValue1Alone(t *testing.T) {
	cases := map[string]bool{
		"1":     true,
		"0":     false,
		"":      false,
		"true":  false,
		"yes":   false,
		" 1":    false,
		"1 ":    false,
		"TRUE":  false,
		"01":    false,
		"false": false,
	}

	for value, want := range cases {
		got := remoteLookupPermitted(false, environment(map[string]string{remoteLookupVariable: value}))
		if got != want {
			t.Errorf("%s=%q permits the remote lookup: %v, want %v", remoteLookupVariable, value, got, want)
		}
	}
}

// TestTheVariableWithTheValue0CancelsNoOption holds the port reading that the variable is a
// permission and never a refusal.
func TestTheVariableWithTheValue0CancelsNoOption(t *testing.T) {
	if !remoteLookupPermitted(true, environment(map[string]string{remoteLookupVariable: "0"})) {
		t.Errorf("%s=0 cancels --lookup-remote", remoteLookupVariable)
	}
}

// TestTheVariableAloneAsksForNoLookup holds `ja4plus/cli.py:529` at `v1.3.0`: the variable
// permits the disclosure, and it asks for no lookup.
func TestTheVariableAloneAsksForNoLookup(t *testing.T) {
	remote := &fakeRemote{application: "remote app"}
	var notice bytes.Buffer

	identify := newIdentifier(false, false, environment(map[string]string{remoteLookupVariable: "1"}), &notice, remote.lookup)
	if identify != nil {
		t.Fatal("a run that names no lookup option builds an identifier")
	}

	if got := identify.application(unknownFingerprint); got != "" {
		t.Errorf("a nil identifier returns %q", got)
	}

	if notice.Len() != 0 {
		t.Errorf("a run without a lookup writes a notice: %q", notice.String())
	}

	if len(remote.calls) != 0 {
		t.Errorf("a run without a lookup sends %d requests", len(remote.calls))
	}
}

func TestTheLookupOptionAloneSendsNoRemoteRequest(t *testing.T) {
	remote := &fakeRemote{application: "remote app"}
	var notice bytes.Buffer

	identify := newIdentifier(true, false, environment(nil), &notice, remote.lookup)

	if got := identify.application(unknownFingerprint); got != "" {
		t.Errorf("the local lookup returns %q for a fingerprint the table does not hold", got)
	}

	if len(remote.calls) != 0 {
		t.Errorf("--lookup alone sends %d remote requests", len(remote.calls))
	}

	if notice.Len() != 0 {
		t.Errorf("--lookup alone writes the disclosure notice: %q", notice.String())
	}
}

func TestTheLookupOptionAndTheVariableReachTheRemoteLookup(t *testing.T) {
	remote := &fakeRemote{application: "remote app"}
	var notice bytes.Buffer

	identify := newIdentifier(true, false, environment(map[string]string{remoteLookupVariable: "1"}), &notice, remote.lookup)

	if got := identify.application(unknownFingerprint); got != "remote app" {
		t.Errorf("the application is %q, want %q", got, "remote app")
	}

	if len(remote.calls) != 1 || remote.calls[0] != unknownFingerprint {
		t.Errorf("the remote requests are %q, want one for %q", remote.calls, unknownFingerprint)
	}
}

func TestTheRemoteLookupOptionAloneReachesTheRemoteLookup(t *testing.T) {
	remote := &fakeRemote{application: "remote app"}
	var notice bytes.Buffer

	identify := newIdentifier(false, true, environment(nil), &notice, remote.lookup)

	if got := identify.application(unknownFingerprint); got != "remote app" {
		t.Errorf("the application is %q, want %q", got, "remote app")
	}
}

// TestThePermittedRunWritesTheNoticeOnce holds FR-db-enrichment-6 of the port: one run writes
// one disclosure notice, whatever count of fingerprints it looks up.
func TestThePermittedRunWritesTheNoticeOnce(t *testing.T) {
	remote := &fakeRemote{}
	var notice bytes.Buffer

	identify := newIdentifier(true, true, environment(nil), &notice, remote.lookup)
	identify.application("a_b_c")
	identify.application("d_e_f")

	if got := strings.Count(notice.String(), "\n"); got != 1 {
		t.Fatalf("the run writes %d notice lines, want 1: %q", got, notice.String())
	}

	for _, want := range []string{"https://ja4db.com", "--lookup-remote", remoteLookupVariable} {
		if !strings.Contains(notice.String(), want) {
			t.Errorf("the notice names no %q: %q", want, notice.String())
		}
	}
}

func TestALocalHitSendsNoRemoteRequest(t *testing.T) {
	local := ja4plus.LookupFingerprint(knownFingerprint)
	if local == nil {
		t.Fatalf("the mapping table holds no entry for %s", knownFingerprint)
	}

	remote := &fakeRemote{application: "remote app"}
	identify := newIdentifier(true, true, environment(nil), &bytes.Buffer{}, remote.lookup)

	if got := identify.application(knownFingerprint); got != local.Application {
		t.Errorf("the application is %q, want the local %q", got, local.Application)
	}

	if len(remote.calls) != 0 {
		t.Errorf("a local hit sends %d remote requests", len(remote.calls))
	}
}

// TestARemoteFailureReadsAsAMiss holds the port reading that a lookup enriches a fingerprint
// and never fails the run. `ja4plus/ja4db.py:495` at `v1.3.0` treats every failure as a miss.
func TestARemoteFailureReadsAsAMiss(t *testing.T) {
	remote := &fakeRemote{err: errors.New("connection refused")}
	identify := newIdentifier(false, true, environment(nil), &bytes.Buffer{}, remote.lookup)

	if got := identify.application(unknownFingerprint); got != "" {
		t.Errorf("a failed remote lookup returns %q", got)
	}
}

func TestARepeatedFingerprintSendsOneRemoteRequest(t *testing.T) {
	remote := &fakeRemote{}
	identify := newIdentifier(false, true, environment(nil), &bytes.Buffer{}, remote.lookup)

	for range 3 {
		identify.application(unknownFingerprint)
	}

	if len(remote.calls) != 1 {
		t.Errorf("three lookups of one missed fingerprint send %d requests, want 1", len(remote.calls))
	}
}

// TestTheRemoteCacheHoldsABoundedCountOfEntries holds the bound that keeps a long-running
// monitor from growing the cache without a limit.
func TestTheRemoteCacheHoldsABoundedCountOfEntries(t *testing.T) {
	remote := &fakeRemote{}
	identify := newIdentifier(false, true, environment(nil), &bytes.Buffer{}, remote.lookup)

	for i := range maxRemoteCacheEntries + 10 {
		identify.application(fmt.Sprintf("fp_%d", i))
	}

	if got := len(identify.cache); got > maxRemoteCacheEntries {
		t.Errorf("the cache holds %d entries, and the bound is %d", got, maxRemoteCacheEntries)
	}
}

func TestTheAnalyzeCommandAcceptsTheRemoteLookupOption(t *testing.T) {
	err := runAnalyze([]string{"testdata-absent.pcap", "--lookup-remote"})
	if err == nil {
		t.Fatal("runAnalyze opens a capture file that does not exist")
	}

	if strings.Contains(err.Error(), "unknown option") {
		t.Errorf("analyze refuses --lookup-remote: %v", err)
	}
}

func TestTheWatchCommandAcceptsTheRemoteLookupOption(t *testing.T) {
	options, err := parseWatchArgs([]string{"--interface", "en0", "--lookup-remote"})
	if err != nil {
		t.Fatalf("watch refuses --lookup-remote: %v", err)
	}

	if !options.lookupRemote {
		t.Error("the remote lookup option is false, and the arguments hold --lookup-remote")
	}
}

func TestTheUsageTextNamesTheRemoteLookupOptionAndTheVariable(t *testing.T) {
	for _, want := range []string{"--lookup-remote", remoteLookupVariable} {
		if !strings.Contains(usageText(), want) {
			t.Errorf("the usage text names no %q", want)
		}
	}
}
