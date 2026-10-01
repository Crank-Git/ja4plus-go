package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/Crank-Git/ja4plus-go"
	"github.com/Crank-Git/ja4plus-go/ja4db"
)

// remoteLookupVariable names the environment variable that permits the remote lookup.
//
// The name and the rule follow the port under parity rule 2. `ja4plus/cli.py:78` of
// `Crank-Git/ja4plus` at tag `v1.3.0` states the name. The maintainer ruled on 2026-10-01 UTC
// that this program reads it, and issue #804 is the reversal path.
const remoteLookupVariable = "JA4PLUS_DB_LOOKUP"

// remoteLookupNotice discloses the remote lookup once for each run.
//
// A fingerprint describes traffic that the operator observed, so the notice names the third
// party that receives it and the two ways to stop the request. `ja4plus/cli.py:84` of the
// port at `v1.3.0` states the same text.
const remoteLookupNotice = "Notice: the remote lookup is on. Each fingerprint the bundled mapping file holds " +
	"no entry for goes to the lookup service at https://ja4db.com. To stop it, pass no " +
	"--lookup-remote option and unset " + remoteLookupVariable + "."

// maxRemoteCacheEntries bounds the cache of remote answers.
//
// A monitor runs until the operator stops it, so a cache without a bound grows with each
// new fingerprint. The identifier empties the cache when it reaches the bound.
const maxRemoteCacheEntries = 4096

// remoteLookupFunc returns the record that the lookup service holds for one fingerprint.
// It returns nil and nil when the service holds no record.
type remoteLookupFunc func(ctx context.Context, fingerprint string) (*ja4plus.LookupResult, error)

// lookupFromJA4DB asks `ja4db.com` for the fingerprint.
//
// A nil configuration gives the default endpoint and a client with the 10 second timeout of
// FR-lookup-10.
func lookupFromJA4DB(ctx context.Context, fingerprint string) (*ja4plus.LookupResult, error) {
	return ja4db.LookupFingerprintRemote(ctx, nil, fingerprint)
}

// remoteLookupPermitted reports whether the operator permits the remote lookup.
//
// The option and the variable each permit it, and neither one refuses it. So
// `JA4PLUS_DB_LOOKUP=0` cancels no option. The variable permits the lookup with the value
// `1` alone, because a privacy gate that guesses at a value opens on a value the operator
// did not intend. `ja4plus/cli.py:490` of the port at `v1.3.0` states both rules.
func remoteLookupPermitted(option bool, getenv func(string) string) bool {
	return option || getenv(remoteLookupVariable) == "1"
}

// identifier returns the application that a fingerprint identifies.
//
// A nil identifier serves a run that asks for no lookup, and it returns an empty string.
// One identifier serves one goroutine, because the cache holds no lock.
type identifier struct {
	// remote is nil when the operator permits no remote lookup.
	remote remoteLookupFunc
	// cache holds each remote answer, and a miss too, so a repeated fingerprint sends one
	// request.
	cache map[string]string
	// ctx ends every remote request. A run of `watch` cancels it at the first stop request,
	// and the identifier then sends no new request.
	ctx context.Context
	// deadline bounds one remote request. A zero value leaves the bound to the client
	// timeout of `ja4db`, which is 10 seconds.
	deadline time.Duration
}

// newIdentifier returns the identifier that the options ask for, or nil for a run without a
// lookup.
//
// The variable permits the remote lookup and asks for no lookup, so a run that names neither
// lookup option returns nil. When the run permits the remote lookup, the function writes the
// disclosure notice to notice once.
func newIdentifier(lookup, lookupRemote bool, getenv func(string) string, notice io.Writer, remote remoteLookupFunc) *identifier {
	if !lookup && !lookupRemote {
		return nil
	}

	if !remoteLookupPermitted(lookupRemote, getenv) {
		return &identifier{}
	}

	_, _ = fmt.Fprintln(notice, remoteLookupNotice)

	return &identifier{remote: remote, cache: make(map[string]string), ctx: context.Background()}
}

// bounded returns the identifier with a context that ends each remote request and a deadline
// for each request. It returns nil for a nil identifier.
func (id *identifier) bounded(ctx context.Context, deadline time.Duration) *identifier {
	if id == nil {
		return nil
	}

	id.ctx = ctx
	id.deadline = deadline

	return id
}

// application returns the application that the mapping table or the lookup service holds for
// the fingerprint, and an empty string when neither holds one.
//
// The mapping table answers first, so a hit sends no request. A failed remote lookup reads as
// a miss, because the lookup enriches a fingerprint that the run already produced.
// `ja4plus/ja4db.py:495` of the port at `v1.3.0` states the same rule.
func (id *identifier) application(fingerprint string) string {
	if id == nil {
		return ""
	}

	if record := ja4plus.LookupFingerprint(fingerprint); record != nil {
		return record.Application
	}

	if id.remote == nil {
		return ""
	}

	if cached, ok := id.cache[fingerprint]; ok {
		return cached
	}

	// A canceled context ends the run, so a request now delays the exit and changes no
	// result that the operator waits for.
	if id.ctx.Err() != nil {
		return ""
	}

	ctx := id.ctx
	if id.deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, id.deadline)

		defer cancel()
	}

	application := ""
	if record, err := id.remote(ctx, fingerprint); err == nil && record != nil {
		application = record.Application
	}

	if len(id.cache) >= maxRemoteCacheEntries {
		clear(id.cache)
	}

	id.cache[fingerprint] = application

	return application
}
