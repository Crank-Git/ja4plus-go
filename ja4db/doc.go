// Package ja4db asks the ja4db.com service for the record of one JA4+ fingerprint.
//
// # Network
//
// LookupFingerprintRemote is the one function of this package, and it performs network
// input and network output. It is opt-in: the caller supplies the context, and the caller
// supplies the client.
//
// The core package github.com/Crank-Git/ja4plus-go imports no HTTP client, so a program
// that imports the core package alone reaches no network. Its LookupFingerprint reads the
// embedded table or the cache file, and it makes no request.
//
// The maintainer ruled on 2026-08-14 that the remote lookup lives in this package, and
// docs/audit/network-boundary.md holds the record and the reason.
//
// # Transport
//
// A caller that supplies no client gets one that carries a timeout of 10 seconds. That
// client verifies the server certificate, because this package sets no transport of its own
// and the transport of the standard library verifies it.
//
// A lookup follows a redirect to the https scheme alone, and it returns an error for any
// other scheme. The request path carries the fingerprint, so a plain scheme discloses it.
// A caller that states a redirect policy keeps that policy.
//
// That rule governs a redirect, and it governs no first request. The default endpoint carries
// the https scheme. A caller that states an endpoint states the scheme of the first request,
// and this package sends the request to the endpoint the caller names.
//
// A lookup reads at most 1 MB of the response body, and it returns an error beyond that
// bound. It escapes the fingerprint before it builds the request path. It sends a
// User-Agent header that names this library and its version.
//
// #73 built each rule of this section, and docs/specs/features/09-database-lookup.md holds
// the requirements FR-lookup-8 through FR-lookup-17.
package ja4db
