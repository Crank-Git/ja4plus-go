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
package ja4db
