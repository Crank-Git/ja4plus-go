# Types and helpers

**This page indexes every exported name that is neither a fingerprinter nor a processor.**
[Fingerprinters](fingerprinters.md) and [Processors](processors.md) hold the other two
groups.

## The result types

| Type | What holds it |
|---|---|
| [`FingerprintResult`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#FingerprintResult) | Every `ProcessPacket` call and every window close returns a slice of it. |
| [`HASSHResult`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#HASSHResult) | `JA4SSHFingerprinter.GetHASSHFingerprints` returns a slice of it. |
| [`SSHSessionInfo`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#SSHSessionInfo) | `InterpretJA4SSH` returns one. |

**The [output schema](../output-schema.md#the-library-result) page states every field of
`FingerprintResult` and what it holds.** This page names the type and links the signature,
and it repeats no field.

**HASSH is not a JA4+ method.** It is a separate SSH fingerprint that the SSH handshake
produces, and this library reports it beside JA4SSH.

## The key log

**A key log holds the TLS secrets that decrypt a capture.** The library reads a secret only
when the caller supplies one, and it reads no key material outside the reader the caller
passes.

| Name | What it is |
|---|---|
| [`KeyLog`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#KeyLog) | The secrets of one or more connections. The client random identifies each one. |
| [`ParseKeyLog`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ParseKeyLog) | Reads a key log in the NSS key log format. |
| [`ReadKeyLogFromCapture`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ReadKeyLogFromCapture) | Reads the Decryption Secrets Blocks of a pcapng capture. |
| [`KeyLog.Secret`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#KeyLog.Secret) | Returns the secret of one label for one connection. |
| [`KeyLog.ClientRandoms`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#KeyLog.ClientRandoms) | Returns the client random of every connection, sorted. |
| [`KeyLog.Len`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#KeyLog.Len) | Returns the count of secrets. |
| [`ErrNoSecret`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#ErrNoSecret) | Reports that no secret is available for the connection. |

**A `KeyLog` does not change after the constructor returns, so any number of goroutines read
one.** It is the one exported type of this library that more than one goroutine may share
without a mutex.

**`ErrNoSecret` reaches two callers.** One supplied no key log, and one supplied a key log
that holds no secret for the connection. Compare it with `errors.Is`.

## The QUIC decryption function

[`DecryptQUICPacket`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#DecryptQUICPacket)
returns the frame bytes of one QUIC packet that a secret protects. `KeyLog.Secret` returns
that secret.

- **A long header packet carries its own lengths**, so it ignores the connection identifier
  length the caller passes.
- **A short header packet does not**, so the caller states the Destination Connection ID
  length.
- **It returns `ErrNoSecret` when the caller supplies no secret**, and it produces no
  fingerprint in that case.

RFC 9001 Section 5.1 states the key derivation, and Section 5.4.1 states the header
protection.

## The database lookup

**The lookup maps a fingerprint to the application that produces it.** The
[Usage](../usage.md#the-database-lookup) page states which function reaches the network and
which one does not.

| Name | What it is |
|---|---|
| [`LookupResult`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#LookupResult) | The record the mapping table holds for one fingerprint. |
| [`LookupFingerprint`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#LookupFingerprint) | Reads the local mapping table. It performs no network call. |
| [`LookupFingerprintRemote`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#LookupFingerprintRemote) | Reads a remote endpoint. The caller opts in with a context and a config. |
| [`RemoteLookupConfig`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#RemoteLookupConfig) | The endpoint and the HTTP client of a remote lookup. |
| [`DatabaseInfo`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#DatabaseInfo) | The source, the path, the entry count and the modification time of the active table. |
| [`GetDatabaseInfo`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#GetDatabaseInfo) | Returns the `DatabaseInfo` of the active table. |
| [`CachedDatabasePath`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#CachedDatabasePath) | Returns the path of the cached mapping file, and it creates the directory. |

**`LookupFingerprint` returns `nil` for a fingerprint the table does not hold.**
`LookupFingerprintRemote` returns `nil` and `nil` for the same case, and it returns `nil`
and an error for a transport failure, a status other than 200, and a body it cannot decode.

## The interpretation helpers

**Each function below reads a value and estimates something about the endpoint.** An
estimate is not a fingerprint, and no FoxIO vector holds one.

| Function | What it estimates |
|---|---|
| [`InterpretJA4SSH`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#InterpretJA4SSH) | The session type of one JA4SSH value. It returns `nil` for a value it cannot read. |
| [`LookupHASSH`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#LookupHASSH) | The name of a known HASSH fingerprint. It returns an empty string for an unknown one. |
| [`EstimateOS`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#EstimateOS) | The operating system, from the observed time-to-live. |
| [`EstimateHopCount`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#EstimateHopCount) | The hop count, from the observed time-to-live. |
| [`CalculateDistance`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#CalculateDistance) | The distance in miles, from a one-way latency. |
| [`CalculateDistanceKm`](https://pkg.go.dev/github.com/Crank-Git/ja4plus-go#CalculateDistanceKm) | The distance in kilometers, from a one-way latency. |

**No fingerprint value of this library reads one of these functions.** The
[JA4LS](../methods/ja4ls.md) page states that part b writes the observed time-to-live and
that no branch computes a hop count. A caller that wants an estimate calls the function
itself.
