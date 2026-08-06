---
name: run
description: Build and run the ja4plus command-line program against a capture. Use when asked to run the tool, try a change by hand, print fingerprints for a capture, or inspect the database.
allowed-tools: Bash, Read
---

# Run ja4plus

The project is a library and a command-line program. There is no server and nothing to
deploy. To see a change work, run the program against a capture.

## 1. Build

```
make build
```

The binary lands at `bin/ja4plus`. The build needs no cgo and no libpcap.

## 2. Get a capture

Use the FoxIO corpus. Fetch it once:

```
make corpus
```

Useful captures for each method:

| Capture | Exercises |
|---|---|
| `testdata/foxio/pcap/tls12.pcap` | JA4, JA4S, JA4X, JA4T, JA4TS, JA4L |
| `testdata/foxio/pcap/http1-with-cookies.pcapng` | JA4H |
| `testdata/foxio/pcap/ssh2.pcapng` | JA4SSH |
| `testdata/foxio/pcap/dhcp.pcapng` | JA4D |
| `testdata/foxio/pcap/dhcpv6.pcap` | JA4D6 |
| `testdata/foxio/pcap/quic-tls-handshake.pcapng` | JA4 over QUIC |

## 3. Run

```
./bin/ja4plus testdata/foxio/pcap/tls12.pcap
```

For machine-readable output, including the raw fingerprint forms:

```
./bin/ja4plus --json testdata/foxio/pcap/tls12.pcap
```

## 4. Inspect the database

```
./bin/ja4plus db info
```

It prints the source (`embedded` or `cache`), the record count and the cache path.

`./bin/ja4plus db update` downloads a new database. **It reaches the network.** Do not run
it as part of an automated check.

## 5. Check the version

```
./bin/ja4plus --version
```

## What to expect

- Every failure names its cause and exits with a non-zero status.
- The library itself writes nothing. All output belongs to the command-line program. If a
  change makes the library print something, that is a defect.
- A capture with no matching traffic produces no fingerprint and exits zero. That is not
  a failure.

## Do not

- Do not run a live capture. The library reads packets that the caller supplies, and the
  program reads a file.
- Do not run `db update` in a test or a hook.
