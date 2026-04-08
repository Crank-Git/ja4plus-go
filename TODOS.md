# TODOs

## Live capture CLI subcommand

**What:** Add `ja4plus live --interface eth0` for real-time packet capture.

**Why:** Biggest missing feature for end-users. The Python reference has this via scapy.

**Pros:** Makes the tool usable for live traffic analysis without a tcpdump+pcap round-trip.

**Cons:** Requires CGO + libpcap binding (`gopacket/pcap`). Complicates cross-compilation and the build matrix. On ARM64/Jetson, libpcap should be available but CGO adds complexity.

**Context:** Go would use `gopacket/pcap` which wraps libpcap via CGO. Consider whether to make this a separate binary or use build tags to gate the feature. The `Processor` type already supports per-packet processing, so the CLI just needs a capture loop.

**Depends on:** Nothing. Independent of fingerprint correctness.

## Remote JA4DB API fallback

**What:** Query `ja4db.com/api/read/{fingerprint}` when not found in embedded CSV.

**Why:** Useful for threat intel workflows where the local database is stale.

**Pros:** Better identification coverage without manual database updates.

**Cons:** Adds `net/http` dependency. Network calls in a library are surprising behavior. Needs API key management and error handling for network failures.

**Context:** The Python reference falls back to the API automatically. For the Go library, consider making this opt-in: accept an optional `http.Client` or API lookup interface in the `Processor` constructor rather than making implicit network calls.

**Depends on:** Nothing. Independent of fingerprint correctness.
