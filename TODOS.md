# TODOs

## Live capture CLI subcommand

**What:** Add `ja4plus live --interface eth0` for real-time packet capture.

**Why:** Biggest missing feature for end-users. The Python reference has this via scapy.

**Pros:** Makes the tool usable for live traffic analysis without a tcpdump+pcap round-trip.

**Cons:** Requires CGO + libpcap binding (`gopacket/pcap`). Complicates cross-compilation and the build matrix. On ARM64/Jetson, libpcap should be available but CGO adds complexity.

**Context:** Go would use `gopacket/pcap` which wraps libpcap via CGO. Consider whether to make this a separate binary or use build tags to gate the feature. The `Processor` type already supports per-packet processing, so the CLI just needs a capture loop.

**Depends on:** Nothing. Independent of fingerprint correctness.
