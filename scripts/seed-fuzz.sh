#!/bin/sh
# seed-fuzz.sh writes the FoxIO-derived seed inputs of the fuzz corpus.
# FR-fuzz-22 of `docs/specs/features/06-fuzz-testing.md` states the requirement.
#
# The script reads the FoxIO corpus, and it copies no byte of a capture into the tree.
# For each record it finds, it reads these numbers and nothing else.
#   - The protocol version.
#   - The cipher suite identifiers, in order.
#   - The TLS extension identifiers, in order.
#   - The HTTP method and the HTTP header names, in order.
# It then builds a new record from those numbers, with a fixed filler for every other
# field. Each number above is an identifier of an IANA registry, and the output holds no
# random value, no session identifier, no key share, no host name, no header value and no
# certificate of the capture. So the output carries no FoxIO license obligation, and
# FR-fuzz-23 tracks the result in git.
#
# The corpus is optional. A fresh clone holds no corpus, and this script then writes
# nothing and reports success. `make corpus` fetches the corpus.
#
# The script reads a classic pcap file, and it reads no pcapng file. `## The formats this
# script reads` of `testdata/fuzz/README.md` states the reason.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
corpus=$root/testdata/foxio/pcap
out=$root/internal/parser/testdata/fuzz
reducer=$root/scripts/seed-fuzz-reduce.awk

if [ ! -d "$corpus" ]; then
	echo "seed-fuzz: no FoxIO corpus at testdata/foxio/pcap."
	echo "seed-fuzz: run 'make corpus' to fetch it. The tracked seed corpus needs no fetch."
	exit 0
fi

# write_seed builds one seed file from the first capture that holds the named record.
# It takes the record kind, the fuzz target and the seed file name.
write_seed() {
	kind=$1
	target=$2
	name=$3

	for capture in "$corpus"/*.pcap; do
		[ -f "$capture" ] || continue

		record=$(od -An -v -tx1 "$capture" | awk -v kind="$kind" -f "$reducer" 2>/dev/null) || continue
		[ -n "$record" ] || continue

		mkdir -p "$out/$target"
		# `printf` writes the backslash of each escape. `echo` reads that backslash as an
		# escape of its own, and it then writes the byte rather than the escape.
		printf 'go test fuzz v1\n[]byte("%s")\n' "$record" \
			> "$out/$target/$name-$(basename "$capture" .pcap)"

		echo "seed-fuzz: $target/$name-$(basename "$capture" .pcap) <- $(basename "$capture")"
		return 0
	done

	echo "seed-fuzz: no capture holds a $kind record. The target keeps its tracked seeds."
	return 0
}

write_seed clienthello FuzzParseClientHelloReadsAnyPayload accepts-the-reduced-client-hello-of
write_seed serverhello FuzzParseServerHelloReadsAnyPayload accepts-the-reduced-server-hello-of
write_seed http FuzzParseHTTPRequestReadsAnyPayload accepts-the-reduced-request-of

echo "seed-fuzz: done. Run 'go test ./internal/parser/' to replay every seed."
