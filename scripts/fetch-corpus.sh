#!/usr/bin/env bash
#
# Fetch the FoxIO corpus at the commit in `testdata/foxio.pin`.
#
# The corpus is FoxIO-licensed material, so `.gitignore` keeps `testdata/foxio/` out of the
# repository. Never commit a fetched file.
#
# The script writes three directories.
#
#   testdata/foxio/pcap/        the captures
#   testdata/foxio/python/      the per-stream vectors
#   testdata/foxio/wireshark/   the per-packet vectors
#
# `JA4PLUS_CORPUS_URL` names the archive to read. The tests set it to a local archive, so
# that no test reaches the network.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$root/testdata/foxio.pin"
corpus_dir="$root/testdata/foxio"
fetched_file="$corpus_dir/.fetched"

fail() {
	echo "fetch-corpus: $1" >&2
	exit 1
}

if [ ! -f "$pin_file" ]; then
	fail "$pin_file is absent. The pin names the FoxIO commit to fetch."
fi

commit="$(tr -d '[:space:]' <"$pin_file")"
if [ -z "$commit" ]; then
	fail "$pin_file names no commit."
fi

if [ -f "$fetched_file" ] && [ "$(tr -d '[:space:]' <"$fetched_file")" = "$commit" ]; then
	echo "fetch-corpus: the corpus is present at $commit. The script downloads nothing."
	exit 0
fi

url="${JA4PLUS_CORPUS_URL:-https://codeload.github.com/FoxIO-LLC/ja4/tar.gz/$commit}"

mkdir -p "$corpus_dir"

# The staging directory sits below the ignored corpus directory, so an interrupted run
# leaves nothing that git reports.
stage="$(mktemp -d "$corpus_dir/.stage.XXXXXX")"

# `rmdir` removes the corpus directory only when this run created it and left it empty. An
# empty directory would tell the conformance suite that a corpus is present.
cleanup() {
	rm -rf "$stage"
	rmdir "$corpus_dir" 2>/dev/null || true
}
trap cleanup EXIT

# curl writes the archive to a file, so a failed transfer never reaches tar.
if ! curl --fail --location --silent --show-error \
	--connect-timeout 30 --max-time 900 \
	--output "$stage/corpus.tar.gz" "$url"; then
	fail "the network did not deliver $url. The script leaves the corpus in place."
fi

mkdir -p "$stage/src"
if ! tar -xzf "$stage/corpus.tar.gz" -C "$stage/src" --strip-components=1; then
	fail "the archive at $commit does not extract. The script leaves the corpus in place."
fi

# The archive holds the source paths on the left, and the corpus holds the names on the
# right. A missing source path means that FoxIO moved the corpus at this commit.
sources=(pcap python/test/testdata wireshark/test/testdata)
targets=(pcap python wireshark)

for index in "${!sources[@]}"; do
	if [ ! -d "$stage/src/${sources[$index]}" ]; then
		fail "the archive at $commit holds no ${sources[$index]}. The script leaves the corpus in place."
	fi
done

# The script replaces the corpus only after every source directory arrives, so a failed run
# keeps the previous corpus complete.
for index in "${!sources[@]}"; do
	rm -rf "${corpus_dir:?}/${targets[$index]}"
	mv "$stage/src/${sources[$index]}" "$corpus_dir/${targets[$index]}"
done

# The fetched file is the last write, so it names a complete corpus and never a partial one.
echo "$commit" >"$fetched_file"

echo "fetch-corpus: the corpus is at $commit."
echo "fetch-corpus: $(find "$corpus_dir/pcap" -type f | wc -l | tr -d ' ') captures, \
$(find "$corpus_dir/python" -type f | wc -l | tr -d ' ') per-stream vectors, \
$(find "$corpus_dir/wireshark" -type f | wc -l | tr -d ' ') per-packet vectors."
