#!/usr/bin/env bash
#
# Fetch the FoxIO corpus at the commit in `testdata/foxio.pin`.
#
# The corpus is FoxIO-licensed material, so `.gitignore` keeps `testdata/foxio/` out of the
# repository. Never commit a fetched file.
#
# The script writes four directories.
#
#   testdata/foxio/pcap/        the captures
#   testdata/foxio/python/      the per-stream vectors
#   testdata/foxio/wireshark/   the per-packet vectors
#   testdata/foxio/reference/   the rest of the FoxIO repository at the pinned commit
#
# `.claude/rules/rulings.md` requires a reading to cite a file and a line at the pinned
# commit. The reference tree holds each cited file under the name the FoxIO repository
# uses, so `reference/python/test/test_ja4_output.py:15` reads here. #165 opened because
# the corpus held no such file, and three slices had already paid for that.
#
# The reference tree holds the whole repository except the captures and the two vector
# directories, which the three directories above already hold. The download reads the
# whole archive either way, so the reference tree costs 2.5 MB of disk and no network.
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

# The guard reads the directories as well as the commit. A corpus that an earlier version
# of this script wrote names the pinned commit and holds no reference tree, and that
# corpus must fetch again.
corpus_is_complete() {
	[ -f "$fetched_file" ] || return 1
	[ "$(tr -d '[:space:]' <"$fetched_file")" = "$commit" ] || return 1

	for directory in pcap python wireshark reference; do
		[ -d "$corpus_dir/$directory" ] || return 1
	done
}

if corpus_is_complete; then
	echo "fetch-corpus: the corpus is present at $commit. The script downloads nothing."
	exit 0
fi

url="${JA4PLUS_CORPUS_URL:-https://codeload.github.com/FoxIO-LLC/ja4/tar.gz/$commit}"

mkdir -p "$corpus_dir"

# A run that a `SIGKILL` stops never reaches the trap, so it leaves a staging directory.
# This sweep removes the leftovers of such a run.
rm -rf "${corpus_dir:?}"/.stage.* "${corpus_dir:?}"/*.previous

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
# `--max-filesize` bounds the body, as `.claude/rules/external-apis.md` requires. The FoxIO
# repository is 16 MB at the pinned commit, so 512 MB leaves room for growth.
if ! curl --fail --location --silent --show-error \
	--connect-timeout 30 --max-time 900 --max-filesize 536870912 \
	--output "$stage/corpus.tar.gz" "$url"; then
	fail "the network did not deliver $url. The script leaves the corpus in place."
fi

# `--no-same-owner` stops the archive from naming the owner of an extracted file.
mkdir -p "$stage/src"
if ! tar -xzf "$stage/corpus.tar.gz" -C "$stage/src" --strip-components=1 --no-same-owner; then
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

# Each path here carries a citation that `docs/specs/foxio/` already holds, so a silent
# loss of one breaks a reading this repository depends on. `technical_details/` decides
# every schema. The two harness files state which captures FoxIO enumerates. The four
# reference implementations decide behaviour where the image is silent, and
# `wireshark/source/packet-ja4.c` alone carries 147 citations.
#
# A missing path here means that FoxIO moved the material at this commit, and the script
# stops rather than write a reference tree that a reading cannot cite.
cited=(
	technical_details
	python/ja4.py
	python/test/test_ja4_output.py
	wireshark/source/packet-ja4.c
	wireshark/test/test_tshark_output.py
	zeek
	rust
)

for path in "${cited[@]}"; do
	if [ ! -e "$stage/src/$path" ]; then
		fail "the archive at $commit holds no $path. The script leaves the corpus in place."
	fi
done

# The fetched file goes first, because an interrupted replace must not leave a file that
# names the previous commit beside a corpus that holds two commits.
rm -f "$fetched_file"

# The script replaces the corpus only after every source directory arrives, so a failed run
# keeps the previous corpus complete. Each directory moves aside before the new one
# arrives, so a failed move restores the previous directory rather than losing it.
for index in "${!sources[@]}"; do
	target="${corpus_dir:?}/${targets[$index]}"

	if [ -d "$target" ] && ! mv "$target" "$target.previous"; then
		fail "the script cannot move $target aside. The corpus is unchanged."
	fi

	if ! mv "$stage/src/${sources[$index]}" "$target"; then
		mv "$target.previous" "$target" 2>/dev/null || true
		fail "the script cannot write $target. The corpus holds the previous ${targets[$index]}."
	fi

	rm -rf "$target.previous"
done

# The staged tree now holds the whole repository except the three directories the loop
# moved out of it. The move below therefore writes one copy of each file, and a reader
# never compares the corpus with itself.
# The loop above already replaced the captures and the two vector directories, so neither
# message below may state that the corpus is unchanged. The script removed the fetched file
# before the loop, so the next run reads an incomplete corpus and fetches again.
if [ -d "$corpus_dir/reference" ] && ! mv "$corpus_dir/reference" "$corpus_dir/reference.previous"; then
	fail "the script cannot move $corpus_dir/reference aside. The corpus holds the new captures and the new vectors, and the next run fetches again."
fi

if ! mv "$stage/src" "$corpus_dir/reference"; then
	mv "$corpus_dir/reference.previous" "$corpus_dir/reference" 2>/dev/null || true
	fail "the script cannot write $corpus_dir/reference. The corpus holds the new captures, the new vectors and the previous reference, and the next run fetches again."
fi

rm -rf "${corpus_dir:?}/reference.previous"

# The fetched file is the last write, so it names a complete corpus and never a partial one.
echo "$commit" >"$fetched_file"

echo "fetch-corpus: the corpus is at $commit."
echo "fetch-corpus: $(find "$corpus_dir/pcap" -type f | wc -l | tr -d ' ') captures, \
$(find "$corpus_dir/python" -type f | wc -l | tr -d ' ') per-stream vectors, \
$(find "$corpus_dir/wireshark" -type f | wc -l | tr -d ' ') per-packet vectors, \
$(find "$corpus_dir/reference" -type f | wc -l | tr -d ' ') reference files."
