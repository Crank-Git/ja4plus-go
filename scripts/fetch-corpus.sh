#!/usr/bin/env bash
#
# Fetch the FoxIO corpus at the commit that `testdata/foxio.pin` names. One archive gives
# the captures, the two vector sets and the reference tree.
#
# #797 read the reference tree at a second pin, `testdata/foxio-reading.pin`, from
# 2026-10-01 UTC. #801 reread each citation at `testdata/foxio.pin` and removed the second pin, so
# a reading and a vector name one commit again.
#
# The corpus is FoxIO-licensed material, so `.gitignore` keeps `testdata/foxio/` out of the
# repository. Never commit a fetched file.
#
# The script writes four directories.
#
#   testdata/foxio/pcap/        the captures
#   testdata/foxio/python/      the per-stream vectors
#   testdata/foxio/wireshark/   the per-packet vectors
#   testdata/foxio/reference/   the rest of the FoxIO repository
#
# `.claude/rules/rulings.md` requires a reading to cite a file and a line at the pinned
# commit. The reference tree holds each cited file under the name the FoxIO repository
# uses, so `reference/python/test/test_ja4_output.py:15` reads here. #165 opened because
# the corpus held no such file, and three slices had already paid for that.
#
# The reference tree holds the whole repository except the captures and the two vector
# directories, which the three directories above already hold.
#
# `JA4PLUS_CORPUS_URL` names the archive. The tests set it to a local archive, so that no
# test reaches the network.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$root/testdata/foxio.pin"
corpus_dir="$root/testdata/foxio"
fetched_file="$corpus_dir/.fetched"

fail() {
	echo "fetch-corpus: $1" >&2
	exit 1
}

# read_pin prints the commit that the pin file names.
read_pin() {
	if [ ! -f "$1" ]; then
		fail "$1 is absent. The pin names the FoxIO commit to fetch."
	fi

	local pin
	pin="$(tr -d '[:space:]' <"$1")"
	if [ -z "$pin" ]; then
		fail "$1 names no commit."
	fi

	echo "$pin"
}

commit="$(read_pin "$pin_file")"

# The archive holds the source paths on the left, and the corpus holds the names on the
# right. A missing source path means that FoxIO moved the corpus at the pin.
sources=(pcap python/test/testdata wireshark/test/testdata)
targets=(pcap python wireshark)

# Each path here carries a citation that `docs/specs/foxio/` already holds, so a silent
# loss of one breaks a reading this repository depends on. `technical_details/` decides
# every schema. The two harness files state which captures FoxIO enumerates. The four
# reference implementations decide behavior where the image is silent, and
# `wireshark/source/packet-ja4.c` alone carries 147 citations.
#
# A missing path here means that the pin names a commit that moved the material, and the
# script stops rather than write a reference tree that a reading cannot cite.
cited=(
	technical_details
	python/ja4.py
	python/test/test_ja4_output.py
	wireshark/source/packet-ja4.c
	wireshark/test/test_tshark_output.py
	zeek
	rust
)

# The guard reads the directories as well as the commit. A corpus that an earlier version
# of this script wrote names the pinned commit and holds no reference tree, and that
# corpus must fetch again. A corpus that #797 wrote holds a reference tree at the second
# pin, and its `.fetched` file names `testdata/foxio.pin` alone. So the guard also requires that
# no `.fetched-reading` file remains, and such a corpus fetches once more.
corpus_is_complete() {
	[ -f "$fetched_file" ] || return 1
	[ "$(tr -d '[:space:]' <"$fetched_file")" = "$commit" ] || return 1
	[ ! -e "$corpus_dir/.fetched-reading" ] || return 1

	for directory in "${targets[@]}" reference; do
		[ -d "$corpus_dir/$directory" ] || return 1
	done
}

if corpus_is_complete; then
	echo "fetch-corpus: the corpus is present at $commit. The script downloads nothing."
	exit 0
fi

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

# download extracts the archive of the URL into the directory. The second argument names
# the commit for the failure messages.
#
# curl writes the archive to a file, so a failed transfer never reaches tar.
# `--max-filesize` bounds the body, as `.claude/rules/external-apis.md` requires. The FoxIO
# repository is 16 MB at `27f0cbf9`, so 512 MB leaves room for growth.
# `--no-same-owner` stops the archive from naming the owner of an extracted file.
download() {
	local url="$1" pinned="$2" into="$3"

	if ! curl --fail --location --silent --show-error \
		--connect-timeout 30 --max-time 900 --max-filesize 536870912 \
		--output "$into.tar.gz" "$url"; then
		fail "the network did not deliver $url. The script leaves the corpus in place."
	fi

	mkdir -p "$into"
	if ! tar -xzf "$into.tar.gz" -C "$into" --strip-components=1 --no-same-owner; then
		fail "the archive at $pinned does not extract. The script leaves the corpus in place."
	fi
}

# replace moves the staged directory to the corpus path. The previous directory moves aside
# first, so a failed move restores it rather than losing it.
replace() {
	local staged="$1" target="$2"

	if [ -d "$target" ] && ! mv "$target" "$target.previous"; then
		fail "the script cannot move $target aside, and the next run fetches again."
	fi

	if ! mv "$staged" "$target"; then
		mv "$target.previous" "$target" 2>/dev/null || true
		fail "the script cannot write $target, and the next run fetches again."
	fi

	rm -rf "$target.previous"
}

download "${JA4PLUS_CORPUS_URL:-https://codeload.github.com/FoxIO-LLC/ja4/tar.gz/$commit}" "$commit" "$stage/archive"

for index in "${!sources[@]}"; do
	if [ ! -d "$stage/archive/${sources[$index]}" ]; then
		fail "the archive at $commit holds no ${sources[$index]}. The script leaves the corpus in place."
	fi
done

for path in "${cited[@]}"; do
	if [ ! -e "$stage/archive/$path" ]; then
		fail "the archive at $commit holds no $path. The script leaves the corpus in place."
	fi
done

# The fetched file goes first, because an interrupted replace must not leave a file that
# names the previous commit beside a corpus that holds two commits.
rm -f "$fetched_file" "$corpus_dir/.fetched-reading"

# The script replaces the corpus only after every path arrives, so a failed run keeps the
# previous corpus complete. Each source directory moves out of the archive first, so the
# reference tree holds no capture and no vector a second time.
for index in "${!sources[@]}"; do
	replace "$stage/archive/${sources[$index]}" "${corpus_dir:?}/${targets[$index]}"
done
replace "$stage/archive" "${corpus_dir:?}/reference"

# The fetched file is the last write, so it names a complete corpus and never a partial one.
echo "$commit" >"$fetched_file"

echo "fetch-corpus: the corpus is at $commit."

echo "fetch-corpus: $(find "$corpus_dir/pcap" -type f | wc -l | tr -d ' ') captures, \
$(find "$corpus_dir/python" -type f | wc -l | tr -d ' ') per-stream vectors, \
$(find "$corpus_dir/wireshark" -type f | wc -l | tr -d ' ') per-packet vectors, \
$(find "$corpus_dir/reference" -type f | wc -l | tr -d ' ') reference files."
