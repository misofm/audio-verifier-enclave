#!/bin/sh
# Rebuilds crates/libflac/flac-1.5.0 from the libFLAC 1.5.0 release archive: checks the
# archive's SHA-256, copies each file the vendored tree holds (the stream decoder's sources and
# the headers they include) from it, and applies crates/libflac/patches in order. A clean
# `git status` afterwards shows that the tree is the release plus the patches.
#
# usage: scripts/vendor-libflac.sh path/to/flac-1.5.0.tar.xz
set -eu

archive=$1
expected=f2c1c76592a82ffff8413ba3c4a1299b6c7ab06c734dee03fd88630485c2b920
actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
	echo "libFLAC archive SHA-256 is $actual, expected $expected" >&2
	exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/crates/libflac/flac-1.5.0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xJf "$archive" -C "$work"

cd "$dest"
find . -type f | while read -r path; do
	cp "$work/flac-1.5.0/$path" "$path"
done
for patch in "$root"/crates/libflac/patches/*.patch; do
	patch -p1 --fuzz=0 --no-backup-if-mismatch --forward < "$patch"
done
