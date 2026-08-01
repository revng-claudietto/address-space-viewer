#!/bin/sh
# Build the demo, record it, and film the viewer playing it back.
#
# The demo is built into a scratch directory rather than into the checkout,
# so the paths in the recording -- which the viewer puts on screen -- are the
# program's own and nothing else's.
#
# Usage: tools/demo-video.sh [OUTPUT-DIRECTORY]
# Needs: a C compiler, one of the two backends, playwright with a browser,
# and ffmpeg for anything but .webm.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${1:-$here/out}
size=${SIZE:-1600x900}
backend=${BACKEND:-strace}

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$out"

echo "building the demo"
"${CC:-cc}" -O0 -g -o "$scratch/demo" "$here/demo/demo.c"

echo "recording it with the $backend backend"
"$here/as-trace" record --backend "$backend" -o "$out/demo.json" \
	-- "$scratch/demo" >"$scratch/stdout" 2>"$scratch/stderr" || {
	cat "$scratch/stderr" >&2
	exit 1
}
tail -n 1 "$scratch/stderr" >&2

echo "drawing the first step"
"$here/as-trace" shot "$out/demo.json" -o "$out/poster.png" \
	--event 0 --size "$size"

echo "filming the whole timeline"
"$here/as-trace" film "$out/demo.json" -o "$out/address-space.mp4" \
	--size "$size" --ms "${MS:-650}" --hold "${HOLD:-1800}"

ls -l "$out"
