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

# A README cannot play a video: GitHub keeps <video> only for its own asset
# hosts, and proxies images from a private repo's releases without the
# credentials to fetch them.  What it does render is a file in the
# repository, so the same recording is filmed again, smaller and quicker,
# and turned into the one animated format a README will show.
if command -v ffmpeg >/dev/null 2>&1; then
	echo "filming it again for the README"
	"$here/as-trace" film "$out/demo.json" -o "$scratch/short.mp4" \
		--size 1280x720 --ms "${GIF_MS:-320}" --hold 900
	palette=$scratch/palette.png
	frames="fps=7,scale=900:-1:flags=lanczos"
	ffmpeg -v error -y -i "$scratch/short.mp4" \
		-vf "$frames,palettegen=max_colors=40:stats_mode=diff" "$palette"
	ffmpeg -v error -y -i "$scratch/short.mp4" -i "$palette" \
		-lavfi "$frames[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle" \
		"$out/address-space.gif"
fi

ls -l "$out"
