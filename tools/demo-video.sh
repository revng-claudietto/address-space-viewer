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
	--size "$size" --ms "${MS:-650}" --hold "${HOLD:-1800}" --fps "${FPS:-8}"

# Animated webp, and lossless.  gif has 256 colours to spend on a dark
# panel full of antialiased text; lossy webp spends its error budget on the
# edges of glyphs, which is exactly where it shows.  Neither is worth it for
# a picture whose whole content is small text, so nothing is thrown away.
#
# The frames come from `film --keep-frames`, which photographs the page
# rather than screen-recording it.  A browser's own recorder writes VP8 at a
# bitrate meant for a screen share, and encoding that losslessly preserves
# its artefacts perfectly: the same fifteen steps were 12 MB of carefully
# kept mush that way, and are 1.4 MB of exact pixels this way, because the
# noise was most of what there was to compress.
#
# 800 points wide, because that is under the width of the column a README
# is rendered in and so is shown at its own size -- an image wider than the
# column is resampled by the browser, which is the one scaling step no
# encoder setting can undo.
#
# 800 of layout, not 800 of shrunken 1280.  The type in the viewer is ten
# and eleven pixels; at 1280 laid out on 800 it comes out at seven, and
# seven pixel type is not clean however it is rasterised.  The page lays
# out for the window instead, and every glyph is drawn at the size it is
# read at.
#
# Then twice the pixels for the same 800, which is what a modern display
# asks the browser for: an 800 pixel image shown at 800 points on one of
# them is stretched to 1600 and looks it.  The README asks for it back at
# 800 wide.
if command -v img2webp >/dev/null 2>&1; then
	fps=${LOOP_FPS:-6}
	echo "photographing the whole timeline again, for the README"
	"$here/as-trace" film "$out/demo.json" -o "$scratch/short.mp4" \
		--size "${LOOP_SIZE:-800x760}" --zoom "${LOOP_ZOOM:-2}" \
		--ms "${LOOP_MS:-360}" --hold 900 --fps "$fps" \
		--keep-frames "$scratch/frames"
	img2webp -loop 0 -d $((1000 / fps)) -lossless -m 6 -min_size \
		"$scratch"/frames/*.png -o "$out/address-space.webp"
fi

ls -l "$out"
