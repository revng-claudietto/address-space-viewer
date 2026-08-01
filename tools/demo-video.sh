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

# A README cannot play a video: GitHub keeps <video> only for files
# uploaded to GitHub itself, and drops the element everywhere else -- which
# is true of a public repository as much as a private one.  What it does
# render is an image in the repository, so the same recording is filmed
# again as an animation.
#
# Animated webp rather than gif: gif has 256 colours to spend on a dark
# panel full of antialiased text, and paying for legibility in palette
# entries costs more than it is worth.  webp keeps the pixels the browser
# was given, which is why the animation is filmed at the width it is drawn
# at rather than scaled down to fit a budget.
if command -v ffmpeg >/dev/null 2>&1; then
	# The demo's own work starts where it reserves its arena, which is the
	# only PROT_NONE mapping in the recording.  Fifteen steps from there is
	# the whole of what the program does to its own memory.
	from=$(python3 -c "
import json
events = json.load(open('$out/demo.json'))['events']
start = next((e['seq'] for e in events
              if e['category'] == 'map'
              and (e.get('args') or {}).get('prot') == 'PROT_NONE'), 1)
print(max(0, start - 1))")

	echo "filming steps $from to $((from + 15)) again, for the README"
	"$here/as-trace" film "$out/demo.json" -o "$scratch/short.webm" \
		--size 1280x720 --ms "${LOOP_MS:-420}" --hold 900 \
		--from "$from" --to "$((from + 15))"
	ffmpeg -v error -y -i "$scratch/short.webm" -vf fps=10 \
		-c:v libwebp -lossless 0 -q:v 55 -preset picture -loop 0 -an \
		"$out/address-space.webp"
fi

ls -l "$out"
