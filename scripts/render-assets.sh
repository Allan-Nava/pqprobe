#!/bin/sh
# render-assets.sh — rasterise docs/assets/*.svg into the PNGs the web needs.
#
# The SVGs are the source. PNGs exist for the two places SVG is not accepted:
# Open Graph / Twitter cards (no platform renders SVG) and the iOS home-screen
# icon. They are committed, so nobody needs this script to build the site — run
# it only after editing an SVG.
#
#   scripts/render-assets.sh
#
# Uses headless Chrome, which every machine that has a browser already has. No
# ImageMagick, no rsvg, nothing to install. If Chrome is missing the script says
# so and exits 1 rather than leaving a stale PNG behind.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
assets="$root/docs/assets"

chrome=""
for c in \
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
	"/Applications/Chromium.app/Contents/MacOS/Chromium" \
	"$(command -v google-chrome || true)" \
	"$(command -v chromium || true)" \
	"$(command -v chromium-browser || true)"
do
	[ -n "$c" ] && [ -x "$c" ] && chrome="$c" && break
done

if [ -z "$chrome" ]; then
	echo "render-assets.sh: no Chrome or Chromium found — cannot rasterise" >&2
	echo "  the committed PNGs in docs/assets/ are still valid; edit the SVGs" >&2
	echo "  and re-run this on a machine with a browser." >&2
	exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-assets.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

# shot <source.svg> <width> <height> <out.png>
shot() {
	src=$1 w=$2 h=$3 out=$4
	"$chrome" --headless --disable-gpu --hide-scrollbars \
		--screenshot="$tmp/shot.png" --window-size="$w,$h" \
		"file://$assets/$src" >/dev/null 2>&1
	mv "$tmp/shot.png" "$assets/$out"
	printf '  %-22s %sx%s\n' "$out" "$w" "$h"
}

echo "rendering docs/assets PNGs with $(basename "$chrome"):"
shot og-card.svg 1200 630 og-card.png
shot logo.svg     512  512 logo.png
shot logo.svg     180  180 apple-touch-icon.png
