#!/bin/sh
# render-assets.sh — rasterise docs/assets/*.svg into the PNGs the web needs.
#
# The SVGs are the source. PNGs exist for the two places SVG is not accepted:
# Open Graph / Twitter cards (no platform renders SVG) and the iOS home-screen
# icon. They are committed, so nobody needs this script to build the site — run
# it only after editing an SVG.
#
#   scripts/render-assets.sh           rasterise, and record what was rasterised
#   scripts/render-assets.sh --check   fail if a PNG is missing or its SVG moved
#
# --check needs no browser and runs in CI: it compares the SVGs against the
# checksums recorded in docs/assets/.rendered when they were last rendered. An
# edited SVG with a stale PNG is exactly the failure nobody sees — the site
# looks right, the social card is last month's.
#
# Uses headless Chrome, which every machine that has a browser already has. No
# ImageMagick, no rsvg, nothing to install. If Chrome is missing the script says
# so and exits 1 rather than leaving a stale PNG behind.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
assets="$root/docs/assets"

# ---------------------------------------------------------------------------
# The checksum record: `<sha256>  <file>` for each source SVG.
# ---------------------------------------------------------------------------
record="$assets/.rendered"
sources="og-card.svg logo.svg"
outputs="og-card.png logo.png apple-touch-icon.png"

sums() {
	if command -v sha256sum >/dev/null 2>&1; then hash=sha256sum
	elif command -v shasum >/dev/null 2>&1; then hash="shasum -a 256"
	else echo "render-assets.sh: no sha256sum or shasum" >&2; exit 2
	fi
	for f in $sources; do
		# Printed relative, so the record does not depend on where the tree lives.
		printf '%s  %s\n' "$($hash "$assets/$f" | cut -d' ' -f1)" "$f"
	done
}

if [ "${1:-}" = "--check" ]; then
	bad=0
	for f in $outputs; do
		[ -f "$assets/$f" ] || { echo "render-assets.sh: docs/assets/$f is missing" >&2; bad=1; }
	done
	if [ ! -f "$record" ]; then
		echo "render-assets.sh: docs/assets/.rendered is missing — run scripts/render-assets.sh" >&2
		exit 1
	fi
	if ! sums | diff -u "$record" - >/dev/null; then
		echo "render-assets.sh: an SVG changed since the PNGs were rendered:" >&2
		sums | diff -u "$record" - >&2 || :
		echo "" >&2
		echo "  run scripts/render-assets.sh and commit the PNGs" >&2
		exit 1
	fi
	[ "$bad" -eq 0 ] || exit 1
	echo "docs/assets PNGs are in step with their SVGs"
	exit 0
fi

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

sums > "$record"
echo "  recorded the source checksums in docs/assets/.rendered"
