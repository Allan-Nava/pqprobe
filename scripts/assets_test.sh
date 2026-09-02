#!/bin/sh
# assets_test.sh — the rendered-asset freshness gate, against fixtures.
#
# `render-assets.sh --check` is the only thing standing between an edited logo
# and a social card from last month: the page looks right either way, and the
# card is only ever seen by people who are not looking at the page. So the gate
# is asserted, and asserted without a browser — --check must not need one.
#
#   sh scripts/assets_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/render-assets.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-assets-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

hash_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
	else shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# fixture <dir> — SVGs, their PNGs, and a record that matches.
fixture() {
	d=$1
	mkdir -p "$d"
	printf '<svg>og</svg>\n'   > "$d/og-card.svg"
	printf '<svg>logo</svg>\n' > "$d/logo.svg"
	printf 'png' > "$d/og-card.png"
	printf 'png' > "$d/logo.png"
	printf 'png' > "$d/apple-touch-icon.png"
	{
		printf '%s  og-card.svg\n' "$(hash_of "$d/og-card.svg")"
		printf '%s  logo.svg\n'    "$(hash_of "$d/logo.svg")"
	} > "$d/.rendered"
}

# expect <exit> <name> <dir>
expect() {
	want=$1 name=$2 dir=$3
	got=0
	ASSETS_DIR="$dir" sh "$gate" --check >/dev/null 2>&1 || got=$?
	if [ "$got" -eq "$want" ]; then ok "$name"; else
		notok "$name (wanted exit $want, got $got)"
	fi
}

printf 'render-assets.sh --check:\n'

fixture "$tmp/clean"
expect 0 "PNGs in step with their SVGs pass" "$tmp/clean"

fixture "$tmp/edited"
printf '<svg>og, but redrawn</svg>\n' > "$tmp/edited/og-card.svg"
expect 1 "an edited SVG with a stale PNG fails" "$tmp/edited"

fixture "$tmp/gone"
rm "$tmp/gone/apple-touch-icon.png"
expect 1 "a missing PNG fails even when the checksums match" "$tmp/gone"

fixture "$tmp/norecord"
rm "$tmp/norecord/.rendered"
expect 1 "no record at all fails" "$tmp/norecord"

fixture "$tmp/truncated"
printf '%s  og-card.svg\n' "$(hash_of "$tmp/truncated/og-card.svg")" > "$tmp/truncated/.rendered"
expect 1 "a record that is missing a source fails" "$tmp/truncated"

# The whole point of --check is that CI can run it. A browser there would mean
# the gate gets deleted the first time the install step breaks.
fixture "$tmp/nobrowser"
got=0
ASSETS_DIR="$tmp/nobrowser" PATH=/usr/bin:/bin sh "$gate" --check >/dev/null 2>&1 || got=$?
[ "$got" -eq 0 ] && ok "--check needs no browser" ||
	notok "--check exited $got with no browser on PATH, wanted 0"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
