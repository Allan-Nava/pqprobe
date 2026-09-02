#!/bin/sh
# release_test.sh — the release tooling, tested against fixtures.
#
# The notes extractor is what the Release workflow puts in front of everybody
# who reads a release, and every failure mode is silent: the wrong section, an
# empty body, the link-reference block pasted in as content. So it is asserted
# rather than eyeballed.
#
#   sh scripts/release_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
notes="$root/scripts/release-notes.sh"
release="$root/scripts/release.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-release-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

cat > "$tmp/CHANGELOG.md" <<'MD'
# Changelog

Preamble that belongs to no release.

## [Unreleased]

### Added

- **Something in flight** (PQ-99) — not released yet.

## [0.2.0] - 2026-09-02

### Added

- **A second thing** (PQ-10) — with a `code span`.

### Fixed

- **A first thing** (PQ-11) — one line.

## [0.1.0] - 2026-08-01

First release.

[0.2.0]: https://example.test/releases/tag/v0.2.0
[0.1.0]: https://example.test/releases/tag/v0.1.0
MD

run() { CHANGELOG_FILE="$tmp/CHANGELOG.md" sh "$notes" "$@"; }

printf 'release-notes.sh:\n'

got=$(run --version 2>/dev/null || :)
[ "$got" = "0.2.0" ] && ok "--version is the newest released section, not Unreleased" ||
	notok "--version gave \`$got\`, wanted 0.2.0"

got=$(run 2>/dev/null || :)
case "$got" in
*"A second thing"*"A first thing"*) ok "no argument means the newest release, whole body" ;;
*) notok "the default body is wrong: $got" ;;
esac

case "$(run 2>/dev/null || :)" in
*"Something in flight"*) notok "the Unreleased section leaked into the release notes" ;;
*) ok "the Unreleased section is not part of a release" ;;
esac

case "$(run 2>/dev/null || :)" in
*"example.test"*) notok "the link-reference block leaked into the notes" ;;
*) ok "the link references are not part of the body" ;;
esac

case "$(run 2>/dev/null || :)" in
*"## ["*) notok "the heading of the next section leaked in" ;;
*) ok "a section stops at the next heading" ;;
esac

got=$(run v0.1.0 2>/dev/null || :)
[ "$got" = "First release." ] && ok "a leading v is accepted and the oldest section is reachable" ||
	notok "v0.1.0 gave \`$got\`"

got=0; run 9.9.9 >/dev/null 2>&1 || got=$?
[ "$got" -eq 1 ] && ok "a version with no section is an error, not an empty body" ||
	notok "9.9.9 exited $got, wanted 1"

got=0; run Unreleased >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "asking for Unreleased is a usage error" ||
	notok "Unreleased exited $got, wanted 2"

printf '\nrelease.sh:\n'

got=0; sh "$release" >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "no version is a usage error" || notok "no version exited $got, wanted 2"

got=0; sh "$release" 1.2 >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "a version that is not X.Y.Z is refused" || notok "1.2 exited $got, wanted 2"

got=0; sh "$release" not-a-version >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "a non-numeric version is refused" || notok "prose exited $got, wanted 2"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
