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

# The documented flow is two steps: look at the diff, then --commit. After the
# first step there is no [Unreleased] section any more — it has become
# [X.Y.Z] - <today> — and the second step must recognise its own work instead of
# refusing with "nothing to release".
printf '\nrelease.sh state:\n'

state() { CHANGELOG_FILE="$1" sh "$release" "$2" --state 2>/dev/null || :; }

cat > "$tmp/fresh.md" <<'MD'
# Changelog

## [Unreleased]

### Added

- **A thing** (PQ-1) — in flight.

## [0.1.0] - 2026-08-01

First.
MD
got=$(state "$tmp/fresh.md" 0.2.0)
[ "$got" = "prepare" ] && ok "an Unreleased section with entries is ready to prepare" ||
	notok "state gave \`$got\`, wanted prepare"

cat > "$tmp/prepared.md" <<'MD'
# Changelog

## [0.2.0] - 2026-09-02

### Added

- **A thing** (PQ-1) — released.

## [0.1.0] - 2026-08-01

First.
MD
got=$(state "$tmp/prepared.md" 0.2.0)
[ "$got" = "already-prepared" ] && ok "a CHANGELOG already dated for this version is recognised, not refused" ||
	notok "state gave \`$got\`, wanted already-prepared"

got=$(state "$tmp/prepared.md" 0.3.0)
[ "$got" = "nothing" ] && ok "a different version with nothing pending is nothing to release" ||
	notok "state gave \`$got\`, wanted nothing"

cat > "$tmp/empty.md" <<'MD'
# Changelog

## [Unreleased]

## [0.1.0] - 2026-08-01

First.
MD
got=$(state "$tmp/empty.md" 0.2.0)
[ "$got" = "nothing" ] && ok "an Unreleased section with no entries is nothing to release" ||
	notok "state gave \`$got\`, wanted nothing"

# PQ-49. Two releases in a row were committed and tagged before the SEO check
# noticed that llms.txt still named the previous version — both needed an amend
# on top of a tag. Neither property below can be tested by running release.sh:
# it is the script that runs this one. So they are asserted structurally, the
# way gates_test.sh asserts wiring.
printf '\nrelease.sh shape:\n'

line_of() { grep -n "$1" "$release" | head -1 | cut -d: -f1; }

branch=$(line_of '^if \[ "\$state" = already-prepared \]')
render=$(line_of 'scripts/seo\.sh render')
close=$(awk -v start="$branch" 'NR > start && /^fi$/ { print NR; exit }' "$release")
if [ -n "$render" ] && [ -n "$close" ] && [ "$render" -gt "$close" ]; then
	ok "the derived files are rendered in both states, not only when preparing"
else
	notok "seo.sh render (line ${render:-none}) is inside the state branch closing at line ${close:-none}: an already-dated CHANGELOG commits llms.txt describing the previous version"
fi

check=$(line_of 'scripts/seo\.sh check')
commit=$(line_of '^git commit ')
if [ -n "$check" ] && [ -n "$commit" ] && [ "$check" -lt "$commit" ]; then
	ok "the derived files are checked before the commit, while the fix is still an edit"
else
	notok "seo.sh check (line ${check:-none}) does not run before git commit (line ${commit:-none}): the only fix left is an amend on top of a tag"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
