#!/bin/sh
# version_test.sh — the "every commit is a version" gate, against fixtures.
#
# The rule is that every commit ships as a tagged vX.Y.Z with its own CHANGELOG
# section. A rule nobody checks is a habit, and habits lapse on the busy day —
# so it is a gate, and the gate is asserted here against throwaway git
# repositories rather than against this one.
#
#   sh scripts/version_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/version.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-version-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# repo <dir> <changelog-version> [tag] — a git repository with one commit.
repo() {
	d=$1 v=$2 tag=${3:-}
	mkdir -p "$d"
	{
		printf '# Changelog\n\n'
		printf '## [%s] - 2026-09-02\n\n### Added\n\n- something.\n\n' "$v"
		printf '## [0.0.1] - 2026-08-01\n\nFirst.\n\n'
		printf '[%s]: https://example.test/tag/v%s\n' "$v" "$v"
	} > "$d/CHANGELOG.md"
	git -C "$d" init -q 2>/dev/null || git -C "$d" init -q
	git -C "$d" config user.email t@example.test
	git -C "$d" config user.name test
	git -C "$d" add -A
	git -C "$d" commit -qm "a commit"
	[ -n "$tag" ] && git -C "$d" tag -a "$tag" -m "$tag"
	return 0
}

# expect <exit> <name> <dir>
expect() {
	want=$1 name=$2 dir=$3
	got=0
	( cd "$dir" && CHANGELOG_FILE="$dir/CHANGELOG.md" sh "$gate" check >/dev/null 2>&1 ) || got=$?
	if [ "$got" -eq "$want" ]; then ok "$name"; else
		notok "$name (wanted exit $want, got $got)"
	fi
}

printf 'version.sh current:\n'

repo "$tmp/ok" 0.2.0 v0.2.0
got=$(CHANGELOG_FILE="$tmp/ok/CHANGELOG.md" sh "$gate" current 2>/dev/null || :)
[ "$got" = "0.2.0" ] && ok "current is the newest CHANGELOG version" ||
	notok "current gave \`$got\`, wanted 0.2.0"

printf '\nversion.sh check:\n'

expect 0 "HEAD tagged with the version the CHANGELOG names passes" "$tmp/ok"

repo "$tmp/untagged" 0.2.0
expect 1 "an untagged commit fails — every commit is a version" "$tmp/untagged"

repo "$tmp/mismatch" 0.2.0 v0.3.0
expect 1 "a tag that disagrees with the CHANGELOG fails" "$tmp/mismatch"

repo "$tmp/unreleased" Unreleased v0.2.0
expect 1 "a CHANGELOG whose top section is Unreleased fails" "$tmp/unreleased"

# The tag is usually pushed a moment after the branch, and a CI job that fails
# for that would be red on every release. --warn says it out loud and exits 0.
repo "$tmp/warn" 0.2.0
got=0
( cd "$tmp/warn" && CHANGELOG_FILE="$tmp/warn/CHANGELOG.md" sh "$gate" check --warn >/dev/null 2>&1 ) || got=$?
[ "$got" -eq 0 ] && ok "--warn turns a missing tag into a warning" ||
	notok "--warn exited $got, wanted 0"

# ...but only a *missing* tag. A tag that contradicts the CHANGELOG is a wrong
# release, and no amount of hurry makes that a warning.
repo "$tmp/warnbad" 0.2.0 v0.3.0
got=0
( cd "$tmp/warnbad" && CHANGELOG_FILE="$tmp/warnbad/CHANGELOG.md" sh "$gate" check --warn >/dev/null 2>&1 ) || got=$?
[ "$got" -eq 1 ] && ok "--warn still fails on a tag that contradicts the CHANGELOG" ||
	notok "--warn on a mismatch exited $got, wanted 1"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
