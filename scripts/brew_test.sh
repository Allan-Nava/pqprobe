#!/bin/sh
# brew_test.sh — the Homebrew formula is generated, and it has to stay in step.
#
# A tap is the one delivery route where a stale file is invisible until somebody
# installs the wrong version: `brew install` reads whatever the formula says, so
# a formula still naming v0.2.0 after v0.3.0 shipped installs v0.2.0 and looks
# like it worked. So the formula is rendered from the CHANGELOG, and `check` is a
# gate — asserted here against fixtures.
#
#   sh scripts/brew_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/brew.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-brew-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

changelog() {
	printf '# Changelog\n\n## [%s] - 2026-09-02\n\n### Added\n\n- a thing.\n' "$1" > "$tmp/CHANGELOG.md"
}

run() { CHANGELOG_FILE="$tmp/CHANGELOG.md" FORMULA_FILE="$tmp/pqprobe.rb" sh "$gate" "$@"; }

printf 'brew.sh render:\n'

changelog 0.3.0
run write >/dev/null 2>&1 || :
formula=$(cat "$tmp/pqprobe.rb" 2>/dev/null || echo "")

case "$formula" in
*'tag: "v0.3.0"'*) ok "the formula pins the tag the CHANGELOG names" ;;
*) notok "no tag: \"v0.3.0\" in the formula" ;;
esac

case "$formula" in
*'version "0.3.0"'*) ok "the version is stated rather than inferred" ;;
*) notok "no explicit version in the formula" ;;
esac

# A formula that fetched a tarball would need its sha256, and that cannot be
# known before the commit carrying the formula exists. Cloning the tag sidesteps
# the chicken and egg — but only if nothing else reintroduces a checksum.
case "$formula" in
*sha256*) notok "the formula carries a sha256, which cannot be known at render time" ;;
*) ok "no checksum to go stale" ;;
esac

case "$formula" in
*'depends_on "go" => :build'*) ok "it builds from source, so one formula covers every platform" ;;
*) notok "no go build dependency" ;;
esac

case "$formula" in
*'system "go", "build"'*|*std_go_args*) ok "it uses the standard Go build arguments" ;;
*) notok "no go build in install" ;;
esac

case "$formula" in
*"test do"*) ok "it has a test block, so brew can prove the binary runs" ;;
*) notok "no test block" ;;
esac

if command -v ruby >/dev/null 2>&1; then
	if ruby -c "$tmp/pqprobe.rb" >/dev/null 2>&1; then
		ok "the formula is valid Ruby"
	else
		notok "the formula is not valid Ruby"
	fi
fi

printf '\nbrew.sh check:\n'

got=0; run check >/dev/null 2>&1 || got=$?
[ "$got" -eq 0 ] && ok "a formula in step with the CHANGELOG passes" ||
	notok "check exited $got on a fresh formula, wanted 0"

changelog 0.4.0
got=0; run check >/dev/null 2>&1 || got=$?
[ "$got" -eq 1 ] && ok "a formula left behind by a release fails" ||
	notok "check exited $got on a stale formula, wanted 1"

rm -f "$tmp/pqprobe.rb"
got=0; run check >/dev/null 2>&1 || got=$?
[ "$got" -eq 1 ] && ok "a missing formula fails rather than passing quietly" ||
	notok "check exited $got with no formula, wanted 1"

got=0; run wat >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "an unknown mode is a usage error" ||
	notok "an unknown mode exited $got, wanted 2"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
