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

# `brew audit` rejects an explicit version when it can be scanned from the URL:
# "Stable: `version 0.25.1` is redundant with version scanned from URL". The
# first version of this renderer stated it anyway — my preference, and Homebrew's
# audit is the authority. So the assertion is the opposite of what it was.
case "$formula" in
*'version "0.3.0"'*|*'version "'*'"'*) notok "the formula states a version, which brew audit calls redundant with the tag" ;;
*) ok "no redundant version line: Homebrew scans it from the tag" ;;
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

printf '\nthe Brew workflow:\n'

wf="$root/.github/workflows/brew.yml"
if [ -f "$wf" ]; then
	ok "there is a workflow that exercises the tap"
else
	notok ".github/workflows/brew.yml is missing: the formula would only ever be checked by our own renderer"
fi

if [ -f "$wf" ]; then
	# Comments are stripped first: this file explains the traps it avoids, and a
	# check that matched the prose describing a mistake would flag the
	# documentation of the fix as the mistake itself. (It did, first time.)
	effective=$(grep -vE '^[[:space:]]*#' "$wf")

	# `brew install ./path/to.rb` is disabled in current Homebrew ("Calling brew
	# install with a path is disabled"), and it is the obvious thing to write.
	if printf '%s\n' "$effective" | grep -qE 'brew (install|audit|style)[^|]*\./|brew install .*\.rb'; then
		notok "it installs or audits by path, which Homebrew disabled — tap the checkout and use the qualified name"
	else
		ok "it goes through a tap rather than a path"
	fi

	# Homebrew 6+ refuses third-party taps unless trusted, and a headless run
	# then fails or hangs. Found by running it here.
	if printf '%s\n' "$effective" | grep -q "HOMEBREW_NO_REQUIRE_TAP_TRUST"; then
		ok "tap trust is disabled, so a headless install does not stall on it"
	else
		notok "no HOMEBREW_NO_REQUIRE_TAP_TRUST: Homebrew 6+ will ignore the tap"
	fi

	# The trap checkfleet paid for (CF-159): macos-13 was retired, and a job
	# asking for a label with no runners behind it queues forever rather than
	# failing — so the workflow never concludes and verifies nothing.
	if printf '%s\n' "$effective" | grep -qE "macos-13([^0-9-]|$)"; then
		notok "macos-13 is retired: that leg queues forever instead of failing"
	else
		ok "no retired runner label"
	fi

	if printf '%s\n' "$effective" | grep -q "timeout-minutes"; then
		ok "there is a hang guard"
	else
		notok "no timeout-minutes: a stalled install looks like a busy one"
	fi

	# The point of the whole thing: an install that is never run proves nothing.
	if printf '%s\n' "$effective" | grep -q "brew install"; then
		ok "it actually installs"
	else
		notok "it never runs brew install"
	fi
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
