#!/bin/sh
# gates_test.sh — every gate has to be wired everywhere it belongs.
#
# The failure this exists for: `scripts/backlog_issues_test.sh` ran in CI and
# not in `scripts/release.sh`, so a local release skipped it. Nothing announces
# that. A gate nobody runs is a gate that passes, and the whole point of
# writing them is that they run without being remembered.
#
#   sh scripts/gates_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ci="$root/.github/workflows/ci.yml"
rel="$root/scripts/release.sh"

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

printf 'every *_test.sh runs in CI and in release.sh:\n'
for f in "$root"/scripts/*_test.sh; do
	n=$(basename "$f")
	# This file is the one asserting the others; it runs from both like the rest.
	grep -q "$n" "$ci" || notok "$n is never run by CI"
	grep -q "$n" "$rel" || notok "$n is never run by scripts/release.sh"
	grep -q "$n" "$ci" && grep -q "$n" "$rel" && ok "$n"
done

printf '\nevery gate script is wired too:\n'
for n in docs.sh seo.sh action.sh repo-meta.sh goreleaser.sh version.sh render-assets.sh; do
	[ -f "$root/scripts/$n" ] || { notok "scripts/$n is missing"; continue; }
	grep -q "$n" "$ci" || notok "$n is never run by CI"
	grep -q "$n" "$rel" || notok "$n is never run by scripts/release.sh"
	grep -q "$n" "$ci" && grep -q "$n" "$rel" && ok "$n"
done

# The inverse direction, and the bug that got past everything: this file
# asserted that every script *that exists* is wired, and said nothing about a
# workflow naming a script that does not. Deleting `scripts/brew.sh` and
# `brew_test.sh` for the cask left two lines in the release gates, and the next
# tag would have died with "cannot open scripts/brew_test.sh".
printf '\nevery script a workflow names actually exists:\n'
missing=0
for f in "$root"/.github/workflows/*.yml "$rel"; do
	# Comments describe scripts that were removed on purpose, so read the
	# effective file — the same lesson as every other check here.
	grep -vE '^[[:space:]]*#' "$f" |
		grep -oE 'scripts/[A-Za-z0-9_.-]+\.sh' | sort -u |
		while IFS= read -r ref; do
			[ -f "$root/$ref" ] || printf '%s -> %s\n' "$(basename "$f")" "$ref"
		done > "$root/.gates-missing.$$"
	if [ -s "$root/.gates-missing.$$" ]; then
		while IFS= read -r line; do
			notok "$line does not exist"
			missing=1
		done < "$root/.gates-missing.$$"
	fi
	rm -f "$root/.gates-missing.$$"
done
[ "$missing" -eq 0 ] && ok "no workflow or release step names a script that is gone"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
