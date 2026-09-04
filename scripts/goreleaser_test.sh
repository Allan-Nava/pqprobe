#!/bin/sh
# goreleaser_test.sh — the release config, and the cask it publishes.
#
# The cask is generated at tag time and lands in somebody else's repository, so
# nothing in this checkout will ever show it to you. Everything that can go
# wrong therefore goes wrong *after* a tag is pushed, in front of whoever runs
# `brew install`. These are the invariants worth asserting before then.
#
#   sh scripts/goreleaser_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cfg="${GORELEASER_FILE:-$root/.goreleaser.yaml}"
gate="$root/scripts/goreleaser.sh"

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

printf 'the config:\n'

[ -f "$cfg" ] && ok "there is a .goreleaser.yaml" || notok ".goreleaser.yaml is missing"

if [ -f "$cfg" ]; then
	grep -q "^version: 2" "$cfg" && ok "schema version 2" || notok "no schema version"

	# Six platforms, the same set the archives promised before goreleaser.
	for pair in "goos:" "goarch:"; do
		grep -q "$pair" "$cfg" || notok "no $pair in builds"
	done
	grep -q "CGO_ENABLED=0" "$cfg" && ok "CGO off: the binary has to stay static" ||
		notok "CGO_ENABLED=0 is missing — a dynamically linked binary is not what this ships"
	grep -q -- "-trimpath" "$cfg" && ok "trimpath: reproducible paths" || notok "no -trimpath"

	printf '\nthe cask:\n'
	grep -q "^homebrew_casks:" "$cfg" && ok "it publishes a cask" ||
		notok "no homebrew_casks block"
	grep -q "name: homebrew-tap" "$cfg" && ok "into the tap repository" ||
		notok "the cask does not name the tap repository"
	grep -q "HOMEBREW_TAP_GITHUB_TOKEN" "$cfg" && ok "with the token the tap push needs" ||
		notok "no token: the cask cannot be pushed to another repository"

	# The binary is unsigned, so macOS quarantines it and Gatekeeper refuses to
	# run it. checkfleet's cask strips the attribute on install; without that
	# the install succeeds and the binary does not.
	grep -q "com.apple.quarantine" "$cfg" &&
		ok "the quarantine attribute is stripped on install" ||
		notok "no quarantine strip: an unsigned cask installs and then will not run"

	# The lesson the sibling repo paid for (CF-160): without this a v1.0.0-rc.1
	# tag pushes its cask to the tap, and every `brew install` hands out a
	# release candidate — the opposite of what an rc is for.
	grep -q 'skip_upload: "auto"' "$cfg" &&
		ok "a prerelease does not become the cask everybody installs" ||
		notok "skip_upload is not \"auto\": an rc tag would publish itself to the tap"
fi

printf '\nthe gate:\n'
if [ -x "$gate" ]; then
	ok "there is a gate script"
	if sh "$gate" check >/dev/null 2>&1; then
		ok "the real config passes it"
	else
		notok "scripts/goreleaser.sh check fails on this repository"
	fi
else
	notok "scripts/goreleaser.sh is missing"
fi

# goreleaser's own opinion, which is the only authority on whether the file is
# valid. Skipped rather than failed when it is not installed: CI installs it,
# and a contributor without it should still be able to run the suite.
printf '\ngoreleaser itself:\n'
if command -v goreleaser >/dev/null 2>&1; then
	if goreleaser check --config "$cfg" >/dev/null 2>&1; then
		ok "goreleaser check passes"
	else
		notok "goreleaser check fails:"
		goreleaser check --config "$cfg" 2>&1 | sed 's/^/       /' >&2
	fi
else
	ok "goreleaser is not installed here; CI runs the check (skipped)"
fi

printf '\nthe release workflow:\n'
wf="$root/.github/workflows/release.yml"
# Comments stripped, and the real thing looked for rather than the word: the
# first version of this passed because the workflow's comment said "No
# goreleaser" and because scripts/release-notes.sh contains "release-notes".
effective=$(grep -vE '^[[:space:]]*#' "$wf")
if printf '%s\n' "$effective" | grep -q "goreleaser/goreleaser-action"; then
	ok "the release runs the goreleaser action"
else
	notok "the release workflow does not run goreleaser"
fi
if printf '%s\n' "$effective" | grep -q -- "--release-notes"; then
	ok "the notes still come from CHANGELOG.md, not from commit subjects"
else
	notok "no --release-notes: the release would be a list of commit messages"
fi
if printf '%s\n' "$effective" | grep -q "HOMEBREW_TAP_GITHUB_TOKEN"; then
	ok "the tap token reaches goreleaser"
else
	notok "the workflow never passes HOMEBREW_TAP_GITHUB_TOKEN"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
