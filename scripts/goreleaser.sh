#!/bin/sh
# goreleaser.sh — the release config gate (PQ-42).
#
#   scripts/goreleaser.sh check     validate .goreleaser.yaml and the cask
#   scripts/goreleaser.sh snapshot  build locally without publishing anything
#
# The cask this config publishes is generated at tag time and pushed to
# *another* repository, so nothing in this checkout ever shows it to you: every
# mistake surfaces after the tag, in front of somebody running `brew install`.
# `check` is therefore two things — goreleaser's own validation, and the
# invariants goreleaser cannot know about:
#
#   * the binary must stay static (CGO off) and reproducible (-trimpath);
#   * the cask must strip the quarantine attribute, because the binary is
#     unsigned and macOS would otherwise install it and refuse to run it;
#   * skip_upload must be "auto", or a prerelease tag publishes its cask to the
#     tap and every `brew install` hands out a release candidate.
#
# `snapshot` is the way to see the cask before a tag exists: it writes
# dist/homebrew/Casks/pqprobe.rb and publishes nothing.
#
# POSIX sh only. GORELEASER_FILE points at a fixture.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cfg="${GORELEASER_FILE:-$root/.goreleaser.yaml}"
mode="${1:-check}"

[ -f "$cfg" ] || { echo "goreleaser.sh: no such file: $cfg" >&2; exit 2; }

check() {
	bad=0
	err() { printf 'goreleaser.sh: %s\n' "$1" >&2; bad=$((bad + 1)); }

	grep -q "^version: 2" "$cfg" || err "no schema version 2"
	grep -q "CGO_ENABLED=0" "$cfg" || err "CGO is not disabled: this ships a static binary"
	grep -q -- "-trimpath" "$cfg" || err "no -trimpath: the build would not be reproducible"
	grep -q "^homebrew_casks:" "$cfg" || err "no cask: brew install would have nothing to install"
	grep -q "name: homebrew-tap" "$cfg" || err "the cask does not name the tap repository"
	grep -q "HOMEBREW_TAP_GITHUB_TOKEN" "$cfg" || err "no tap token: the cask cannot be pushed"
	grep -q "com.apple.quarantine" "$cfg" ||
		err "the cask does not strip the quarantine attribute: unsigned, it would install and then refuse to run"
	grep -q 'skip_upload: "auto"' "$cfg" ||
		err "skip_upload is not \"auto\": a prerelease tag would publish its cask to the tap"

	if command -v goreleaser >/dev/null 2>&1; then
		goreleaser check --config "$cfg" >/dev/null 2>&1 ||
			err "goreleaser check failed — run: goreleaser check"
	fi

	if [ "$bad" -gt 0 ]; then
		printf '\n%d problem(s) in %s\n' "$bad" "${cfg#"$root/"}" >&2
		exit 1
	fi
	printf 'goreleaser OK — static build, cask to homebrew-tap, quarantine stripped, prereleases skipped\n'
}

snapshot() {
	command -v goreleaser >/dev/null 2>&1 ||
		{ echo "goreleaser.sh: goreleaser is not installed" >&2; exit 2; }
	cd "$root"
	goreleaser release --snapshot --clean --skip=publish,validate
	printf '\nthe cask this would publish:\n\n'
	sed 's/^/  /' dist/homebrew/Casks/pqprobe.rb
}

case "$mode" in
check)    check ;;
snapshot) snapshot ;;
*)
	echo "usage: scripts/goreleaser.sh [check|snapshot]" >&2
	exit 2
	;;
esac
