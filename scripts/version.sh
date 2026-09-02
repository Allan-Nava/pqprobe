#!/bin/sh
# version.sh — every commit ships as a tagged version, and this checks it.
#
#   scripts/version.sh current          the version the CHANGELOG names
#   scripts/version.sh check            HEAD is tagged with exactly that version
#   scripts/version.sh check --warn     a *missing* tag is a warning, not a failure
#
# The house rule is that a commit is a release: a dated `## [X.Y.Z]` section and
# an annotated `vX.Y.Z` tag on the commit that carries it. The point is not
# ceremony — it is that the CHANGELOG becomes the dated history of the tool
# rather than of the code, and `git log` can answer "when did this behaviour
# change?" without reading diffs.
#
# `--warn` exists because the branch and the tag are two pushes: a job that
# failed in the seconds between them would be red on every release, and a check
# like that gets switched off. A tag that *contradicts* the CHANGELOG is never a
# warning — that is a wrong release, and hurry does not make it right.
#
# POSIX sh and awk only. CHANGELOG_FILE overrides the file, for the tests.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
changelog="${CHANGELOG_FILE:-$root/CHANGELOG.md}"
mode="${1:-check}"
warn=0
[ "${2:-}" = "--warn" ] && warn=1

[ -f "$changelog" ] || { echo "version.sh: no such file: $changelog" >&2; exit 2; }

# The first `## [...]` heading in the file, whatever it says — including
# `Unreleased`, because refusing that is the caller's job, not a silent skip.
top() {
	awk '/^## \[/ {
		i = index($0, "["); j = index($0, "]")
		print substr($0, i + 1, j - i - 1); exit
	}' "$changelog"
}

current() {
	v=$(top)
	[ -n "$v" ] || { echo "version.sh: CHANGELOG.md has no version section" >&2; exit 1; }
	printf '%s\n' "$v"
}

check() {
	v=$(top)
	if [ -z "$v" ]; then
		echo "version.sh: CHANGELOG.md has no version section" >&2
		exit 1
	fi
	case "$v" in
	[Uu]nreleased)
		echo "version.sh: the newest CHANGELOG section is [Unreleased] — a commit is a release, so it needs a version" >&2
		exit 1
		;;
	esac
	case "$v" in
	[0-9]*.[0-9]*.[0-9]*) ;;
	*) echo "version.sh: \`$v\` is not X.Y.Z" >&2; exit 1 ;;
	esac

	# --points-at rather than `describe`: the question is whether *this* commit
	# is a release, not whether one happened somewhere behind it.
	tags=$(git tag --points-at HEAD 2>/dev/null | grep '^v' || :)

	if [ -z "$tags" ]; then
		msg="HEAD is not tagged — the CHANGELOG says $v, so it wants a v$v tag"
		if [ "$warn" -eq 1 ]; then
			echo "version.sh: $msg (the tag may not be pushed yet)" >&2
			exit 0
		fi
		echo "version.sh: $msg" >&2
		exit 1
	fi

	if ! printf '%s\n' "$tags" | grep -qx -- "v$v"; then
		echo "version.sh: HEAD is tagged $(printf '%s' "$tags" | tr '\n' ' ')but the CHANGELOG names $v" >&2
		exit 1
	fi

	printf 'version OK — HEAD is v%s, and the CHANGELOG says so\n' "$v"
}

case "$mode" in
current) current ;;
check)   check ;;
*)
	echo "usage: scripts/version.sh [current|check [--warn]]" >&2
	exit 2
	;;
esac
