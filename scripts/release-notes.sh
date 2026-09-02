#!/bin/sh
# release-notes.sh — lift one release's notes out of CHANGELOG.md.
#
#   scripts/release-notes.sh              the newest released section
#   scripts/release-notes.sh 0.2.0        that section (a leading v is fine)
#   scripts/release-notes.sh --version    print which version that would be
#
# The CHANGELOG is written for people and is the only description of a release
# anybody edits. Re-typing it into a GitHub release is how the two stop
# agreeing, so the release workflow reads it from here. `[Unreleased]` is never
# a release: asking for it, or for a version that has no section, is an error
# rather than an empty release body.
#
# POSIX sh and awk only. CHANGELOG_FILE overrides the file, for the tests.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
changelog="${CHANGELOG_FILE:-$root/CHANGELOG.md}"

[ -f "$changelog" ] || { echo "release-notes.sh: no such file: $changelog" >&2; exit 2; }

# The first `## [X.Y.Z]` heading in the file, Unreleased skipped.
newest() {
	awk '
		/^## \[/ {
			s = $0
			i = index(s, "["); j = index(s, "]")
			v = substr(s, i + 1, j - i - 1)
			if (tolower(v) == "unreleased") next
			print v; exit
		}
	' "$changelog"
}

case "${1:-}" in
--version) newest; exit 0 ;;
esac

want=${1:-$(newest)}
want=${want#v}

[ -n "$want" ] || { echo "release-notes.sh: CHANGELOG.md has no released section" >&2; exit 1; }
case "$want" in
[Uu]nreleased) echo "release-notes.sh: Unreleased is not a release" >&2; exit 2 ;;
esac

body=$(awk -v want="$want" '
	/^## \[/ {
		s = $0
		i = index(s, "["); j = index(s, "]")
		v = substr(s, i + 1, j - i - 1)
		if (v == want) { inside = 1; next }
		if (inside) exit
		next
	}
	# The link-reference block at the bottom belongs to the file, not to a release.
	inside && /^\[[^]]+\]:/ { next }
	inside { print }
' "$changelog")

# Trim the blank lines a section picks up at either end.
body=$(printf '%s\n' "$body" | awk 'NF { blank = 0; hold = hold sep $0; sep = "\n"; next }
	{ if (hold != "") sep = sep "\n" } END { if (hold != "") print hold }')

if [ -z "$body" ]; then
	echo "release-notes.sh: CHANGELOG.md has no section for $want" >&2
	exit 1
fi

printf '%s\n' "$body"
