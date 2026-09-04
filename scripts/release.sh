#!/bin/sh
# release.sh — turn the work in front of you into a version.
#
#   scripts/release.sh 0.2.0            check everything and show the diff
#   scripts/release.sh 0.2.0 --commit   ...then make the commit and the tag
#   scripts/release.sh 0.2.0 --state    say what it would do, and touch nothing
#
# **Every commit ships as a tagged version**, so this is the normal way to
# commit here rather than a ceremony for occasional releases: it expects a dirty
# tree — that pending work is what is being released — and produces exactly one
# commit with a `vX.Y.Z` tag on it. `scripts/version.sh` is the gate that keeps
# the rule honest afterwards.
#
# What it does, in order: refuse an existing tag, run every gate CI runs, turn
# the `[Unreleased]` CHANGELOG section into `[X.Y.Z] - <today>` with its link
# reference, rewrite every backlog item carrying `ver=unreleased` to
# `ver=X.Y.Z`, regenerate ROADMAP.md, and — with `--commit` — commit the lot and
# tag it.
#
# What it never does: **push**. Not the commit, not the tag. Publishing is a
# decision, the release workflow triggers on the tag arriving at GitHub, and a
# script that pushes turns "let me look at the diff" into a published release.
#
# The two steps are one flow: after the first, `[Unreleased]` has *become*
# `[X.Y.Z] - <today>`, so the second has to recognise its own work instead of
# refusing with "nothing to release". That decision is `--state`, it is made
# before anything slow runs, and it is what the tests assert.
#
# POSIX sh only. RELEASE_DRY_RUN=1 stops after the checks; CHANGELOG_FILE and
# BACKLOG_FILE point at fixtures. Both exist for the tests, which must never be
# able to rewrite the real files.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

version=${1:-}
commit=0
state_only=0
case "${2:-}" in
--commit) commit=1 ;;
--state)  state_only=1 ;;
'') ;;
*) echo "release.sh: unknown option ${2}" >&2; exit 2 ;;
esac

changelog="${CHANGELOG_FILE:-$root/CHANGELOG.md}"
backlog="${BACKLOG_FILE:-$root/BACKLOG.md}"

case "$version" in
'' ) echo "usage: scripts/release.sh <X.Y.Z> [--commit]" >&2; exit 2 ;;
esac
version=${version#v}
case "$version" in
[0-9]*.[0-9]*.[0-9]*) ;;
*) echo "release.sh: \`$version\` is not X.Y.Z" >&2; exit 2 ;;
esac

tag="v$version"
today=$(date +%Y-%m-%d)

say() { printf '\n== %s\n' "$1"; }

# prepare           — there is an [Unreleased] section with entries to date
# already-prepared  — the top section is already [<version>]: step two of the flow
# nothing           — neither, so there is no release to make
release_state() {
	top=$(awk '/^## \[/ {
		i = index($0, "["); j = index($0, "]")
		print substr($0, i + 1, j - i - 1); exit
	}' "$changelog")

	case "$top" in
	[Uu]nreleased)
		entries=$(awk '/^## \[[Uu]nreleased\]/ { inside = 1; next } /^## \[/ { inside = 0 } inside' \
			"$changelog" | grep -c '^- ' || :)
		[ "$entries" -gt 0 ] && { echo prepare; return; }
		echo nothing
		;;
	"$version") echo already-prepared ;;
	*)          echo nothing ;;
	esac
}

state=$(release_state)

if [ "$state_only" -eq 1 ]; then
	printf '%s\n' "$state"
	exit 0
fi

if [ "$state" = nothing ]; then
	echo "release.sh: nothing to release as $version — CHANGELOG.md needs an [Unreleased] section with entries" >&2
	exit 1
fi

# ---------------------------------------------------------------------------
say "the tree"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
	echo "release.sh: $tag already exists" >&2
	exit 1
fi
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || echo "note: on branch $branch, not main"

# A dirty tree is expected: those changes are the release. Everything in it goes
# into the commit, so it is printed rather than assumed.
pending=$(git status --porcelain)
if [ -n "$pending" ]; then
	echo "these changes will be part of $tag:"
	printf '%s\n' "$pending" | sed 's/^/  /'
else
	echo "nothing pending — $tag would tag HEAD ($(git rev-parse --short HEAD)) as it stands"
fi
echo "$tag is free"

# ---------------------------------------------------------------------------
say "what is going out"
case "$state" in
prepare)
	entries=$(awk '/^## \[Unreleased\]/ { inside = 1; next } /^## \[/ { inside = 0 } inside' \
		"$changelog" | grep -c '^- ' || :)
	echo "$entries entry/entries under [Unreleased]"
	ticks=$(grep -c 'ver=unreleased' "$backlog" || :)
	echo "$ticks backlog item(s) marked ver=unreleased"
	;;
already-prepared)
	echo "CHANGELOG.md is already dated for $version — this is step two of the flow"
	;;
esac

# ---------------------------------------------------------------------------
say "the gates"
unformatted=$(gofmt -l ./cmd ./internal ./pq)
[ -z "$unformatted" ] || { echo "not gofmt'd:" >&2; echo "$unformatted" >&2; exit 1; }
go vet ./...
go test ./...
go test -race ./... >/dev/null
./scripts/backlog.sh lint
./scripts/backlog.sh check
sh scripts/backlog_test.sh >/dev/null && echo "backlog tests OK"
sh scripts/backlog_issues_test.sh >/dev/null && echo "issue planner tests OK"
./scripts/docs.sh check
sh scripts/docs_test.sh >/dev/null && echo "docs tests OK"
sh scripts/release_test.sh >/dev/null && echo "release tests OK"
./scripts/repo-meta.sh lint
sh scripts/repo-meta_test.sh >/dev/null && echo "metadata tests OK"
sh scripts/render-assets.sh --check
sh scripts/assets_test.sh >/dev/null && echo "asset tests OK"
sh scripts/version_test.sh >/dev/null && echo "version tests OK"
sh scripts/contrib_test.sh >/dev/null && echo "contrib isolation OK"
sh scripts/gates_test.sh >/dev/null && echo "gates all wired OK"
sh scripts/brew_test.sh >/dev/null && echo "formula tests OK"
sh scripts/seo_test.sh >/dev/null && echo "SEO tests OK"
sh scripts/action.sh check >/dev/null && echo "action.yml OK"
sh scripts/action_test.sh >/dev/null && echo "action tests OK"

[ "${RELEASE_DRY_RUN:-0}" = 1 ] && { say "dry run — nothing was rewritten"; exit 0; }

# ---------------------------------------------------------------------------
if [ "$state" = already-prepared ]; then
	say "already prepared"
	echo "CHANGELOG.md, BACKLOG.md and ROADMAP.md were rewritten by the first step"
else

say "CHANGELOG.md"
tmp=$(mktemp "${TMPDIR:-/tmp}/pqprobe-release.XXXXXX")
trap 'rm -f "$tmp"' EXIT INT HUP TERM

awk -v v="$version" -v d="$today" '
	/^## \[Unreleased\]/ { printf "## [%s] - %s\n", v, d; next }
	{ print }
' CHANGELOG.md > "$tmp"

# The link reference goes with the other ones at the bottom of the file, newest
# first, so the section headings stay linkable.
awk -v v="$version" -v repo="https://github.com/Allan-Nava/pqprobe" '
	!done && /^\[[0-9]+\.[0-9]+\.[0-9]+\]:/ {
		printf "[%s]: %s/releases/tag/v%s\n", v, repo, v
		done = 1
	}
	{ print }
	END { if (!done) printf "\n[%s]: %s/releases/tag/v%s\n", v, repo, v }
' "$tmp" > CHANGELOG.md
echo "[Unreleased] is now [$version] - $today"

say "BACKLOG.md"
sed "s/ver=unreleased/ver=$version/g" BACKLOG.md > "$tmp" && mv "$tmp" BACKLOG.md
./scripts/backlog.sh roadmap

# The formula is generated from the CHANGELOG, so it is rendered *after* the
# section is dated and *inside* this commit — the tap is this repository, and a
# formula bumped in a later commit would be a commit that is not a version.
say "Formula/pqprobe.rb"
./scripts/brew.sh write

# The sitemap's lastmod and llms.txt's version belong to this release, so they
# are rendered inside its commit for the same reason the formula is.
say "docs/sitemap.xml, robots.txt, llms.txt"
sh scripts/seo.sh render

fi

say "the diff"
git --no-pager diff --stat

if [ "$commit" -eq 0 ]; then
	cat <<MSG

Nothing has been committed. Read the diff, then:

  scripts/release.sh $version --commit

MSG
	exit 0
fi

say "commit and tag"
git add -A
git commit -q -m "pqprobe $version" -m "$(./scripts/release-notes.sh "$version" | head -3)"
git tag -a "$tag" -m "pqprobe $version" -m "$(./scripts/release-notes.sh "$version")"
echo "committed $(git rev-parse --short HEAD) and tagged $tag"

# The rules this repository runs on, checked on the thing they were just applied
# to: the tag matches the CHANGELOG, and the formula installs it.
./scripts/version.sh check
./scripts/brew.sh check
sh scripts/seo.sh check

cat <<MSG

Not pushed — that is your call. The Release workflow runs when the tag arrives:

  git push origin main
  git push origin $tag

MSG
