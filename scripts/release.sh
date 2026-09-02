#!/bin/sh
# release.sh — prepare a release, locally, and stop before the part that is the
# maintainer's call.
#
#   scripts/release.sh 0.2.0            check everything and show the diff
#   scripts/release.sh 0.2.0 --commit   also commit and tag vX.Y.Z
#
# What it does, in order: refuse to run on a dirty tree or an existing tag, run
# every gate CI runs, turn the `[Unreleased]` CHANGELOG section into
# `[X.Y.Z] - <today>` with its link reference, rewrite every backlog item
# carrying `ver=unreleased` to `ver=X.Y.Z`, and regenerate ROADMAP.md.
#
# What it never does: **push**. Not the commit, not the tag. Publishing is a
# decision, the release workflow triggers on the tag arriving at GitHub, and a
# script that pushes turns "let me look at the diff" into a published release.
#
# POSIX sh only. RELEASE_DRY_RUN=1 stops after the checks, which is what the
# tests use.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

version=${1:-}
commit=0
[ "${2:-}" = "--commit" ] && commit=1

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

# ---------------------------------------------------------------------------
say "the tree"
if [ -n "$(git status --porcelain)" ]; then
	echo "release.sh: the working tree is not clean — commit or stash first" >&2
	git status --short >&2
	exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
	echo "release.sh: $tag already exists" >&2
	exit 1
fi
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || echo "note: on branch $branch, not main"
echo "clean, $tag is free, HEAD is $(git rev-parse --short HEAD)"

# ---------------------------------------------------------------------------
say "what is going out"
if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
	echo "release.sh: CHANGELOG.md has no [Unreleased] section — nothing to release" >&2
	exit 1
fi
unreleased=$(awk '/^## \[Unreleased\]/ { inside = 1; next } /^## \[/ { inside = 0 } inside' CHANGELOG.md | grep -c '^- ' || :)
[ "$unreleased" -gt 0 ] || {
	echo "release.sh: the [Unreleased] section has no entries" >&2
	exit 1
}
echo "$unreleased entry/entries under [Unreleased]"
ticks=$(grep -c 'ver=unreleased' BACKLOG.md || :)
echo "$ticks backlog item(s) marked ver=unreleased"

# ---------------------------------------------------------------------------
say "the gates"
unformatted=$(gofmt -l ./cmd ./internal)
[ -z "$unformatted" ] || { echo "not gofmt'd:" >&2; echo "$unformatted" >&2; exit 1; }
go vet ./...
go test ./...
go test -race ./... >/dev/null
./scripts/backlog.sh lint
./scripts/backlog.sh check
sh scripts/backlog_test.sh >/dev/null && echo "backlog tests OK"
./scripts/docs.sh check
sh scripts/docs_test.sh >/dev/null && echo "docs tests OK"
sh scripts/release_test.sh >/dev/null && echo "release tests OK"
./scripts/repo-meta.sh lint
sh scripts/repo-meta_test.sh >/dev/null && echo "metadata tests OK"
sh scripts/render-assets.sh --check
sh scripts/assets_test.sh >/dev/null && echo "asset tests OK"

[ "${RELEASE_DRY_RUN:-0}" = 1 ] && { say "dry run — nothing was rewritten"; exit 0; }

# ---------------------------------------------------------------------------
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

cat <<MSG

Not pushed — that is your call. The Release workflow runs when the tag arrives:

  git push origin main
  git push origin $tag

MSG
