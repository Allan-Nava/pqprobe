#!/bin/sh
# hooks.sh — install and verify this repository's git hooks (PQ-77).
#
#   scripts/hooks.sh install [repo]   copy the hooks into .git/hooks
#   scripts/hooks.sh check   [repo]   fail if they are missing or stale
#
# Copied rather than pointed at with core.hooksPath, because setting that would
# take .git/hooks out of service — and this repository already has hooks living
# there that nothing in it installed (a knowledge-graph rebuild on post-commit
# and post-checkout). Protecting a branch by breaking somebody else's tooling is
# not a trade this repository makes.
#
# A hook is a local file and a clone does not carry it, which is exactly why
# `check` exists and why the GitHub ruleset on main is the enforcement rather
# than the hook: the hook is the fast, local, offline half that tells you before
# the network does.
#
# POSIX sh only.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
src="$root/scripts/hooks"
mode="${1:-check}"
repo="${2:-$root}"

gitdir=$(git -C "$repo" rev-parse --git-dir 2>/dev/null) || {
	echo "hooks.sh: not a git repository: $repo" >&2
	exit 2
}
case "$gitdir" in
/*) ;;
*) gitdir="$repo/$gitdir" ;;
esac
dest="$gitdir/hooks"

hooks="pre-push"

case "$mode" in
install)
	mkdir -p "$dest"
	for h in $hooks; do
		cp "$src/$h" "$dest/$h"
		chmod +x "$dest/$h"
		echo "installed $h"
	done
	;;
check)
	bad=0
	for h in $hooks; do
		if [ ! -x "$dest/$h" ]; then
			echo "hooks.sh: $h is not installed — run: scripts/hooks.sh install" >&2
			bad=1
		elif ! cmp -s "$src/$h" "$dest/$h"; then
			echo "hooks.sh: $h differs from scripts/hooks/$h — run: scripts/hooks.sh install" >&2
			bad=1
		fi
	done
	[ "$bad" = 0 ] || exit 1
	echo "hooks OK — $hooks installed and current"
	;;
*)
	echo "usage: scripts/hooks.sh [install|check] [repo]" >&2
	exit 2
	;;
esac
