#!/bin/sh
# docs.sh — the dead-link gate for the documentation (PQ-17).
#
# The site is one committed static file, so nothing builds it and nothing would
# notice a link that stopped resolving. This script does:
#
#   scripts/docs.sh check    every local link and asset resolves, exit 1 if not
#   scripts/docs.sh links    list what it checked, for eyeballing
#
# Checked:
#   * href/src in docs/index.html that are not http(s), mailto or a fragment —
#     the file has to exist under docs/
#   * href="#id" in docs/index.html — the id has to exist in the same file
#   * ](path) in the Markdown at the repository root and under docs/ — the file
#     has to exist, with any #fragment stripped
#
# Not checked: external URLs. A gate that fails the build because somebody
# else's site is down is a gate people disable.
#
# POSIX sh and awk only — this repository has no dependencies, and neither does
# its tooling. DOCS_ROOT overrides the tree, so the gate can be tested against
# a fixture rather than against this repository.

set -eu

root="${DOCS_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
mode="${1:-check}"

bad=0
n=0

report() { # report <file> <link> <why>
	printf '%s: %s: %s\n' "$1" "$2" "$3" >&2
	bad=$((bad + 1))
}

# ---------------------------------------------------------------------------
# docs/index.html: assets, local pages, and same-page anchors.
# ---------------------------------------------------------------------------
html="$root/docs/index.html"
if [ -f "$html" ]; then
	ids=$(awk '{ while (match($0, /id="[^"]+"/)) {
			print substr($0, RSTART + 4, RLENGTH - 5)
			$0 = substr($0, RSTART + RLENGTH) } }' "$html" | sort -u)

	refs=$(awk '{ while (match($0, /(href|src)="[^"]*"/)) {
			r = substr($0, RSTART, RLENGTH)
			sub(/^(href|src)="/, "", r); sub(/"$/, "", r)
			if (r != "") print r
			$0 = substr($0, RSTART + RLENGTH) } }' "$html" | sort -u)

	for ref in $refs; do
		case "$ref" in
		http://*|https://*|mailto:*|data:*) continue ;;
		'#'*)
			n=$((n + 1))
			id=${ref#\#}
			printf '%s\n' "$ids" | grep -qx -- "$id" ||
				report "docs/index.html" "$ref" "no element carries that id"
			[ "$mode" = links ] && printf '  docs/index.html  %s\n' "$ref"
			;;
		*)
			n=$((n + 1))
			path=${ref%%#*}
			[ -e "$root/docs/$path" ] ||
				report "docs/index.html" "$ref" "docs/$path does not exist"
			[ "$mode" = links ] && printf '  docs/index.html  %s\n' "$ref"
			;;
		esac
	done
fi

# ---------------------------------------------------------------------------
# Markdown: the root briefs and the docs pages.
# ---------------------------------------------------------------------------
for md in "$root"/*.md "$root"/docs/*.md; do
	[ -f "$md" ] || continue
	rel=${md#"$root"/}
	dir=$(dirname -- "$md")

	# One link per line, so a path with no spaces survives the shell loop.
	links=$(awk '{ while (match($0, /\]\([^)]+\)/)) {
			l = substr($0, RSTART + 2, RLENGTH - 3)
			if (l != "") print l
			$0 = substr($0, RSTART + RLENGTH) } }' "$md" | sort -u)

	for l in $links; do
		case "$l" in
		http://*|https://*|mailto:*|'#'*) continue ;;
		esac
		n=$((n + 1))
		path=${l%%#*}
		[ -z "$path" ] && continue
		[ -e "$dir/$path" ] || report "$rel" "$l" "$path does not exist"
		[ "$mode" = links ] && printf '  %-16s %s\n' "$rel" "$l"
	done
done

if [ "$bad" -gt 0 ]; then
	printf '\n%d dead link(s) in the documentation\n' "$bad" >&2
	exit 1
fi
printf 'docs OK — %d local link(s) resolve\n' "$n"
