#!/bin/sh
# repo-meta.sh — keep the GitHub "About" box in the repository.
#
#   scripts/repo-meta.sh lint     validate .github/repo-meta (no network)
#   scripts/repo-meta.sh show     print what would be applied
#   scripts/repo-meta.sh check    compare with what GitHub currently has (gh)
#   scripts/repo-meta.sh apply    write it to GitHub (gh repo edit)
#
# The description, the homepage and the topics are the only part of this project
# that lives outside git by default, which is how they end up eighteen months
# stale. Here they are data, reviewed in a diff like everything else.
#
# `lint` is the CI gate: it needs no token and catches the failures that would
# otherwise surface as a silently rejected API call — a description over
# GitHub's 350 characters, a topic GitHub will not accept, a homepage that
# disagrees with the canonical URL of the published page.
#
# `apply` changes something people see outside this repository, so it is a
# maintainer action like a push: nothing runs it on your behalf except the Repo
# metadata workflow, which a maintainer starts by hand.
#
# POSIX sh and awk only — this repository has no dependencies, and neither does
# its tooling. REPO_META, DOCS_HTML and REPO override the data file, the
# published page and the repository, so the gate can be tested against a
# fixture rather than against this repository — where every case would pass or
# fail for the reason the real files give it.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
meta="${REPO_META:-$root/.github/repo-meta}"
mode="${1:-lint}"

[ -f "$meta" ] || { echo "repo-meta.sh: no such file: $meta" >&2; exit 2; }

field() { # field <key> — the value of `key:`, trimmed, first occurrence wins
	awk -v k="$1" '
		/^[ \t]*#/ { next }
		{ i = index($0, ":"); if (i == 0) next
		  key = substr($0, 1, i - 1)
		  gsub(/^[ \t]+|[ \t]+$/, "", key)
		  if (key != k) next
		  val = substr($0, i + 1)
		  gsub(/^[ \t]+|[ \t]+$/, "", val)
		  print val; exit }
	' "$meta"
}

description=$(field description)
homepage=$(field homepage)
topics=$(field topics | tr ',' '\n' | awk '{ gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "") print }')

lint() {
	bad=0
	err() { printf '.github/repo-meta: %s\n' "$1" >&2; bad=$((bad + 1)); }

	# A pipeline runs in a subshell, so a counter incremented inside one never
	# reaches this scope. The topic checks write their findings to a file, and
	# this scope counts them.
	badfile=$(mktemp "${TMPDIR:-/tmp}/pqprobe-meta.XXXXXX")
	trap 'rm -f "$badfile"' EXIT INT HUP TERM

	len=$(printf '%s' "$description" | wc -c | tr -d ' ')
	[ -n "$description" ] || err "no description"
	[ "$len" -le 350 ] || err "the description is $len characters — GitHub's limit is 350"

	[ -n "$homepage" ] || err "no homepage"
	case "$homepage" in https://*) ;; *) err "the homepage must be an https URL" ;; esac

	# The published page states its own canonical URL. Two answers to "where does
	# this live" is how the link in the About box outlives the site it points at.
	html="${DOCS_HTML:-$root/docs/index.html}"
	if [ -f "$html" ]; then
		canon=$(awk '/rel="canonical"/ { i = index($0, "href=\""); if (i) {
			r = substr($0, i + 6); j = index(r, "\""); print substr(r, 1, j - 1); exit } }' "$html")
		if [ -n "$canon" ] && [ "$canon" != "$homepage" ]; then
			err "the homepage is $homepage but docs/index.html says the canonical URL is $canon"
		fi
	fi

	n=$(printf '%s\n' "$topics" | grep -c . || :)
	[ "$n" -ge 1 ] || err "no topics"
	[ "$n" -le 20 ] || err "$n topics — GitHub keeps at most 20"

	# Read line by line rather than `for t in $topics`: word splitting would turn
	# `post quantum` into two acceptable topics and send both to GitHub.
	printf '%s\n' "$topics" | while IFS= read -r t; do
		[ -n "$t" ] || continue
		case "$t" in
		*[!a-z0-9-]*) printf 'topic `%s` is not lowercase letters, digits and hyphens\n' "$t" ;;
		-*|*-)        printf 'topic `%s` starts or ends with a hyphen\n' "$t" ;;
		esac
	done > "$badfile"

	# GitHub de-duplicates silently, so a repeated topic is a wasted slot out of
	# twenty and a drift `check` would report for ever.
	printf '%s\n' "$topics" | sort | uniq -d | while IFS= read -r t; do
		[ -n "$t" ] && printf 'topic `%s` appears twice\n' "$t"
	done >> "$badfile"

	while IFS= read -r line; do
		[ -n "$line" ] && err "$line"
	done < "$badfile"

	if [ "$bad" -gt 0 ]; then
		printf '\n%d problem(s) in .github/repo-meta\n' "$bad" >&2
		exit 1
	fi
	printf 'repo-meta OK — a %d-character description and %d topics\n' "$len" "$n"
}

show() {
	printf 'description  %s\n\n' "$description"
	printf 'homepage     %s\n\n' "$homepage"
	printf 'topics       %s\n' "$(printf '%s\n' "$topics" | tr '\n' ' ')"
}

need_gh() {
	command -v gh >/dev/null 2>&1 ||
		{ echo "repo-meta.sh: gh is not installed — cannot talk to GitHub" >&2; exit 2; }
}

repo_arg() {
	if [ -n "${REPO:-}" ]; then printf '%s' "$REPO"
	else gh repo view --json nameWithOwner --jq .nameWithOwner
	fi
}

check() {
	need_gh
	repo=$(repo_arg)
	cur_desc=$(gh repo view "$repo" --json description --jq '.description // ""')
	cur_home=$(gh repo view "$repo" --json homepageUrl --jq '.homepageUrl // ""')
	cur_top=$(gh repo view "$repo" --json repositoryTopics \
		--jq '[.repositoryTopics[]?.name] | sort | join(" ")')
	want_top=$(printf '%s\n' "$topics" | sort | tr '\n' ' ' | sed 's/ *$//')

	drift=0
	[ "$cur_desc" = "$description" ] ||
		{ printf 'description differs\n  GitHub: %s\n  here:   %s\n' "$cur_desc" "$description"; drift=1; }
	[ "$cur_home" = "$homepage" ] ||
		{ printf 'homepage differs\n  GitHub: %s\n  here:   %s\n' "$cur_home" "$homepage"; drift=1; }
	[ "$cur_top" = "$want_top" ] ||
		{ printf 'topics differ\n  GitHub: %s\n  here:   %s\n' "$cur_top" "$want_top"; drift=1; }

	[ "$drift" -eq 0 ] && { printf '%s matches .github/repo-meta\n' "$repo"; return 0; }
	echo ""
	echo "run scripts/repo-meta.sh apply to write .github/repo-meta to GitHub"
	return 1
}

apply() {
	need_gh
	lint >/dev/null
	repo=$(repo_arg)
	set -- gh repo edit "$repo" --description "$description" --homepage "$homepage"
	# Line by line, for the same reason lint checks it that way.
	oldifs=$IFS; IFS='
'
	for t in $topics; do
		[ -n "$t" ] && set -- "$@" --add-topic "$t"
	done
	IFS=$oldifs
	"$@" >/dev/null
	printf 'applied to %s:\n\n' "$repo"
	show
	echo ""
	echo "note: --add-topic only adds. A topic dropped from .github/repo-meta stays"
	echo "      on GitHub until it is removed there — \`repo-meta.sh check\` says so."
}

case "$mode" in
lint)  lint ;;
show)  show ;;
check) check ;;
apply) apply ;;
*)
	echo "usage: scripts/repo-meta.sh [lint|show|check|apply]" >&2
	exit 2
	;;
esac
