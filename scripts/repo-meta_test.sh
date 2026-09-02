#!/bin/sh
# repo-meta_test.sh — the About-box gate, against fixtures.
#
# Everything this gate catches fails *silently* on GitHub: a description over
# 350 characters, a topic with a capital letter, a twenty-first topic. The API
# accepts the call and drops the field, so the only place the mistake can be
# caught is here — which makes the gate itself worth asserting.
#
#   sh scripts/repo-meta_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/repo-meta.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-meta-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# The canonical-URL cross-check reads the published page. Under test it reads
# this fixture, or every case would fail for the wrong reason.
printf '%s\n' '<link rel="canonical" href="https://example.test/thing/">' > "$tmp/index.html"

# meta <file> <description> <homepage> <topics>
meta() {
	printf '# a fixture\ndescription: %s\n\nhomepage: %s\n\ntopics: %s\n' \
		"$2" "$3" "$4" > "$1"
}

# expect <exit> <name> <file>
expect() {
	want=$1 name=$2 file=$3
	got=0
	REPO_META="$file" DOCS_HTML="$tmp/index.html" sh "$gate" lint >/dev/null 2>&1 || got=$?
	if [ "$got" -eq "$want" ]; then ok "$name"; else
		notok "$name (wanted exit $want, got $got)"
	fi
}

printf 'repo-meta.sh lint:\n'

meta "$tmp/good" "A short, honest description." "https://example.test/thing/" "tls, ml-kem, sre"
expect 0 "a valid file passes" "$tmp/good"

long=$(awk 'BEGIN { while (i++ < 360) printf "x" }')
meta "$tmp/long" "$long" "https://example.test/thing/" "tls"
expect 1 "a description over GitHub's 350 characters fails" "$tmp/long"

meta "$tmp/upper" "Fine." "https://example.test/thing/" "TLS, ml-kem"
expect 1 "a topic with a capital letter fails" "$tmp/upper"

meta "$tmp/space" "Fine." "https://example.test/thing/" "post quantum"
expect 1 "a topic with a space fails" "$tmp/space"

meta "$tmp/hyphen" "Fine." "https://example.test/thing/" "-tls"
expect 1 "a topic starting with a hyphen fails" "$tmp/hyphen"

many=$(awk 'BEGIN { for (i = 1; i <= 21; i++) printf "%stopic-%d", (i > 1 ? ", " : ""), i }')
meta "$tmp/many" "Fine." "https://example.test/thing/" "$many"
expect 1 "21 topics fails — GitHub keeps 20" "$tmp/many"

meta "$tmp/http" "Fine." "http://example.test/thing/" "tls"
expect 1 "a homepage that is not https fails" "$tmp/http"

meta "$tmp/canon" "Fine." "https://example.test/elsewhere/" "tls"
expect 1 "a homepage that disagrees with the page's canonical URL fails" "$tmp/canon"

meta "$tmp/nodesc" "" "https://example.test/thing/" "tls"
expect 1 "no description fails" "$tmp/nodesc"

meta "$tmp/notopics" "Fine." "https://example.test/thing/" ""
expect 1 "no topics fails" "$tmp/notopics"

# GitHub silently de-duplicates, so a repeated topic is a slot wasted out of
# twenty and a diff that never converges: `check` would report drift for ever.
meta "$tmp/dupe" "Fine." "https://example.test/thing/" "tls, ml-kem, tls"
expect 1 "the same topic twice fails" "$tmp/dupe"

printf '\nrepo-meta.sh plan:\n'

# `apply` used to run `gh repo edit --add-topic`, which only ever adds: a topic
# dropped from the file stayed on GitHub, so `check` reported drift for ever —
# and with a token in CI, that is a job that fails on every push and can never
# be made to pass. The topics have to be *set*, as a whole list.
plan=$(REPO_META="$tmp/good" DOCS_HTML="$tmp/index.html" REPO=owner/repo sh "$gate" plan 2>&1 || :)

case "$plan" in
*--add-topic*) notok "plan still adds topics one by one — a removal can never converge" ;;
*) ok "topics are not added one by one" ;;
esac

case "$plan" in
*"repos/owner/repo/topics"*) ok "plan sets the whole topic list through the topics API" ;;
*) notok "plan does not set the topic list wholesale: $plan" ;;
esac

n=$(printf '%s\n' "$plan" | grep -o 'names\[\]=' | wc -l | tr -d ' ')
[ "$n" -eq 3 ] && ok "one names[] entry per topic in the file" ||
	notok "$n names[] entries, wanted 3"

case "$plan" in
*"--description"*) ok "plan still sets the description" ;;
*) notok "plan does not set the description" ;;
esac

# plan must be readable without touching anything, like `backlog.sh issues`.
case "$plan" in
*"gh api"*|*"gh repo edit"*) ok "plan prints the commands rather than running them" ;;
*) notok "plan prints nothing runnable: $plan" ;;
esac

printf '\nrepo-meta.sh usage:\n'

got=0; REPO_META="$tmp/missing" sh "$gate" lint >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "a missing data file is a usage error" ||
	notok "a missing data file exited $got, wanted 2"

got=0; REPO_META="$tmp/good" DOCS_HTML="$tmp/index.html" sh "$gate" wat >/dev/null 2>&1 || got=$?
[ "$got" -eq 2 ] && ok "an unknown mode is a usage error" ||
	notok "an unknown mode exited $got, wanted 2"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
