#!/bin/sh
# docs_test.sh — the dead-link gate has to fail on a dead link.
#
# Red first: each case plants exactly one broken reference in a fixture tree and
# asserts scripts/docs.sh reports it. Run against a fixture rather than this
# repository, so a passing repository cannot make the test vacuous.
#
#   sh scripts/docs_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/docs.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-docs-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0
fail=0

ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# fixture <dir> — a tree the gate is happy with.
fixture() {
	d=$1
	mkdir -p "$d/docs/assets"
	printf 'x' > "$d/docs/assets/logo.svg"
	cat > "$d/docs/index.html" <<'HTML'
<a href="assets/logo.svg">asset</a>
<a href="#top">anchor</a>
<a href="https://example.test/away">external</a>
<section id="top">here</section>
HTML
	cat > "$d/README.md" <<'MD'
[the site](docs/index.html) and [an anchor](docs/index.html#top).
[external](https://example.test/away)
MD
}

# expect <exit> <name> <dir>
expect() {
	want=$1 name=$2 dir=$3
	got=0
	DOCS_ROOT="$dir" sh "$gate" check >/dev/null 2>&1 || got=$?
	if [ "$got" -eq "$want" ]; then ok "$name"; else
		notok "$name (wanted exit $want, got $got)"
	fi
}

printf 'docs.sh:\n'

fixture "$tmp/clean"
expect 0 "a tree with no dead link passes" "$tmp/clean"

fixture "$tmp/asset"
rm "$tmp/asset/docs/assets/logo.svg"
expect 1 "a missing asset in index.html fails" "$tmp/asset"

fixture "$tmp/anchor"
printf '<a href="#nowhere">gone</a>\n' >> "$tmp/anchor/docs/index.html"
expect 1 "an href to an id that does not exist fails" "$tmp/anchor"

fixture "$tmp/md"
printf '[gone](docs/missing.md)\n' >> "$tmp/md/README.md"
expect 1 "a Markdown link to a missing file fails" "$tmp/md"

fixture "$tmp/mdanchor"
printf '[still here](docs/index.html#top)\n' >> "$tmp/mdanchor/README.md"
expect 0 "a Markdown link with a fragment is checked as a path" "$tmp/mdanchor"

fixture "$tmp/ext"
printf '[down right now](https://example.invalid/nope)\n' >> "$tmp/ext/README.md"
expect 0 "an external URL is never checked" "$tmp/ext"

# A space in a path is not exotic — `docs/release notes.md` is one commit away —
# and word splitting turns one live link into two dead ones, which fails CI over
# a file that is right there.
fixture "$tmp/space"
printf 'x' > "$tmp/space/docs/release notes.md"
printf '[the notes](docs/release notes.md)\n' >> "$tmp/space/README.md"
expect 0 "a link whose path contains a space is one link, and it resolves" "$tmp/space"

fixture "$tmp/spacegone"
printf '[the notes](docs/release notes.md)\n' >> "$tmp/spacegone/README.md"
expect 1 "a missing path containing a space still fails" "$tmp/spacegone"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
