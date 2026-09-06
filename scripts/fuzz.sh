#!/bin/sh
# fuzz.sh — run every fuzz target for a short, bounded time.
#
#   sh scripts/fuzz.sh          each target for FUZZTIME (default 10s)
#   FUZZTIME=2m sh scripts/fuzz.sh
#   sh scripts/fuzz.sh --list   print the targets and exit
#
# Why this exists (PQ-66): three of the parsers it drives read bytes an
# *endpoint* chose — a DNS answer, an LDAP response, a MySQL greeting. A wrong
# answer there is a bug; a panic is a monitoring tool that dies halfway through
# somebody's fleet, which is exactly the property INTENT.md means by "safe to
# point at production".
#
# Why a script rather than a line in CI: `go test` runs one -fuzz target per
# invocation, so the list has to live somewhere, and a list that lives in a
# workflow is a list nobody can run before pushing.
#
# The seed corpus runs on every `go test ./...` — that part is always on. This
# is the other half: new inputs, for a bounded time, in CI and before a release.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

fuzztime=${FUZZTIME:-10s}

# Discovered rather than listed, and across every package: a target added
# without a line here would never be fuzzed, and nothing would say so. The
# output is `<package> <target>` pairs, because `go test` fuzzes one at a time.
targets=$(grep -roE --include='*_test.go' --exclude-dir=contrib \
	'^func Fuzz[A-Za-z0-9_]+' "$root"/internal "$root"/cmd "$root"/pq 2>/dev/null |
	sed -E "s|^$root/||" | sed -E 's|/[^/]*_test\.go:func | |' | sort -u)

if [ -z "$targets" ]; then
	echo "fuzz: no Fuzz* targets found — that is either a mistake or a deletion nobody meant" >&2
	exit 1
fi

if [ "${1:-}" = "--list" ]; then
	echo "$targets"
	exit 0
fi

fail=0
echo "$targets" | while read -r pkg t; do
	[ -n "$t" ] || continue
	printf '  %-22s %-28s %s ' "$pkg" "$t" "$fuzztime"
	if go test "./$pkg/" -run "^$t\$" -fuzz "^$t\$" -fuzztime "$fuzztime" >"$root/.fuzz.$$" 2>&1; then
		echo "ok"
	else
		echo "FAIL"
		tail -25 "$root/.fuzz.$$"
		rm -f "$root/.fuzz.$$"
		exit 1
	fi
	rm -f "$root/.fuzz.$$"
done || fail=1

# A crash is written to <package>/testdata/fuzz/<target>/ and becomes a
# permanent seed, so the next plain `go test` reproduces it without the fuzzer.
[ "$fail" -eq 0 ] || {
	echo
	echo "a failing input was saved under <package>/testdata/fuzz — commit it: it is now a test"
	exit 1
}
