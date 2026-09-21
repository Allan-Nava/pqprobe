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
# FUZZ_TARGETS overrides the discovery, for scripts/fuzz_test.sh: the real
# targets take minutes and cannot be made to fail on demand.
targets=${FUZZ_TARGETS:-}
[ -n "$targets" ] || targets=$(grep -roE --include='*_test.go' --exclude-dir=contrib \
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

# one <pkg> <target> — runs the target once, leaving its output in $log.
one() {
	go test "./$1/" -run "^$2\$" -fuzz "^$2\$" -fuzztime "$fuzztime" >"$log" 2>&1
}

# A failure is a finding when Go saved the input that caused it: that file is
# the bug, it becomes a permanent seed, and the next plain `go test` reproduces
# it without the fuzzer. A failure with **no** saved input is the fuzzing
# coordinator missing its own deadline — seen on a loaded CI runner at 1.1M
# executions on a commit that passed locally at 5.1M. Retrying a gate is a way
# to hide a real bug, so this is deliberately narrow: one retry, only when
# nothing was saved, and the second occurrence fails like any other (PQ-77).
saved_an_input() {
	grep -q 'Failing input written to' "$log"
}

echo "$targets" > "$root/.fuzz-targets.$$"
while read -r pkg t; do
	[ -n "${t:-}" ] || continue
	printf '  %-22s %-28s %s ' "$pkg" "$t" "$fuzztime"
	log="$root/.fuzz.$$"
	if one "$pkg" "$t"; then
		echo "ok"
	elif saved_an_input; then
		echo "FAIL"
		tail -25 "$log"
		fail=1
		break
	else
		printf 'retrying (no failing input was saved — that is a deadline, not a finding) '
		if one "$pkg" "$t"; then
			echo "ok"
		else
			echo "FAIL"
			tail -25 "$log"
			fail=1
			break
		fi
	fi
done < "$root/.fuzz-targets.$$"
rm -f "$root/.fuzz-targets.$$" "$root/.fuzz.$$"

# A crash is written to <package>/testdata/fuzz/<target>/ and becomes a
# permanent seed, so the next plain `go test` reproduces it without the fuzzer.
[ "$fail" -eq 0 ] || {
	echo
	echo "if a failing input was saved under <package>/testdata/fuzz, commit it: it is now a test"
	exit 1
}
