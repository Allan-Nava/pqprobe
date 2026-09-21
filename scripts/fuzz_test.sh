#!/bin/sh
# fuzz_test.sh — the fuzz gate has to tell a finding from a flake (PQ-77).
#
# The failure that produced this: FuzzLDAPResponse came back
# "context deadline exceeded" on a loaded CI runner after 1.1M executions, with
# **no** failing input written — and passed locally at 5.1M executions on the
# same commit. That is the fuzzing coordinator not shutting its workers down
# inside the deadline, not a parser that hangs.
#
# Retrying a gate is a way to hide a real bug, so the rule is narrow and the
# test is what keeps it narrow: retry **only** when Go reports no failing input,
# and fail on the second occurrence. A genuine hang reproduces and writes a
# crasher; a flake does not.
#
# Driven with a fake `go` on PATH, because the real one would take minutes and
# would not fail on demand.
#
#   sh scripts/fuzz_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/fuzz.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-fuzz-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# fakego <script> — a `go` earlier on PATH than the real one.
fakego() {
	mkdir -p "$tmp/bin"
	printf '#!/bin/sh\n%s\n' "$1" > "$tmp/bin/go"
	chmod +x "$tmp/bin/go"
}

run() { # run <name> <want-exit>
	got=0
	( cd "$root" && PATH="$tmp/bin:$PATH" FUZZTIME=1s FUZZ_TARGETS="internal/probe FuzzOne" \
		sh "$gate" >"$tmp/out" 2>&1 ) || got=$?
	if [ "$got" = "$2" ]; then ok "$1"; else notok "$1 (exit $got, want $2)"; cat "$tmp/out"; fi
}

echo "fuzz.sh"

# A clean run stays a clean run.
fakego 'exit 0'
run "a target that passes passes" 0

# The flake: no failing input, so the second attempt is allowed — and here it
# succeeds, which is what a flake does.
fakego 'n=$(cat "$TMPDIR/pqprobe-fuzz-attempts" 2>/dev/null || echo 0)
echo $((n + 1)) > "$TMPDIR/pqprobe-fuzz-attempts"
if [ "$n" = 0 ]; then echo "--- FAIL: FuzzOne (40.07s)"; echo "    context deadline exceeded"; exit 1; fi
exit 0'
TMPDIR="$tmp" run "a deadline with no failing input is retried once" 0

# The same flake twice is not a flake any more.
rm -f "$tmp/pqprobe-fuzz-attempts"
fakego 'echo "--- FAIL: FuzzOne (40.07s)"; echo "    context deadline exceeded"; exit 1'
TMPDIR="$tmp" run "the same deadline twice fails" 1

# A real finding is never retried: Go wrote the input, and re-running would only
# waste a minute before failing anyway.
fakego 'echo "--- FAIL: FuzzOne (2.11s)"
echo "    Failing input written to testdata/fuzz/FuzzOne/abc123"
exit 1'
run "a failing input fails immediately" 1
grep -q "testdata/fuzz" "$tmp/out" && ok "the failing input is named in the output" \
	|| notok "the output does not name the failing input"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
