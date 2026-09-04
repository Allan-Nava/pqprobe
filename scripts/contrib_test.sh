#!/bin/sh
# contrib_test.sh — the nested module must not be able to contaminate the root.
#
# contrib/utls exists because uTLS is a dependency and the root module has none
# — a product property enforced in CI, not an aesthetic. The whole arrangement
# rests on the nested module being invisible to the root: its own go.mod, its
# own go.sum, and a relative replace so it always builds from the checkout
# rather than from a version that has to be published first.
#
# Each of those is one careless edit away from being untrue, and the failure is
# silent: the root would gain a dependency and nobody would notice until the
# binary stopped being the thing the README promises.
#
#   sh scripts/contrib_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

printf 'the root module:\n'

if grep -qE '^\s*require\b' "$root/go.mod"; then
	notok "go.mod declares a requirement — the root module has none, by design"
else
	ok "go.mod still declares no requirement"
fi

if [ -f "$root/go.sum" ] && [ -s "$root/go.sum" ]; then
	notok "go.sum is non-empty"
else
	ok "there is still no root go.sum"
fi

# The contrib module's imports must not appear anywhere the root binary builds
# from. This is the check that would catch somebody "simplifying" by importing
# uTLS directly.
if grep -rqE '"github.com/refraction-networking/utls"' "$root/cmd" "$root/internal" "$root/pq" 2>/dev/null; then
	notok "the root packages import uTLS"
else
	ok "no root package imports uTLS"
fi

printf '\nthe nested module:\n'

for f in go.mod go.sum; do
	if [ -f "$root/contrib/utls/$f" ]; then
		ok "contrib/utls has its own $f"
	else
		notok "contrib/utls/$f is missing"
	fi
done

if grep -q 'replace github.com/Allan-Nava/pqprobe => ../..' "$root/contrib/utls/go.mod"; then
	ok "it resolves pqprobe from the checkout, so it needs no published version"
else
	notok "contrib/utls/go.mod does not replace pqprobe with ../.. — it would need a tag before it could build"
fi

# `go build ./...` at the root must not walk into it: that is what keeps the
# root build dependency-free in practice and not just in intention.
if (cd "$root" && go list ./... 2>/dev/null | grep -q contrib); then
	notok "go list ./... at the root includes contrib — the nested module is not nested"
else
	ok "the root go list does not reach into contrib"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
