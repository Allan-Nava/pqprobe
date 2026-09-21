#!/bin/sh
# hooks_test.sh — the pre-push hook has to refuse the push it exists to refuse
# (PQ-77).
#
# Red first, and against a throwaway repository rather than this one: a test
# that proved the hook works by *not pushing* would pass with the hook deleted.
# Every case drives the hook the way git drives it — two arguments, the refs on
# stdin — and asserts the exit status and what it said.
#
#   sh scripts/hooks_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
hook="$root/scripts/hooks/pre-push"
installer="$root/scripts/hooks.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-hooks-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0
fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# run <name> <want-status> <refs-on-stdin> [env assignment]
# Drives the hook as git does: $1 remote name, $2 remote URL, refs on stdin.
run() {
	name=$1 want=$2 refs=$3
	out=$(printf '%s\n' "$refs" | env ${4:-IGNORE=1} sh "$hook" origin https://example.test/repo.git 2>&1) && got=0 || got=$?
	if [ "$got" = "$want" ]; then
		ok "$name"
	else
		notok "$name (exit $got, want $want)"
		printf '       %s\n' "$out"
	fi
	last_out=$out
}

echo "pre-push"

# The push this whole item exists to stop.
run "refuses a push to main" 1 \
	"refs/heads/main $(printf %040d 1) refs/heads/main $(printf %040d 2)"
case "$last_out" in
	*"pull request"*) ok "the refusal says what to do instead" ;;
	*) notok "the refusal does not name the practice: $last_out" ;;
esac

# A feature branch is the whole point of refusing main. Blocking it too would
# make the hook something people uninstall on day two.
run "allows a feature branch" 0 \
	"refs/heads/pq-77-protect-main $(printf %040d 1) refs/heads/pq-77-protect-main $(printf %040d 0)"

# Deleting main remotely is the same push wearing a different hat.
run "refuses deleting main" 1 \
	"(delete) $(printf %040d 0) refs/heads/main $(printf %040d 2)"

# The escape hatch is explicit and loud, because a hook nobody can get past on
# the one day it matters is a hook that gets deleted rather than overridden.
run "an explicit override is honoured" 0 \
	"refs/heads/main $(printf %040d 1) refs/heads/main $(printf %040d 2)" \
	PQPROBE_ALLOW_MAIN_PUSH=1

# Several refs in one push: one bad ref is enough to refuse the push, because
# git offers no way to reject only part of it.
run "refuses a mixed push that includes main" 1 \
	"refs/heads/feature $(printf %040d 1) refs/heads/feature $(printf %040d 0)
refs/heads/main $(printf %040d 1) refs/heads/main $(printf %040d 2)"

echo "installer"

# The installer must not clobber the hooks that are already there: this
# repository drives a knowledge-graph rebuild from post-commit and
# post-checkout, and a gate that silently removed them would be a gate that
# broke somebody else's tooling to protect a branch.
repo="$tmp/repo"
mkdir -p "$repo"
git -C "$repo" init -q
printf '#!/bin/sh\necho existing\n' > "$repo/.git/hooks/post-commit"
chmod +x "$repo/.git/hooks/post-commit"

if sh "$installer" install "$repo" >/dev/null 2>&1; then
	ok "the installer runs"
else
	notok "the installer failed"
fi
[ -x "$repo/.git/hooks/pre-push" ] && ok "pre-push is installed and executable" \
	|| notok "pre-push was not installed"
grep -q existing "$repo/.git/hooks/post-commit" 2>/dev/null \
	&& ok "an existing hook is left alone" \
	|| notok "the installer clobbered an existing hook"

# check reports an uninstalled hook rather than installing it behind your back.
bare="$tmp/bare"
mkdir -p "$bare"
git -C "$bare" init -q
if sh "$installer" check "$bare" >/dev/null 2>&1; then
	notok "check passed on a repository with no hook"
else
	ok "check fails when the hook is missing"
fi
if sh "$installer" check "$repo" >/dev/null 2>&1; then
	ok "check passes once it is installed"
else
	notok "check failed on an installed hook"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
