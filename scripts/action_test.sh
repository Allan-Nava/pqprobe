#!/bin/sh
# action_test.sh — action.yml is delivery, and it broke in the one way nothing
# local was checking.
#
# actionlint validates workflows, not action metadata, and `bash -n` validates
# the script without knowing that GitHub evaluates `${{ ... }}` *anywhere* in a
# run string — including inside a shell comment. The comment explaining that
# inputs must not travel through an expression was itself an empty expression,
# and the action failed to load at all.
#
#   sh scripts/action_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/action.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-action-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

good() {
	cat > "$1" <<'YML'
name: pqprobe
description: probe some endpoints
inputs:
  targets:
    description: "what to probe"
    required: false
    default: ""
outputs:
  findings:
    description: "the findings"
    value: ${{ steps.probe.outputs.findings }}
runs:
  using: composite
  steps:
    - id: probe
      shell: bash
      env:
        TARGETS: ${{ inputs.targets }}
      run: |
        echo "probing $TARGETS"
YML
}

expect() { # expect <exit> <name> <file>
	got=0
	ACTION_FILE="$3" sh "$gate" check >/dev/null 2>&1 || got=$?
	if [ "$got" -eq "$1" ]; then ok "$2"; else notok "$2 (wanted exit $1, got $got)"; fi
}

printf 'action.sh check:\n'

good "$tmp/ok.yml"
expect 0 "a valid composite action passes" "$tmp/ok.yml"

# The failure that actually happened.
good "$tmp/expr-comment.yml"
cat >> "$tmp/expr-comment.yml" <<'YML'
        # never through ${{ }} inside this script
        echo done
YML
expect 1 "an expression inside a run block fails, comment or not" "$tmp/expr-comment.yml"

good "$tmp/expr-real.yml"
cat >> "$tmp/expr-real.yml" <<'YML'
        echo "${{ inputs.targets }}"
YML
expect 1 "an input interpolated into a run block fails — that is the injection rule" "$tmp/expr-real.yml"

good "$tmp/nodesc.yml"
grep -v '^description:' "$tmp/nodesc.yml" > "$tmp/nodesc.new" && mv "$tmp/nodesc.new" "$tmp/nodesc.yml"
expect 1 "an action with no description fails" "$tmp/nodesc.yml"

good "$tmp/notcomposite.yml"
sed 's/using: composite/using: node20/' "$tmp/notcomposite.yml" > "$tmp/nc.new" && mv "$tmp/nc.new" "$tmp/notcomposite.yml"
expect 1 "a non-composite action fails: this one installs a binary and runs it" "$tmp/notcomposite.yml"

good "$tmp/noshell.yml"
grep -v '      shell: bash' "$tmp/noshell.yml" > "$tmp/ns.new" && mv "$tmp/ns.new" "$tmp/noshell.yml"
expect 1 "a run step with no shell fails — composite steps require one" "$tmp/noshell.yml"

expect 2 "a missing file is a usage error" "$tmp/nope.yml"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
