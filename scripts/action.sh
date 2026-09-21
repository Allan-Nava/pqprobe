#!/bin/sh
# action.sh — validate action.yml, the way it broke.
#
#   scripts/action.sh check
#
# actionlint validates workflows, not action metadata, and `bash -n` validates
# the embedded script without knowing that GitHub evaluates `${{ ... }}`
# *anywhere* in a run string — including inside a shell comment. That is not a
# hypothetical: the comment explaining that inputs must not travel through an
# expression was itself an empty expression, and the action failed to load at
# all with "An expression was expected".
#
# So the rule this gate enforces is the same one that comment was trying to
# state: **no `${{` inside a run block, ever**. Inputs reach the shell through
# `env:`, where a hostile string is a value rather than code — and the day
# somebody writes the explanation again, it cannot break the file.
#
# POSIX sh and awk only. ACTION_FILE points at a fixture.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
file="${ACTION_FILE:-$root/action.yml}"

[ -f "$file" ] || { echo "action.sh: no such file: $file" >&2; exit 2; }

bad=0
err() { printf 'action.yml: %s\n' "$1" >&2; bad=$((bad + 1)); }

grep -q '^name:' "$file" || err "no name"
grep -q '^description:' "$file" || err "no description — GitHub shows it in the marketplace and in every workflow that uses this"
grep -q '^runs:' "$file" || err "no runs section"
grep -q 'using: composite' "$file" ||
	err "not a composite action: this one installs a binary with the runner toolchain, which is why there is no image to keep in step"

# Every step under runs.steps needs a shell or a uses.
awk '
	/^runs:/ { inruns = 1; next }
	inruns && /^[a-z]/ { inruns = 0 }
	inruns && /^    - / { step++; has = 0 }
	inruns && (/shell:/ || /uses:/) { has = 1 }
	inruns && /^    - / && step > 1 && !prevhas { print prevline }
	inruns && /^    - / { prevhas = 0; prevline = "step " step " has neither shell nor uses" }
	inruns && (/shell:/ || /uses:/) { prevhas = 1 }
	END { if (step > 0 && !prevhas) print "step " step " has neither shell nor uses" }
' "$file" | while IFS= read -r line; do
	printf 'action.yml: %s\n' "$line" >&2
done > /dev/null

steps=$(grep -c '^    - ' "$file" || :)
shells=$(grep -cE '^      (shell:|uses:)' "$file" || :)
[ "$steps" -le "$shells" ] || err "$steps step(s) but only $shells with a shell or uses — a composite run step needs a shell"

# The rule. Line by line so the offending line can be printed, and only inside
# run blocks: `env:` and `outputs:` are exactly where an expression belongs.
awk '
	/^      run: \|/ { inrun = 1; next }
	inrun && /^      [a-z-]+:/ { inrun = 0 }
	inrun && /^    - / { inrun = 0 }
	inrun && index($0, "${{") { printf "%d: %s\n", NR, $0 }
' "$file" > "$root/.action-expr.$$" 2>/dev/null || :
if [ -s "$root/.action-expr.$$" ]; then
	while IFS= read -r line; do
		err "an expression inside a run block (GitHub evaluates it even in a comment) — pass it through env: instead: $line"
	done < "$root/.action-expr.$$"
fi
rm -f "$root/.action-expr.$$"

# The workflow that exercises the action (PQ-77). `uses: ./` with
# `version: ${{ github.sha }}` installs the commit CI is running on — and on a
# `pull_request` event that is the *merge* commit, which exists only as
# refs/pull/N/merge. The Go module proxy cannot fetch it: "invalid version:
# unknown revision", every time, on every pull request. It went unnoticed for as
# long as work went straight to main, which is the shape of failure this
# repository keeps finding: a gate that was only ever exercised on the happy
# path.
wf="${WORKFLOW_FILE:-}"
if [ -z "$wf" ] && [ -z "${ACTION_FILE:-}" ]; then
	wf="$root/.github/workflows/ci.yml"
fi
if [ -n "$wf" ] && [ -f "$wf" ] && grep -q 'pull_request' "$wf"; then
	awk '
		/^[[:space:]]*#/ { next }   # a comment explaining the rule is not a breach of it
		/uses: \.\// { inaction = 1 }
		inaction && /version:/ {
			if (index($0, "github.sha") && !index($0, "pull_request.head.sha")) {
				printf "%d: %s\n", NR, $0
			}
			inaction = 0
		}
		/^  [a-z]/ { inaction = 0 }
	' "$wf" | while IFS= read -r line; do
		printf '%s\n' "$line"
	done > "$root/.action-wf.$$" 2>/dev/null || :
	if [ -s "$root/.action-wf.$$" ]; then
		while IFS= read -r line; do
			err "the workflow installs github.sha, which on a pull_request is the merge commit and cannot be fetched by the module proxy — use \${{ github.event.pull_request.head.sha || github.sha }}: $line"
		done < "$root/.action-wf.$$"
	fi
	rm -f "$root/.action-wf.$$"
fi

if [ "$bad" -gt 0 ]; then
	printf '\n%d problem(s) in action.yml\n' "$bad" >&2
	exit 1
fi
printf 'action.yml OK — composite, %d step(s), no expression inside a run block\n' "$steps"
