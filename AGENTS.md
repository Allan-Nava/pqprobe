# AGENTS.md — pqprobe

`pqprobe` (`github.com/Allan-Nava/pqprobe`) dials one TLS endpoint with several
deliberately different client shapes and reports which classes of client can
still complete a handshake with it. One static Go binary, zero dependencies, no
application data ever sent: `internal/clientprofile` defines the client shapes,
`internal/probe` performs one handshake and classifies how it ended,
`internal/verdict` turns a set of results into a class and findings,
`internal/inventory` reads the target list, `internal/output` renders,
`cmd/pqprobe` is the CLI.

This file is the operating brief for agents working in the repo.
[CLAUDE.md](CLAUDE.md) is a copy of it for Claude Code — when they disagree,
this file wins and CLAUDE.md gets fixed.

[INTENT.md](INTENT.md) says **why** the tool exists, what it commits to and what
is deliberately out of scope. Read it before proposing a feature: a non-goal
there is a decision, not a gap.

## Working rules (ALWAYS)

- **Every feature earns its place against one sentence**: *say which client
  classes this endpoint still accepts, and how it refuses the others*. A check
  that grades a TLS configuration belongs in `testssl.sh`; a check that watches
  certificate lifecycles belongs in
  [checkfleet](https://github.com/Allan-Nava/checkfleet); anything that sends a
  request belongs somewhere else entirely.
- **Zero dependencies, no requests, no subprocesses.** `go.mod` has no `require`
  block and CI enforces it, along with a grep that fails the build on `net/http`
  or `os/exec`. pqprobe handshakes and closes. That is what makes it safe to
  point at production, and it is a product property, not an aesthetic.
- **A profile is a capability class, never a fingerprint.** Go's `crypto/tls`
  cannot reproduce Chrome's ClientHello, and no report may imply that it can.
  Profiles pin *groups and versions*; the client names travel as prose so a
  finding can say who is affected.
- **Grade against the baseline.** Every post-quantum conclusion is conditional
  on the classical profile having connected. An endpoint nobody reached is
  `unreachable` with an ERROR — grading it would put every firewalled host in
  the "intolerant" bucket, and a monitoring system that does that is one nobody
  reads.
- **An alert is not a reset.** The peer that declines a group has negotiated;
  the peer that vanishes mid-hello is broken for every client that offers
  ML-KEM. `Kind.Abrupt()` is the only predicate that may stand for this
  distinction — do not re-derive it from error strings at the call site.
- **Capability and certificate stay separate.** The dialler never verifies; the
  chain is verified afterwards from what the peer sent. A tool that reported an
  expired certificate as "refuses post-quantum clients" would be worse than no
  tool.
- **Exit 0 whenever the probe ran.** Findings are output. Only `--exit-on`
  produces a non-zero exit; a usage error or an unparseable target list exits 2.
- **Worst findings first**, in every renderer, and a finding carries `Value`/
  `Unit` wherever there is a number, so a machine consumer never parses
  `Message`.
- **Test first, always.** The failing test lands before the implementation. The
  URL-versus-SNI parsing bug (`?q=1` read as a server name) was found this way,
  by a table case written before the parser was finished.
- **Backlog first**: work exists in `BACKLOG.md` with a `PQ-n` id, and
  `ROADMAP.md` is generated — run `scripts/backlog.sh roadmap` after editing the
  backlog or CI fails. Commits and CHANGELOG entries reference the id.
- **Align everything**: a new profile, class or flag lands in the same commit as
  its README row, its `--help` text, its tests, the backlog tick and the
  CHANGELOG line.
- **Releases**: every release is a tagged `vX.Y.Z` with a new `CHANGELOG.md`
  section (Keep a Changelog). `minor` for new profiles, classes or flags;
  `patch` for fixes. **Never `git push`**, tags included — that is the
  maintainer's call. No `Co-Authored-By` trailers.

## Pattern for adding a profile or a class

1. **Backlog first**: a `PQ-n` with a milestone, `prio`, `size` and `labels`.
   Regenerate the roadmap.
2. **Red first**: stand up a local server in the test with the property planted
   — a restricted group list, a version ceiling, a ClientHello size limit — and
   watch the assertion fail for the right reason. No production endpoint is ever
   named in a test.
3. **A profile pins its groups and versions.** Falling back to Go's defaults
   means the run proves something different after every toolchain upgrade.
4. **A class states what to do about it.** The `Hint` names the affected clients
   and the next action, because the class name alone tells an operator nothing
   at 03:00.
5. **Two tests minimum**: one that plants the condition and asserts it is found
   *and correctly attributed*, and one that asserts a healthy endpoint stays
   quiet.
6. `go test -race ./...`, `gofmt`, `go vet`.
7. **Close the loop**: CHANGELOG referencing the `PQ-n`, tick the backlog with
   `ver=X.Y.Z`, regenerate the roadmap, tag. No push.

## Known traps / technical rules

- **A large ClientHello is split across TCP segments**, and a middlebox that
  drops the second one produces a hang, not an error. That is why `KindTimeout`
  counts as abrupt: on a post-quantum profile a timeout is a size symptom, not a
  slow server.
- **Go reports a locally generated alert as a plain error string**, not as
  `tls.AlertError` — "no mutually supported group" never becomes a typed alert.
  The classifier tests the string as well, and both paths mean *civil refusal*.
- **`InsecureSkipVerify` is load-bearing here.** It is not a shortcut: it is
  what keeps an expiry problem from being reported as a capability problem.
  Never "fix" it.
- **The URL form is parsed before the `=sni` form.** A query string contains an
  `=`, so splitting on it first turns `https://h/x?q=1` into a probe of `h` with
  server name `1` — a silently wrong result rather than an error.
- **`[group:vars]` is not a list of hosts**, and `ansible_host=` is the address
  that actually resolves. Both rules exist because the alternative is a page of
  DNS errors that look like a real finding.
- **Profiles of one endpoint are dialled in sequence.** Three connections
  landing at once measures a connection limit instead of a capability.
- **Post-quantum key exchange is a TLS 1.3 feature.** An endpoint that tops out
  at 1.2 can never satisfy a PQ-required client, whatever its group list says —
  that is `no-tls13`, and it is a ceiling rather than a setting.
