# Backlog — pqprobe

Single source of truth for what is planned. Items keep a stable `PQ-n` id so
commits, the CHANGELOG and issues can reference them. New ideas go here rather
than into scattered TODO comments.

[ROADMAP.md](ROADMAP.md) is a **generated** view of this file, grouped by
milestone. Do not edit it by hand — run `scripts/backlog.sh roadmap` after
touching this file, or CI will fail.

## How to write an item

```
## M3 — Title of the milestone <!-- ms: target=v0.2.0 phase=now -->

- [ ] **PQ-15 — Short name**: what it is, why it earns its place, what it
  needs to touch. <!-- pq: prio=high size=L labels=probe,verdict -->
```

- The **id never changes**. Adding an item means taking the next free number,
  never reusing a retired one. Moving an item to a different milestone is fine;
  renumbering it is not.
- `- [ ]` is open, `- [x]` is shipped, and a shipped item carries the release it
  went out in: `ver=0.1.0`.
- Metadata lives in a trailing `<!-- pq: ... -->` comment. Keys: `prio`
  (`high|med|low`), `size` (`S|M|L|XL`), `labels` (comma-separated, from the
  vocabulary below), `ver` (shipped items only).
- Milestone metadata is a trailing `<!-- ms: ... -->` on the heading. Keys:
  `target` (the release it aims at, or `ongoing`) and `phase`
  (`shipped|now|next|later|ongoing`).
- Labels: `probe`, `profile`, `verdict`, `inventory`, `output`, `cli`,
  `delivery`, `integration`, `tests`, `docs`, `release`, `project`.

`scripts/backlog.sh lint` enforces all of the above; `scripts/backlog.sh next`
prints what to pick up.

## M1 — Tell the two refusals apart <!-- ms: target=v0.1.0 phase=shipped -->

- [x] **PQ-1 — Client profiles as capability classes**: `classic`,
  `pq-preferred`, `pq-only`, `tls13-only` and `tls12`, each pinning its own
  group list and TLS version window so an upgrade of the Go toolchain cannot
  quietly change what a run proves. Each profile names the real clients it
  stands for, and nothing in the code branches on that name.
  <!-- pq: prio=high size=M labels=profile ver=0.1.0 -->
- [x] **PQ-2 — Abrupt vs civil refusal**: the classification the whole tool
  rests on. A TLS alert means the peer parsed the ClientHello and declined the
  group; a reset, a timeout, an EOF or a non-TLS record means it choked on the
  hello itself, which is the failure a CDN turns into an outage. `Kind.Abrupt()`
  is the one predicate the verdict reads.
  <!-- pq: prio=high size=M labels=probe ver=0.1.0 -->
- [x] **PQ-3 — Handshake and certificate graded separately**: the dialler never
  verifies, the chain is verified afterwards from the certificates the peer
  sent. An expired certificate must not be reported as "this endpoint refuses
  post-quantum clients", and a capability answer must not depend on the local
  trust store. <!-- pq: prio=high size=S labels=probe ver=0.1.0 -->
- [x] **PQ-4 — Verdict against a baseline**: every post-quantum conclusion is
  conditional on the classical profile having connected. An endpoint that
  answered nothing is `unreachable` with an ERROR finding, never
  `pq-intolerant`. <!-- pq: prio=high size=M labels=verdict ver=0.1.0 -->
- [x] **PQ-5 — The size-intolerant server, in a test**: a listener that serves
  TLS normally under a ClientHello size limit and drops the connection above it,
  reproducing the real failure offline and deterministically. Without it the
  classifier is an opinion. <!-- pq: prio=high size=M labels=tests ver=0.1.0 -->
- [x] **PQ-6 — Fleet input**: targets from arguments, a flat list, or an Ansible
  INI inventory — with `ansible_host` winning over the alias and `[group:vars]`
  never read as hosts. `1.2.3.4=origin.example` dials an address while sending a
  server name, which is the only way to reproduce a CDN-only failure from a
  workstation. <!-- pq: prio=high size=M labels=inventory ver=0.1.0 -->
- [x] **PQ-7 — Three renderers**: text worst-first with the hint on its own
  line, `--json` with every per-profile result, `--findings` as the flat array
  the rest of the toolchain already speaks (empty array, never `null`).
  <!-- pq: prio=high size=M labels=output ver=0.1.0 -->
- [x] **PQ-8 — Exit 0 whenever the probe ran**: findings are output, not an
  error. Only `--exit-on` produces exit 1; a usage error is 2. A wrapper that
  treats a WARN as a broken check teaches everyone to ignore the check.
  <!-- pq: prio=high size=S labels=cli ver=0.1.0 -->

## M2 — Say it more precisely <!-- ms: target=v0.2.0 phase=now -->

- [ ] **PQ-9 — HelloRetryRequest visibility**: a peer that answers the hybrid
  key share with an HRR down to X25519 costs an extra round trip and is a
  different state from one that never saw ML-KEM. Go does not expose it, so this
  needs `tls.Config.KeyLogWriter` plumbing or a hand-parsed ServerHello.
  <!-- pq: prio=high size=L labels=probe -->
- [ ] **PQ-10 — Real ClientHello shapes**: profiles built with uTLS so a run can
  claim a browser fingerprint, not only a capability class. Behind a build tag
  and clearly separated, because the zero-dependency default is what makes the
  binary safe to run anywhere. <!-- pq: prio=med size=XL labels=profile -->
- [ ] **PQ-11 — ClientHello size sweep**: pad the hello in steps and report the
  byte size at which the peer stops answering, so an intolerant middlebox can be
  shown the number rather than argued with.
  <!-- pq: prio=high size=M labels=probe -->
- [ ] **PQ-12 — Multi-address endpoints**: a hostname behind several A/AAAA
  records is several stacks. Probe each address and report the inconsistent one,
  because one bad node out of six is exactly the shape that survives a manual
  check. <!-- pq: prio=high size=M labels=probe,inventory -->
- [ ] **PQ-13 — Watch mode**: re-probe on an interval and print only the
  transitions, for the window in which a CDN or a load balancer is being
  changed. <!-- pq: prio=low size=M labels=cli -->

## M3 — Fit the toolchain <!-- ms: target=v0.3.0 phase=next -->

- [ ] **PQ-14 — checkfleet module**: emit the same findings under a `pq` module
  in [checkfleet](https://github.com/Allan-Nava/checkfleet) so a fleet already
  described in `checkfleet.yml` gains the check without a second inventory.
  <!-- pq: prio=high size=M labels=integration -->
- [ ] **PQ-15 — Prometheus textfile output**: `--textfile` writing
  `pqprobe_class{target=…}` for a node exporter, so the state is graphable
  without a scraper of its own. <!-- pq: prio=med size=S labels=output -->
- [x] **PQ-16 — Release pipeline**: tag-driven archives for six platforms with
  one `SHA256SUMS`, a provenance attestation, the multi-arch `ghcr.io` image
  (smoke-tested after it is pushed) and release notes lifted from the CHANGELOG
  section by `scripts/release-notes.sh` rather than retyped. No goreleaser and
  no release bot: the pipeline has as few dependencies as the binary.
  `scripts/release.sh` runs every gate, rewrites the CHANGELOG and the backlog
  ticks, tags — and never pushes.
  <!-- pq: prio=high size=M labels=release ver=0.2.0 -->
- [x] **PQ-30 — The About box as data**: the description, homepage and topics
  live in `.github/repo-meta` and go to GitHub through
  `scripts/repo-meta.sh apply`. They are the only part of the project that lives
  outside git by default, which is how they end up eighteen months stale. `lint`
  is a CI gate — a description over 350 characters or a topic GitHub will not
  accept is a silently ignored API call, not an error — and it fails when the
  homepage disagrees with the canonical URL of the published page. Fixtures
  first: the test suite is what found the word-splitting bug that would have
  sent `post quantum` to GitHub as two topics.
  <!-- pq: prio=med size=S labels=project,delivery ver=0.2.0 -->
- [x] **PQ-32 — Every commit is a version**: a commit lands with its own dated
  CHANGELOG section and a `vX.Y.Z` tag on it, so the changelog is the dated
  history of the tool rather than of the code. `scripts/release.sh` is how you
  commit — gates, section, backlog ticks, roadmap, one commit, one tag — and
  `scripts/version.sh check` is the gate that keeps it honest, strict on a tag
  and warning-only on a branch push, because the branch and the tag are two
  pushes and a check that is red between them gets switched off.
  <!-- pq: prio=high size=S labels=release,project ver=0.2.0 -->
- [x] **PQ-31 — Backlog to issues, automatically**: the existing planner runs on
  a push that touches `BACKLOG.md`, so the issues are a view of the backlog
  without anybody remembering to sync them. One direction only: ticking an item
  closes its issue, closing an issue changes nothing.
  <!-- pq: prio=med size=S labels=project ver=0.2.0 -->
- [x] **PQ-17 — Docs site**: `docs/` published to GitHub Pages as a single
  committed static page — no generator, no build step and no external request
  beyond the badges, which is the same property the binary has. A POSIX-sh
  dead-link gate (`scripts/docs.sh`) runs in CI and again before every deploy,
  because nothing builds the page and a link that stopped resolving would
  otherwise be found by a reader.
  <!-- pq: prio=med size=M labels=docs ver=0.2.0 -->
- [x] **PQ-29 — Brand assets**: a mark that states what the tool measures — one
  client class arrives, the oversized hybrid hello is cut off before the wall —
  as `logo.svg`, `favicon.svg`, a wordmark and a 1200×630 social card, with
  `scripts/render-assets.sh` rasterising the two places SVG is not accepted and
  `--check` failing CI when a PNG is older than its SVG — asserted against a
  fixture, browser-free, because a gate CI cannot run is a gate that gets
  deleted. Hand-written SVG: an icon is not worth a dependency.
  <!-- pq: prio=med size=S labels=docs,project ver=0.2.0 -->
- [x] **PQ-21 — Intent document**: [INTENT.md](INTENT.md) — why the tool
  exists, the goals in priority order, the non-goals as decisions rather than
  gaps, and where the boundary with `testssl.sh`, checkfleet and crowdsim runs.
  The one document a proposal is measured against before anybody writes it, and
  the only way an agent can tell "missing" apart from "deliberately absent".
  <!-- pq: prio=high size=S labels=docs,project ver=0.2.0 -->

## M4 — Later <!-- ms: target=ongoing phase=later -->

- [ ] **PQ-18 — Beyond key exchange**: post-quantum *authentication* (ML-DSA
  certificates) is the next migration, and the failure mode is again a size one
  — a chain several kilobytes long. Worth a profile once there is anything to
  probe. <!-- pq: prio=low size=L labels=profile -->
- [ ] **PQ-19 — QUIC**: the same question over HTTP/3, where a large
  ClientHello has to fit an initial packet and the failure is even quieter.
  <!-- pq: prio=med size=XL labels=probe -->
- [ ] **PQ-20 — Non-HTTPS ports**: SMTP STARTTLS, IMAP, syslog-TLS and MySQL
  TLS all handshake, and none of them are covered by a web-shaped probe.
  <!-- pq: prio=low size=L labels=probe -->

## M5 — Make the verdict actionable <!-- ms: target=v0.4.0 phase=later -->

The class is the answer; these items are what an operator needs *around* it —
which group exactly, was it a flap or a wall, what changed since yesterday, and
how the answer reaches a pull request without a second tool.

- [ ] **PQ-22 — Per-group capability map**: `pq-preferred` says a hybrid
  handshake works; it does not say *which* hybrid group. Dial each group Go can
  offer on its own and report the accepted set, so a migration can be planned
  against the group the peer actually supports rather than against the one this
  binary happened to put first. Still capability classes: one connection per
  group, in sequence, and no claim about extension order.
  <!-- pq: prio=high size=M labels=probe,profile -->
- [ ] **PQ-23 — Confirm before condemning**: `pq-intolerant` is the finding an
  operator will take to a CDN vendor, and a single reset can also be a
  half-closed conntrack entry. Re-dial an abrupt result once before the class is
  assigned, record both attempts, and say in the finding whether the refusal
  reproduced. A flap and a wall must not render identically.
  <!-- pq: prio=high size=S labels=probe,verdict -->
- [ ] **PQ-24 — Baseline diff**: `--baseline run.json` compares this run against
  a stored one and reports the *transitions* — `pq-ready` → `pq-intolerant` is
  the finding, and an endpoint that was already broken yesterday is not news at
  the top of the output. The complement of watch mode (PQ-13) for anything that
  runs on a schedule. <!-- pq: prio=high size=M labels=output,cli -->
- [ ] **PQ-25 — ALPN as a variable**: ALPN is bytes in the same hello, and a CDN
  offers `h2,http/1.1` where a health check offers nothing. Dial `pq-preferred`
  both ways and report when the answer differs — an endpoint that takes a hybrid
  hello bare and drops it with ALPN is size-intolerant with a threshold in
  between, and today that reads as a flap.
  <!-- pq: prio=med size=S labels=probe,verdict -->
- [ ] **PQ-26 — mTLS is not a refusal**: an endpoint that asks for a client
  certificate fails the handshake *after* the key exchange it was being asked
  about. Detect the client-auth stage and say so — `pq-ready, client
  certificate required` — instead of grading a mutual-TLS origin as a peer that
  refuses post-quantum clients. <!-- pq: prio=high size=M labels=probe,verdict -->
- [ ] **PQ-27 — Pull-request delivery**: an `action.yml` and a `--markdown`
  renderer, so the fleet table lands in a PR comment or a job summary with the
  worst endpoint first. The same findings, a shape a review can read; no new
  checks. <!-- pq: prio=med size=M labels=delivery,output -->
- [ ] **PQ-28 — `explain <class>`**: print what a class means, which real
  clients it affects and what to do next, without a network call — the hint text
  an operator gets at 03:00, reachable before the incident and quotable in a
  ticket. <!-- pq: prio=low size=S labels=cli,docs -->
