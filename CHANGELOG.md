# Changelog

All notable changes to pqprobe are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versioning is
[Semantic Versioning](https://semver.org/). Every release is a tagged `vX.Y.Z`
with its own section; `minor` for new profiles, checks or flags, `patch` for
fixes. Items reference their `PQ-n` id in [BACKLOG.md](BACKLOG.md).

## [Unreleased]

### Added

- **Intent document** (PQ-21) — [INTENT.md](INTENT.md): why pqprobe exists, its
  goals in priority order, its non-goals as decisions rather than gaps, the
  invariants with their reasons, and where the boundary with `testssl.sh`,
  checkfleet and crowdsim runs.
- **Documentation site** (PQ-17) — [docs/](docs/index.html) published to GitHub
  Pages at <https://allan-nava.github.io/pqprobe/>: one committed static page
  covering the classes, the profiles, install, every flag, the exit codes, the
  findings reference and the scope, with no build step and no external request
  beyond the badges. `scripts/docs.sh check` is a POSIX-sh dead-link gate that
  runs in CI and again before each deploy; `scripts/docs_test.sh` tests the gate
  against a fixture.
- **Logo and social card** (PQ-29) — hand-written SVG in
  [docs/assets/](docs/assets): the mark shows what the tool measures, one client
  class arriving and the oversized hybrid hello cut off before the wall.
  `scripts/render-assets.sh` rasterises the Open Graph card and the iOS icon,
  the two places SVG is not accepted.
- **Release pipeline** (PQ-16) — a tag is the only trigger: archives for six
  platforms, one `SHA256SUMS`, a provenance attestation, the multi-arch
  `ghcr.io/allan-nava/pqprobe` image smoke-tested after it is pushed, and
  release notes lifted from this file by `scripts/release-notes.sh`. No
  goreleaser and no release bot — the pipeline has as few dependencies as the
  binary. `scripts/release.sh <X.Y.Z>` runs every gate, turns `[Unreleased]`
  into a dated section, rewrites `ver=unreleased` in the backlog, regenerates
  the roadmap and tags; it never pushes.
- **The About box as data** (PQ-30) — the repository description, homepage and
  topics live in [.github/repo-meta](.github/repo-meta).
  `scripts/repo-meta.sh` lints them in CI (GitHub's 350-character limit, the
  topic charset, no repeated topic, and the homepage agreeing with the published
  page's canonical URL), `check` reports drift against GitHub and `apply` writes
  it. The topic list is read line by line: a topic containing a space is a
  finding, not two topics silently sent to GitHub. `scripts/repo-meta_test.sh`
  covers the gate against fixtures — it is what found both of those.
- **Backlog to issues, automatically** (PQ-31) — the existing planner now runs
  on a push that touches `BACKLOG.md`, one direction only.

### Fixed

- **`issues --apply` could not create the labels it needs** (PQ-31) —
  `ensure_labels` had been carried over from a sibling project and still offered
  `parser` and `check` while the linter enforced `probe`, `profile`, `verdict`
  and `inventory`. The first real sync created thirteen labels and a milestone,
  then died on `could not add label: 'probe' not found`. There is now **one**
  vocabulary, `labels=` in `scripts/backlog.sh`, read by the linter and by the
  label bootstrap alike; a label with no colour or description is a hard error;
  and `backlog_issues_test.sh` compares the two lists so they cannot drift
  again.
- **The Repo metadata workflow failed for a state it could not change** (PQ-30)
  — the default `GITHUB_TOKEN` cannot edit repository metadata
  (`administration` is not a grantable workflow permission), so a drift check on
  every push was permanently red. It now applies the file when a
  `REPO_META_TOKEN` secret exists and proves it converged; without one, drift is
  a warning with the fix in it. A job that is red for something it cannot fix is
  a job people learn to ignore — the same reason the tool exits 0 on a WARN.
- **A freshness gate for the rendered assets** (PQ-29) —
  `scripts/render-assets.sh --check` compares the SVGs against the checksums
  recorded when the PNGs were rendered, so an edited logo cannot ship with last
  month's social card. It needs no browser, which is what lets CI run it, and
  `scripts/assets_test.sh` asserts exactly that along with each way the check
  has to fail.
- **M5 — Make the verdict actionable** (PQ-22…PQ-28) planned in
  [BACKLOG.md](BACKLOG.md): a per-group capability map, a re-dial before an
  abrupt result is condemned, `--baseline` transitions, ALPN as a variable,
  mutual TLS told apart from a refusal, pull-request delivery and
  `explain <class>`.

## [0.1.0] - 2026-09-02

First release: the asymmetry between a classical client and a
post-quantum-capable one, from a single static binary.

### Added

- **Client profiles as capability classes** (PQ-1) — `classic`, `pq-preferred`,
  `pq-only`, `tls13-only`, `tls12`. Each pins its own key exchange group list
  and TLS version window, so a toolchain upgrade cannot change what a run
  proves, and each names the real clients it stands for.
- **Abrupt versus civil refusal** (PQ-2) — the classification everything rests
  on. A TLS alert means the peer parsed the ClientHello and declined the group;
  a reset, timeout, EOF or non-TLS record means it choked on the hello itself.
  Only the second is an outage waiting for a CDN to flip a default.
- **Handshake and certificate graded separately** (PQ-3) — the dialler never
  verifies; the chain is verified afterwards from the certificates the peer
  sent. An expired certificate is reported as an expiry, never as "this
  endpoint refuses post-quantum clients".
- **Verdicts against a baseline** (PQ-4) — `pq-ready`, `pq-capable`, `pq-blind`,
  `pq-refusing`, `pq-intolerant`, `no-tls13`, `unreachable`, `tls-broken`. Every
  post-quantum conclusion is conditional on the classical profile having
  connected; an endpoint that answered nothing gets an ERROR, not a grade.
- **A size-intolerant server in the test suite** (PQ-5) — a listener that serves
  TLS normally below a ClientHello size limit and drops the connection above it,
  reproducing the real production failure offline and deterministically.
- **Fleet input** (PQ-6) — targets from arguments, a flat list (`--list`) or an
  Ansible INI inventory (`--inventory`, `--group`), with `ansible_host=` winning
  over the alias and `[group:vars]` never read as hosts. `1.2.3.4=origin.example`
  dials an address while sending a server name, the way a CDN does.
- **Three renderers** (PQ-7) — text worst-first, `--json` with every
  per-profile result, `--findings` as the flat array the sibling tools speak
  (an empty array, never `null`). Certificate expiry and a leaf-only chain are
  reported alongside.
- **Exit 0 whenever the probe ran** (PQ-8) — findings are output, not an error.
  `--exit-on S` opts into exit 1; a usage error is exit 2.

[0.1.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.1.0
