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

- [x] **PQ-9 — HelloRetryRequest visibility**: neither `KeyLogWriter` nor a
  hand-parsed ServerHello was needed. An HRR is precisely the case where *we*
  send a second ClientHello, so a six-line wrapper that reads the record header
  of our own outgoing bytes counts them — and measures the first hello for free,
  which is the number the whole size conversation turns on (272 B classical
  against ~1495 B hybrid, on real endpoints). The first run of the test also
  corrected the premise: Go sends key shares for the hybrid group *and* X25519,
  so falling back to X25519 costs no retry at all; an HRR means the only group in
  common was a third one, usually P-256 or P-384. Reported as a cost, not a
  failure. <!-- pq: prio=high size=L labels=probe ver=0.9.0 -->
- [ ] **PQ-10 — Real ClientHello shapes**: profiles built with uTLS so a run can
  claim a browser fingerprint, not only a capability class. Behind a build tag
  and clearly separated, because the zero-dependency default is what makes the
  binary safe to run anywhere. <!-- pq: prio=med size=XL labels=profile -->
- [x] **PQ-34 — An ad-hoc capability class**: `--groups X25519MLKEM768,X25519`
  dials exactly that set, in that order, with `pq-preferred`'s version window so
  the two are comparable. It is visible — its own handshake finding, since the
  caller asked for the dial — and it does not decide the class, because a set
  somebody described is a question rather than a baseline. Names are the ones
  reports print, case-free and round-tripped by a test; an unknown name is a
  usage error listing the known groups, never a silently smaller set.
  <!-- pq: prio=med size=S labels=cli,profile ver=0.12.0 -->
- [x] **PQ-11 — ClientHello size sweep**: `--size-sweep` grows the hybrid hello
  through 2048…12288 bytes, stops at the first size that goes unanswered, and
  reports the bracket in *measured* bytes — the number that went on the wire,
  not the one the sweep asked for. The padding is ALPN entries, which is the
  only field Go lets a client grow (no padding extension, and the TLS 1.3
  cipher list is fixed); the finding says so, because a peer that inspects ALPN
  may treat it differently from a hello made large by a key share, and a number
  quoted without its method is a number that gets argued with. Asserted offline
  against a listener that dies above a limit.
  <!-- pq: prio=high size=M labels=probe ver=0.10.0 -->
- [x] **PQ-12 — Multi-address endpoints**: `--per-address` resolves each name
  and probes every A/AAAA record by address with the name still as the SNI, and
  one `addresses` finding per name names the node that answers differently —
  one bad stack out of six is invisible to a name-only probe, which hits
  whichever address the resolver felt like handing over. A name that does not
  resolve keeps its target so no endpoint silently vanishes from a fleet report.
  Running it also turned up a real classification bug: an address with no route
  from the prober was read as `tls-broken`, claiming the port had answered. It
  is now `unroutable` → `unreachable`, and both hints offer the local route
  first, because an AAAA record probed without IPv6 egress fails in exactly this
  way. <!-- pq: prio=high size=M labels=probe,inventory ver=0.7.0 -->
- [ ] **PQ-13 — Watch mode**: re-probe on an interval and print only the
  transitions, for the window in which a CDN or a load balancer is being
  changed. <!-- pq: prio=low size=M labels=cli -->

## M3 — Fit the toolchain <!-- ms: target=v0.3.0 phase=next -->

- [ ] **PQ-14 — checkfleet module**: emit the same findings under a `pq` module
  in [checkfleet](https://github.com/Allan-Nava/checkfleet) so a fleet already
  described in `checkfleet.yml` gains the check without a second inventory.
  <!-- pq: prio=high size=M labels=integration -->
- [x] **PQ-36 — SEO for the published page**: the crawler-facing half of the
  site, generated from the page rather than maintained beside it —
  `sitemap.xml`, `robots.txt` and an `llms.txt` for the crawlers that read prose
  — plus `robots`/`theme-color`/`og:locale` meta, a JSON-LD `SoftwareApplication`
  graph, and width/height on the external badges so they cannot shift the hero
  as they load. `scripts/seo.sh check` is a CI gate because every failure here
  is silent: a canonical that drifted from the About box, a sitemap naming last
  month's URL, a JSON-LD block truncated by an edit. The classes table is
  deliberately *not* marked up as an `FAQPage`: it is documentation, and
  claiming otherwise to chase a rich result would be a claim about the content
  that is not true. `robots.txt` on a project page is shipped knowing crawlers
  read only the domain root's, which belongs to another repository.
  <!-- pq: prio=med size=S labels=docs,delivery ver=0.16.0 -->
- [ ] **PQ-15 — Prometheus textfile output**: `--textfile` writing
  `pqprobe_class{target=…}` for a node exporter, so the state is graphable
  without a scraper of its own. <!-- pq: prio=med size=S labels=output -->
- [x] **PQ-33 — Homebrew and the published image**: `brew tap` on this
  repository and `brew install pqprobe`, from a `Formula/pqprobe.rb` that
  `scripts/brew.sh` renders inside the release commit — the tap is the repo, so
  there is no second repository to keep in step and no token for a bot to push
  with. The formula clones the tag and builds from source (one formula for
  macOS and Linux, Intel and ARM; a tarball would need a sha256 that cannot
  exist while rendering the file the tag will point at). `brew.sh check` is a CI
  gate, because `brew install` reads whatever the formula says: one left at the
  previous version installs the old binary and looks like it worked. The
  `ghcr.io` image was already published by PQ-16 and documented nowhere — the
  install pages said `docker build` and never `docker pull`.
  <!-- pq: prio=high size=S labels=delivery,docs ver=0.4.0 -->
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

## M5 — Make the verdict actionable <!-- ms: target=v0.15.0 phase=shipped -->

The class is the answer; these items are what an operator needs *around* it —
which group exactly, was it a flap or a wall, what changed since yesterday, and
how the answer reaches a pull request without a second tool.

- [x] **PQ-22 — Per-group capability map**: `pq-preferred` says a hybrid
  handshake works; it does not say *which* hybrid group. `--per-group` dials
  each group Go can offer on its own — ML-KEM, X25519, P-256, P-384, P-521,
  pinned to TLS 1.3 — and the `groups` finding reports the accepted set with the
  two refusals kept apart, so a migration can be planned against the group the
  peer actually supports. The single-group profiles are held out of the verdict:
  no real client dials that way, and grading on it would call a peer intolerant
  for declining P-521. <!-- pq: prio=high size=M labels=probe,profile ver=0.3.0 -->
- [x] **PQ-23 — Confirm before condemning**: an abrupt result is re-dialled
  once before the class is assigned (`Dialer.DoConfirmed`, `--confirm`, on by
  default), both attempts are recorded, and the three outcomes read differently:
  *reproduced on a second dial* for a wall, *only on the second attempt* plus a
  WARN for a flap — which is graded on the handshake that worked, never as BAD —
  and nothing at all for a civil refusal, which is not re-dialled because an
  alert is an answer the peer chose to give. A healthy fleet therefore pays no
  extra connections. <!-- pq: prio=high size=S labels=probe,verdict ver=0.5.0 -->
- [x] **PQ-24 — Baseline diff**: `--baseline run.json` compares this run
  against a stored `--json` run and reports only the *transitions* — a
  regression graded by the class it fell to, an improvement stated quietly, an
  endpoint that appeared or vanished named — while an endpoint that has not
  changed produces nothing at all, because a diff that always has something in
  it is a diff nobody reads. A file that is not a pqprobe document is an error
  rather than an empty comparison: one that silently parsed as nothing would
  report "no changes" for ever. <!-- pq: prio=high size=M labels=output,cli ver=0.8.0 -->
- [x] **PQ-25 — ALPN as a variable**: `--alpn-check` dials `pq-preferred` a
  second time carrying `h2,http/1.1` and one `alpn` finding compares the two,
  with both measured hello sizes, because the smallness of the difference is the
  point — eighteen bytes between working and not means a threshold sits in
  between, every browser and CDN fails, and a bare health check keeps saying the
  endpoint is fine. The pair is *derived* from `pq-preferred` so the ALPN list
  is the only variable: the first version pinned TLS 1.3, offered fewer cipher
  suites and produced a **smaller** hello, which the offline test caught.
  <!-- pq: prio=med size=S labels=probe,verdict ver=0.11.0 -->
- [x] **PQ-26 — mTLS is not a refusal**: the peer's `CertificateRequest` is
  recorded during the handshake, through `GetClientCertificate` — the only
  reliable signal, since on TLS 1.2 the alert that follows is indistinguishable
  from "no mutually supported group" by its text. The premise needed correcting:
  on **TLS 1.3** the handshake does not fail at all, because the objection
  arrives after the client is finished and pqprobe never reads, so the class was
  never wrong there — what was missing was the note that keeps `pq-ready` from
  being read as "usable". Where a certificate request does break every profile
  the class is `mtls-required` with an ERROR: the endpoint refused the prober,
  not post-quantum clients, and pqprobe holds no key material by design.
  <!-- pq: prio=high size=M labels=probe,verdict ver=0.6.0 -->
- [x] **PQ-27 — Pull-request delivery**: `--markdown` renders a table
  worst-first with the detail in `<details>` blocks, and `action.yml` is a
  composite action that installs the binary, writes that report to the job
  summary, exposes the findings array as an output and fails the step only on
  `exit-on`. Same findings, same order, same `--min-severity`, no new checks and
  no colour. The action is tested the way it will be used — a CI job that runs
  `uses: ./` against the commit under test — because an action nobody exercises
  is a file that used to work.
  <!-- pq: prio=med size=M labels=delivery,output ver=0.14.0 -->
- [x] **PQ-35 — Egress through a proxy, but only SOCKS5**: `--socks5
  HOST:PORT`, RFC 1928, no authentication — pqprobe holds no credentials by
  design and a proxy that wants some says so in those words. The host goes to
  the proxy **unresolved**, because inside a network that is often the only place
  it resolves; combining it with `--per-address` is warned about, since that
  resolves here. HTTP `CONNECT` stays out and the flag is named `--socks5` to
  say so rather than disappoint later. A failure at the proxy is kind `proxy`
  and never abrupt: asserted, because reading it as abrupt would put somebody
  else's endpoint in the `pq-intolerant` bucket for a fault on this side.
  <!-- pq: prio=med size=M labels=probe,cli ver=0.15.0 -->
- [x] **PQ-28 — `explain <class>`**: meaning, affected clients and next action
  for any class, with no network call, so it is runnable while the endpoint is
  still refusing. No argument lists them all, a leading `--` is tolerated
  because that is what a hand types, and an unknown word is a usage error that
  prints the vocabulary. A table-driven test asserts that *every* class has an
  explanation and that its status matches the grading table, so a class added
  later cannot arrive without one.
  <!-- pq: prio=low size=S labels=cli,docs ver=0.13.0 -->
