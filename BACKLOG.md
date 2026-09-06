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
  `delivery`, `integration`, `tests`, `docs`, `release`, `project`, `ux`.

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

## M2 — Say it more precisely <!-- ms: target=v0.18.0 phase=shipped -->

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
- [x] **PQ-13 — Watch mode**: `--watch D` prints the first report in full — you
  have to know the state you are watching from — and from then on only the
  transitions, timestamped, reusing the diff PQ-24 already built. A tick that
  found nothing prints nothing, because in that window a screen of unchanged
  endpoints is what hides the line that matters. Two refusals rather than
  surprises: a **5s floor**, since the interval is a rate against somebody's
  endpoint and `--watch 100ms` is a typo; and `--json`/`--findings`/`--markdown`
  are rejected up front, because a stream of documents is not a document.
  Ctrl-C stops it and exits 0 — the probe ran.
  <!-- pq: prio=low size=M labels=cli ver=0.18.0 -->

## M3 — Fit the toolchain <!-- ms: target=v0.23.0 phase=shipped -->

- [x] **PQ-14 — checkfleet module**: shipped as `checks.pq` in
  [checkfleet](https://github.com/Allan-Nava/checkfleet) (CF-187, its v1.30.0),
  importing `pq/` rather than reimplementing anything — the alert-versus-reset
  classification stays in one place, and a second copy there would have been the
  copy that goes quietly wrong. A fleet already described in `checkfleet.yml`
  gains the check without a second inventory. A healthy endpoint is one row; a
  failing one keeps the verdict *and* the handshake that produced it, because
  that pair is the argument somebody takes to a vendor, and `unreachable` arrives
  as ERROR rather than BAD because it is not a grade.
  Its own gates found four things missing one at a time — the moduledoc entry,
  the permissions entry, the `init` scaffold snippet, and the generated page,
  which its generator refused to write until the prose existed in
  `docs/modules.md`. That is what those gates are for.
  <!-- pq: prio=high size=M labels=integration ver=0.23.0 -->
- [x] **PQ-39 — A public surface for embedders**: `pq/` — strings in, reports
  out, no internal types leaking, so `internal/` stays free to move. `Probe`,
  `Classes`, `Explain`, `Describe`, with findings that carry `Value`/`Unit` so a
  consumer never parses prose. An unreachable target is a report with class
  `unreachable`, never an error: a fleet check has to keep going and name the
  node that is down; an error is only ever something the caller got wrong. The
  zero-dependency gates named `cmd` and `internal` explicitly, so a new public
  package would have slipped past both — widened in the same commit.
  <!-- pq: prio=high size=M labels=integration ver=0.22.0 -->
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
  read only the host root's — which is `Allan-Nava.github.io`, and which already
  generates its `Sitemap:` lines from a daily sync over the sitemaps that answer
  200, so shipping one *is* the mechanism.
  <!-- pq: prio=med size=S labels=docs,delivery ver=0.16.0 -->
- [x] **PQ-15 — Prometheus textfile output**: `--textfile FILE` writes eight
  families for a node exporter's textfile collector — the class as a label, the
  severity as a number to threshold on (`pqprobe_status > 1`), findings per
  status, certificate days taken from the finding rather than recomputed, per
  profile handshake results and the measured hello sizes, and the run
  timestamp, without which a probe that silently stopped looks exactly like a
  fleet that is fine. Written to a temporary file in the same directory and
  renamed over the target, because the collector reads whatever is there when it
  scrapes, half a file included; asserted first, before any of the metric names.
  A side output rather than a renderer, so it combines with all of them and is
  rewritten on every `--watch` tick.
  <!-- pq: prio=med size=S labels=output ver=0.19.0 -->
- [x] **PQ-43 — A gate for a script that was deleted**: `gates_test.sh`
  asserted that every script *that exists* is wired to CI and to `release.sh`,
  and said nothing about the inverse — a workflow naming a script that is gone.
  Removing `scripts/brew.sh` and `brew_test.sh` for the cask left two lines in
  the tag gates, so the next release would have died with `cannot open
  scripts/brew_test.sh`, after the tag was already pushed. It also left the
  `Brew` workflow triggering on `Formula/**`, a path that no longer exists —
  which fails the other way, silently: the workflow would simply never run
  again. Both directions are asserted now, over the effective YAML.
  <!-- pq: prio=high size=S labels=tests,release ver=0.27.1 -->
- [x] **PQ-42 — Homebrew via a goreleaser cask, like checkfleet**: the in-repo
  formula built from source, so `brew install` asked every user for Go and a
  compile. A **cask** hands over the prebuilt binary from the release instead,
  and goreleaser is what generates and pushes one — to
  `Allan-Nava/homebrew-tap`, the tap the sibling tools already use.
  This reverses the "no goreleaser" decision recorded in PQ-16, and the reason
  it was right to reverse: that argument was about the *binary* having no
  dependencies, and the binary is untouched — nothing goreleaser does enters
  `go.mod`, and `contrib_test.sh` still asserts it, now as a goreleaser
  `before` hook so a release stops if a dependency ever appears.
  Gone with the formula: `Formula/`, `scripts/brew.sh`, `brew_test.sh` and the
  render step in `release.sh`. In their place `scripts/goreleaser.sh check` and
  `goreleaser_test.sh` assert what cannot be seen from a checkout, because the
  cask is generated at tag time in another repository: static build, tap token,
  the quarantine strip an unsigned binary needs, and `skip_upload: "auto"` so a
  release candidate never becomes the cask everybody installs (CF-160, borrowed).
  Verified locally with `goreleaser check` and a snapshot build that printed the
  cask it would publish.
  <!-- pq: prio=high size=M labels=delivery,release ver=0.27.0 -->
- [x] **PQ-41 — Homebrew, verified by Homebrew**: `scripts/brew.sh check`
  compares the formula against the script that writes it, which cannot notice
  that *Homebrew* disagrees — and it did: running `brew audit` by hand said
  "Stable: `version 0.25.1` is redundant with version scanned from URL", an
  error that would have reached anybody tapping this repo. The version line is
  gone (Homebrew reads it off the tag) and there is now a `Brew` workflow that
  taps the checkout, runs `brew style` and `brew audit`, installs
  `--build-from-source` on both arm64 and Intel, runs the formula's own `brew
  test`, asserts `version --short` matches the CHANGELOG, and probes a real
  endpoint with the installed binary. After a release, weekly (a tap rots on its
  own), on demand, and on a pull request that touches the formula — where the
  install is skipped, because the tag it clones does not exist yet.
  Three traps encoded rather than rediscovered: `brew install ./path.rb` is
  disabled, Homebrew 6+ ignores untrusted taps in a headless run, and
  `macos-13` is retired — a job asking for it **queues forever** instead of
  failing, which is how checkfleet lost a day (CF-159). `brew_test.sh` asserts
  all three against the effective YAML, comments stripped, because the first
  version of that check flagged the comment explaining the fix as the mistake.
  <!-- pq: prio=high size=M labels=delivery,tests ver=0.26.0 -->
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
- [x] **PQ-40 — Gates that catch a missed edit**: three times a scripted edit
  stopped matching its anchor and was written back unchanged, silently — once
  because `gofmt` had realigned struct tags — and `--watch` shipped with its
  loop never called, found only by running the binary. Two gates now make that
  class of mistake visible: `scripts/gates_test.sh` asserts every gate script
  and every `*_test.sh` is wired to **both** CI and `scripts/release.sh` (it
  caught `backlog_issues_test.sh`, which CI ran and a local release skipped, and
  then caught itself), and a two-way test walks the probe's `FlagSet` against
  `--help`, so a flag declared and not documented — or documented and not
  declared — fails. Proved by planting an undocumented flag and watching it go
  red. The flags now live in one `newProbeFlags`, which is what made them
  enumerable at all.
  <!-- pq: prio=high size=S labels=tests,project ver=0.25.1 -->
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

- [x] **PQ-37 — `--findings` non parla la forma che i tool fratelli consumano**: il
  README promette *«the flat findings array the sibling tools speak»*, ma l'array
  emesso è `{check, target, status, message, value, unit}` con `status`
  maiuscolo (`OK`/`WARN`/`BAD`), mentre l'aggregatore che lo consuma davvero —
  `infra-digest.py` di HiWay, che raccoglie i findings di ~20 health-check —
  vuole un oggetto **avvolto** con un id **stabile** per la deduplica:
  `{check, status, summary, findings: [{id, severity, title, detail}]}`, con
  `severity` minuscolo. Senza l'`id` l'aggregatore non può fare fingerprint fra
  run successive, che è tutto il suo lavoro. Trovato integrando pqprobe come
  producer: è stato necessario tradurre nel wrapper, e una traduzione in ogni
  consumatore è esattamente ciò che una forma condivisa dovrebbe evitare.
  Le strade sono due e vanno entrambe bene, purché se ne scelga una: emettere la
  forma avvolta (magari dietro `--findings=wrapped`), oppure correggere la riga
  del README, che oggi promette un'interoperabilità che non c'è.
  Shipped as `--findings=wrapped`, and the README line was corrected too: the
  promise is now true *and* precise about which shape is which. The flat array
  is untouched, so no existing caller changes. The `id` is a fingerprint of
  check plus target and deliberately not of the message — days-to-expiry and
  byte counts move on their own, and an id derived from the text would report a
  new problem every morning, which is the opposite of deduplication. The flag
  keeps working bare through `IsBoolFlag`, so the shape needs the `=`.
  <!-- pq: prio=med size=M labels=output,integration ver=0.21.0 -->

- [x] **PQ-38 — `version` non è incorporabile**: stampa `pqprobe dev`, cioè nome
  **più** versione, e `version --help` stampa la stessa cosa (il sottocomando
  ignora i flag). Chi la mette in un'intestazione generata ottiene
  `pqprobe pqprobe dev`. Basterebbe che `version` emettesse la sola stringa di
  versione, o un `--short`. Piccolo, ma lo incontra chiunque lo incorpori al
  primo tentativo.
  Shipped as `--short` (and `-s`) rather than by changing what the bare command
  prints: `pqprobe version` is what a person runs and it keeps saying `pqprobe
  X.Y.Z`, while `--short` gives the string alone. The flags are no longer
  ignored either — `version --help` says what it accepts, and a typo exits 2
  instead of printing the version and looking like success.
  <!-- pq: prio=low size=S labels=cli,ux ver=0.20.0 -->

- [x] **PQ-10 — Real ClientHello shapes**: `contrib/utls/`, a module of its own
  with its own `go.mod` and a **relative** replace on the root — so it always
  builds from the checkout and never waits for a version to be published — plus
  `pqprobe-utls`, a second binary. The root stays dependency-free, and
  `scripts/contrib_test.sh` is the gate that keeps that true: no `require` in
  the root `go.mod`, no root `go.sum`, no root package importing uTLS, and
  `go list ./...` not reaching into contrib.
  It does not judge: whether a failure was a civil refusal or the peer choking
  on the hello comes from `pq.Classify`, which this item had to expose first —
  two copies of that distinction is one too many. Real numbers: Chrome 131's
  hello is **1721 bytes** and negotiates ML-KEM against `example.com`.
  Running it found something the item had not foreseen: the `HelloSafari_16_0`
  and `HelloIOS_14` presets fail against *any* modern server with "invalid
  signature by the server certificate" — their own doing, not the endpoint's. So
  a failure inside the client is flagged `Local` and rendered `SKIP` with a note
  saying it says nothing about this endpoint. Reporting it as "example.com
  refuses Safari" would have been the exact lie this tool exists to avoid.
  <!-- pq: prio=med size=XL labels=profile ver=0.25.0 -->
- [x] **PQ-44 — What the chain costs today**: the honest half of PQ-18 that can
  be done before anything serves an ML-DSA certificate — measure the chain on
  the wire (`chain-size`, the sum of the DER the peer actually sent) and say
  what the number is *for*. Post-quantum authentication is a size problem in the
  other direction: an ML-DSA-65 signature is ~3.3 KB against 64 bytes for ECDSA
  and its public key ~2 KB, so each certificate gains roughly 4 KB and a typical
  3 KB chain lands past 10. A chain already at 8 KB is a WARN now, while
  shortening it is a choice rather than an outage. Real numbers today:
  `example.com` 2718 bytes over 3 certificates, `github.com` 3658 over 4.
  It also carries the explanation the tool was missing: `docs/background.md` now
  says what ML-KEM *is* — a hybrid, 1216 bytes of key share, ~1500 on the wire
  against an MTU of 1500 — and what ML-DSA will be. A tool whose whole subject
  is one number should explain where the number comes from.
  <!-- pq: prio=med size=M labels=verdict,docs ver=0.29.0 -->
- [x] **PQ-18 — Beyond key exchange**: **closed as superseded, not as built**,
  and the distinction is the whole content of this entry. Its actionable half
  shipped as PQ-44: the chain is measured on every run and the finding says what
  the number is for, which is the only thing that can be true today.
  The other half — a profile that offers ML-DSA and reports whether the peer can
  authenticate with it — is blocked on the ecosystem rather than on us. Go
  exposes no ML-DSA signature scheme, so a client cannot offer one; no public
  endpoint serves such a certificate, so there would be nothing to answer. A
  profile written now would be code no test could exercise against anything,
  which is the one thing this repository refuses everywhere else.
  When something does serve ML-DSA, that is a new item with a real red test in
  front of it, not this one reopened. Leaving it open as a reminder was costing
  more than it was worth: an item nobody can act on is indistinguishable, in a
  backlog, from one nobody has got to.
  <!-- pq: prio=low size=L labels=profile ver=0.29.1 -->
- [x] **PQ-19 — QUIC**: `contrib/quic` and `pqprobe-quic`, a second nested
  module on the pattern PQ-10 established — a QUIC stack is a dependency and the
  root has none. Same capability classes, so the two answers are comparable, and
  every profile offers `h3`, which over QUIC is not optional the way ALPN is
  over TCP.
  The point of a separate probe is the failure, not the transport: a peer that
  declines a group answers with a CRYPTO_ERROR carrying the alert — civil, the
  same judgement as over TCP, and deferred to `pq.Classify` wherever the error
  is TLS-shaped. A path that cannot carry the Initial packet gives **nothing**:
  UDP has no reset, so where TCP produces a connection reset there is only
  silence until the deadline, which reads exactly like an endpoint that is not
  there. Asserted against a real quic-go listener, including that a dead UDP
  port times out on the caller's deadline rather than on the stack's own.
  Real answers: `cloudflare.com` and `www.google.com` negotiate
  X25519MLKEM768 over h3.
  <!-- pq: prio=med size=XL labels=probe ver=0.28.0 -->
- [x] **PQ-20 — Non-HTTPS ports**: `--starttls smtp|imap|postgres`. Implicit
  TLS never needed anything — 465, 993 and 6514 already worked — so the item was
  really the other half: reaching TLS through a protocol's own negotiation.
  Verified against three in-process servers that speak the real exchanges, and
  on `smtp.gmail.com:587`, which is `pq-ready`.
  A refused upgrade is the new class **`no-tls`** with an ERROR, never
  `pq-intolerant`: a relay with TLS switched off refused *TLS*, and grading that
  as a post-quantum failure would send somebody hunting a middlebox that does
  not exist. The table-driven test from PQ-28 refused the new class until it had
  an explanation, which is what that test is for.
  MySQL is left out on purpose: its upgrade needs the connection-phase packet
  format rather than a line protocol, and it earns its own item rather than a
  footnote here. What is sent is documented in INTENT.md, because "no
  application data" needed the exact clause.
  <!-- pq: prio=low size=L labels=probe ver=0.24.0 -->

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

## M6 — Reach the rest of the fleet <!-- ms: target=v0.32.0 phase=shipped -->

Everything shipped so far answers *this* endpoint, over a path that already
works. These items are the cases where the answer is missing not because the
grading is wrong but because the connection never happened — a protocol whose
upgrade is not a line exchange, an address family the resolver decided for us, a
prober with no route, and a fleet that arrives on a pipe instead of in a file.
Each one turns a page of failures that look like findings back into a single
true statement.

- [x] **PQ-45 — MySQL STARTTLS**: the port PQ-20 deliberately left out. Its
  upgrade is not a line protocol: the server opens with a handshake packet and
  the client answers with a connection-phase response carrying `CLIENT_SSL`,
  which is packet framing rather than a `STARTTLS` line, and folding it into the
  same switch as SMTP would have made that switch a parser. Ports 3306 and 33060
  are where a fleet's data actually lives, and a database driver is exactly the
  kind of client that pins an old TLS stack — the group list there is worth
  knowing before an operator finds out from an outage. The bytes sent stay
  inside the handshake and get the same clause in INTENT.md that PQ-20 needed;
  the red test is an in-process server that speaks the real packet exchange,
  and a server with TLS switched off must come out as `no-tls`, never
  `pq-intolerant`.
  Shipped as `--starttls mysql`. The client answers the server's greeting with a
  32-byte SSLRequest — the first 32 bytes of a login packet and nothing after
  them, which is precisely where the user, the password and the database would
  have gone — and the capability flags in the greeting are what say whether
  `CLIENT_SSL` is on offer at all: absent, it is `no-tls`. Verified against a
  real MySQL 8.4 as well as the in-process server: `pq-blind`, P-256 after a
  hello retry, which is exactly the stack this item was worth writing for — a
  database that no post-quantum-only client will ever reach, and that no health
  check would report.
  Writing the server first paid again: MySQL is the only protocol here where the
  *server* speaks first, and a port that accepts the connection and then says
  nothing — a blocked host, an instance still starting — hung the probe for
  ever, because `--timeout` covers the TLS handshake and there was no TLS
  handshake yet. The plaintext negotiation is now bounded by the same deadline,
  for every protocol.
  The X Protocol on 33060 stays out, on the same grounds MySQL itself stayed out
  of PQ-20: it is a protobuf-framed negotiation rather than this packet
  exchange, and a test asserts the spoken list so it cannot arrive by accident.
  <!-- pq: prio=med size=M labels=probe ver=unreleased -->

- [x] **PQ-46 — Choose the address family**: `--net tcp4|tcp6`, because today
  the resolver chooses and the run does not say so. A dual-stack name that
  answers on A and dies on AAAA reports whatever the prober's resolver felt like
  handing over that minute — the same class of blindness `--per-address` (PQ-12)
  fixed for a single name, still present for the fleet, and the reason a
  finding can flip between two runs with nothing having changed on the endpoint.
  Pinning the family makes an IPv6-only failure reproducible on demand and makes
  the two answers comparable. The selected family belongs in the report, not
  only in the flag: a run that could only use IPv4 has to say so, or its silence
  reads as "IPv6 is fine".
  Shipped as `--net tcp4|tcp6`, with the family stated as an `OK` finding —
  `net` — carrying the hint that the other family was not probed here. Writing
  the test first paid immediately: a `tcp6` dial against a v4 listener came back
  as Go's plain "no suitable address found", which classified as `other` and
  would have been read as the endpoint doing something. It is `unroutable` now,
  for the same reason PQ-12 made a missing route one: it is a fact about the
  prober, and this time about a flag the operator passed. `--per-address`
  probes only the records of the selected family, and a name that resolves with
  nothing in it keeps its target with "resolved, but no address in the IPv6
  family" — a different sentence from "did not resolve", and one that sends
  somebody to a different place. With `--socks5` the second hop is the proxy's
  choice and pqprobe says so rather than implying the endpoint was reached over
  one family. `pq.Options.Net` carries it to embedders, where an unknown family
  is an error rather than a quietly wider run.
  <!-- pq: prio=high size=S labels=probe,cli ver=unreleased -->

- [x] **PQ-47 — A prober with no route says it once**: PQ-12 already refuses to
  call an unroutable address `tls-broken`, which was the dangerous half. The
  half left over is volume — a workstation without IPv6 egress produces one
  `unroutable` per AAAA record across the whole fleet, and forty findings that
  are all the same local fact bury the one finding that is about an endpoint. A
  preflight that establishes what this prober can reach at all, reported once as
  a run-level note, and the per-target results attributed to it rather than
  repeated. It is not a new judgement: it is the existing one, said once and in
  the right place. The test plants a family with no route and asserts both that
  the note appears and that no endpoint is graded on it.
  Shipped as the `egress` finding, ERROR, carrying the number of endpoints it
  accounts for in `Value`, plus `probe.HasEgress` — a UDP "dial" against a
  documentation prefix, which is a route lookup and a local bind with no packet
  sent, in a tool whose contract is that it never sends what it did not say it
  would. Two things the item had not settled fell out of writing it: the check
  runs **only** when something already failed that way, so a healthy fleet pays
  nothing at all; and a family can only be blamed when it is knowable — an
  address literal or a pinned `--net`. A name dialled unpinned had every one of
  its addresses tried, so naming a family there would be a guess in a report.
  The endpoints it explains stop guessing too: their verdict hint now points at
  the finding instead of repeating "the usual cause". Verified on this machine,
  which has no IPv6 route: one line for the run, and the endpoint that failed
  for a missing AAAA record rather than a missing route kept its own hint.
  <!-- pq: prio=med size=M labels=probe,verdict,output ver=unreleased -->

- [x] **PQ-49 — The release renders its derived files in both states**: two
  releases in a row committed and tagged before `seo.sh check` noticed that
  `docs/llms.txt` still named the previous version, so both needed an amend on
  top of a tag — the one operation that goes badly wrong once a tag has been
  pushed. The cause is a branch: `seo.sh render` lives inside the arm taken only
  when the CHANGELOG still has an `[Unreleased]` section, so a release whose
  section is already dated — a state `release.sh --state` explicitly
  recognises and accepts — skips it and commits derived files that describe the
  version before. The render is idempotent, so it belongs after the branch, not
  inside one arm of it; and the check that catches it has to run *before* the
  commit, because a gate that only fails afterwards is a gate whose fix is an
  amend. Asserted structurally, the way `gates_test.sh` asserts wiring: no gate
  script can run the whole gate suite, since `release.sh` is what runs it.
  Shipped: the render moved out of the branch — it is idempotent, so running it
  twice costs nothing and skipping it once cost two amended tags — and the check
  moved ahead of `git commit`, leaving only the one thing that genuinely cannot
  be checked before the tag exists (`version.sh check`) behind it. Two
  structural assertions in `release_test.sh` hold both lines in place, by line
  number against the branch they must sit outside of.
  <!-- pq: prio=high size=S labels=release,tests ver=unreleased -->

- [x] **PQ-48 — Targets on stdin**: `pqprobe -` reads the target list from the
  pipe, in the same forms `--inventory` already accepts. The fleet that needs
  probing is usually the output of something else — a `dig`, a Consul query, an
  `awk` over a config — and today that has to become a temporary file first,
  which is the step people skip, which is how a stale list gets probed. Small,
  but it is the difference between composing with the tools around it and being
  a destination. `-` is a target name nobody has, and everything downstream —
  parsing, `--per-address`, the renderers — is unchanged.
  Shipped in all three spellings — a `-` target, `--list -`, `--inventory -` —
  because a pipe is a file that happens to have no name and nobody should have
  to remember which one works. Two edges the item had not foreseen: `permute`
  filed the bare dash with the flags, and it also had to keep accepting one as a
  *value*, or `--list -` and `-` would have meant different things; and stdin is
  one stream, so two claims on it is a usage error with exit 2 rather than half
  a fleet probed and a report that looks complete.
  <!-- pq: prio=low size=S labels=inventory,ux ver=unreleased -->

## M7 — Encrypted Client Hello <!-- ms: target=v0.35.0 phase=shipped -->

ECH is the same question this tool already asks, one layer further out: it is a
**client capability that makes the ClientHello bigger**, on top of a hybrid
hello that is already ~1.5 KB against an MTU of 1500. Chrome and Firefox offer
it today, so a path that tolerates ML-KEM and not ML-KEM-plus-ECH breaks for
real browsers while every health check stays green — which is the failure this
repository exists to name. Nothing here grades a *configuration*: an endpoint
without ECH has not failed anything, and no item in this milestone may make it
look like it has.

- [x] **PQ-50 — ECH as a capability class**: a profile that offers Encrypted
  Client Hello with a config the caller supplies (`--ech-config BASE64`), and a
  finding that says whether the peer **accepted** it — `ConnectionState.
  ECHAccepted`, not an inference from the handshake having worked. Go supports
  ECH on both sides, so the whole thing is assertable offline against a listener
  holding the matching key, which is the bar every profile here has had to
  clear. The number that matters is the hello: ECH is worth an item because of
  what it adds to a hybrid ClientHello already sitting on the MTU, and the
  finding carries the measured bytes for both, not prose about them.
  A server that declines and answers with a retry config has *negotiated* —
  `tls.ECHRejectionError`, a civil refusal in the sense `Kind.Abrupt()` already
  means — and it must never be graded as the peer choking on the hello.
  Shipped as `--ech-config BASE64` and a **pair** of profiles, `ech:off` and
  `ech:on`, both pinned to TLS 1.3. The pair is the item's real content: ECH
  requires 1.3, so a single ECH profile compared against plain `pq-preferred`
  would have differed in two things at once — exactly the mistake PQ-25 made and
  wrote down. Acceptance comes from `ConnectionState.ECHAccepted`, and the new
  kind `ech-reject` is not abrupt.
  Real numbers: `crypto.cloudflare.com` accepts it and the hello goes 1489 B →
  1661 B, **+172 bytes** on top of the ML-KEM key share; `github.com` declines
  the same config, `OK`, class untouched.
  Running it also turned up something no reading of the API would have shown:
  when a peer declines ECH, Go verifies its certificate against the config's
  *public name* before trusting the retry configs, and `InsecureSkipVerify` does
  not disable that path. An endpoint behind a private CA therefore answers with
  a verification error, which is the capability-versus-certificate confusion
  this repository exists to avoid — so it is classified as the same event, a
  declined ECH, and the error text says why. The offline test builds an
  ECHConfigList by hand, wire format and all, because there is no helper for it
  anywhere and being assertable offline is the bar every profile here clears.
  <!-- pq: prio=high size=M labels=profile,probe ver=unreleased -->

- [x] **PQ-51 — The config comes from DNS, not from a paste**: pasting base64 is
  not a fleet workflow, and the ECH config lives in the HTTPS resource record
  (type 65) of the name being probed. Go's resolver exposes no arbitrary record
  type, so this is a small DNS query written here — the same kind of lookup
  `--per-address` already performs, still no dependency and still not a request
  in the sense INTENT.md means. A name with no HTTPS record simply has no ECH to
  offer and that is stated, never graded; a record that does not parse is said
  in those words rather than silently becoming "ECH not accepted", which would
  blame the endpoint for our parser.
  Shipped as `--ech` and `--dns HOST:PORT`: a DNS client written here — query
  builder, answer walker with compression pointers, SvcParam parser — because
  Go's resolver exposes no arbitrary record type and this module has no
  dependencies. One lookup per **name**, not per target: a fleet behind one CDN
  resolves to the same record many times over, and asking per address would be a
  small flood nobody asked for. A truncated answer is retried over TCP, which is
  ordinary rather than exotic here: a record carrying an ECH config passes 512
  bytes easily, and half a record parsed as a whole one is a config that fails
  inside the handshake, where it reads as the endpoint's fault. Every answer
  record is scanned rather than only the one whose owner matches, because an
  answer routinely arrives as a CNAME plus the record for the canonical name —
  refusing that would mean no ECH for every endpoint behind a CDN, which is
  nearly every endpoint that has ECH at all.
  It also needed the run to stop assuming one profile set for the whole fleet:
  the config differs per endpoint, so `run` now takes the profiles *for a
  target*. The lookup happens once, before the run — a `--watch` that re-queried
  every tick would report a config rotation as an endpoint change, which is a
  different finding from the one it looks like.
  Verified against real DNS: `crypto.cloudflare.com` fetched and accepted,
  1489 B → 1661 B, the same +172 bytes the pasted config produced;
  `github.com` publishes none and says so once, keeping its ordinary profiles.
  <!-- pq: prio=med size=L labels=probe,inventory ver=unreleased -->

- [x] **PQ-52 — ECH does not decide the class**: it is findings and a hint, on
  the pattern `--per-group` established — no real client is ECH-only, so an
  endpoint that does not offer it must not fall into a worse bucket for a
  capability nobody requires yet. What the report gains is the sentence an
  operator needs: whether the browsers that *do* offer ECH still complete a
  handshake here, and how much of the MTU the combination is using. `explain`
  gains the vocabulary in the same commit, because the table-driven test refuses
  a finding nobody can look up.
  The grading half shipped with PQ-50 and is asserted there: the pair is held
  out of the classification, and an endpoint cut off with ECH keeps its class.
  What was left is the vocabulary, and it needed `explain` to stop being a
  dictionary of *classes* only — ECH is deliberately not one, so it had no entry
  to look up. `Topics()` and `ExplainTopic()` answer for the words a report uses
  and never grades (`ech`, `ech-reject`), the listing shows them, an unknown word
  prints both vocabularies, and a topic renders without a status because it has
  none — a grade is exactly what it is not. A test asserts no word is both.
  <!-- pq: prio=med size=S labels=verdict,output,docs ver=unreleased -->

## M8 — Reach the ports that are left <!-- ms: target=v0.36.0 phase=shipped -->

PQ-20 and PQ-45 established the pattern and the boundary: TLS reached through a
protocol's own negotiation, **only** the negotiation on the wire, and a peer
that will not upgrade graded `no-tls` rather than as a post-quantum failure.
What is left is the rest of the ports where a fleet's old TLS stacks actually
live — a directory server, a news or file transfer daemon, a chat server — none
of which any browser will ever visit, which is exactly why nobody has noticed
what their group lists look like.

- [x] **PQ-53 — The remaining line protocols**: `--starttls ftp` (`AUTH TLS`,
  RFC 4217) and `--starttls nntp` (`STARTTLS`, RFC 4642). Both are the SMTP
  shape — a coded greeting, one command, a coded answer — so the item is small
  by construction and the test server is the one that already exists. The two
  edges that are not SMTP: NNTP greets `200` *or* `201` depending on whether
  posting is allowed, and both are a healthy server, while FTP's refusal is a
  `5xx` that must arrive as `no-tls` and never as a grade.
  Shipped — and the "small by construction" premise was wrong in exactly one
  place, which running it found. FTP does **not** share SMTP's multi-line rule:
  RFC 959 marks continuation with a dash on the first line and then says nothing
  about the lines that follow, which carry banners and terms of use with no code
  at all. Reusing `expectSMTP` turned a real server's `220-Welcome` into "the
  server answered See https://…" — a refusal that never happened, on an endpoint
  that was fine, which is the precise failure mode this tool exists to avoid.
  `expectFTP` is its own reader now, bounded at 100 lines, and the test server
  speaks the real banner shape rather than the one the code expected.
  Verified against a real FTPS server: `pq-blind`.
  <!-- pq: prio=med size=S labels=probe ver=unreleased -->

- [x] **PQ-54 — LDAP StartTLS**: `--starttls ldap`, the extended operation of
  RFC 4511 §4.14 — a BER-encoded request carrying OID 1.3.6.1.4.1.1466.20037,
  and a response whose `resultCode` decides it. Not a line protocol, so it needs
  what MySQL needed: enough of the encoding to ask the question and read the
  answer, and nothing more. It earns its place because a directory server is the
  most likely thing in a fleet to be running a TLS stack nobody has touched in a
  decade, on a port no browser will ever complain about.
  A non-zero result code is `no-tls` with the server's own diagnostic message
  quoted, because "unwilling to perform" and "protocol error" send an operator
  to two different places.
  Shipped with just enough BER to ask and to read the answer — a length reader
  that refuses the long forms nobody uses here, and a field walker. No bind is
  sent, which is what would carry credentials. The first run hung both sides for
  five seconds: the request's outer length was written as a constant that had
  drifted from its contents by two bytes, so the test server waited for a
  message that had already arrived in full. The lengths are arithmetic now.
  <!-- pq: prio=med size=M labels=probe ver=unreleased -->

- [x] **PQ-55 — XMPP**: `--starttls xmpp`, the stream header and the
  `<starttls/>` of RFC 6120, on 5222. The `to=` attribute is the server name
  pqprobe is already sending as SNI, and a server that is a virtual host will
  answer differently without it — which is the same reason `1.2.3.4=origin`
  exists. `<failure/>`, or features without a `<starttls/>` element, is `no-tls`.
  Shipped by *scanning* for the elements that decide it rather than parsing:
  there is no XML document at this point, only the opening of one, and a parser
  waiting for a close tag that will never arrive is a hang rather than an
  answer. Bounded at 16 KB, on top of the deadline PQ-45 put on every plaintext
  negotiation. A target with no name to open a stream to is told to use the
  `address=name` form rather than being sent an empty `to=`.
  <!-- pq: prio=low size=M labels=probe ver=unreleased -->

## M9 — The edges of everyday use <!-- ms: target=v0.38.0 phase=shipped -->

Nothing here changes what pqprobe knows. These are the three places where the
tool as *used* — in a pipeline gate, at a shell prompt, against a resolver that
is not the machine's own — is narrower than what it can say.

- [x] **PQ-56 — `--exit-on` takes a class as well as a status**: today it takes
  a severity, so "fail the pipeline when an endpoint is `pq-intolerant`" has to
  be spelled as `--exit-on BAD` — which also fires on `pq-refusing`, on a
  certificate about to expire, and on anything BAD that ships later. A gate that
  fires for reasons its author did not choose is a gate somebody switches off.
  The two vocabularies are already distinguishable on sight and `explain`
  already answers for both, so one flag can take either; a word that is neither
  is a usage error listing both, exactly as `explain` does.
  Shipped. One decision the item had left open: a status is a *threshold* — at
  or above, as it always was — and a class is **exact**. Classes are not a
  scale, and letting `--exit-on pq-blind` fire on something worse would report
  two different findings under one name, which is the thing the flag was meant
  to stop.
  <!-- pq: prio=high size=S labels=cli,output ver=unreleased -->

- [x] **PQ-57 — Completions and a man page, generated**: `pqprobe completion
  bash|zsh|fish` and a `pqprobe.1`, both written from the *flag set* and the
  same help text the binary prints, never hand-maintained beside it. PQ-40 is
  the precedent and the reason: a flag documented in one place and declared in
  another drifts silently, and the two-way test that caught it only covers
  `--help`. A gate asserts every declared flag appears in every generated
  artefact, so a new flag cannot ship half-visible.
  Shipped as `pqprobe completion bash|zsh|fish` and `pqprobe man`, both written
  from `newProbeFlags()` and from `usageTo` — nothing is committed, so there is
  no artefact that can go stale between releases and no new gate script to wire.
  The test walks the FlagSet against all four outputs, and it corrected its own
  first assumption immediately: fish spells a long option `-l name`, not
  `--name`, so "every flag appears" had to be per-shell rather than one
  substring everywhere. The man page indents the help as a literal block rather
  than rewording it — a second wording is a second thing to keep true — with the
  two sequences roff reads as markup escaped. Verified by rendering it with
  `man` and by sourcing the bash and zsh scripts in their own shells.
  <!-- pq: prio=med size=M labels=cli,delivery,docs ver=unreleased -->

- [x] **PQ-58 — `--dns` governs every lookup pqprobe makes**: it was introduced
  for the ECH record (PQ-51) and governs only that, so `--per-address` still
  resolves through the machine's own resolver — a run that asked one resolver
  about ECH and another about addresses, and said nothing about the split. From
  inside a network where the interesting answer is the *internal* one, that is
  not a preference, it is a wrong answer. One resolver setting, used everywhere
  pqprobe asks a question, and stated in the report where it changes what was
  probed.
  Shipped: `probe.ResolverAt` — Go's own resolver rather than the system one,
  because the cgo path asks whatever the host is configured with and would
  ignore the flag — passed to `ExpandAddresses` *and* to the dialler through
  `net.Dialer.Resolver`, which is the half the item had not noticed: a target
  named rather than addressed is resolved by the dial, and without that field
  the flag would have governed everything except the connection it was set for.
  One `resolver` finding says which one answered. Verified: `--dns 1.1.1.1:53`
  resolves the fleet through it, and a dead resolver makes the dial itself fail
  rather than quietly falling back.
  <!-- pq: prio=med size=S labels=probe,inventory,cli ver=unreleased -->

## M10 — The hybrids we do not offer, proved against stacks that are not Go <!-- ms: target=v0.41.0 phase=shipped -->

Two halves of one problem, and the first was found by starting the second.
Every test in this repository stands on a Go listener, so the distinction the
whole tool rests on has never met OpenSSL, nginx or HAProxy — and the first real
container stood up showed pqprobe reporting a **fully post-quantum endpoint** as
`tls-broken`, because Go exposes three hybrid groups and pqprobe only ever
offers one.

```
X25519MLKEM768      4588 (0x11ec)   the one every profile offers
SecP256r1MLKEM768   4587 (0x11eb)   never offered, never named, never probed
SecP384r1MLKEM1024  4589 (0x11ed)   the same
```

- [x] **PQ-59 — The other two hybrids exist and we can negotiate them**: they go
  into `Probed` so `--per-group` dials them, into `GroupName` so a report can
  print them, and into `IsPQ` — which today would call a completed
  `SecP256r1MLKEM768` handshake *classical*, so even an endpoint that connected
  would be graded `pq-blind`. Verified against OpenSSL 3.5.8 configured with the
  P-256 hybrid alone: Go completes that handshake today, so this is a gap in
  what pqprobe *offers*, not a limitation of the language.
  What must not change is the browser answer: Chrome and Firefox offer
  X25519MLKEM768, so `pq-preferred` keeps offering exactly what they do. A peer
  that speaks only another hybrid is still unreachable *for them*, and a class
  that pretended otherwise would be the same lie in the other direction.
  Shipped, and it carried a decision the item had not stated: the constants
  exist only in **Go 1.26**, so the module now requires it — go.mod, both contrib
  modules, the Dockerfile, the CI and release pins, the README badge. Building
  on 1.25 would still have compiled with raw codepoints and produced a *different
  run*: the group would be advertised and never completed, which is precisely the
  toolchain-dependent answer this repository refuses everywhere else. The minimum
  is the version that implements them, not the one that accepts the number.
  The printed names are pinned in `GroupName` rather than taken from Go's
  `String()` — a test asserts the exact three, so what a report says cannot move
  under a compiler upgrade. Verified twice: offline against a listener whose only
  group is the P-256 hybrid, and against the OpenSSL 3.5.8 container that found
  this, where `--per-group` now reports `accepted: SecP256r1MLKEM768`.
  The class is still `tls-broken` there, which is PQ-60's job and deliberately
  not this one's.
  <!-- pq: prio=high size=M labels=profile,probe ver=unreleased -->

- [x] **PQ-60 — "post-quantum, in a group your clients do not offer"**: the
  sentence the report cannot say today. With PQ-59 the handshakes exist; this is
  the finding and the hint that turn them into an action — a `hybrid` finding
  naming which hybrids the peer accepts and which it refuses, an honest class
  for the peer that takes only the P-256 or P-384 one (today `tls-broken`, which
  says the port is faulty when it is fully capable and merely FIPS-shaped), and
  the `explain` vocabulary in the same commit.
  Shipped as the `hybrid` finding and the class `pq-other-hybrid` (BAD). The
  rule the item needed and did not have: the single-group probes may **soften**
  `tls-broken` and may never create a grade. No real client dials one group at a
  time — grading on that is how a peer gets called intolerant for declining
  P-521 — but they are evidence that a peer is not broken, and turning "the port
  is faulty" into "it is configured for somebody else" is the one thing they are
  allowed to do.
  Two shapes, both verified against real OpenSSL 3.5.8 containers: with only the
  P-256 hybrid the class moves from `tls-broken` to `pq-other-hybrid`, and with
  the realistic FIPS list (hybrid plus classical NIST curves) the class stays
  `pq-blind` — browsers do get a handshake — while the finding says the work is
  a group policy rather than switching post-quantum on, because it is already on.
  The verdict finding for the new class is BAD rather than the branch's usual
  ERROR: something *was* concluded, and ERROR is the bucket for endpoints that
  never answered. `tls-broken` also gained the pointer that would have prevented
  the whole confusion — run `--per-group` before believing it.
  <!-- pq: prio=high size=M labels=verdict,output,docs ver=unreleased -->

- [x] **PQ-61 — An interop lab, in CI, against stacks that are not Go**:
  containers standing up OpenSSL 3.5 `s_server` with each hybrid on its own,
  nginx, HAProxy and a listener that truncates the ClientHello, with pqprobe
  asserting the class each one deserves. Containers live in CI and in a script,
  never in `go.mod` and never in the binary — the zero-dependency property is
  about what ships, and this is what proves what ships is right.
  It earns its place by having already paid: the first container written found
  PQ-59. Every offline test in this repository asserts pqprobe against *Go's own
  TLS stack*, which means the alert-versus-reset distinction — the one thing the
  tool exists to get right — has never been checked against an implementation
  that does not share our bugs.
  Shipped as `scripts/interop.sh` with five cases, all green: OpenSSL 3.5 with
  hybrid plus classical (`pq-ready`), classical only (`pq-blind`), the P-256
  hybrid alone (`pq-other-hybrid`, the case that started this milestone), an
  OpenSSL with TLS 1.3 switched off (`no-tls13`), and nginx with a classical
  curve list (`pq-blind`). Wired to CI as its own job and to `release.sh`, where
  it **skips** without Docker — a maintainer's laptop is not a reason to block a
  release, and CI runs it either way; `gates_test.sh` was extended first and
  went red until both were wired.
  The harness itself provided the lesson: POSIX sh has no locals, and `ready()`
  assigned to a variable called `class`, quietly overwriting the expected class
  of the case being run. Four assertions compared a result against itself and
  reported failure while the tool had been right about all four — a reminder
  that a test harness is code, and that a red result is worth reading before it
  is believed.
  <!-- pq: prio=high size=XL labels=tests,probe ver=unreleased -->

## M11 — Reproduce the failures, not only the successes <!-- ms: target=v0.44.0 phase=shipped -->

The lab from PQ-61 proves the answers pqprobe gives when a handshake *works*.
The classes it exists for are the other ones — the wall, the refused upgrade,
the endpoint that wants a certificate — and every one of them is still asserted
against a Go listener with the condition planted by hand. This milestone points
the lab at the failures.

- [x] **PQ-62 — The wall, against a real server and a real packet filter**: an
  OpenSSL 3.5 behind `iptables -m length --length 1000:65535 -j DROP`, which is
  what a middlebox that cannot carry the second segment of a large ClientHello
  actually does to a connection. The classical hello (285 B) crosses, the hybrid
  one (1.5 KB) never arrives, and the class has to be `pq-intolerant` with the
  failure recorded as a timeout — reproduced on the second dial, since a wall is
  not a flap. `--size-sweep` in the same case brackets where the drop begins, so
  the number the report quotes is measured against a filter whose threshold is
  known.
  Proved by hand before the item was written: it lands exactly there.
  Shipped as two lab cases — the class, and the sweep that has to *find* the
  wall rather than merely be graded next to it — and the case table grew a fifth
  column for that second kind of assertion.
  The lab itself needed two fixes that had nothing to do with pqprobe and
  everything to do with honest testing. `openssl s_server` serves one connection
  at a time **and exits** on a client that completes a handshake and closes
  without reading its `-www` response, so every case after the first looked like
  a dead port; it runs in a restart loop now. And readiness was being asked from
  outside the container, where `docker run -p` publishes the port immediately —
  so "ready" answered within a second, while the image was still installing
  OpenSSL, and five servers came back `tls-broken` at once. Which is never what
  five different servers do: a result that uniform is a fault in the harness, and
  reading it that way is what found both bugs.
  <!-- pq: prio=high size=M labels=tests,probe ver=unreleased -->

- [x] **PQ-63 — The plaintext negotiations, against real daemons**: Postfix,
  Dovecot, OpenLDAP, MySQL and Postgres in the lab, because every `--starttls`
  protocol was written from an RFC and asserted against an in-process Go fake
  that agrees with our reading of it by construction. FTP already caught this
  the expensive way — a real server's banner turned a healthy endpoint into a
  refusal, and only running it against one found it. A daemon with TLS switched
  off is in the table too: `no-tls`, never a post-quantum verdict.
  Shipped: Postfix, Dovecot, OpenLDAP, MySQL and Postgres, plus a Postgres with
  TLS off asserting `no-tls`. Every negotiation written from an RFC now answers
  a daemon that was not written from our reading of it — the BER StartTLS
  request in particular, which until now had only been read by a fake that
  agreed with it by construction.
  Third-party daemons are asserted as `any-tls`, a new expectation meaning *the
  negotiation reached a handshake*: what is under test there is the upgrade, not
  the group list somebody's image ships with, and pinning that would turn an
  upstream improvement into a red build. The servers the lab configures itself
  keep exact classes.
  Two things the containers taught. Dovecot's greeting is **two lines**, the
  first a provisional `* OK Waiting for authentication process to respond..` —
  our reader takes the first `* OK` and the command queues behind it, which
  works, but no fake would have shown it. And Dovecot 2.4 rewrote its
  configuration schema entirely, so the case is pinned to 2.3: chasing a config
  format is not what this lab is for, and the IMAP on the wire is the same.
  <!-- pq: prio=high size=L labels=tests,probe ver=unreleased -->

- [x] **PQ-64 — The other terminators, and the certificate they ask for**:
  HAProxy and Envoy, which sit in front of more origins than nginx does, plus an
  OpenSSL with `-Verify` so `mtls-required` is asserted against a server that
  really does demand a client certificate. Today that class rests on
  `GetClientCertificate` firing in a Go handshake, and the TLS 1.2 leg of it —
  where the alert is indistinguishable from "no mutually supported group" — has
  never met a real implementation.
  Shipped, and the most valuable part was not the one the item named: Envoy is
  **BoringSSL**, so the alert-versus-reset distinction now holds across three
  independent TLS implementations rather than one plus OpenSSL. If it were a
  property of a library instead of a property of TLS, this is where it would
  have shown.
  Both mTLS legs are asserted. On TLS 1.3 the class stays `pq-ready` and the
  report owes the reader the `client-auth` finding — exactly what PQ-26 claimed
  and could only demonstrate against Go until now — so the case asserts the
  class *and* the finding. On TLS 1.2 the handshake fails and the class is
  `mtls-required`, which is the leg that had never met a real server.
  <!-- pq: prio=med size=M labels=tests,probe ver=unreleased -->

## M12 — What the audit found <!-- ms: target=v0.44.1 phase=shipped -->

One review of `internal/`, `cmd/` and `pq/` against no diff at all — the tree
was clean and every milestone shipped — looking for the failures the tests were
shaped not to see. Seven, and the same mistake three times.

- [x] **PQ-65 — Seven bugs, and one of them graded a healthy endpoint**: the
  audit's own list, fixed with a failing test in front of each.
  **A number derived from a hello that never went out**, three times over: a
  sweep step that failed before writing read as *no size limit found in the
  swept range*; the ALPN pair reported `Value: -1519` and a hint beginning
  "-1519 bytes of ALPN is the difference"; the ECH pair called the whole hello
  the cost of ECH. Zero is a real byte count, and using it as a sentinel is how
  a probe that never reached the wire turns into evidence. 0.29.2 had already
  fixed this once, for the case where *every* attempt wrote nothing — the mixed
  case survived it.
  **XMPP stopped reading at `<proceed`, mid-element.** With the tail in a later
  TCP segment those plaintext bytes were still in the socket when TLS started,
  `tls.Client` read them as a record header, and the kind was `record` — which
  is abrupt, which grades a healthy XMPP server `pq-intolerant`. Reproduced by
  splitting the element across two writes, and it is the worst of the seven:
  the tool's one job is to not say that.
  **The generated zsh completion overwrote zsh's own `words` array**, which *is*
  the command line being completed, so every branch that inspected it read the
  class list instead and none could match.
  **`--port` replaced an explicitly written `:443`**, so `--port 8443
  origin.example:443` probed an endpoint nobody named. The parser is the only
  place that still knows, so `Target.PortWritten` records it.
  **`pq.Probe` dropped unparseable targets** unless every one of them failed: an
  embedder's fleet check reported on nine nodes out of ten and looked complete.
  They arrive as reports with class `unreachable` now, like everything else that
  cannot be probed.
  <!-- pq: prio=high size=M labels=probe,verdict,cli,integration ver=unreleased -->

## M13 — Invariants a machine can check <!-- ms: target=v0.45.0 phase=shipped -->

The audit (PQ-65) found seven bugs in code that every gate called green, and
they had one shape: an invariant this repository states in prose, checked by a
test written by whoever wrote the code. Three of them were the *same* mistake in
three places, and one of them — a byte count derived from a hello that never
went out — had already been fixed once, in 0.29.2, for a neighbouring case.

A fuzzer and a property do not share the author's assumptions. Go has both in
the standard library, so this costs no dependency: `go test -fuzz` and a table
of invariants over generated inputs.

There is a second reason, and it is the one INTENT.md cares about: three of
these parsers read bytes **an endpoint chose** — a DNS answer, an LDAP response,
a MySQL greeting. A panic there is not a wrong answer, it is a monitoring tool
that dies halfway through somebody's fleet.

- [x] **PQ-66 — Fuzz the parsers that read what a peer sent**: the HTTPS/SVCB
  answer walker with its compression pointers, the BER reader, the MySQL
  greeting, the XMPP element reader. No panic, no unbounded read, no hang, and
  a seed corpus taken from the real captures already in the tests — the
  Cloudflare ECH record, slapd's response, MySQL 8.4's greeting. Wired into CI
  with a short run per parser, because a fuzz target nobody runs is a file.
  Shipped: five targets and `scripts/fuzz.sh`, which **discovers** them rather
  than listing them — a target added without a line somewhere would otherwise
  never run and nothing would say so. CI gives each 40s, `release.sh` 10s, and
  the seed corpus runs in every `go test`. About 15 million executions found no
  crash in these five, which is the answer the item was owed: the bounds checks
  hold.
  <!-- pq: prio=high size=M labels=tests,probe ver=unreleased -->

- [x] **PQ-67 — The verdict's invariants, as properties**: for *any* set of
  results — generated, not chosen — the class is one of `Classes()`, a
  post-quantum grade never appears without a working baseline, no finding
  carries a negative byte count or a number derived from an unsent hello, every
  finding with a `Value` has a `Unit`, the findings are sorted worst-first, and
  every class the evaluator can produce has an explanation. Every one of those
  sentences is already written in prose somewhere in this repository; three of
  them were false last week and no gate said so.
  Shipped, and it earned itself back in under a minute: it found `ech` reporting
  **-1 bytes** — inside the guard added the same day by PQ-65, which tested for
  a zero hello and not for a *negative difference*. ECH cannot make a hello
  smaller, so the pair is reported only when the difference is positive; the
  same correction went into the ALPN pair. The failing input is committed under
  `testdata/fuzz`, so it is a plain test case from now on and needs no fuzzer to
  reproduce. Twenty-three million executions later, clean.
  <!-- pq: prio=high size=M labels=tests,verdict ver=unreleased -->

- [x] **PQ-68 — Fuzz the target parser, and pin what it may never do**: the
  `?q=1` bug lives here — a query string contains an `=`, and reading it as a
  server name is a silently wrong probe. Fuzz `Parse` for panics, and assert the
  properties a target must satisfy however it was written: a port nobody wrote
  is never marked as written (PQ-65), an SNI is never taken from a path or a
  query, and a parsed target's address round-trips through `String`.
  Shipped, and three more bugs with it — one on its own seed list, two from the
  fuzzer.
  `origin.example:` split cleanly into a host and an **empty port**, so the run
  dialled `origin.example:` and failed with an error about an address rather
  than about the line somebody typed. `]:` became the host `]:` and the address
  `[]:]:443`, which nothing can dial and no message explained. And
  `origin.example=#0000` put `#0000` into the ClientHello as a server name: the
  same family as the `?q=1` bug, which the table case had fixed only for the URL
  form. All three are usage errors now, naming the word that caused them.
  <!-- pq: prio=med size=S labels=tests,inventory ver=unreleased -->

## M14 — The contract with machines <!-- ms: target=v0.48.0 phase=now -->

M13 pinned the invariants the tool owes *itself*. These are the ones it owes
everything downstream: checkfleet imports `pq/`, an aggregator deduplicates on
the finding `id`, a node exporter scrapes the textfile, a CI job reads
`--findings`. Not one of those shapes is asserted anywhere. Renaming a JSON
field, dropping a metric label or reordering a nested object passes every gate
in this repository and breaks a consumer silently — which is the same failure
mode PQ-65 found inside the tool, one layer out.

- [x] **PQ-69 — Golden files for every machine-facing output**: `--json`,
  `--findings`, `--findings=wrapped` and the Prometheus textfile, rendered from
  a fixed set of reports and compared byte for byte. A deliberate change updates
  the golden file in the same commit and shows up in the diff as what it is: a
  change to somebody else's parser. The fixture has to cover the shapes that
  actually vary — a healthy endpoint, an unreachable one, a finding with
  `value`/`unit`, one with a hint, a class that is not a grade.
  Shipped, with the markdown report in as well — it is pasted into a pull
  request by a machine, and its table structure is what a job summary renders.
  The fixture goes through `verdict.Evaluate` with a fixed clock rather than
  hand-writing findings, so the golden is a contract over the whole pipeline
  from results to document, not over a struct literal. Proved by renaming
  `tool` to `toolname` and watching it go red, because a gate nobody has seen
  fail is a gate nobody knows works.
  The rule is in AGENTS.md and CLAUDE.md now: a deliberate change is
  `-update` **in the same commit**, and the diff is the review.
  <!-- pq: prio=high size=M labels=output,tests ver=unreleased -->

- [ ] **PQ-70 — Say which contract a document speaks**: the JSON carries the
  tool version and nothing else a consumer can branch on, and the wrapped
  findings promise a *stable id* for deduplication without ever stating what it
  is computed from. A `schema` field with a number that only moves when the
  shape does, and one page — `docs/schema.md` — saying what each field means,
  what `id` is a fingerprint of (check plus target, deliberately not the
  message, or every morning is a new problem), and which parts are allowed to
  grow. Generated from the types where it can be, so it cannot drift.
  <!-- pq: prio=high size=M labels=output,docs,integration -->

- [ ] **PQ-71 — The public API can ask what the CLI can ask**: `pq.Options`
  carries profiles, timeout, ALPN, SOCKS5, concurrency, expiry thresholds and
  `Net` — and cannot reach a mail server, because `--starttls` never made it
  across. Nor `--per-group`, `--size-sweep` or ECH. An embedder that wants the
  answer for port 587 has to shell out to the binary, which is the thing `pq/`
  exists to avoid. Whatever is added arrives with the same rule the CLI has: an
  unknown value is an error, never a quietly different run.
  <!-- pq: prio=med size=M labels=integration -->
