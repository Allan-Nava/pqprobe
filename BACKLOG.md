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

## M6 — Reach the rest of the fleet <!-- ms: target=v0.30.0 phase=now -->

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

- [ ] **PQ-47 — A prober with no route says it once**: PQ-12 already refuses to
  call an unroutable address `tls-broken`, which was the dangerous half. The
  half left over is volume — a workstation without IPv6 egress produces one
  `unroutable` per AAAA record across the whole fleet, and forty findings that
  are all the same local fact bury the one finding that is about an endpoint. A
  preflight that establishes what this prober can reach at all, reported once as
  a run-level note, and the per-target results attributed to it rather than
  repeated. It is not a new judgement: it is the existing one, said once and in
  the right place. The test plants a family with no route and asserts both that
  the note appears and that no endpoint is graded on it.
  <!-- pq: prio=med size=M labels=probe,verdict,output -->

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

- [ ] **PQ-48 — Targets on stdin**: `pqprobe -` reads the target list from the
  pipe, in the same forms `--inventory` already accepts. The fleet that needs
  probing is usually the output of something else — a `dig`, a Consul query, an
  `awk` over a config — and today that has to become a temporary file first,
  which is the step people skip, which is how a stale list gets probed. Small,
  but it is the difference between composing with the tools around it and being
  a destination. `-` is a target name nobody has, and everything downstream —
  parsing, `--per-address`, the renderers — is unchanged.
  <!-- pq: prio=low size=S labels=inventory,ux -->
