# Changelog

All notable changes to pqprobe are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versioning is
[Semantic Versioning](https://semver.org/). Every release is a tagged `vX.Y.Z`
with its own section; `minor` for new profiles, checks or flags, `patch` for
fixes. Items reference their `PQ-n` id in [BACKLOG.md](BACKLOG.md).

## [0.25.1] - 2026-09-04

### Fixed

- **`backlog_issues_test.sh` never ran in a release** (PQ-40) — CI ran it and
  `scripts/release.sh` did not, so every local release skipped the issue
  planner's tests. Nothing announces a gate that runs in one place and not the
  other: it simply passes wherever it is missing.

### Added

- **Two gates for the mistake that keeps happening** (PQ-40) — a scripted edit
  whose anchor no longer matches is written back unchanged, *silently*, and
  everything downstream believes it landed. It has happened three times here;
  once `--watch` shipped with its loop never called, and only running the binary
  found it.

  `scripts/gates_test.sh` asserts every gate script and every `*_test.sh` is
  wired to **both** CI and `scripts/release.sh`. It found the bug above, and
  then found itself unwired, which is the best first day a gate can have.

  A two-way test in `cmd/pqprobe/main_test.go` walks the probe's `FlagSet`
  against `--help`: a flag declared and not documented, or documented and not
  declared, now fails. Proved by planting `--undocumented-on-purpose` and
  watching it go red. The flags moved into one `newProbeFlags`, which is what
  makes them enumerable — the same lesson as every other testability seam in
  this repo.

  The trap is written into `AGENTS.md`, because the durable fix is not a gate:
  assert the anchor, re-read a file a formatter may have touched, and run the
  feature rather than trusting the diff.

## [0.25.0] - 2026-09-04

### Added

- **A real browser ClientHello** (PQ-10) — [contrib/utls](contrib/utls): a
  module of its own, with its own `go.mod`, its own `go.sum` and its own binary
  `pqprobe-utls`. Chrome 131's hello is **1721 bytes** and negotiates ML-KEM
  against `example.com`; Firefox 120's is 659 and does not. That is the question
  the capability classes deliberately refuse to answer, and it now has a home
  that costs the default binary nothing.

  A build tag would not have been enough, which is why this moved out of M2:
  uTLS is a dependency, so `go.mod` would carry a `require` and CI fails the
  build on exactly that. The nested module has a **relative** replace on the
  root, so it always builds from the checkout instead of waiting for a version
  to be published, and `scripts/contrib_test.sh` keeps the arrangement honest —
  no `require` in the root `go.mod`, no root `go.sum`, no root package importing
  uTLS, and `go list ./...` not reaching into contrib. CI builds and tests it in
  a job of its own, so somebody else's dependency can never fail the build of
  the binary that has none.

  It does not judge: whether a failure was a civil refusal or the peer choking
  on the hello comes from `pq.Classify`, exposed for exactly this. Two copies of
  that distinction is one copy too many.

- **`pq.Classify`** (PQ-10) — the alert-versus-abrupt judgement, available to an
  embedder that dials with its own TLS stack.

### Fixed

- **The classifier missed two of Go's own refusal strings** (PQ-10) — the brief
  quoted "no mutually supported group" as the canonical case caught by string.
  That string does not exist in Go: the real ones are `no mutually supported
  protocol versions` and `tls: server selected unsupported group`, read out of
  the toolchain source rather than remembered, and neither was in the list. Both
  are locally generated refusals, so both are civil — they classify as `alert`
  now instead of `other`, and the brief quotes what Go actually says.
- **A uTLS preset that fails against everything no longer blames the endpoint**
  (PQ-10) — `HelloSafari_16_0` and `HelloIOS_14` cannot verify a modern server's
  handshake signature, against *any* server including a local listener. Found by
  running the tool. Those failures are flagged `Local` and rendered `SKIP` with a
  note saying they say nothing about this endpoint; reporting "example.com
  refuses Safari" would have been the exact mistake this toolchain exists to
  avoid.

## [0.24.0] - 2026-09-04

### Added

- **Ports that are not 443** (PQ-20) — `--starttls smtp|imap|postgres` reaches
  TLS through the protocol's own negotiation. Implicit TLS never needed anything
  (465, 993 and 6514 already worked), so the missing half was this one:
  `smtp.gmail.com:587` comes back **pq-ready**, verified live, and the mutual-TLS
  note from PQ-26 correctly points out that Gmail asks for a client certificate.

  What goes on the wire is stated exactly, in the help, the docs and
  `INTENT.md`: a greeting is read, then `EHLO` and `STARTTLS`, or `a1 STARTTLS`,
  or Postgres's eight-byte `SSLRequest`. No mail, no query, no credential. That
  is the line — without the negotiation these ports cannot be probed at all, and
  with anything more this would be a different tool, so the promise in INTENT.md
  gained the clause rather than being left approximately true.

  A peer that will not upgrade gets the new class **`no-tls`** with an `ERROR`,
  never `pq-intolerant`: a relay with TLS switched off has refused *TLS*, and
  grading that as a post-quantum failure would send somebody hunting a middlebox
  that does not exist. The table-driven test from PQ-28 refused to let the class
  exist without an explanation, which is exactly what it was written for.

  MySQL is deliberately not included: its upgrade rides the connection-phase
  packet format rather than a line protocol, so it earns its own item instead of
  a footnote.

## [0.23.0] - 2026-09-04

### Changed

- **M3 — Fit the toolchain is complete** (PQ-14 … PQ-17, PQ-21, PQ-29 … PQ-33,
  PQ-36): the checkfleet module, the Prometheus textfile output, the release
  pipeline, Homebrew and the published image, the docs site and its SEO, the
  About box as data, the issue sync, the intent document, and "every commit is a
  version".

  The last item was PQ-14, and it shipped in **checkfleet v1.30.0** as
  `checks.pq` (CF-187 there), importing this repository's `pq/` package. It
  reimplements nothing: the alert-versus-reset classification stays in one
  place, which is the only reason the module was worth having rather than a
  second copy that goes quietly wrong. A fleet already described in
  `checkfleet.yml` gains the check without a second inventory.

  Three milestones of five are now closed (M1, M2, M3, M5 — four), and what is
  left in M4 is `ongoing` by construction: uTLS and QUIC each need a separate
  module to keep this binary dependency-free, ML-DSA needs something to probe,
  and the non-HTTPS ports are a capability rather than a refinement.

## [0.22.0] - 2026-09-03

### Added

- **A public surface for embedders** (PQ-39) — [pq/](pq/pq.go): `Probe`,
  `Classes`, `Explain`, `Describe`. Strings in, reports out, and nothing
  internal leaking through it, so the packages that do the work stay free to
  move.

  It exists because PQ-14 (the checkfleet module) turned out to be impossible as
  written: every package here is under `internal/`, which no other module may
  import, so the only alternatives were duplicating the alert-versus-reset
  classification inside checkfleet — the one thing in this tool that must live
  in exactly one place — or exposing a surface. This is the surface.

  Two contract decisions, both asserted: an **unreachable target is a report**
  with class `unreachable`, never an error, because a fleet check has to keep
  going and name the node that is down — an error is only ever something the
  caller got wrong (no targets, an unknown profile, nothing parseable); and
  findings carry `Value`/`Unit`, so an embedder never parses `Message`.

### Fixed

- **The zero-dependency gates only looked at `cmd` and `internal`** (PQ-39) —
  both the CI check and `scripts/release.sh` named those two directories, so the
  new public package would have slipped past the `net/http`/`os/exec` grep and
  the gofmt check. Widened in the same commit that created the hole.

## [0.21.0] - 2026-09-03

### Added

- **`--findings=wrapped`** (PQ-37) — the shape a fleet aggregator actually
  consumes: `{check, status, summary, findings:[{id, severity, title, detail}]}`
  with lowercase severities. The flat array is untouched, so `--findings` keeps
  behaving exactly as it did and no existing caller changes; the flag answers to
  both because it implements `IsBoolFlag`, which is also why the shape needs the
  `=` rather than a space.

  The **id** is the whole point, and it is a fingerprint of the check and the
  target — never of the message. Days-to-expiry and byte counts move on their
  own, so an id derived from the text would report a new problem every morning,
  which is the opposite of what an aggregator wants; a test pins that by
  changing the message and asserting the id does not move. Two findings of one
  check on one target in a single run get a suffix instead of colliding.

### Fixed

- **The README promised interoperability that did not exist** (PQ-37) — it
  called the flat array "the flat findings array the sibling tools speak" while
  the aggregator that reads it wanted the wrapped object, so every consumer
  translated. Both shapes now exist and the README says which is which, rather
  than one line covering for the gap.

## [0.20.0] - 2026-09-03

### Added

- **`pqprobe version --short`** (PQ-38) — the version alone, `0.20.0`, for a
  generated header or a Docker tag. The bare command still prints `pqprobe
  0.20.0`, because that is what a person running it wants and changing it would
  break anybody parsing it today; what was broken is that the *only* form
  printed the name twice when embedded: `pqprobe pqprobe 0.19.1`.

### Fixed

- **`version` ignored its flags** (PQ-38) — `version --help` printed the version
  and said nothing about what the subcommand accepts, and a typo did the same,
  which is how a typo survives into a script. `--help` now describes it and an
  unknown flag exits 2 naming the real one.

## [0.19.1] - 2026-09-03

### Changed

- **`ux` is a label, and `medium` is not a priority** — PQ-37 and PQ-38 arrived
  with `prio=medium` (the vocabulary is `high|med|low`) and `labels=…,ux`, which
  the linter rejected and so blocked the release. `ux` was clearly deliberate —
  "how the tool reads and embeds" is not `cli` and not `docs` — so it joins the
  vocabulary properly: one entry in `scripts/backlog.sh`, which the label gate
  then required a colour and a description for, and a line in the backlog's own
  how-to. `prio` was corrected to `med` rather than the vocabulary widened: a
  fourth spelling of three priorities is how a filter starts missing items.
- **graphify wired into this repository** — `graphify claude install` (a
  `PreToolUse` hook in [.claude/settings.json](.claude/settings.json) plus a
  section in `CLAUDE.md`) and `graphify hook install` (post-commit and
  post-checkout git hooks, local to the clone). The graph is built with
  `graphify update .`: 568 nodes, 1338 edges, 57 communities, AST-only, no API
  key and no cost. The most connected node is `verdict.Evaluate` at 49 edges,
  which is the right answer for this tool.

  Three deliberate decisions, since each one is the kind that gets undone by
  somebody tidying up:
  - `graphify-out/` is **gitignored**, as in the sibling repos: it is derived
    from the sources and rebuilt by a command.
  - The `graphify` section lives in `CLAUDE.md` and **not** in `AGENTS.md`, so
    the brief stays tool-neutral. Because this repository's own rule says
    CLAUDE.md is a copy of AGENTS.md and a divergence means AGENTS.md wins, the
    section says in as many words that it is the exception — otherwise the next
    reader "fixes" it by deleting the only documentation of the graph.
  - `.gitattributes` was dropped: `graphify hook install` writes a
    `graphify-out/graph.json merge=graphify` line, and with the directory
    ignored that attribute has nothing to apply to.

  Not a CI gate, and not going to be: that would make graphify a build
  dependency of a project whose entire argument is having none.

## [0.19.0] - 2026-09-03

### Added

- **Prometheus textfile output** (PQ-15) — `--textfile
  /var/lib/node_exporter/pqprobe.prom` writes eight families: the class as a
  label, the severity as a number so an alert is `pqprobe_status > 1`, findings
  per status, `pqprobe_cert_expiry_days` taken from the finding rather than
  recomputed, `pqprobe_handshake_ok` and the measured `pqprobe_hello_bytes` per
  profile, and `pqprobe_last_run_timestamp_seconds` — alert on that one too,
  because a probe that silently stopped running looks exactly like a fleet that
  is fine.

  The file is written to a temporary file in the same directory and renamed over
  the target, and that is the first thing the tests assert rather than the
  metric names: the collector reads whatever is in the file when it scrapes,
  including half of it, and an old run's series left behind would report one
  target as two classes at once. It is a side output rather than a renderer, so
  it combines with `--json`, `--markdown` or plain text, and is rewritten on
  every `--watch` tick.

  Label values go through Go's `%q`, which is exactly Prometheus escaping for
  the three characters that matter — the first version escaped them itself and
  then handed the result to `%q`, escaping everything twice. A target is a
  string somebody else chose, so the test uses one with a quote and a backslash
  in it.

## [0.18.1] - 2026-09-03

### Changed

- **M2 — Say it more precisely is complete** (PQ-9, PQ-11, PQ-12, PQ-13,
  PQ-34): HelloRetryRequest and the measured ClientHello size, the size sweep,
  every address behind a name, watch mode, and an ad-hoc `--groups` capability
  class. Target recorded as the release that finished it rather than the one it
  was aimed at eighteen versions ago.
- **PQ-10 (real ClientHello shapes with uTLS) moved to M4** — with the reason
  written into the item, because "behind a build tag" is not enough and finding
  that out at implementation time would cost a day. uTLS is a dependency: it
  would put a `require` in `go.mod`, and CI fails the build on exactly that,
  because the zero-dependency binary is a product property in `INTENT.md` and
  not an aesthetic. The only shape that keeps it is a **separate module**
  (`contrib/utls/` with its own `go.mod`), invisible to the root module and its
  gates — which is also why it is XL: the work is mapping capability classes
  onto fingerprints without letting the default binary imply it sends them.

  M2 therefore closes on the five items that *are* the milestone. Claiming a
  sixth by quietly reinterpreting it would have been the other way to reach
  100%.

## [0.18.0] - 2026-09-03

### Added

- **Watch mode** (PQ-13) — `--watch 30s` re-probes on an interval and prints
  only what moved, reusing the transition diff `--baseline` already built. The
  first report goes out in full, because you have to know the state you are
  watching from; after that a quiet tick prints **nothing at all**, since the
  window this exists for — a CDN or a load balancer being changed — is one where
  a screen of unchanged endpoints hides the line that matters.

  Two refusals instead of surprises: the interval has a **5s floor**, because it
  is a rate against somebody's production endpoint and `--watch 100ms` is a typo
  rather than an intention; and `--watch` with `--json`, `--findings` or
  `--markdown` is a usage error, because a stream of documents is not a document
  and being told now beats finding out halfway through a pipe. Ctrl-C stops it
  cleanly and exits **0** — the probe ran, which is the contract everywhere else
  in this tool.

## [0.17.0] - 2026-09-03

### Added

- **The SEO gate refuses a sitemap URL with nothing behind it** (PQ-36) — found
  while porting `scripts/seo.sh` to segcheck, where the first sitemap listed
  `running-in-containers.html` and GitHub Pages serves `docs/` exactly as
  committed: the `.md` answers 200 and the `.html` 404s. A declared URL that
  does not exist wastes crawl budget on every crawl, which is the same reason
  the host root only lists sitemaps that answer 200. pqprobe's sitemap holds one
  URL today, so nothing was broken here — the gate is in so the second one
  cannot arrive broken.

## [0.16.1] - 2026-09-03

### Fixed

- **The note about `robots.txt` on GitHub Pages was wrong** (PQ-36) — 0.16.0
  said a project page's `robots.txt` "is read by nobody" and only becomes
  correct on a custom domain. Half right, and the wrong half is the useful half.
  Crawlers do read only the **host root's** — `https://allan-nava.github.io/robots.txt`
  — but that host belongs to `Allan-Nava.github.io`, which already generates its
  per-project `Sitemap:` lines from a daily sync (`robots-sync.yml`) that
  enumerates the owner's non-fork repos with Pages enabled and keeps the ones
  whose `/<repo>/sitemap.xml` answers **200**. No list to maintain, nothing to
  declare.

  So the actual rule is the opposite of "wait for a custom domain": **ship a
  sitemap that answers 200 and the host root picks it up by itself** — which is
  why 28 of that owner's live Pages sites are missing from it, pqprobe among
  them until 0.16.0. Verified rather than assumed: the site, its sitemap and its
  `llms.txt` all answer 200, and the host root currently lists `checkfleet` and
  `Hugo-TuttoCampo`. Corrected in `scripts/seo.sh`, the generated `robots.txt`
  header and the backlog item.

## [0.16.0] - 2026-09-02

### Added

- **SEO for the published page** (PQ-36) — the crawler-facing half of the site,
  generated from the page rather than maintained beside it: `sitemap.xml`,
  `robots.txt`, and an [llms.txt](docs/llms.txt) for the crawlers that read
  prose rather than markup. In the page: `robots`, `theme-color` and
  `og:locale` meta, `og:image:alt`, a JSON-LD `SoftwareApplication` graph with
  its author and site, and width/height on the external badges so they cannot
  shift the hero as they arrive — layout shift is a ranking factor and the
  badges are the only external requests on the page.

  `scripts/seo.sh check` is a CI gate, because every failure here is silent: a
  canonical that drifted from the About box, a sitemap naming last month's URL,
  a JSON-LD block truncated by an edit. Nothing renders differently and the page
  quietly stops being found. Two things stated rather than glossed: the classes
  table is **not** marked up as an `FAQPage` — it is documentation, and claiming
  otherwise to chase a rich result would be a claim about the content that is not
  true — and `robots.txt` on a GitHub *project* page is read by nobody, since
  crawlers only fetch the domain root's, which belongs to another repository. It
  ships because it costs nothing and becomes correct on a custom domain.

### Fixed

- **The GitHub Action failed to load** (PQ-27) — with `An expression was
  expected`, because GitHub evaluates `${{ … }}` anywhere in a `run` string
  **including inside a shell comment**, and the comment explaining that inputs
  must not travel through an expression was itself an empty one. Neither
  `bash -n` nor actionlint caught it: actionlint reads workflows, not action
  metadata. There is now `scripts/action.sh check` with seven fixture tests,
  enforcing exactly the rule that comment was trying to state — no expression
  inside a run block, ever — so the day somebody writes the explanation again it
  cannot break the file. CI validates the action before using it.

## [0.15.0] - 2026-09-02

### Added

- **Egress through a SOCKS5 proxy** (PQ-35) — `--socks5 HOST:PORT` reaches every
  endpoint through a no-auth SOCKS5 proxy (RFC 1928), which from many networks
  is the only way out. SOCKS5 and nothing else: HTTP `CONNECT` is a *request*,
  and sending one would trade away the property that makes this binary safe to
  point at production, so the flag is named after what it supports rather than
  disappointing you later. No authentication either — pqprobe holds no
  credentials by design, and a proxy that wants some says exactly that.

  The host name is sent **unresolved** so the proxy resolves it, because inside
  a network that is frequently the only place it can be resolved; combining
  `--per-address` with `--socks5` prints a warning, since the former resolves
  here. A failure at the proxy is the new `proxy` kind and is **never** abrupt,
  asserted by a test against a fake proxy that wants credentials, refuses, or is
  not there: reading any of those as abrupt would file somebody else's endpoint
  as `pq-intolerant` for a fault on this side.

### Changed

- **M5 — Make the verdict actionable is complete** (PQ-22 … PQ-28, PQ-35): the
  per-group map, confirmation before condemning, the baseline diff, ALPN as a
  variable, mutual TLS told apart from a refusal, pull-request delivery,
  `explain`, and proxy egress.

## [0.14.0] - 2026-09-02

### Added

- **Pull-request delivery** (PQ-27) — `--markdown` renders the run as a table,
  worst endpoint first, with each endpoint's findings in a collapsible
  `<details>` block: the same findings, the same order and the same
  `--min-severity` as every other renderer, with no colour, because a comment
  carrying terminal escapes would be unreadable in the one place this format
  exists for. An empty run says so in a sentence rather than printing an empty
  table.
- **A GitHub Action** (PQ-27) — [action.yml](action.yml), composite: it installs
  the binary with the runner's Go toolchain (no image to pull), writes the
  markdown report to the job summary, exposes the findings array as the
  `findings` output and fails the step only on `exit-on`. Its inputs reach the
  shell through the environment, never through `${{ }}` inside the script. CI
  runs `uses: ./` against the commit under test, because an action nobody
  exercises is a file that used to work.

## [0.13.0] - 2026-09-02

### Added

- **`pqprobe explain <class>`** (PQ-28) — what a class means, which real clients
  it affects and what to do next, with **no network call**: runnable while the
  incident is still on, which is the point, since the hints otherwise exist only
  inside a run and finding out what the word meant would mean reproducing the
  failure. No argument lists every class; a leading `--` is tolerated because
  that is what a hand types; an unknown word prints the vocabulary and exits 2.
  A table-driven test asserts every class has an explanation whose status agrees
  with the grading table, so a class added later cannot arrive without one.

## [0.12.0] - 2026-09-02

### Added

- **An ad-hoc capability class** (PQ-34) — `--groups X25519MLKEM768,X25519`
  dials exactly that set, in that order, with the same version window as
  `pq-preferred` so the two results are comparable. It shows up as
  `custom:X25519MLKEM768+X25519` with its own handshake finding — the caller
  asked for that dial — and it does not decide the class, because a set somebody
  described is a question, not a baseline. Group names are the ones reports
  print, case-insensitive and round-tripped by a test, and an unknown name is a
  usage error listing the known ones rather than a silently smaller set: a run
  that quietly dropped a group would prove something other than what was asked.

## [0.11.0] - 2026-09-02

### Added

- **ALPN as a variable** (PQ-25) — `--alpn-check` dials the same client a second
  time carrying `h2,http/1.1`, the list a browser or CDN actually sends, and one
  `alpn` finding compares the two with both measured hello sizes: `ALPN makes no
  difference (1495 B against 1513 B)`, or `the same client connects without ALPN
  and is refused with h2,http/1.1`. Eighteen bytes is nothing unless the peer has
  a threshold in between — and then every browser and every CDN fails while a
  bare probe keeps calling the endpoint healthy, which without the pair reads as
  a flap.

  The two profiles are identical apart from the ALPN list, and a test keeps them
  that way. The first version of the probe pinned TLS 1.3 while its pair allows
  1.2, so it offered fewer cipher suites and sent a *smaller* hello — a
  comparison of two variables, which is a comparison of nothing. The offline
  test caught it.

## [0.10.0] - 2026-09-02

### Added

- **ClientHello size sweep** (PQ-11) — `--size-sweep` grows the hybrid hello
  through 2048, 3072, 4096, 6144, 8192 and 12288 bytes, stops at the first size
  the peer will not answer, and reports the bracket in one `size-limit` finding:
  `answered up to 3080 B and stopped answering at 4100 B`. Both numbers are
  measured on the wire, because a number taken to a vendor has to be the one
  that was actually sent. `example.com` answers 12261 B; the sweep says so
  rather than guessing.

  The padding is ALPN entries — the only field Go lets a client grow, since
  there is no padding extension and the TLS 1.3 cipher list is fixed — and the
  finding states that, because a peer that inspects ALPN may treat such a hello
  differently from one made large by a key share. Asserted offline against a
  listener that serves TLS below a size limit and vanishes above it. The sweep
  never touches the class: a padded hello asks how big is too big, which is not
  whether a realistic client can connect.

## [0.9.0] - 2026-09-02

### Added

- **HelloRetryRequest, and the ClientHello size** (PQ-9) — every successful
  handshake now reports the size of the hello it sent, measured on the wire:
  `hello 272 B` for the classical profile against `hello 1495 B` for the hybrid
  one, on real endpoints. That gap is the reason this tool exists, and it is now
  a number rather than a claim. A handshake that says `after a hello retry` cost
  an extra round trip.

  It needed neither `KeyLogWriter` nor a hand-parsed ServerHello, which is what
  the item assumed: an HRR is precisely the case where *pqprobe* sends a second
  ClientHello, so a small wrapper that reads the record header of our own
  outgoing bytes counts them, and measures the first one for free. The test's
  first run also corrected what the finding means — Go sends key shares for the
  hybrid group **and** X25519, so falling back to X25519 costs no retry; an HRR
  means the only group in common was a third one, usually P-256 or P-384 on an
  older or policy-restricted stack.

## [0.8.1] - 2026-09-02

### Changed

- **Planned work, not shipped work**: `PQ-34` (an ad-hoc `--groups` capability
  class) and `PQ-35` (egress through SOCKS5 only — HTTP `CONNECT` is a request
  and stays out) are now in [BACKLOG.md](BACKLOG.md), and `PQ-9` says that the
  cost of going hybrid belongs with the HelloRetryRequest work rather than in an
  item of its own: a finding that graded latency alone would be a performance
  check, which is a different tool. No behaviour changed — this section exists
  because a commit here is a version, and the dated history of what got planned
  is worth as much as the history of what got built.

## [0.8.0] - 2026-09-02

### Added

- **Baseline diff** (PQ-24) — `--baseline yesterday.json` compares this run
  against a stored `--json` run and reports the **transitions**: a regression
  graded by the class it fell to (`pq-ready → pq-intolerant`), an improvement
  stated quietly, and an endpoint that appeared or vanished named. An endpoint
  that has not changed produces nothing at all — an endpoint broken yesterday is
  not today's news, and a diff that always has something in it is a diff nobody
  reads. A baseline that is not a pqprobe `--json` document is an error, not an
  empty comparison: one that silently parsed as nothing would report "no
  changes" for ever. Running it also showed that a transition for a *vanished*
  endpoint has no report of its own to be printed under, so it names itself
  rather than reading as a statement about whichever endpoint it was filed with.

## [0.7.0] - 2026-09-02

### Added

- **Probe every address behind a name** (PQ-12) — `--per-address` resolves each
  name and dials every A/AAAA record by address, with the name still travelling
  as the SNI (the `1.2.3.4=origin.example` form, applied automatically). One
  `addresses` finding per name says whether the pool agrees and names the node
  that does not: `7 addresses disagree: 6 pq-ready, 1 unreachable`. One bad
  stack out of six is invisible to a name-only probe, which hits whichever
  address the resolver felt like handing over. A name that does not resolve
  keeps its target, so no endpoint silently disappears from a fleet report.

### Fixed

- **An address with no route was reported as a broken endpoint** (PQ-12) —
  found by running `--per-address` from a host without IPv6 egress: the AAAA
  records were classified `other`, which the verdict read as `tls-broken`, "the
  port answered but no client profile completed a handshake". The port never
  answered. There is now a `unroutable` kind that grades as `unreachable`, and
  the hints on both the verdict and the pool finding offer the local route as
  the first explanation instead of advising somebody to drain a node they simply
  cannot reach.

## [0.6.0] - 2026-09-02

### Added

- **Mutual TLS is told apart from a refusal** (PQ-26) — the peer's
  `CertificateRequest` is recorded during the handshake (via
  `GetClientCertificate`, which changes nothing about it and still holds no key
  material), and reported as a `client-auth` finding. A new `mtls-required`
  class covers the case where the certificate request is what broke every
  profile: the endpoint refused *pqprobe*, not post-quantum clients, so it gets
  an ERROR and no capability verdict.

  The item's premise turned out to be wrong, and the tests are what showed it:
  on **TLS 1.3** a mutual-TLS origin does not fail at all — the objection
  arrives after the client's Finished and pqprobe never reads — so the class was
  never mistaken there. What was missing was the note that keeps `pq-ready` from
  being read as "usable". On **TLS 1.2**, where client auth happens inside the
  handshake, the alert is indistinguishable from "no mutually supported group"
  by its text alone, and the recorded request is the only thing that tells them
  apart.

## [0.5.0] - 2026-09-02

### Added

- **Confirm before condemning** (PQ-23) — an abrupt failure is now dialled a
  second time before the class is assigned, because `pq-intolerant` is the
  finding somebody takes to a CDN vendor and one reset is also what a stale
  connection-tracking entry, a load balancer mid-reconfiguration or a node being
  drained looks like. Three outcomes, three different readings: both dials cut
  off is `no handshake (reset) — twice` with *reproduced on a second dial* in the
  verdict hint; cut off and then connected is a WARN saying *only on the second
  attempt* and names the state — **flapping, not walled** — while the class is
  still decided by the handshake that worked; and an alert is never re-dialled,
  because it is an answer the peer chose to give. So a healthy fleet pays no
  extra connections at all. `--confirm=false` dials once. The results carry
  `attempts`, `first_kind`, `reproduced` and `flapped` in `--json`.

## [0.4.0] - 2026-09-02

### Added

- **Homebrew** (PQ-33) — `brew tap allan-nava/pqprobe
  https://github.com/Allan-Nava/pqprobe && brew install pqprobe`. The tap is
  this repository: [Formula/pqprobe.rb](Formula/pqprobe.rb) is generated by
  `scripts/brew.sh` inside the release commit, so there is no second repository
  to keep in step and no token for a bot to push with — and no bot commit, which
  could not be a version. The formula clones the tag and builds from source, one
  formula for macOS and Linux on Intel and ARM, with Go as the only build
  dependency; a tarball would have needed a `sha256` that cannot exist while
  rendering the file the tag will point at. `scripts/brew.sh check` is a CI
  gate: `brew install` reads whatever the formula says, so one left at the
  previous version installs the old binary and looks like it worked.

### Fixed

- **The published image was documented nowhere** (PQ-33) — every release since
  0.2.0 pushes `ghcr.io/allan-nava/pqprobe` multi-arch with a provenance
  attestation and smoke-tests it after the push, while the install pages said
  `docker build` and never `docker pull`. README, `docs/install.md` and the site
  now give the pull, with a note to pin the version for anything scheduled.

## [0.3.0] - 2026-09-02

### Added

- **Per-group capability map** (PQ-22) — `--per-group` dials each key exchange
  group on its own (X25519MLKEM768, X25519, P-256, P-384, P-521, pinned to TLS
  1.3 because that is where `key_share` lives) and reports the accepted set in
  one `groups` finding: `accepted: X25519, P-256 · declined with an alert:
  X25519MLKEM768, P-384, P-521`. It answers *which* group a migration can be
  planned against instead of "some hybrid handshake worked". One handshake per
  group, in sequence, and no request — as ever.

  It is a **report, not a grade**: the single-group profiles are held out of the
  classification, because no real client offers one group and a peer that
  declines P-521 is not intolerant. They also emit one finding rather than five
  handshake findings, which would have buried the three that carry the answer.
  The alert-versus-cut-off distinction survives inside the map, where on the
  hybrid group it is a size symptom.

## [0.2.0] - 2026-09-02

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
- **Every commit is a version** (PQ-32) — the house rule, now enforceable:
  a commit lands with its own dated `## [X.Y.Z]` section and a `vX.Y.Z` tag on
  it. `scripts/release.sh <X.Y.Z> --commit` is how you commit — it expects the
  dirty tree in front of you, runs every gate, dates the section, ticks the
  backlog, regenerates the roadmap and makes one commit plus an annotated tag.
  `scripts/version.sh check` is the gate: strict on a tag, warning-only on a
  branch push, because the branch and the tag are two pushes and a check that is
  red between them is a check people switch off.
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
- **`repo-meta.sh apply` could not remove a topic** (PQ-30) — it used
  `gh repo edit --add-topic`, which only ever adds, so a topic dropped from
  `.github/repo-meta` stayed on GitHub: `check` would report drift for ever and,
  with a token in CI, the workflow would fail on every push with no way to make
  it pass. The topics are now **set** through `PUT /repos/{owner}/{repo}/topics`,
  and a new `plan` mode prints the commands `apply` would run so the whole-list
  behaviour is assertable without a network call.
- **The dispatch input reached the shell through `${{ }}`** (PQ-31) — the
  milestone filter of the Backlog issues workflow was interpolated straight into
  a `run:` block. It now travels in the environment and is validated (`M` and
  digits, comma-separated) before it is used as an argument. Only a maintainer
  can dispatch that workflow, but it holds a token that can write issues, and
  that is not a reason to paste a string into a command line.
- **The dead-link gate split a path containing a space into two links** (PQ-17)
  — `docs/release notes.md` would have been reported as two dead links, failing
  CI over a file that was right there. The link lists are now read line by line
  from a file rather than through a pipe, so the counters stay in the shell that
  reports them.
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

[0.25.1]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.25.1
[0.25.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.25.0
[0.24.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.24.0
[0.23.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.23.0
[0.22.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.22.0
[0.21.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.21.0
[0.20.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.20.0
[0.19.1]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.19.1
[0.19.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.19.0
[0.18.1]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.18.1
[0.18.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.18.0
[0.17.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.17.0
[0.16.1]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.16.1
[0.16.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.16.0
[0.15.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.15.0
[0.14.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.14.0
[0.13.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.13.0
[0.12.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.12.0
[0.11.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.11.0
[0.10.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.10.0
[0.9.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.9.0
[0.8.1]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.8.1
[0.8.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.8.0
[0.7.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.7.0
[0.6.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.6.0
[0.5.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.5.0
[0.4.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.4.0
[0.3.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.3.0
[0.2.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.2.0
[0.1.0]: https://github.com/Allan-Nava/pqprobe/releases/tag/v0.1.0
