# INTENT.md — pqprobe

**Why this repository exists**, what it commits to doing, and what it
*deliberately* does not do. This is the intent document. It outlives individual
features, and it is what a proposal gets measured against before anybody writes
it.

| File | The question it answers |
|---|---|
| **`INTENT.md`** (this one) | **Why** the tool exists, what it is for, what is out of scope |
| [`README.md`](README.md) | **What** it is — install, the profiles, how to read a result |
| [`docs/`](docs/index.md) | **How** to use it, page by page — published at [allan-nava.github.io/pqprobe](https://allan-nava.github.io/pqprobe/) |
| [`AGENTS.md`](AGENTS.md) · [`CLAUDE.md`](CLAUDE.md) | **How work happens here** — operating rules and known traps, for people and for AI agents |
| [`BACKLOG.md`](BACKLOG.md) · [`ROADMAP.md`](ROADMAP.md) | **What is missing** — the single source of planned work, and its generated view |
| [`CHANGELOG.md`](CHANGELOG.md) | **What changed** — every release is a tagged `vX.Y.Z` |

---

## 1. In one line

Answer, on demand and in one second, the question an outage answers in four
hours: **which classes of client can still complete a TLS handshake with this
endpoint, and how does it refuse the others.**

## 2. The problem it solves

Post-quantum key exchange arrived as a default, not as a migration. Chrome and
Edge 131+, Firefox 132+, Go 1.24+, OpenSSL 3.5+ and a growing number of CDNs
offer a hybrid ML-KEM key share without anybody deciding to, and that key share
makes the ClientHello roughly 1.2 KB — large enough to be split across TCP
segments, and large enough that a middlebox, a load balancer or a TLS
terminator with an opinion about hello sizes will drop it.

The failure that produces is the worst shape a failure can have:

- **Every check you already run keeps passing.** `curl` offers classical groups
  only, so does the load balancer's health probe, so does the monitoring agent.
  The origin's own logs show 200s. The endpoint is, by every instrument on the
  premises, up.
- **The refusal is silent.** Nothing is logged, because nothing was parsed. The
  connection resets, or hangs, or ends mid-hello — on the path, before the
  server that would have written the log line.
- **It looks like an application problem.** A fraction of users, from certain
  browsers, through one CDN, get a connection error. That is diagnosed by
  reading application code, for hours, by people who were woken for the wrong
  reason.

And the distinction that would end the investigation is not visible to any
general-purpose scanner: a peer that sends a **TLS alert** to a hybrid hello has
parsed it and declined a group — a setting, a pinned group list, a negotiation
that worked. A peer that **resets, times out or vanishes** choked on the hello
itself, and is broken for every client that so much as *offers* ML-KEM, however
happy that client would have been with X25519.

pqprobe exists to produce that distinction, from a workstation, against
production, without sending a request.

## 3. Goals, in priority order

1. **Tell the two refusals apart, and never blur them.** A civil refusal is a
   configuration and an abrupt one is an outage waiting for a vendor to flip a
   default. `Kind.Abrupt()` is the single predicate that carries the
   distinction, and a timeout counts as abrupt because a hello split across
   segments fails by hanging, not by erroring.
2. **Be safe to point at production.** A handshake and a close. No request, no
   body, no credentials, no application data, no subprocess, no dependency —
   there is nothing in the binary that can change state on the far side. That is
   a product property, not an aesthetic, and CI enforces it.
3. **Never grade an endpoint nobody reached.** Every post-quantum conclusion is
   conditional on the classical profile having connected. An endpoint that
   answered nothing is `unreachable` with an ERROR. A tool that files every
   firewalled host under "intolerant" is a tool people learn to ignore.
4. **Say who is affected, in the finding.** A class name tells an operator
   nothing at 03:00. Each one carries the real clients it breaks — Chrome and
   Edge 131+, Firefox 132+, a CDN with post-quantum enabled — and the next
   action, because the finding is what gets pasted into a ticket.
5. **Keep capability and certificate separate.** The dialler never verifies; the
   chain is checked afterwards from the certificates the peer sent. Reporting an
   expired certificate as "refuses post-quantum clients" would be worse than no
   tool at all, which is why `InsecureSkipVerify` is load-bearing here rather
   than a shortcut.
6. **Answer for a fleet, from the inventory that already exists.** An Ansible
   INI file, a flat list, or arguments — with `ansible_host=` winning over the
   alias and `address=servername` available, because the only way to reproduce a
   CDN-only failure from a workstation is to dial one address while sending
   somebody else's server name, and the only way to find the one broken node out
   of six is to dial all six.
7. **Be a check, not a gate.** Exit 0 whenever the probe ran; findings are
   output. `--exit-on` is how a pipeline opts into failing.

## 4. Non-goals (explicit)

None of these is a gap waiting to be filled. Each one is a decision.

- **Not a TLS scanner.** No cipher suite enumeration, no configuration grade, no
  CVE chasing, no protocol-downgrade matrix. `testssl.sh` and `sslyze` do that
  thoroughly, and a run of pqprobe that also did it would take minutes and
  answer a question nobody asked.
- **Not a certificate monitor.** Leaf expiry and a leaf-only chain are reported
  because the certificates are already in hand from the handshake. Lifecycle,
  renewal windows and issuer policy belong in
  [checkfleet](https://github.com/Allan-Nava/checkfleet).
- **Not a load generator, and never a request.** A handful of connections per
  endpoint, sequential within an endpoint. Traffic, mixes and knees belong in
  [crowdsim](https://github.com/HiWay-Media/crowdsim).
- **Not a fingerprinting tool.** Go's `crypto/tls` cannot reproduce Chrome's
  ClientHello — its extension order, its GREASE values, its padding — and no
  output may imply that it can. Profiles pin **groups and versions**: the
  property that decides whether a post-quantum-capable client finishes a
  handshake. If a real fingerprint is ever needed it arrives behind a build tag
  (PQ-10), clearly separated, never as the default binary.
- **No dependencies, ever.** `go.mod` carries no `require` block and CI fails on
  `net/http` or `os/exec`. A zero-dependency static binary is what makes it
  reasonable to run this inside somebody else's production network on somebody
  else's say-so.
- **Not a monitoring system.** No time series, no dashboard, no alert routing,
  no state between runs beyond what a `--baseline` file is handed. It emits
  findings; Prometheus, checkfleet and whatever already pages get to keep their
  jobs.
- **No real hostnames, anywhere.** No production endpoint is named in a test, a
  fixture or a commit message. Test conditions are planted in a local listener —
  a restricted group list, a version ceiling, a ClientHello size limit — which
  is also the only way they reproduce deterministically and offline.
- **Not a fixer.** It never reconfigures, retries around, or works past a broken
  peer. The output names the affected clients and the next action; the change is
  somebody's decision, made with the finding in hand.

## 5. Principles — the invariants, with the why

| Principle | Why |
|---|---|
| **A profile pins its own groups and versions** | Falling back to Go's defaults means the run proves something different after every toolchain upgrade, silently. |
| **A profile is a capability class; the client names are prose** | Nothing branches on "Chrome". The names exist so a finding can say who is affected, and so no reader believes a fingerprint was sent. |
| **`Kind.Abrupt()` is the only place the alert/reset distinction lives** | Re-deriving it from an error string at a call site is how the one thing the tool is for gets quietly wrong in a renderer. |
| **The verdict reads the baseline first** | Without that ordering, unreachable and intolerant collapse into the same bucket, and the "intolerant" finding stops meaning anything. |
| **The dialler never verifies** | Trust-store state and certificate lifetime must not be able to change a capability answer. |
| **Worst findings first, in every renderer** | The output is read under pressure, often in a terminal that has already scrolled. |
| **Every finding with a number carries `Value`/`Unit`** | A machine consumer that has to parse `Message` breaks the day the prose improves. |
| **Profiles of one endpoint are dialled in sequence** | Three connections landing together measures a connection limit and reports it as a capability. |
| **Exit 0 whenever the probe ran** | A check that fails the pipeline on every deviation is a check people route around. Only `--exit-on` opts in; usage errors are 2. |
| **The URL form is parsed before the `=sni` form** | A query string contains an `=`; splitting on that first turns `https://h/x?q=1` into a probe of `h` with server name `1` — wrong, and silently so. Found by a table case written before the parser. |
| **`[group:vars]` is never a list of hosts** | Otherwise a fleet run acquires an endpoint called `ansible_user`, and a page of DNS errors that looks like a real finding. |
| **The failing test lands first** | The classifier is otherwise an opinion. The size-intolerant listener exists because the production failure had to be reproducible offline before anything could be believed about it. |
| **`BACKLOG.md` is the source, `ROADMAP.md` is generated** | Two hand-maintained plans disagree, and the one that matters is whichever nobody opened. CI fails on a stale roadmap. |
| **A feature lands aligned** | A profile, class or flag ships in the same commit as its README row, its `--help` text, its tests, its backlog tick and its CHANGELOG line — or the documentation starts describing a different tool. |

## 6. Boundaries — what lives where

```
                      ┌──────────────────────────────────────────────┐
                      │           pqprobe (this repo, MIT)           │
   client shapes   ──▶│  internal/clientprofile  groups + versions   │
   one handshake   ──▶│  internal/probe          dial, classify how  │
                      │                          it ended            │
   the answer      ──▶│  internal/verdict        class + findings     │
   the fleet       ──▶│  internal/inventory      args, list, Ansible  │
   how it reads    ──▶│  internal/output         text · json ·        │
                      │                          findings             │
   the CLI         ──▶│  cmd/pqprobe             flags, exit status    │
                      └──────────────┬───────────────────────────────┘
                                     │ explicit boundaries
   ┌───────────────────┬─────────────┴──────┬──────────────────────────┐
   ▼                   ▼                    ▼                          ▼
 testssl.sh /      checkfleet           crowdsim                 your platform
 sslyze            certificate          load, mixes,             dashboards, alerts,
 config grading,   lifecycles,          knees, traffic           the change you make
 cipher suites,    renewal, issuers                              once you have the
 CVEs                                                            finding
```

Practical rule: *"can this class of client still handshake here, and how is it
refused"* → this repository. Anything about the TLS configuration's quality, the
certificate's life, the traffic it can take, or what your fleet does about the
answer → one of the neighbours above.

## 7. How a change gets in

In this order — the order is the point:

1. **A `PQ-n` in [`BACKLOG.md`](BACKLOG.md)** with a milestone, `prio`, `size`
   and `labels`; then `scripts/backlog.sh roadmap`.
2. **Does it survive the one sentence?** *Say which client classes this endpoint
   still accepts, and how it refuses the others.* If the honest answer is
   "it grades a configuration" or "it sends a request", it belongs in a
   neighbouring tool.
3. **Red first**, against a local listener with the property planted, and watch
   the assertion fail for the right reason.
4. **The class states what to do about it.** A `Hint` that names the affected
   clients and the next action, or the class is a label nobody can act on.
5. **Two tests minimum**: one that plants the condition and asserts it is found
   *and correctly attributed*, and one that asserts a healthy endpoint stays
   quiet.
6. `go test -race ./...`, `gofmt`, `go vet`.
7. **Align everything in the same commit**: README row, `--help`, docs, tests,
   the backlog tick, the CHANGELOG line referencing the `PQ-n`.
8. **A tagged release**, prepared locally. Never `git push` — tags included.

## 8. How we can tell it is working

- **An endpoint that is up for `curl` and down for a CDN is named in one
  command**, with the affected clients spelled out, instead of after hours of
  reading application code.
- **No finding has ever had to be walked back as a certificate problem, a trust
  store problem, or a firewall problem.** The separations in §3 are what buy
  that.
- **A BAD verdict is taken to a vendor and survives the conversation**, because
  it distinguishes the reset from the alert and can show the byte size at which
  the peer stopped answering.
- **It gets pointed at production without a meeting**, because "handshake and
  close, no dependencies, no requests" is checkable in the source and enforced
  in CI.
- **`go test ./...` still opens no external connection**, so anybody can run the
  whole suite anywhere.

## 9. Who this is for

Whoever owns the path between a browser and an origin — platform, SRE and
DevOps engineers running load balancers, TLS terminators, CDN configurations and
the fleets behind them — and who would like to find out which of their endpoints
cannot take a post-quantum ClientHello *before* a CDN changes a default on their
behalf.

Also the **AI agents** working in this repository, for which a written intent is
the only way to tell "missing" apart from "deliberately absent" — see
[`AGENTS.md`](AGENTS.md).

## 10. Maintaining this file

`INTENT.md` changes rarely: it is updated when the **purpose** changes, not when
the facts do. Update it when a goal is added or dropped, when a non-goal stops
being one (a real fingerprint in the default binary, say, or state kept between
runs), when a boundary with a neighbouring tool moves, or when a principle is
genuinely revised. Everything factual — flags, classes, profiles, group names —
lives in [`README.md`](README.md), [`docs/`](docs/index.md) and
[`CHANGELOG.md`](CHANGELOG.md), which are the living sources.

Last reviewed: 2026-09-02.
