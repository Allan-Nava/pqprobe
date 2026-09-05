# Findings

Every run emits findings: `check`, `target`, `status`, `message`, an optional
`value`/`unit`, and a `hint` that says what to do. Worst first, always.

## Statuses

| Status | Meaning |
|---|---|
| `OK` | the statement is fine |
| `WARN` | works today, with something to plan |
| `BAD` | a class of client cannot connect |
| `ERROR` | the probe could not run — nothing below it can be concluded |

`ERROR` sorts **above** `BAD` on purpose: an endpoint that was never reached is
not an endpoint that passed, and an operator has to see it first.

## Checks

| Check | Target | What it says |
|---|---|---|
| `handshake` | `host:port/profile` | one attempt: negotiated version, group, cipher, ALPN, the **measured ClientHello size** and elapsed ms — or how it failed |
| `verdict` | `host:port` | the class, with the affected clients named in the hint |
| `groups` | `host:port` | with `--per-group`: which groups the peer accepted alone, and how it refused the others |
| `expiry` | `host:port` | days to leaf expiry (`--expiry-warn`, `--expiry-bad`) |
| `chain` | `host:port` | chain does not verify, or the peer sent the leaf alone |
| `chain-size` | `host:port` | what the chain costs on the wire, and the headroom it leaves for post-quantum certificates |
| `client-auth` | `host:port` | the peer requested a client certificate: this endpoint is mutual TLS |
| `ech` | `host:port` | with `--ech-config`: whether the peer accepted Encrypted Client Hello, and what it costs on the wire |
| `egress` | `host:port` | this prober has no route for an address family, said once for the whole run rather than per endpoint |
| `net` | `host:port` | with `--net`: the address family this run was pinned to, so its silence about the other one cannot be read as an answer |
| `addresses` | the name | with `--per-address`: how many addresses the name has, and which one answers differently |
| `transition` | `host:port` | with `--baseline`: the class changed since a stored run, or the endpoint is new or gone |
| `size-limit` | `host:port` | with `--size-sweep`: the ClientHello sizes the peer answered and the first it did not |
| `alpn` | `host:port` | with `--alpn-check`: whether offering `h2,http/1.1` changes the answer |
| `tls-version` | `host:port` | TLS 1.3 did not complete while 1.2 did |

A failed handshake is a `WARN` on its own, never a `BAD`: whether it matters is
the verdict's job to say, and a per-profile `BAD` would count the same fact
twice.

## Classes

`pqprobe explain <class>` — and `explain ech`, for the words that are reported
rather than graded — prints any of these out of context: meaning, affected
clients, next action, without touching the network.

| Class | Status | Meaning |
|---|---|---|
| `pq-ready` | OK | hybrid key exchange works, including for a client that requires it |
| `pq-capable` | WARN | ML-KEM is negotiated when offered, but the pq-only profile did not complete |
| `pq-blind` | WARN | no post-quantum support; capable clients still connect on a classical group |
| `pq-refusing` | BAD | capable clients are refused **with an alert** while classical ones connect |
| `pq-intolerant` | BAD | capable clients are **cut off** while classical ones connect |
| `no-tls13` | WARN | TLS 1.2 is the ceiling, so post-quantum is out of reach here |
| `no-tls` | ERROR | the plaintext upgrade was refused, so there was no handshake to grade — not a grade |
| `mtls-required` | ERROR | the peer wants a client certificate and no handshake survived it — not a grade |
| `unreachable` | ERROR | nothing answered |
| `tls-broken` | ERROR | the port answered and no profile completed a handshake |

## The per-group map

`--per-group` adds one TLS 1.3 handshake per key exchange group — ML-KEM,
X25519, P-256, P-384, P-521 — each offering that group and nothing else, in
sequence. The `groups` finding reports what came back:

```console
OK    groups    accepted: X25519, P-256 · declined with an alert: X25519MLKEM768, P-384, P-521
```

It is a report, not a grade: no real client dials with a single group, so the
map never moves the class. What it answers is *which* group a migration can be
planned against, instead of "some hybrid handshake worked". The two refusals
stay apart here too — `declined with an alert` is a policy, `cut off` is the
failure this tool exists for, and on the hybrid group it is also a size signal.

## Confirmed, or flapping

An abrupt failure is dialled a second time before the class is assigned, because
`pq-intolerant` is the finding somebody takes to a CDN vendor and one reset is
also what a stale connection-tracking entry or a node being drained looks like.
An alert is never re-dialled: it is an answer the peer chose to give.

| What the two dials did | How it reads |
|---|---|
| both cut off | `no handshake (reset) — twice`, and the verdict hint says *reproduced on a second dial* |
| cut off, then connected | a `WARN` handshake finding: *only on the second attempt* — the endpoint is **flapping, not walled** |
| an alert | one dial, and nothing about attempts in the output |

A flap never becomes a `BAD` class: the endpoint connected, so it is graded on
that, and the instability is reported next to it. `--confirm=false` dials once.

## When ALPN is the difference

`--alpn-check` dials `pq-preferred` a second time carrying `h2,http/1.1` — the
list a browser or a CDN actually sends — and compares the two:

```console
OK   alpn   ALPN makes no difference (1495 B against 1513 B)
BAD  alpn   the same client connects without ALPN and is refused with h2,http/1.1 (1495 B against 1512 B)
```

Eighteen bytes is nothing, unless the peer has a threshold in between. Then
every browser and every CDN fails while a bare probe — a health check, or
pqprobe without this flag — keeps saying the endpoint is fine, and the two
results look like a flap. The `--size-sweep` finding is where to go next.

The two profiles are identical apart from the ALPN list, deliberately and with a
test to keep it that way: one variable, or the comparison means nothing.

## How big is too big

`--size-sweep` grows the ClientHello in steps — 2048, 3072, 4096, 6144, 8192,
12288 bytes — and stops at the first size the peer will not answer. One
`size-limit` finding carries the bracket, in **measured** bytes:

```console
BAD  size-limit   answered up to 3080 B and stopped answering at 4100 B
OK   size-limit   answered a ClientHello of 12261 B, the largest tried
```

Both numbers are what went on the wire, not what the sweep asked for: a number
taken to a vendor has to be the one that was actually sent.

**How the padding is done, because it matters.** Go exposes no padding extension
and the TLS 1.3 cipher list is not the client's to grow, so the only field left
is the ALPN list. A peer that inspects ALPN may treat a hello padded that way
differently from one made large by a key share — so the finding says so, and the
number should be quoted with the method. It still answers the question that
matters: this peer stopped answering at that size.

The sweep never changes the class. A padded hello asks "how big is too big",
which is not "can a realistic client connect".

## The hello size, and the retry

Every successful handshake reports the size of the ClientHello it sent, measured
on the wire rather than estimated:

```console
OK  handshake/classic        TLS 1.3, X25519, TLS_AES_128_GCM_SHA256, hello 272 B
OK  handshake/pq-preferred   TLS 1.3, X25519MLKEM768, TLS_AES_128_GCM_SHA256, hello 1495 B
```

That gap — a few hundred bytes against roughly 1.5 KB — is the reason this tool
exists, and it is now a number you can quote instead of a claim.

A handshake that says **`after a hello retry`** cost an extra round trip: the
peer took neither key share offered and asked for a third group. Go sends key
shares for the hybrid group *and* X25519, so falling back to X25519 costs
nothing — a retry means the only group in common was something else, usually
P-256 or P-384 on an older or policy-restricted stack. It is reported as a cost,
not a failure: the endpoint works.

## What changed since last time

`--baseline yesterday.json` compares this run against a stored `--json` run.
Only **transitions** are reported:

| Since the baseline | How it reads |
|---|---|
| nothing changed | nothing at all — an endpoint broken yesterday is not today's news |
| it got worse | a `transition` finding graded by the class it fell to: `pq-ready → pq-intolerant` |
| it got better | the same finding, `OK`: somebody should know a fix landed |
| new endpoint | `new since the baseline: pq-ready`, usually an inventory change |
| endpoint gone | `WARN`, and it names itself, because it has no report of its own to be printed under |

A baseline that is not a pqprobe `--json` document is an error, not an empty
comparison: one that silently parsed as nothing would report "no changes" for
ever.

## A name is not a stack

`--per-address` resolves each name and probes **every** A/AAAA record by
address, with the name still travelling as the SNI — the
`1.2.3.4=origin.example` form, applied automatically. One `addresses` finding
per name says whether the pool agrees:

```console
ERROR addresses    7 addresses disagree: 6 pq-ready, 1 unreachable — worst is [2a00:...:200e]:443 (unreachable)
```

One bad node out of six is the shape of failure that survives a manual check: a
name-only probe hits whichever address the resolver felt like handing over, and
the broken stack stays invisible.

An address this host has no route to is `unroutable`, which grades as
`unreachable` — never `tls-broken`, which would claim the port answered. The
hint offers the local route first, because an AAAA record probed from a machine
without IPv6 egress fails in exactly this way.

## Mutual TLS

An endpoint that asks for a client certificate has not refused post-quantum
clients — it has refused *pqprobe*, which holds no key material by design.

On **TLS 1.3** it does not even fail: the peer's objection arrives after the
client's Finished, and pqprobe never reads, so the handshake completes and the
key exchange answer is sound. The `client-auth` finding is there so nobody reads
`pq-ready` as "usable".

On **TLS 1.2** client auth happens inside the handshake, and the alert that
comes back is indistinguishable from "no mutually supported group" by its text
alone. The peer's `CertificateRequest` is recorded during the handshake — that
is what tells the two apart, and when it broke every profile the class is
`mtls-required` with an ERROR rather than a capability verdict.

## Through a proxy

With `--socks5`, a failure that happens at the proxy — it wants credentials, it
refuses, it is not there — is kind `proxy` and never counts as abrupt. The
endpoint has not been reached, so nothing about it is known, and the error names
the proxy so nobody debugs the wrong host.

## Alert versus reset

The two BAD classes look identical from a browser and are different work:

- **`pq-refusing`** — the peer parsed a ClientHello that also offered X25519 and
  P-256, and still said no. Look for a pinned group list, a TLS policy, a
  hardware accelerator with a fixed algorithm set.
- **`pq-intolerant`** — the peer never sent an alert. It reset, timed out or
  vanished. Look for what the ClientHello had to cross: an old TLS library, a
  middlebox, a load balancer that reads the hello, anything that assumes a
  handshake fits one packet.
