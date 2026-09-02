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
| `handshake` | `host:port/profile` | one attempt: negotiated version, group, cipher, ALPN and elapsed ms — or how it failed |
| `verdict` | `host:port` | the class, with the affected clients named in the hint |
| `expiry` | `host:port` | days to leaf expiry (`--expiry-warn`, `--expiry-bad`) |
| `chain` | `host:port` | chain does not verify, or the peer sent the leaf alone |
| `tls-version` | `host:port` | TLS 1.3 did not complete while 1.2 did |

A failed handshake is a `WARN` on its own, never a `BAD`: whether it matters is
the verdict's job to say, and a per-profile `BAD` would count the same fact
twice.

## Classes

| Class | Status | Meaning |
|---|---|---|
| `pq-ready` | OK | hybrid key exchange works, including for a client that requires it |
| `pq-capable` | WARN | ML-KEM is negotiated when offered, but the pq-only profile did not complete |
| `pq-blind` | WARN | no post-quantum support; capable clients still connect on a classical group |
| `pq-refusing` | BAD | capable clients are refused **with an alert** while classical ones connect |
| `pq-intolerant` | BAD | capable clients are **cut off** while classical ones connect |
| `no-tls13` | WARN | TLS 1.2 is the ceiling, so post-quantum is out of reach here |
| `unreachable` | ERROR | nothing answered |
| `tls-broken` | ERROR | the port answered and no profile completed a handshake |

## Alert versus reset

The two BAD classes look identical from a browser and are different work:

- **`pq-refusing`** — the peer parsed a ClientHello that also offered X25519 and
  P-256, and still said no. Look for a pinned group list, a TLS policy, a
  hardware accelerator with a fixed algorithm set.
- **`pq-intolerant`** — the peer never sent an alert. It reset, timed out or
  vanished. Look for what the ClientHello had to cross: an old TLS library, a
  middlebox, a load balancer that reads the hello, anything that assumes a
  handshake fits one packet.
