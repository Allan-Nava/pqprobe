# Client profiles

A profile is a **capability class**, not a fingerprint.

pqprobe builds its ClientHello with Go's `crypto/tls`. It cannot reproduce
Chrome's extension order or a CDN's exact cipher list, and it never claims to.
What a profile pins down is which key exchange groups are offered and which TLS
versions are acceptable — the property that decides whether a
post-quantum-capable client can finish a handshake. The client names below say
*who is affected*; no code branches on them.

| Profile | Groups | Versions | Stands for |
|---|---|---|---|
| `classic` | X25519, P-256 | 1.2–1.3 | curl, `openssl s_client`, any pre-2024 client, every health check you already run |
| `pq-preferred` | X25519MLKEM768, X25519, P-256 | 1.2–1.3 | Chrome/Edge 131+, Firefox 132+, CDNs with post-quantum enabled, Go 1.24+, OpenSSL 3.5+ |
| `pq-only` | X25519MLKEM768 | 1.3 | a client with post-quantum required — the default of the next few years |
| `tls13-only` | X25519, P-256 | 1.3 | a modern client with TLS 1.2 disabled |
| `tls12` | X25519, P-256 | 1.2 | old Java and .NET stacks, embedded boxes, legacy CDN pull agents |

The default set is `classic,pq-preferred,pq-only`: a baseline and the two
post-quantum questions. The version edges cost two more connections per endpoint
and answer a different question, so they are opt-in.

## The set you are migrating to

`--groups X25519MLKEM768,X25519` dials exactly that set, in that order, with the
same version window as `pq-preferred` so the two results are comparable. It
appears as `custom:X25519MLKEM768+X25519` and gets its own handshake finding —
you asked for the dial, you see the result — but it does not decide the class:
the class is about the client shapes this tool defines, and a set you described
is a question rather than a baseline.

Names are the ones reports print (`X25519MLKEM768`, `X25519`, `P-256`, `P-384`,
`P-521`), case-insensitive. An unknown name is a usage error listing the known
ones, never a silently smaller set: a run that quietly dropped a group would
prove something other than what was asked.

## Single-group probes

`--per-group` adds a synthetic profile per group — `group:X25519MLKEM768`,
`group:X25519`, `group:P-256`, `group:P-384`, `group:P-521` — each offering
that group alone, pinned to TLS 1.3 because post-quantum key exchange lives in
the 1.3 `key_share` extension. They are not client classes and no real client
dials that way, so they are kept out of the verdict: they answer *which* groups
the peer accepts, which is what a migration has to be planned against.

## Why `pq-preferred` is the one that matters

It is the realistic client. It offers hybrid ML-KEM **and** classical groups, so
a peer without post-quantum support is still expected to complete it — by
selecting X25519, with or without a HelloRetryRequest. A failure here therefore
does not mean "no post-quantum support". It means *cannot talk to a client that
offered it*, and the reason is usually the ~1.2 KB ClientHello that the ML-KEM
key share produces: it no longer fits one TCP segment, and something on the path
mishandles the second one.

## Why every profile pins its versions and groups

Go's defaults change between releases — that is how `X25519MLKEM768` became a
default in the first place. A profile that inherited them would prove something
different after every toolchain upgrade, which is indistinguishable from the
endpoint having changed.
