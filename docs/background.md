# Background — up for `curl`, down for a CDN

## What ML-KEM is, and why the hello grew

**ML-KEM** (FIPS 203, formerly Kyber) is a key encapsulation mechanism whose
security does not rest on the discrete logarithm problem — the thing a
cryptographically relevant quantum computer would break, and with it every
X25519 and P-256 handshake ever recorded. The word that matters is *recorded*:
traffic captured today can be decrypted years later, which is why the industry
is migrating key exchange first and calls the threat **harvest now, decrypt
later**. It is not a prediction about next year; it is about the shelf life of
what is being copied this afternoon.

`X25519MLKEM768` is a **hybrid**: both an X25519 share and an ML-KEM-768 share,
combined so the session is secure if *either* survives. Nobody is betting on the
new mathematics alone, and nobody is betting on the old.

The cost is size, and it is the entire reason this tool exists:

| | classical | hybrid |
|---|---|---|
| key share in the ClientHello | 32 bytes (X25519) | 32 + **1216** bytes |
| ClientHello on the wire | ~270 bytes | **~1500 bytes** |

Those are measured numbers: `pqprobe probe example.com` prints `hello 273 B` for
the classical profile and `hello 1495 B` for the hybrid one, today.

And ~1500 bytes is exactly the wrong number. A standard Ethernet MTU is 1500,
leaving about 1460 for TCP payload, so **the hybrid ClientHello no longer fits
one segment** — where every ClientHello has fitted one for thirty years. It gets
split, and anything on the path that assumed otherwise now has an opinion about
the second half.

## Why that breaks things that were fine yesterday

Hybrid post-quantum key exchange (`X25519MLKEM768`) is now the default in
Chrome, Edge and Firefox, in Go 1.24+, in OpenSSL 3.5+, and at several CDNs. The
change is invisible on a healthy stack and brutal on an unhealthy one, for the
mechanical reason above: the ClientHello no longer fits in a single TCP
segment.

Anything on the path that assumes it does — an old TLS library, a middlebox
inspecting the hello, a load balancer with its own parser — now has a chance to
mishandle the second segment. When it does, the connection resets or hangs. No
alert is sent, because nothing on the far side got far enough to send one.

What makes this expensive to diagnose is the shape of the evidence:

- `curl` works. So does `openssl s_client`, and so does every existing health
  check, because they all send a small classical ClientHello.
- The origin's own logs show nothing. The handshake never completed, so there is
  no request to log.
- The CDN reports 5xx. The application team looks at an application that is
  serving 200s.

The asymmetry *is* the diagnosis, and it takes about two seconds to see once
something dials both ways:

```console
$ pqprobe probe origin.example.com
BAD   origin.example.com:443  pq-intolerant
  OK    handshake/classic            TLS 1.3, X25519, TLS_AES_128_GCM_SHA256
  WARN  handshake/pq-preferred       no handshake (reset): read: connection reset by peer
```

## The next one: ML-DSA, and the chain

Key exchange is the first migration, not the only one. **ML-DSA** (FIPS 204,
formerly Dilithium) is the post-quantum signature algorithm, and it is what
certificates will eventually be signed with — and it is a size problem again,
in the other direction:

| | ECDSA P-256 | ML-DSA-65 |
|---|---|---|
| signature | 64 bytes | **~3.3 KB** |
| public key | 64 bytes | **~2 KB** |

A certificate carries both, so each one in a chain gains roughly 4 KB. A typical
chain today is two or three certificates and two to four kilobytes — pqprobe
reports it on every run as `chain-size` — and the same chain lands somewhere past
10 KB after the migration. That is larger than the largest handshake message
many stacks accept without special handling, and it travels in the *server's*
direction, so the middleboxes that will object are a different set from the ones
that object today.

Nothing serves ML-DSA certificates yet, so pqprobe cannot probe them. What it
can do is tell you the number you will be starting from, which is why the chain
size is reported before it is a problem: shortening a chain — one intermediate
instead of two, no unnecessary cross-signs — is a choice today and an outage
later.

## The two other states worth planning for

**`pq-blind`** — the endpoint has no ML-KEM but falls back cleanly, so capable
clients connect today. Real, and common: as of September 2026, `github.com`
answers exactly this way while `example.com` and `google.com` are `pq-ready`. It
stops working the day a client *requires* post-quantum, and the industry is
moving that way for "harvest now, decrypt later" reasons.

**`no-tls13`** — post-quantum key exchange lives in the TLS 1.3 `key_share`
extension. An endpoint that tops out at TLS 1.2 cannot get there at all,
whatever its group list says.

## What pqprobe deliberately does not tell you

- Whether a *specific* browser build connects. It probes capability classes,
  not ClientHello fingerprints — see [profiles](profiles.md).
- Whether a HelloRetryRequest happened. Go does not expose it; it is on the
  roadmap (`PQ-9`) because an HRR costs a round trip and is a different state
  from never having seen ML-KEM.
- Anything about the application behind the endpoint. pqprobe completes the
  handshake and closes.
