# Background — up for `curl`, down for a CDN

Hybrid post-quantum key exchange (`X25519MLKEM768`) is now the default in
Chrome, Edge and Firefox, in Go 1.24+, in OpenSSL 3.5+, and at several CDNs. The
change is invisible on a healthy stack and brutal on an unhealthy one, for a
mechanical reason: the ML-KEM key share is roughly 1.2 KB, so the ClientHello
that carries it no longer fits in a single TCP segment.

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
