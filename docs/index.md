# pqprobe

**Which classes of client can still complete a TLS handshake with this
endpoint, now that post-quantum key exchange is on by default in browsers and
CDNs?**

One static Go binary, no dependencies, no application data ever sent.

**Published site: <https://allan-nava.github.io/pqprobe/>** — the same material
as one page ([docs/index.html](index.html)). The Markdown below is the version
that reads well inside the repository.

- [Install](install.md)
- [Usage](usage.md) — flags, output formats, exit status
- [Client profiles](profiles.md) — what each one proves, and what it does not
- [Findings](findings.md) — every check, status and class
- [Background](background.md) — why an endpoint can be up for `curl` and down
  for a CDN
- [Intent](../INTENT.md) — why the tool exists, and what is deliberately out of
  scope

## The one-minute version

```console
$ pqprobe probe origin.example.com
BAD   origin.example.com:443  pq-intolerant
  BAD   verdict                      pq-intolerant — post-quantum-capable clients cannot connect at all, while classical clients can
  WARN  handshake/pq-preferred       no handshake (reset): read: connection reset by peer
  OK    handshake/classic            TLS 1.3, X25519, TLS_AES_128_GCM_SHA256
```

The classical client connected. The one that merely *offered* hybrid ML-KEM was
cut off. Every health check you already run uses the first shape; Chrome, Edge,
Firefox and a CDN with post-quantum enabled use the second.
