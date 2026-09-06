**pqprobe** — 3 endpoint(s): 1 ERROR, 1 BAD, 1 WARN, 0 OK

| Endpoint | Class | Worst |
|---|---|---|
| `gone.example:443` | `unreachable` | ERROR |
| `wall.example:443` | `pq-intolerant` | BAD |
| `origin.example:443` | `pq-ready` | WARN |

<details><summary><code>gone.example:443</code> — unreachable</summary>

- **ERROR** `verdict` — nothing answered; no TLS conclusion available
  - fix reachability first — no statement about post-quantum readiness can be made from a probe that never completed a handshake
- **WARN** `handshake/classic` — no handshake (refused): connect: connection refused
- **WARN** `handshake/pq-only` — no handshake (refused): connect: connection refused
- **WARN** `handshake/pq-preferred` — no handshake (refused): connect: connection refused

</details>

<details><summary><code>wall.example:443</code> — pq-intolerant</summary>

- **BAD** `verdict` — pq-intolerant — post-quantum-capable clients cannot connect at all, while classical clients can
  - the classical client connected and the post-quantum-capable one was cut off (timeout, reproduced on a second dial): every client that merely *offers* ML-KEM fails here — Chrome and Edge 131+, Firefox 132+, a CDN with post-quantum enabled — while curl and your existing health checks keep passing
- **WARN** `chain` — the peer sent the leaf certificate alone, with no intermediate
  - browsers that cached the intermediate will not notice and a fresh client will fail — the most confusing class of TLS bug there is
- **WARN** `expiry` — leaf expires 2026-09-18 (12 days)
- **WARN** `handshake/pq-only` — no handshake (timeout): context deadline exceeded — twice
  - an abrupt end means the peer never sent a TLS alert: it choked on the ClientHello rather than declining it
- **WARN** `handshake/pq-preferred` — no handshake (timeout): context deadline exceeded — twice
  - an abrupt end means the peer never sent a TLS alert: it choked on the ClientHello rather than declining it
- **OK** `chain-size` — the peer sent 1 certificate(s), 1200 bytes of chain
  - post-quantum authentication is the next migration and it is a size problem again: an ML-DSA signature is around 3.3 KB where an ECDSA one is 64 bytes, so this chain grows by roughly 4 KB per certificate when it moves. This is the headroom you have today
- **OK** `handshake/classic` — TLS 1.3, X25519, TLS_AES_128_GCM_SHA256, hello 285 B

</details>

<details><summary><code>origin.example:443</code> — pq-ready</summary>

- **WARN** `chain` — the peer sent the leaf certificate alone, with no intermediate
  - browsers that cached the intermediate will not notice and a fresh client will fail — the most confusing class of TLS bug there is
- **WARN** `expiry` — leaf expires 2026-09-18 (12 days)
- **OK** `chain-size` — the peer sent 1 certificate(s), 1200 bytes of chain
  - post-quantum authentication is the next migration and it is a size problem again: an ML-DSA signature is around 3.3 KB where an ECDSA one is 64 bytes, so this chain grows by roughly 4 KB per certificate when it moves. This is the headroom you have today
- **OK** `verdict` — pq-ready — post-quantum key exchange works, including for a client that requires it
  - nothing to do; re-run after any TLS stack or load balancer change
- **OK** `handshake/classic` — TLS 1.3, X25519, TLS_AES_128_GCM_SHA256, hello 285 B
- **OK** `handshake/pq-only` — TLS 1.3, X25519MLKEM768, TLS_AES_128_GCM_SHA256, hello 1439 B
- **OK** `handshake/pq-preferred` — TLS 1.3, X25519MLKEM768, TLS_AES_128_GCM_SHA256, hello 1507 B

</details>
