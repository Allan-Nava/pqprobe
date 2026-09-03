# Usage

```
pqprobe probe <target>... [flags]
pqprobe profiles
pqprobe explain [class]
pqprobe version
```

`pqprobe explain pq-intolerant` prints what the class means, which real clients
it affects and what to do next — with **no network call**, so it is runnable
while the incident is still on. With no argument it lists every class.

## Targets

| Form | Meaning |
|---|---|
| `example.com` | port 443 assumed |
| `example.com:8443` | explicit port |
| `https://example.com/path` | the path is ignored — pqprobe sends no request |
| `10.0.0.5=origin.example.com` | dial the address, send that server name |

The last form is the one that finds real problems: it is what a CDN does, and
it is how you probe **one node** of a pool that is fronted by a single name.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--profile a,b` | `classic,pq-preferred,pq-only` | client profiles to dial |
| `--per-group` | — | also dial each key exchange group on its own, and report the accepted set |
| `--per-address` | — | probe every A/AAAA record of each name, by address, still sending the name |
| `--size-sweep` | — | grow the ClientHello in steps and report the size at which the peer stops answering |
| `--alpn-check` | — | dial the same client with `h2,http/1.1` too, and report when the ALPN bytes change the answer |
| `--groups a,b` | — | also dial exactly this key exchange group set, in this order (names as reports print them) |
| `--inventory FILE` | — | Ansible INI inventory to take hosts from |
| `--group g,h` | all | restrict to these inventory groups |
| `--list FILE` | — | flat list of targets, one per line |
| `--port N` | `443` | default port for targets written without one |
| `--sni NAME` | — | server name for every target |
| `--alpn a,b` | none | ALPN protocols to offer |
| `--socks5 HOST:PORT` | — | reach every endpoint through a no-auth SOCKS5 proxy |
| `--timeout D` | `10s` | per-handshake timeout |
| `--confirm` | on | re-dial an abrupt failure once before believing it (`--confirm=false` to dial once) |
| `--concurrency N` | `8` | endpoints in flight (profiles of one endpoint are sequential) |
| `--watch D` | — | re-probe every `D` and print only the transitions (minimum 5s, text output only) |
| `--baseline FILE` | — | compare against a previous `--json` run and report the transitions |
| `--markdown` | — | a table and collapsible detail, for a pull request comment or a CI job summary |
| `--json` | — | full report, every profile result included |
| `--findings` | — | flat findings array |
| `--min-severity S` | — | hide findings below `S` |
| `--exit-on S` | never | exit 1 when a finding reaches `S` |
| `--expiry-warn N` | `21` | certificate expiry WARN threshold, days |
| `--expiry-bad N` | `7` | certificate expiry BAD threshold, days |

## Exit status

| Code | Meaning |
|---|---|
| `0` | the probe ran — findings are output, not an error |
| `1` | `--exit-on` threshold reached |
| `2` | usage error, or no target could be parsed |

Exit 0 on a WARN is deliberate. A check that fails the pipeline on every
deviation is a check people learn to ignore.

## While something is being changed

```sh
pqprobe probe --watch 30s --inventory inventory/edge --group edge
```

The first report is printed in full — you have to know the state you are
watching from — and from then on **only the transitions**, timestamped:

```console
watching 6 endpoint(s) every 30s — only transitions from here, Ctrl-C to stop

12:34:56  BAD   10.11.10.5:443  pq-ready → pq-intolerant
12:35:26  OK    10.11.10.5:443  pq-intolerant → pq-ready
```

A tick that found nothing prints nothing: the window this exists for is one
where a screen of unchanged endpoints is what hides the line that matters.

The interval has a **5s floor** — that is a rate against somebody's endpoint,
and `--watch 100ms` is a typo rather than an intention. `--watch` with `--json`,
`--findings` or `--markdown` is refused: a stream of documents is not a
document, and being told now beats finding out halfway through a pipe. Ctrl-C
stops it and exits **0**, because the probe ran.

## Through a proxy

```sh
pqprobe probe --socks5 127.0.0.1:1080 origin.internal.example
```

SOCKS5 and nothing else. HTTP `CONNECT` is a *request*, and sending one would
trade away the property that makes this binary safe to point at production — so
the flag is named after what it supports rather than disappointing you later.

No authentication: pqprobe holds no credentials by design. A proxy that wants
some says so in those words.

The host name is sent to the proxy **unresolved**, because inside a network that
is often the only place it resolves. That is also why `--per-address` and
`--socks5` do not belong together — the first resolves here, which is the
opposite of the point — and pqprobe says so if you combine them.

A failure at the proxy is reported as `proxy` and is never abrupt: it is not the
endpoint cutting you off, and grading it as one would put somebody else's
endpoint in the `pq-intolerant` bucket for a fault on this side.

## In a pull request

There is a composite action, so a repository that owns endpoints can check them
where the change is being reviewed:

```yaml
- uses: Allan-Nava/pqprobe@v0.14.0
  with:
    targets: origin.example.com api.example.com
    args: --per-address
    exit-on: BAD
```

It writes the `--markdown` report to the job summary, exposes the findings array
as the `findings` output, and fails the step only on `exit-on`. Inputs: `targets`,
`args`, `exit-on`, `version`, `summary`.

## In a scheduled job

```sh
pqprobe probe --inventory inventory/edge --group edge \
  --findings --min-severity WARN --exit-on BAD > findings.json
```

With a baseline, the run reports **what changed** rather than what was already
broken — which is what makes a daily check readable on day thirty:

```sh
pqprobe probe --inventory inventory/edge --json > today.json
pqprobe probe --inventory inventory/edge --baseline yesterday.json --exit-on BAD
```

`--findings` is the flat array the sibling tools speak: one object per finding,
`check`/`target`/`status`/`message`/`hint`, with `value` and `unit` where there
is a number. An empty run emits `[]`, never `null`.
