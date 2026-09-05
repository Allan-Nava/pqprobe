# Usage

```
pqprobe probe <target>... [flags]
pqprobe profiles
pqprobe explain [class|topic]
pqprobe version [--short]
```

`pqprobe version` prints `pqprobe X.Y.Z`, and `pqprobe version --short` prints
`X.Y.Z` alone — the form that embeds in a generated header or a Docker tag
without reading `pqprobe pqprobe X.Y.Z`.

`pqprobe explain pq-intolerant` prints what the class means, which real clients
it affects and what to do next — with **no network call**, so it is runnable
while the incident is still on. With no argument it lists every class, and the
**topics** — words a report uses that are deliberately not classes, because they
are reported and never graded: `ech` and `ech-reject` today. A finding nobody can
look up is a finding nobody acts on.

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
| `--inventory FILE` | — | Ansible INI inventory to take hosts from (`-` is stdin) |
| `--group g,h` | all | restrict to these inventory groups |
| `--list FILE` | — | flat list of targets, one per line (`-` is stdin) |
| `--port N` | `443` | default port for targets written without one |
| `--sni NAME` | — | server name for every target |
| `--alpn a,b` | none | ALPN protocols to offer |
| `--starttls PROTO` | — | upgrade to TLS through the protocol's own negotiation first: `smtp`, `imap`, `postgres`, `mysql` |
| `--ech` | — | also dial with Encrypted Client Hello, taking each config from the endpoint's HTTPS DNS record |
| `--dns HOST:PORT` | system | resolver to ask for that record |
| `--ech-config BASE64` | — | the same, with a config you pass instead of one from DNS |
| `--net tcp4\|tcp6` | both | pin the address family every connection uses; the family is stated in the report |
| `--socks5 HOST:PORT` | — | reach every endpoint through a no-auth SOCKS5 proxy |
| `--timeout D` | `10s` | per-handshake timeout |
| `--confirm` | on | re-dial an abrupt failure once before believing it (`--confirm=false` to dial once) |
| `--concurrency N` | `8` | endpoints in flight (profiles of one endpoint are sequential) |
| `--textfile FILE` | — | also write Prometheus textfile-collector metrics to `FILE`, replaced atomically |
| `--watch D` | — | re-probe every `D` and print only the transitions (minimum 5s, text output only) |
| `--baseline FILE` | — | compare against a previous `--json` run and report the transitions |
| `--markdown` | — | a table and collapsible detail, for a pull request comment or a CI job summary |
| `--json` | — | full report, every profile result included |
| `--findings` | — | flat findings array |
| `--findings=wrapped` | — | the wrapped object a fleet aggregator consumes, with a stable id per finding (note the `=`) |
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

## As a metric

```sh
pqprobe probe --inventory inventory/edge --textfile /var/lib/node_exporter/pqprobe.prom
```

Eight families for a node exporter's textfile collector, replaced **atomically**
— the collector reads whatever is in the file when it scrapes, including half of
it:

```
pqprobe_last_run_timestamp_seconds 1788421517
pqprobe_class{target="github.com:443",class="pq-blind"} 1
pqprobe_status{target="github.com:443"} 1
pqprobe_findings{target="github.com:443",status="WARN"} 2
pqprobe_cert_expiry_days{target="github.com:443"} 87.67
pqprobe_handshake_ok{target="github.com:443",profile="pq-only"} 0
pqprobe_hello_bytes{target="github.com:443",profile="pq-preferred"} 1494
```

`pqprobe_status` is the severity as a number — `0` OK, `1` WARN, `2` BAD, `3`
ERROR — so an alert is `pqprobe_status > 1`. Alert on
`pqprobe_last_run_timestamp_seconds` too: a probe that silently stopped running
looks exactly like a fleet that is fine.

It is a side output, not a renderer, so it combines with any of them — and with
`--watch`, where the file is rewritten on every tick.

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

## Ports that are not 443

Implicit TLS needs nothing special — `pqprobe probe mail.example:465` already
works, and so do 993 and 6514. What needed adding is the other half: ports where
TLS is reached through the protocol's own negotiation.

```sh
pqprobe probe --starttls smtp  mx.example:587
pqprobe probe --starttls imap  mail.example:143
pqprobe probe --starttls postgres db.example:5432
pqprobe probe --starttls mysql    db.example:3306
```

Real output, September 2026: `smtp.gmail.com:587` is `pq-ready`.

**What goes on the wire, exactly**: a greeting is read, then `EHLO` and
`STARTTLS`, or `a1 STARTTLS`, or Postgres's eight-byte `SSLRequest`, or MySQL's
32-byte `SSLRequest` — which is the first 32 bytes of a login packet and nothing
after them, stopping exactly where the credentials would have gone. Nothing
else — no mail, no query, no credential, no application data. That is the line
this flag walks: without the negotiation these ports cannot be probed at all,
and with anything more it would be a different tool.

MySQL is the one protocol here where the **server speaks first**, and its
capability flags say whether TLS is on offer at all: no `CLIENT_SSL`, no
upgrade, and that is `no-tls` rather than a post-quantum verdict. It is also why
the plaintext negotiation is bounded by `--timeout` — a port that accepts the
connection and then says nothing is the ordinary failure there. The X Protocol
on 33060 is a different, protobuf-framed negotiation and is deliberately not
spoken.

A peer that will not upgrade gets the class **`no-tls`** with an `ERROR`, never
`pq-intolerant`: a relay with TLS switched off has refused *TLS*, and grading
that as a post-quantum failure would send somebody looking for a middlebox that
does not exist.

## Encrypted Client Hello

```sh
pqprobe probe crypto.cloudflare.com --ech
```

ECH is the question this tool always asks, one layer out: a **client capability
that makes the ClientHello bigger**, on top of a hybrid hello already sitting
near the MTU. Chrome and Firefox send it wherever DNS advertises a config.

It is dialled as a **pair** — the same client with and without ECH, both pinned
to TLS 1.3 — so the only difference on the wire is ECH itself. (PQ-25 learned
that the hard way: a probe that also changed the version window changed the
cipher list, and compared two variables at once.) Acceptance is read from the
connection state, never inferred from the handshake having completed: a server
that ignores the extension completes one too, with the server name still in the
clear.

Real numbers, September 2026: `crypto.cloudflare.com` accepts it and the hello
goes from 1489 B to 1661 B — **+172 bytes** on top of the ML-KEM key share.
`github.com` declines the same config, which is `ech-reject`, an `OK` finding
and no change of class: no client requires ECH, so an endpoint that does not
offer it has failed nothing. The one case that earns a `WARN` is the size story
— the control connects and the ECH twin is cut off.

The config has to be the one that endpoint publishes, or a rejection says
nothing about it — which is why `--ech` reads it from the endpoint's own HTTPS
record (type 65, the `ech=` parameter), one lookup per **name** rather than per
address, so a fleet behind one CDN asks once. Go's resolver exposes no arbitrary
record type, so the query is written into pqprobe: no dependency, and still a
DNS question rather than a request. `--dns HOST:PORT` picks the resolver;
without it, the ones in `/etc/resolv.conf`. A truncated answer is retried over
TCP, because a record carrying an ECH config passes 512 bytes easily and half a
record parsed as a whole one is a config that fails inside the handshake.

An endpoint that publishes nothing keeps the ordinary profiles and says so once
— most of them are in that state, and it is not a failure of anything.
`--ech-config BASE64` still takes a config you choose: it answers a different
question ("what happens if this endpoint is offered *this*"), so asking for both
at once is a usage error rather than a silent precedence rule.

One surprise worth knowing: when a peer declines ECH, Go verifies its
certificate against the config's **public name** before trusting the retry
configs, and `InsecureSkipVerify` does not disable that. An endpoint behind a
private CA therefore answers the ECH probe with a verification error — pqprobe
reports it as the same event, a declined ECH, rather than as something wrong
with the endpoint.

## From a pipe

```sh
dig +short A origin.example | pqprobe probe -
awk '/^web/ {print $1}' hosts.ini | pqprobe probe --list -
```

The fleet worth probing is usually the output of something else, and a `-`
anywhere a file is expected reads it from stdin: as a target, as `--list -`, or
as `--inventory -` for a whole INI. The forms are the ones a file already
accepts, comments and `1.2.3.4=origin.example` included.

Stdin is one stream and is handed over exactly once — asking twice is an error
rather than two readers each getting part of the list, because half a fleet
probed silently is worse than being told.

## One address family at a time

```sh
pqprobe probe --net tcp6 origin.example
```

Without it the resolver chooses, and it chooses again on the next run: a
dual-stack name that answers on its A record and dies on its AAAA can be graded
either way, with nothing having changed on the endpoint. Pinning the family is
what makes that failure reproducible on demand, and what makes the two answers
comparable.

The family is stated in the report as an `OK` finding, not left in the shell
history — a run that could only use IPv4 and says nothing about it reads
afterwards as "IPv6 is fine". With `--per-address` only the records of that
family are probed, so the ones this run excluded do not come back as failures to
read past; a name that resolves with nothing in the family keeps its target and
says so in those words.

An address family excluded here is `unroutable`, never a grade: it is a fact
about this prober, in exactly the way an AAAA record probed from a machine
without IPv6 egress is.

When a run does hit that — addresses this machine has no route to — the reason
is established once, as an `egress` finding carrying the number of endpoints it
accounts for, and those endpoints stop guessing at the cause in their own hints.
It is only said when the family is knowable (an address, or a pinned `--net`)
and when the route really is missing here: an address that is simply unreachable
is a statement about the endpoint, and the report has already made it.

With `--socks5` the flag can only govern the hop to the proxy — which family the
proxy uses to reach the endpoint is its own choice, and pqprobe says so if you
combine them.

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

`--findings` is the flat array: one object per finding,
`check`/`target`/`status`/`message`/`hint`, with `value` and `unit` where there
is a number. An empty run emits `[]`, never `null`.

`--findings=wrapped` is the shape a fleet aggregator consumes:

```json
{
  "check": "pqprobe",
  "status": "warn",
  "summary": "1 endpoint(s): 1 pq-blind",
  "findings": [
    { "id": "ee4b9b852b89", "severity": "warn", "title": "pq-blind — …",
      "detail": "the endpoint fell back to X25519, …",
      "target": "github.com:443", "check": "verdict" }
  ]
}
```

The **id** is the reason it exists: it fingerprints the same problem on the same
target across runs, so an aggregator can tell a finding it has already seen from
a new one. It is built from the check and the target and deliberately **not**
from the message, which carries days and byte counts that change on their own —
an id derived from the text would report a new problem every morning.

Note the `=`: `--findings` still works bare, so `--findings wrapped` would read
`wrapped` as a target.
