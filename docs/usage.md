# Usage

```
pqprobe probe <target>... [flags]
pqprobe profiles
pqprobe version
```

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
| `--inventory FILE` | — | Ansible INI inventory to take hosts from |
| `--group g,h` | all | restrict to these inventory groups |
| `--list FILE` | — | flat list of targets, one per line |
| `--port N` | `443` | default port for targets written without one |
| `--sni NAME` | — | server name for every target |
| `--alpn a,b` | none | ALPN protocols to offer |
| `--timeout D` | `10s` | per-handshake timeout |
| `--confirm` | on | re-dial an abrupt failure once before believing it (`--confirm=false` to dial once) |
| `--concurrency N` | `8` | endpoints in flight (profiles of one endpoint are sequential) |
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

## In a scheduled job

```sh
pqprobe probe --inventory inventory/edge --group edge \
  --findings --min-severity WARN --exit-on BAD > findings.json
```

`--findings` is the flat array the sibling tools speak: one object per finding,
`check`/`target`/`status`/`message`/`hint`, with `value` and `unit` where there
is a number. An empty run emits `[]`, never `null`.
