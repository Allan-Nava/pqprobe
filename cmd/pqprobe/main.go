// Command pqprobe answers one question about a TLS endpoint: which classes of
// client can still complete a handshake with it, now that post-quantum key
// exchange is on by default in browsers and CDNs.
//
// It dials the same endpoint several times with deliberately different client
// shapes and compares the outcomes. The interesting result is never a single
// failure — it is the *asymmetry*: classical client connects, post-quantum
// capable client does not. That is an origin which every existing health check
// calls healthy while a CDN in front of it serves errors.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/inventory"
	"github.com/Allan-Nava/pqprobe/internal/output"
	"github.com/Allan-Nava/pqprobe/internal/probe"
	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "probe":
		os.Exit(cmdProbe(os.Args[2:]))
	case "profiles":
		os.Exit(cmdProfiles())
	case "explain":
		os.Exit(explainTo(os.Stdout, os.Args[2:]))
	case "version", "--version", "-v":
		os.Exit(versionTo(os.Stdout, os.Args[2:], version))
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "pqprobe: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

// watchFloor is the shortest interval --watch will accept. The interval is a
// rate against somebody's production endpoint, and 100ms is a typo rather than
// an intention (PQ-13).
const watchFloor = 5 * time.Second

// watchClock is the timestamp format on a transition line: the time of day,
// because a watch is read while it runs and the date is on the shell prompt.
const watchClock = "15:04:05"

func validWatch(d time.Duration) error {
	if d == 0 {
		return nil
	}
	if d < watchFloor {
		return fmt.Errorf("--watch %s is below the %s floor: that is a rate against somebody's endpoint, not a refresh", d, watchFloor)
	}
	return nil
}

// validWatchOutput refuses --watch with a renderer that emits one whole
// document. A stream of documents is not a document, and finding that out
// halfway through a pipe is worse than being told now.
func validWatchOutput(d time.Duration, renderer string) error {
	if d == 0 || renderer == "" {
		return nil
	}
	return fmt.Errorf("--watch prints transitions as lines; --%s emits one whole document, and a stream of documents is not a document", renderer)
}

// watchTick prints what moved between two runs and returns how many lines it
// printed. A tick that found nothing prints nothing: watch mode exists for the
// window in which something is being changed, and in that window anything else
// is noise to scroll past.
func watchTick(w io.Writer, prev, cur []verdict.Report, now time.Time) int {
	ts := now.Format(watchClock)
	n := 0
	for _, f := range verdict.Transitions(prev, cur) {
		fmt.Fprintf(w, "%s  %-5s %s  %s\n", ts, f.Status, f.Target, f.Message)
		n++
	}
	return n
}

// watchLoop re-probes on an interval and prints only what moved (PQ-13).
//
// The full report has already been printed once: you have to know the state you
// are watching from. After that a quiet tick prints nothing at all, because the
// window this exists for — a CDN or a load balancer being changed — is one
// where a screen full of unchanged endpoints is what hides the line that
// matters.
//
// It runs until interrupted. Ctrl-C is the exit, and it is a clean one: the
// context is cancelled, the tick in flight finishes, nothing is left half
// printed.
func watchLoop(ctx context.Context, w io.Writer, d probe.Dialer, targets []probe.Target,
	profilesFor func(probe.Target) []clientprofile.Profile, opt verdict.Options, concurrency int,
	every time.Duration, prev []verdict.Report, textfile string) int {

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(w, "\nwatching %d endpoint(s) every %s — only transitions from here, Ctrl-C to stop\n",
		len(targets), every)

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(w, "\nstopped.")
			return 0
		case <-ticker.C:
			opt.Now = time.Now()
			cur := run(ctx, d, targets, profilesFor, opt, concurrency)
			// A cancelled tick produces failures that are ours, not the
			// endpoints', and printing them as transitions would be a lie.
			if ctx.Err() != nil {
				fmt.Fprintln(w, "\nstopped.")
				return 0
			}
			watchTick(w, prev, cur, time.Now())
			prev = cur
			// Rewritten every tick: a scrape wants the current state, and a
			// stale file is indistinguishable from a healthy fleet.
			if textfile != "" {
				if err := output.Textfile(textfile, cur, time.Now()); err != nil {
					fmt.Fprintln(w, "pqprobe:", err)
				}
			}
		}
	}
}

// addTransitions compares this run against a stored one and files each
// transition on the report it belongs to (PQ-24). A transition for an endpoint
// this run did not probe has nowhere to live, so it goes on the first report —
// where an operator will still see it.
func addTransitions(path string, reps []verdict.Report) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	defer f.Close()

	old, err := output.LoadReports(f)
	if err != nil {
		return fmt.Errorf("baseline %s: %w", path, err)
	}
	if len(reps) == 0 {
		return nil
	}

	byTarget := make(map[string]int, len(reps))
	for i, r := range reps {
		byTarget[r.Target] = i
	}
	for _, t := range verdict.Transitions(old, reps) {
		at := 0
		if i, ok := byTarget[t.Target]; ok {
			at = i
		}
		reps[at].Finding = append(reps[at].Finding, t)
	}
	for i := range reps {
		finding.SortWorstFirst(reps[i].Finding)
	}
	return nil
}

// egressFindings says once what forty endpoints have in common (PQ-47).
//
// PQ-12 already refused to call an address this host cannot route a property of
// the peer, which was the dangerous half. The half left over is volume: a
// workstation without IPv6 egress produces one `unroutable` per AAAA record
// across the whole fleet, and forty findings that are all the same local fact
// bury the one finding that is about an endpoint.
//
// So the local question is asked once — and only when something has already
// failed that way, so a healthy fleet pays nothing — and the endpoints that
// failed for it stop guessing at the cause, because it is established now. The
// route being present is silence: those addresses are then genuinely
// unreachable, which is a statement about them and one the report already made.
//
// The family has to be *knowable* before it can be blamed: an address literal
// carries it, and so does a run pinned with --net. A name dialled unpinned does
// not — Go tries every address it resolved to, so an unroutable result there
// means all of them failed and says nothing about which family is missing. Those
// keep the per-endpoint hint they already had rather than acquiring a run-level
// claim that might be about the wrong family.
//
// has is injected so the test can plant a prober without a route; production
// passes probe.HasEgress.
func egressFindings(reps []verdict.Report, pinned string, has func(network string) bool) {
	// Which families have unroutable results, and on which reports.
	affected := map[string][]int{}
	for i, r := range reps {
		for _, res := range r.Results {
			if res.Kind != probe.KindUnroutable {
				continue
			}
			host, _, err := net.SplitHostPort(strings.TrimSuffix(r.Target, " "))
			if err != nil {
				host = r.Target
			}
			network := pinned
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
				network = "tcp6"
				if ip.To4() != nil {
					network = "tcp4"
				}
			}
			if network == "" {
				break
			}
			affected[network] = append(affected[network], i)
			break
		}
	}

	for _, network := range []string{"tcp4", "tcp6"} {
		at := affected[network]
		if len(at) == 0 || has(network) {
			continue
		}
		family := probe.NetName(network)
		reps[at[0]].Finding = append(reps[at[0]].Finding, finding.Finding{
			Check:   "egress",
			Target:  reps[at[0]].Target,
			Status:  finding.ERROR,
			Message: fmt.Sprintf("this prober has no %s route: %d endpoint(s) were never dialled", family, len(at)),
			Value:   finding.Num(float64(len(at))),
			Unit:    "endpoints",
			Hint:    "fix the route here, or probe from a host that has one — nothing in those results is a statement about the endpoints, and re-running from this machine will produce them again",
		})
		// Established, so the endpoints stop guessing. The hint they carry was
		// written for the case where nobody knew which of the two it was.
		for _, i := range at {
			for j := range reps[i].Finding {
				if reps[i].Finding[j].Check == "verdict" {
					reps[i].Finding[j].Hint = fmt.Sprintf(
						"see the `egress` finding: this prober has no %s route, so this endpoint was never reached", family)
				}
			}
		}
		finding.SortWorstFirst(reps[at[0]].Finding)
	}
}

// resolverFindings says which resolver answered, once, when it was not the
// machine's own (PQ-58).
//
// A run resolved somewhere else probed something else — different addresses,
// possibly a different ECH config — and two runs of the same fleet that
// disagree for that reason have to say so, or the disagreement looks like the
// endpoints moving.
func resolverFindings(at string, reps []verdict.Report) {
	if at == "" || len(reps) == 0 {
		return
	}
	reps[0].Finding = append(reps[0].Finding, finding.Finding{
		Check:   "resolver",
		Target:  reps[0].Target,
		Status:  finding.OK,
		Message: fmt.Sprintf("every name in this run was resolved by %s (--dns)", at),
		Hint:    "addresses, and any ECH config, came from that resolver rather than this machine's — which is the point from inside a network, and the reason two runs can disagree without anything having moved",
	})
	finding.SortWorstFirst(reps[0].Finding)
}

// netFindings states the address family the run was pinned to, once per report
// (PQ-46).
//
// It is OK, not a problem: the operator asked for it. It exists because the
// absence of it is what misleads — a run that could only use IPv4 and says
// nothing reads afterwards as "IPv6 is fine", and the endpoint whose AAAA
// record is broken was never dialled at all. An unpinned run says nothing,
// because a line on every endpoint of every run is noise nobody reads.
func netFindings(network string, reps []verdict.Report) {
	if network == "" {
		return
	}
	for i := range reps {
		reps[i].Finding = append(reps[i].Finding, finding.Finding{
			Check:   "net",
			Target:  reps[i].Target,
			Status:  finding.OK,
			Message: fmt.Sprintf("dialled over %s only (--net %s)", probe.NetName(network), network),
			Hint:    "the other address family was not probed here; nothing in this report is a statement about it",
		})
		finding.SortWorstFirst(reps[i].Finding)
	}
}

// addressFindings adds one `addresses` finding per name that resolved to more
// than one address, next to the report of the address that differs (PQ-12).
// Grouping happens here because this is the only place that still knows which
// name each target came from.
func addressFindings(names []string, reps []verdict.Report) {
	byName := map[string][]int{}
	var order []string
	for i, n := range names {
		if _, seen := byName[n]; !seen {
			order = append(order, n)
		}
		byName[n] = append(byName[n], i)
	}
	for _, n := range order {
		idxs := byName[n]
		group := make([]verdict.Report, 0, len(idxs))
		for _, i := range idxs {
			group = append(group, reps[i])
		}
		f, at, ok := verdict.AddressConsistency(n, group)
		if !ok {
			continue
		}
		target := idxs[at]
		reps[target].Finding = append(reps[target].Finding, f)
		finding.SortWorstFirst(reps[target].Finding)
	}
}

func usage(w *os.File) { usageTo(w) }

// usageTo is usage() over any writer, so a test can assert that every flag the
// probe accepts is documented — the alignment rule, enforced rather than
// remembered.
func usageTo(w io.Writer) {
	fmt.Fprint(w, `pqprobe — which clients can still handshake with this endpoint?

usage:
  pqprobe probe <target>... [flags]
  pqprobe profiles
  pqprobe explain [class]        what a class means, and what to do about it
  pqprobe version [--short]      --short prints the version alone, for embedding

targets:
  host                     port 443 is assumed
  host:port
  https://host/path        the path is ignored; pqprobe sends no request
  1.2.3.4=origin.example   dial the address, send that server name (what a CDN does)
  -                        read the list from stdin, in these same forms
                           (--list - and --inventory - do the same for a flat
                           list and an INI inventory; stdin is read once)

flags:
  --profile a,b            client profiles to dial (default classic,pq-preferred,pq-only)
  --per-group              also dial each key exchange group on its own and
                           report the accepted set (one extra handshake per
                           group, in sequence)
  --groups a,b             also dial exactly this key exchange group set, in
                           this order (names as reports print them, case-free)
  --alpn-check             also dial the same client with h2,http/1.1 and report
                           when the ALPN bytes change the answer
  --size-sweep             also grow the ClientHello in steps and report the
                           size at which the peer stops answering (stops at the
                           first size that fails)
  --per-address            probe every A/AAAA record of each name, by address,
                           still sending the name (one bad node out of six is
                           invisible to a name-only probe)
  --inventory FILE         Ansible INI inventory to take hosts from
  --group g,h              only these inventory groups
  --list FILE              flat list of targets, one per line
  --port N                 default port for targets written without one (default 443)
  --sni NAME               server name for every target (overrides per-target =sni)
  --alpn a,b               ALPN protocols to offer (default none)
  --starttls PROTO         upgrade to TLS through a protocol's own negotiation
                           first: smtp, imap, postgres, mysql, ftp, nntp,
                           ldap or xmpp. Only the
                           negotiation is sent — no mail, no query, no
                           credential (a MySQL SSLRequest stops exactly where
                           the login would start). Implicit TLS ports (465, 993,
                           6514) need none of this
  --ech                    also dial the same client offering Encrypted Client
                           Hello, taking each endpoint's config from the ech=
                           parameter of its HTTPS DNS record — one lookup per
                           name. An endpoint that publishes none keeps the
                           ordinary profiles and says so, which is not a failure
  --dns HOST:PORT          resolver for every lookup this run makes — target
                           names, --per-address records and the ECH record —
                           because a run resolved somewhere else probed
                           something else (default: this machine's own)
  --ech-config BASE64      also dial the same client offering Encrypted Client
                           Hello with this ECHConfigList — the ech= value of
                           the endpoint's HTTPS DNS record. Dialled as a pair,
                           with and without, so the only difference measured is
                           ECH itself; it reports what ECH costs on the wire and
                           whether the peer accepted it, and never decides the
                           class
  --net tcp4|tcp6          pin the address family every connection uses; the
                           default lets the resolver choose, which is how a
                           dual-stack name gets graded on whichever address it
                           handed over that minute. The family is stated in the
                           report, and an address family excluded here is never
                           a grade against the endpoint
  --socks5 HOST:PORT       reach every endpoint through a no-auth SOCKS5 proxy
                           (the name is sent unresolved, so the proxy resolves
                           it; HTTP CONNECT is a request and is not supported)
  --timeout D              per-handshake timeout (default 10s)
  --confirm                re-dial an abrupt failure once before believing it
                           (default true; --confirm=false to dial once)
  --concurrency N          endpoints in flight (default 8)
  --textfile FILE          also write Prometheus textfile-collector metrics to
                           FILE, replaced atomically (works with any renderer,
                           and is rewritten on every --watch tick)
  --watch D                re-probe every D and print only the transitions, for
                           the window in which something is being changed
                           (minimum 5s; text output only)
  --baseline FILE          compare against a previous --json run and report the
                           transitions: what changed, not what was already broken
  --markdown               a table and collapsible detail, for a pull request
                           comment or a CI job summary
  --json                   full report, every profile result included
  --findings[=SHAPE]       findings as JSON: flat (the default) or wrapped.
                           --findings=wrapped emits {check,status,summary,
                           findings:[{id,severity,title,detail}]} with a stable
                           id per finding, which is what the fleet aggregator
                           deduplicates on. Note the =, not a space: the flag
                           still works bare, so a space would be read as a target
  --min-severity S         hide findings below S (OK|WARN|BAD|ERROR)
  --exit-on S|class        exit 1 when any finding reaches status S — or when
                           any endpoint lands in exactly that class, which is
                           what a pipeline usually means: --exit-on BAD also
                           fires on an expiring certificate (default: never)
  --expiry-warn N          certificate expiry WARN threshold in days (default 21)
  --expiry-bad N           certificate expiry BAD threshold in days (default 7)

exit status:
  0  the probe ran (findings are output, not an error)
  1  --exit-on matched: the status threshold, or the named class
  2  usage error, or no target could be parsed

pqprobe opens TLS connections and sends no application data: no request, no
body, no credentials. It is safe to point at production, and it says nothing
about a client's exact ClientHello fingerprint — only about capability classes.
`)
}

// findingsFormat is --findings, which keeps working as a bare flag and also
// takes a shape: --findings=wrapped (PQ-37).
//
// It implements IsBoolFlag so `--findings` alone still means the flat array —
// every existing command line has to keep working — while `--findings=wrapped`
// selects the wrapped object the fleet aggregator consumes. The value form
// needs the `=`: with IsBoolFlag set, `--findings wrapped` would leave
// "wrapped" as a target, which is why the help says so.
type findingsFormat struct {
	on      bool
	wrapped bool
}

func (f *findingsFormat) String() string {
	switch {
	case f == nil || !f.on:
		return ""
	case f.wrapped:
		return "wrapped"
	}
	return "flat"
}

func (f *findingsFormat) Set(v string) error {
	switch v {
	// "true" is what the flag package passes for a bare boolean flag.
	case "true", "flat", "":
		f.on, f.wrapped = true, false
	case "wrapped":
		f.on, f.wrapped = true, true
	case "false":
		f.on, f.wrapped = false, false
	default:
		return fmt.Errorf("unknown findings shape %q: flat (the default) or wrapped", v)
	}
	return nil
}

func (f *findingsFormat) IsBoolFlag() bool { return true }

// versionTo prints the version (PQ-38).
//
// Bare, it prints "pqprobe X.Y.Z", which is what a person running it wants and
// what it always printed. `--short` prints the version alone, because the other
// form embedded in a generated header reads "pqprobe pqprobe X.Y.Z".
//
// It also stops ignoring its flags: `version --help` used to print the version
// and say nothing about what it accepts, and a typo used to look like success.
func versionTo(w io.Writer, args []string, v string) int {
	short := false
	for _, a := range args {
		switch a {
		case "--short", "-s":
			short = true
		case "--help", "-h":
			fmt.Fprint(w, `usage: pqprobe version [--short]

  --short, -s   print the version alone (1.2.3), for embedding in a header or
                a Docker tag. Without it, the human form: pqprobe 1.2.3
`)
			return 0
		default:
			fmt.Fprintf(w, "pqprobe: version takes --short (or -s), not %q\n", a)
			return 2
		}
	}
	if short {
		fmt.Fprintln(w, v)
		return 0
	}
	fmt.Fprintln(w, "pqprobe", v)
	return 0
}

// explainTo prints what a class means, who it affects and what to do — with no
// network call, because it is meant to be runnable while the incident is still
// on and the endpoint is still refusing. With no argument it lists them all,
// for somebody who half-remembers the word.
func explainTo(w io.Writer, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "classes (pqprobe explain <class> for the rest):")
		for _, c := range verdict.Classes() {
			e, _ := verdict.Explain(c)
			fmt.Fprintf(w, "  %-14s %-5s %s\n", c, e.Status, verdict.Describe(c))
		}
		// The words a report uses that are not classes, because they are
		// reported and never graded (PQ-52).
		fmt.Fprintln(w, "\ntopics:")
		for _, name := range verdict.Topics() {
			fmt.Fprintf(w, "  %s\n", name)
		}
		return 0
	}

	// A leading -- is what a hand types out of habit; refusing it teaches
	// nothing that accepting it does not.
	name := strings.TrimLeft(args[0], "-")
	e, ok := verdict.Explain(verdict.Class(name))
	if !ok {
		e, ok = verdict.ExplainTopic(name)
	}
	if !ok {
		fmt.Fprintf(w, "pqprobe: %q is neither a class nor a topic. These are:\n", args[0])
		for _, c := range verdict.Classes() {
			fmt.Fprintf(w, "  %s\n", c)
		}
		for _, name := range verdict.Topics() {
			fmt.Fprintf(w, "  %s\n", name)
		}
		return 2
	}

	if e.Status == "" {
		// A topic has no status: it is a word a report uses, not a grade.
		fmt.Fprintf(w, "%s\n\n", e.Class)
	} else {
		fmt.Fprintf(w, "%s  (%s)\n\n", e.Class, e.Status)
	}
	fmt.Fprintf(w, "means      %s\n\n", e.Meaning)
	if e.Affected != "" {
		fmt.Fprintf(w, "affects    %s\n\n", e.Affected)
	}
	fmt.Fprintf(w, "do         %s\n", e.Action)
	return 0
}

func cmdProfiles() int {
	for _, p := range clientprofile.All {
		groups := make([]string, 0, len(p.Groups))
		for _, g := range p.Groups {
			groups = append(groups, clientprofile.GroupName(g))
		}
		fmt.Printf("%-13s %s\n", p.Name, p.Summary)
		fmt.Printf("%-13s groups: %s\n", "", strings.Join(groups, ", "))
		fmt.Printf("%-13s clients: %s\n\n", "", p.Clients)
	}
	fmt.Printf("default set: %s\n", strings.Join(clientprofile.Default, ","))
	return 0
}

// probeFlags holds every flag the probe accepts. It exists so *one* place
// declares them and a test can walk the set: a flag declared and never
// documented, or documented and never declared, is invisible until somebody
// tries to use it — which is the mistake that has actually happened here.
type probeFlags struct {
	profiles, groupSet, invFile, groups, listFile *string
	port, sni, alpn, starttls, socks5             *string
	network, echConfig, dns                       *string
	echLookup                                     *bool
	textfile, baseline, minSev, exitOn            *string
	perGroup, sizeSweep, alpnCheck, perAddress    *bool
	confirm, asMarkdown, asJSON                   *bool
	timeout, watch                                *time.Duration
	concurrency, expWarn, expBad                  *int
	findings                                      *findingsFormat
}

func newProbeFlags() (*flag.FlagSet, *probeFlags) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	o := &probeFlags{findings: &findingsFormat{}}

	o.profiles = fs.String("profile", strings.Join(clientprofile.Default, ","), "client profiles to dial")
	o.perGroup = fs.Bool("per-group", false, "also dial each key exchange group on its own")
	o.sizeSweep = fs.Bool("size-sweep", false, "also grow the ClientHello in steps and report the limit")
	o.alpnCheck = fs.Bool("alpn-check", false, "also dial the same client with h2,http/1.1")
	o.groupSet = fs.String("groups", "", "also dial exactly this key exchange group set")
	o.perAddress = fs.Bool("per-address", false, "probe every A/AAAA record of each name")
	o.invFile = fs.String("inventory", "", "Ansible INI inventory")
	o.groups = fs.String("group", "", "inventory groups")
	o.listFile = fs.String("list", "", "flat target list")
	o.port = fs.String("port", inventory.DefaultPort, "default port")
	o.sni = fs.String("sni", "", "server name for every target")
	o.alpn = fs.String("alpn", "", "ALPN protocols")
	o.starttls = fs.String("starttls", "", "upgrade to TLS through this protocol first: smtp, imap, postgres, mysql, ftp, nntp, ldap, xmpp")
	o.socks5 = fs.String("socks5", "", "reach endpoints through a no-auth SOCKS5 proxy")
	o.network = fs.String("net", "", "pin the address family: tcp4 or tcp6")
	o.echConfig = fs.String("ech-config", "", "also dial with Encrypted Client Hello, using this base64 ECHConfigList")
	o.echLookup = fs.Bool("ech", false, "also dial with Encrypted Client Hello, taking each config from DNS")
	o.dns = fs.String("dns", "", "resolver for every lookup, as host:port (default: this machine's)")
	o.timeout = fs.Duration("timeout", 10*time.Second, "per-handshake timeout")
	o.confirm = fs.Bool("confirm", true, "re-dial an abrupt failure once before believing it")
	o.concurrency = fs.Int("concurrency", 8, "endpoints in flight")
	o.textfile = fs.String("textfile", "", "also write Prometheus textfile metrics to this path")
	o.watch = fs.Duration("watch", 0, "re-probe every D and print only the transitions")
	o.baseline = fs.String("baseline", "", "compare against a previous --json run")
	o.asMarkdown = fs.Bool("markdown", false, "markdown for a PR comment or job summary")
	o.asJSON = fs.Bool("json", false, "full JSON report")
	fs.Var(o.findings, "findings", "findings as JSON: flat or wrapped")
	o.minSev = fs.String("min-severity", "", "hide findings below this status")
	o.exitOn = fs.String("exit-on", "", "exit 1 on this status or worse, or on this exact class")
	o.expWarn = fs.Int("expiry-warn", 21, "certificate expiry WARN days")
	o.expBad = fs.Int("expiry-bad", 7, "certificate expiry BAD days")
	return fs, o
}

func cmdProbe(args []string) int {
	fs, o := newProbeFlags()
	profiles, perGroup, sizeSweep, alpnCheck := o.profiles, o.perGroup, o.sizeSweep, o.alpnCheck
	groupSet, perAddress, invFile, groups := o.groupSet, o.perAddress, o.invFile, o.groups
	listFile, port, sni, alpn := o.listFile, o.port, o.sni, o.alpn
	starttls, socks5, timeout, confirm := o.starttls, o.socks5, o.timeout, o.confirm
	network, echConfig, echLookup, dns := o.network, o.echConfig, o.echLookup, o.dns
	concurrency, textfile, watch, baseline := o.concurrency, o.textfile, o.watch, o.baseline
	asMarkdown, asJSON, asFindings := o.asMarkdown, o.asJSON, o.findings
	minSev, exitOn, expWarn, expBad := o.minSev, o.exitOn, o.expWarn, o.expBad
	if err := fs.Parse(permute(args)); err != nil {
		return 2
	}

	renderer := ""
	switch {
	case *asMarkdown:
		renderer = "markdown"
	case asFindings.on:
		renderer = "findings"
	case *asJSON:
		renderer = "json"
	}
	if !probe.ValidStartTLS(*starttls) {
		fmt.Fprintf(os.Stderr, "pqprobe: unknown --starttls protocol %q (have: %s)\n",
			*starttls, strings.Join(probe.StartTLSProtocols(), ", "))
		return 2
	}
	echList, echErr := parseECHConfig(*echConfig)
	if echErr != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", echErr)
		return 2
	}
	if err := validECHFlags(echList, *echLookup); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}
	if !probe.ValidNet(*network) {
		fmt.Fprintf(os.Stderr, "pqprobe: unknown --net address family %q (have: %s)\n",
			*network, strings.Join(probe.Nets(), ", "))
		return 2
	}
	if err := validWatch(*watch); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}
	if err := validWatchOutput(*watch, renderer); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}

	sel, unknown := clientprofile.Select(splitList(*profiles))
	if len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "pqprobe: unknown profile(s): %s (have: %s)\n",
			strings.Join(unknown, ", "), strings.Join(clientprofile.Names(), ", "))
		return 2
	}
	if len(sel) == 0 {
		fmt.Fprintln(os.Stderr, "pqprobe: no profile selected")
		return 2
	}
	if err := validStatus(*minSev); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}
	if err := validExitOn(*exitOn); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}

	targets, errs := collect(fs.Args(), *listFile, *invFile, splitList(*groups), *port, *sni, os.Stdin)
	for _, err := range errs {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		if errors.Is(err, errStdinTwice) {
			return 2
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "pqprobe: no target to probe")
		return 2
	}

	if *perGroup {
		sel = append(sel, clientprofile.GroupProbes()...)
	}
	if *sizeSweep {
		sel = append(sel, clientprofile.SizeProbes()...)
	}
	if *alpnCheck {
		sel = append(sel, clientprofile.ALPNProbe())
	}
	if len(echList) > 0 {
		sel = append(sel, clientprofile.ECHProbes(echList)...)
	}
	if *groupSet != "" {
		custom, unknown := clientprofile.CustomProfile(splitList(*groupSet))
		if len(unknown) > 0 {
			// Not a smaller set silently dialled: that would prove something
			// other than what was asked for.
			known := make([]string, 0, len(clientprofile.Probed))
			for _, id := range clientprofile.Probed {
				known = append(known, clientprofile.GroupName(id))
			}
			fmt.Fprintf(os.Stderr, "pqprobe: unknown group(s): %s (have: %s)\n",
				strings.Join(unknown, ", "), strings.Join(known, ", "))
			return 2
		}
		sel = append(sel, custom)
	}

	// The names are kept, so the pool can be reported per name after the run.
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.ServerName()
	}
	if *network != "" && *socks5 != "" {
		// Truthful about what the flag can still do: the second hop is the
		// proxy's to make, and claiming the endpoint was reached over one
		// family would be a claim about somebody else's routing table.
		fmt.Fprintf(os.Stderr,
			"pqprobe: --net %s applies to the connection to the SOCKS5 proxy; which family the proxy uses to reach the endpoint is its own choice\n", *network)
	}
	if *perAddress && *socks5 != "" {
		fmt.Fprintln(os.Stderr,
			"pqprobe: --per-address resolves names on this host, which is the opposite of what --socks5 is for; the addresses it finds may not be the ones the proxy would reach")
	}
	if *perAddress {
		resolver := probe.Resolver(net.DefaultResolver)
		if r := probe.ResolverAt(*dns); r != nil {
			resolver = r
		}
		expanded, errs := probe.ExpandAddresses(context.Background(), resolver, targets, *network)
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, "pqprobe:", err)
		}
		targets = expanded
		names = make([]string, len(targets))
		for i, t := range targets {
			names[i] = t.ServerName()
		}
	}

	dialer := probe.Dialer{Timeout: *timeout, ALPN: splitList(*alpn), Confirm: *confirm, Socks5: *socks5,
		StartTLS: *starttls, Net: *network, Resolver: probe.ResolverAt(*dns)}
	opt := verdict.DefaultOptions()
	opt.ExpiryWarnDays, opt.ExpiryBadDays = *expWarn, *expBad
	opt.Now = time.Now()

	// The ECH configs are looked up once, before the run: a --watch that
	// re-queried DNS every tick would report a config change as an endpoint
	// change, which is a different finding from the one it looks like.
	profilesFor := func(probe.Target) []clientprofile.Profile { return sel }
	if *echLookup {
		profilesFor = echProfilesFor(context.Background(), os.Stderr, targets, *dns, sel)
	}

	reps := run(context.Background(), dialer, targets, profilesFor, opt, *concurrency)
	if *perAddress {
		addressFindings(names, reps)
	}
	netFindings(*network, reps)
	resolverFindings(*dns, reps)
	egressFindings(reps, *network, probe.HasEgress)

	// The baseline is read *after* the probe: a run that produced findings must
	// still print them if the comparison cannot be made.
	if *baseline != "" {
		if err := addTransitions(*baseline, reps); err != nil {
			fmt.Fprintln(os.Stderr, "pqprobe:", err)
		}
	}

	var err error
	switch {
	case *asMarkdown:
		err = output.Markdown(os.Stdout, reps, finding.Status(*minSev))
	case asFindings.on && asFindings.wrapped:
		err = output.FindingsWrapped(os.Stdout, reps, finding.Status(*minSev))
	case asFindings.on:
		err = output.Findings(os.Stdout, reps, finding.Status(*minSev))
	case *asJSON:
		err = output.JSON(os.Stdout, reps)
	default:
		if err = output.Text(os.Stdout, reps, finding.Status(*minSev)); err == nil {
			err = output.Summary(os.Stdout, reps)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}

	if *textfile != "" {
		if err := output.Textfile(*textfile, reps, time.Now()); err != nil {
			// A metrics file nobody can write is worth saying out loud, and it
			// is not a reason to lose the findings that are already on stdout.
			fmt.Fprintln(os.Stderr, "pqprobe:", err)
		}
	}

	// The first report is out; from here only what moves (PQ-13). It runs until
	// interrupted, so nothing below this line happens during a watch.
	if *watch > 0 {
		return watchLoop(context.Background(), os.Stdout, dialer, targets, profilesFor, opt,
			*concurrency, *watch, reps, *textfile)
	}

	// Exit 0 whenever the probe ran. A monitoring wrapper that treats a WARN as
	// a broken check learns to ignore the check, so the threshold is opt-in.
	if shouldExit(reps, *exitOn) {
		return 1
	}
	return 0
}

// run probes every target with every profile, bounded by concurrency.
//
// The profiles of one endpoint are dialled in sequence, deliberately: they are
// the same endpoint, and three connections landing at once is how a probe
// starts measuring a connection limit instead of a capability.
func run(ctx context.Context, d probe.Dialer, targets []probe.Target, profilesFor func(probe.Target) []clientprofile.Profile, opt verdict.Options, concurrency int) []verdict.Report {
	if concurrency < 1 {
		concurrency = 1
	}
	reps := make([]verdict.Report, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t probe.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var results []probe.Result
			sweepStopped := false
			for _, p := range profilesFor(t) {
				// Once a padded hello has gone unanswered, the sizes above it
				// are a foregone conclusion and four more connections.
				if sweepStopped && clientprofile.IsSizeProbe(p.Name) {
					continue
				}
				r := d.DoConfirmed(ctx, t, p)
				results = append(results, r)
				if clientprofile.IsSizeProbe(p.Name) && !r.OK {
					sweepStopped = true
				}
			}
			reps[i] = verdict.Evaluate(t.String(), results, opt)
		}(i, t)
	}
	wg.Wait()
	return reps
}

// collect assembles the target list from the three sources, applying the
// default port and the global SNI override.
// errStdinTwice is a usage error rather than a target that failed to parse: the
// command as written cannot do what it says, and exiting 0 with part of the
// fleet probed would look like a complete run.
var errStdinTwice = errors.New("stdin can only be read once")

// A `-` anywhere a file is expected — as an operand, as --list or as
// --inventory — means the pipe (PQ-48). The fleet is usually the output of
// something else, and requiring a temporary file first is the step people skip,
// which is how a stale list gets probed.
//
// Stdin is one stream and can be handed over exactly once: two readers would
// each get part of the list, and half a fleet probed silently is worse than an
// error.
func collect(args []string, listFile, invFile string, groups []string, port, sni string, stdin io.Reader) ([]probe.Target, []error) {
	var all []probe.Target
	var errs []error

	taken := ""
	claim := func(who string) io.Reader {
		if taken != "" {
			errs = append(errs, fmt.Errorf("%w: %s and %s both want it", errStdinTwice, taken, who))
			return nil
		}
		taken = who
		return stdin
	}

	var words []string
	for _, a := range args {
		if a != "-" {
			words = append(words, a)
			continue
		}
		if r := claim("the `-` target"); r != nil {
			ts, e := inventory.ReadList(r)
			all, errs = append(all, ts...), append(errs, e...)
		}
	}

	ts, e := inventory.ParseAll(words)
	all, errs = append(all, ts...), append(errs, e...)
	if listFile == "-" {
		if r := claim("--list -"); r != nil {
			ts, e = inventory.ReadList(r)
			all, errs = append(all, ts...), append(errs, e...)
		}
	} else if listFile != "" {
		ts, e = inventory.ReadListFile(listFile)
		all, errs = append(all, ts...), append(errs, e...)
	}
	if invFile == "-" {
		if r := claim("--inventory -"); r != nil {
			ts, e = inventory.ReadAnsibleINI(r, groups)
			all, errs = append(all, ts...), append(errs, e...)
		}
	} else if invFile != "" {
		ts, e = inventory.ReadAnsibleINIFile(invFile, groups)
		all, errs = append(all, ts...), append(errs, e...)
	}
	for i := range all {
		if port != "" && all[i].Port == inventory.DefaultPort {
			all[i].Port = port
		}
		if sni != "" {
			all[i].SNI = sni
		}
	}
	// Deduplicate: the same host in two inventory groups is one endpoint, and
	// probing it twice would double the load and the output.
	seen := map[string]bool{}
	out := all[:0]
	for _, t := range all {
		key := t.Addr() + "|" + t.SNI
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Addr() < out[j].Addr() })
	return out, errs
}

// validECHFlags refuses the two sources of an ECH config at once.
//
// They answer different questions — one asks what this endpoint publishes, the
// other what happens when it is offered a config somebody chose — and a silent
// precedence rule would report a run as if it had asked the other one.
func validECHFlags(list []byte, lookup bool) error {
	if len(list) > 0 && lookup {
		return errors.New("--ech takes the config from each endpoint's HTTPS record and --ech-config takes the one you pass; pick one, because they answer different questions")
	}
	return nil
}

// echProfilesFor looks up the ECH config of every distinct server name and
// returns the profile set each target should be dialled with (PQ-51).
//
// One lookup per *name*, not per target: a fleet behind one CDN resolves to the
// same record many times over, and a run that asked once per address would be a
// small DNS flood nobody asked for. A name with nothing published keeps the
// ordinary profile set and says so once — most endpoints are in that state, and
// it is not a failure of anything.
func echProfilesFor(ctx context.Context, w io.Writer, targets []probe.Target, at string,
	base []clientprofile.Profile) func(probe.Target) []clientprofile.Profile {

	byName := map[string][]clientprofile.Profile{}
	for _, t := range targets {
		name := t.ServerName()
		if _, done := byName[name]; done {
			continue
		}
		if net.ParseIP(name) != nil {
			fmt.Fprintf(w, "pqprobe: %s has no name to look up an ECH config for; dial it with =sni or pass --ech-config\n", name)
			byName[name] = base
			continue
		}
		list, err := probe.LookupECHConfig(ctx, at, name)
		if err != nil {
			fmt.Fprintln(w, "pqprobe:", err)
			byName[name] = base
			continue
		}
		byName[name] = append(append([]clientprofile.Profile{}, base...), clientprofile.ECHProbes(list)...)
	}
	return func(t probe.Target) []clientprofile.Profile {
		if ps, ok := byName[t.ServerName()]; ok {
			return ps
		}
		return base
	}
}

// parseECHConfig decodes the base64 ECHConfigList --ech-config takes — the
// value an HTTPS DNS record publishes as `ech=` (PQ-50).
//
// It is validated here because this is pqprobe's *own* input, and it is the one
// thing that can be checked before anything is dialled: a paste that is not a
// config list would otherwise fail inside the handshake, where the report reads
// as though the endpoint had done something wrong.
func parseECHConfig(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("--ech-config is not base64: %w (it is the `ech=` value of the endpoint's HTTPS DNS record)", err)
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("--ech-config decodes to %d bytes, which is too short for an ECHConfigList", len(raw))
	}
	if n := int(raw[0])<<8 | int(raw[1]); n != len(raw)-2 {
		return nil, fmt.Errorf("--ech-config says it carries %d bytes of configs and has %d: that is not an ECHConfigList", n, len(raw)-2)
	}
	return raw, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// validExitOn accepts either vocabulary --exit-on speaks (PQ-56).
//
// A severity threshold answers "fail on anything this bad or worse", which is
// what a fleet gate usually wants. A class answers "fail on *this*", which is
// what a pipeline that cares about one finding wants — `--exit-on BAD` also
// fires on a certificate about to expire and on whatever BAD ships next, and a
// gate that fires for reasons its author did not choose gets switched off.
func validExitOn(s string) error {
	if s == "" {
		return nil
	}
	if validStatus(s) == nil {
		return nil
	}
	if _, ok := verdict.Explain(verdict.Class(s)); ok {
		return nil
	}
	classes := make([]string, 0, len(verdict.Classes()))
	for _, c := range verdict.Classes() {
		classes = append(classes, string(c))
	}
	return fmt.Errorf("bad --exit-on %q: want a status (OK, WARN, BAD, ERROR) or a class (%s)",
		s, strings.Join(classes, ", "))
}

// shouldExit reports whether --exit-on is satisfied by this run. A status is a
// threshold — at or above; a class is exact, because classes are not a scale
// and pretending they were would make `--exit-on pq-blind` fire on something
// worse and call it the same thing.
func shouldExit(reps []verdict.Report, exitOn string) bool {
	if exitOn == "" {
		return false
	}
	if validStatus(exitOn) == nil {
		for _, r := range reps {
			if finding.AtLeast(r.Worst(), finding.Status(exitOn)) {
				return true
			}
		}
		return false
	}
	for _, r := range reps {
		if string(r.Class) == exitOn {
			return true
		}
	}
	return false
}

func validStatus(s string) error {
	switch finding.Status(s) {
	case "", finding.OK, finding.WARN, finding.BAD, finding.ERROR:
		return nil
	}
	return fmt.Errorf("bad status %q: want OK, WARN, BAD or ERROR", s)
}

// permute moves flags ahead of operands, because Go's flag package stops at
// the first non-flag argument and `pqprobe probe host --json` is the form
// everybody types.
func permute(args []string) []string {
	var flags, operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		// A lone `-` is the pipe, which is a target and not a flag (PQ-48).
		case a == "-":
			operands = append(operands, a)
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			// A flag that takes a value may be written as two words. Only
			// consume the next word when this flag has no "=" in it and the
			// next word is not itself a flag.
			// `-` is a legitimate *value* for the flags that take a file, and
			// a target on its own; both spellings mean the pipe.
			if !strings.Contains(a, "=") && i+1 < len(args) && takesValue(a) &&
				(args[i+1] == "-" || !strings.HasPrefix(args[i+1], "-")) {
				flags = append(flags, args[i+1])
				i++
			}
		default:
			operands = append(operands, a)
		}
	}
	return append(flags, operands...)
}

// takesValue is the list of value-taking flags, kept next to the flag
// definitions above. A boolean flag must not swallow the target that follows
// it: `pqprobe probe --json host` would otherwise probe nothing.
func takesValue(flagArg string) bool {
	name := strings.TrimLeft(flagArg, "-")
	switch name {
	case "profile", "inventory", "group", "list", "port", "sni", "alpn",
		"timeout", "concurrency", "min-severity", "exit-on", "expiry-warn", "expiry-bad",
		"baseline", "groups", "socks5", "watch", "textfile", "starttls", "net",
		"ech-config", "dns":
		return true
	}
	return false
}
