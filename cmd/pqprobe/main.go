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
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
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
	case "version", "--version", "-v":
		fmt.Println("pqprobe", version)
		return
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "pqprobe: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
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
  pqprobe version

targets:
  host                     port 443 is assumed
  host:port
  https://host/path        the path is ignored; pqprobe sends no request
  1.2.3.4=origin.example   dial the address, send that server name (what a CDN does)

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
  --timeout D              per-handshake timeout (default 10s)
  --confirm                re-dial an abrupt failure once before believing it
                           (default true; --confirm=false to dial once)
  --concurrency N          endpoints in flight (default 8)
  --baseline FILE          compare against a previous --json run and report the
                           transitions: what changed, not what was already broken
  --json                   full report, every profile result included
  --findings               flat findings array (the toolchain contract)
  --min-severity S         hide findings below S (OK|WARN|BAD|ERROR)
  --exit-on S              exit 1 when any finding reaches S (default: never)
  --expiry-warn N          certificate expiry WARN threshold in days (default 21)
  --expiry-bad N           certificate expiry BAD threshold in days (default 7)

exit status:
  0  the probe ran (findings are output, not an error)
  1  --exit-on threshold reached
  2  usage error, or no target could be parsed

pqprobe opens TLS connections and sends no application data: no request, no
body, no credentials. It is safe to point at production, and it says nothing
about a client's exact ClientHello fingerprint — only about capability classes.
`)
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

func cmdProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		profiles    = fs.String("profile", strings.Join(clientprofile.Default, ","), "client profiles to dial")
		perGroup    = fs.Bool("per-group", false, "also dial each key exchange group on its own")
		sizeSweep   = fs.Bool("size-sweep", false, "also grow the ClientHello in steps and report the limit")
		alpnCheck   = fs.Bool("alpn-check", false, "also dial the same client with h2,http/1.1")
		groupSet    = fs.String("groups", "", "also dial exactly this key exchange group set")
		perAddress  = fs.Bool("per-address", false, "probe every A/AAAA record of each name")
		invFile     = fs.String("inventory", "", "Ansible INI inventory")
		groups      = fs.String("group", "", "inventory groups")
		listFile    = fs.String("list", "", "flat target list")
		port        = fs.String("port", inventory.DefaultPort, "default port")
		sni         = fs.String("sni", "", "server name for every target")
		alpn        = fs.String("alpn", "", "ALPN protocols")
		timeout     = fs.Duration("timeout", 10*time.Second, "per-handshake timeout")
		confirm     = fs.Bool("confirm", true, "re-dial an abrupt failure once before believing it")
		concurrency = fs.Int("concurrency", 8, "endpoints in flight")
		baseline    = fs.String("baseline", "", "compare against a previous --json run")
		asJSON      = fs.Bool("json", false, "full JSON report")
		asFindings  = fs.Bool("findings", false, "flat findings array")
		minSev      = fs.String("min-severity", "", "hide findings below this status")
		exitOn      = fs.String("exit-on", "", "exit 1 when a finding reaches this status")
		expWarn     = fs.Int("expiry-warn", 21, "certificate expiry WARN days")
		expBad      = fs.Int("expiry-bad", 7, "certificate expiry BAD days")
	)
	if err := fs.Parse(permute(args)); err != nil {
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
	if err := validStatus(*exitOn); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		return 2
	}

	targets, errs := collect(fs.Args(), *listFile, *invFile, splitList(*groups), *port, *sni)
	for _, err := range errs {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
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
	if *perAddress {
		expanded, errs := probe.ExpandAddresses(context.Background(), net.DefaultResolver, targets)
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, "pqprobe:", err)
		}
		targets = expanded
		names = make([]string, len(targets))
		for i, t := range targets {
			names[i] = t.ServerName()
		}
	}

	dialer := probe.Dialer{Timeout: *timeout, ALPN: splitList(*alpn), Confirm: *confirm}
	opt := verdict.DefaultOptions()
	opt.ExpiryWarnDays, opt.ExpiryBadDays = *expWarn, *expBad
	opt.Now = time.Now()

	reps := run(context.Background(), dialer, targets, sel, opt, *concurrency)
	if *perAddress {
		addressFindings(names, reps)
	}

	// The baseline is read *after* the probe: a run that produced findings must
	// still print them if the comparison cannot be made.
	if *baseline != "" {
		if err := addTransitions(*baseline, reps); err != nil {
			fmt.Fprintln(os.Stderr, "pqprobe:", err)
		}
	}

	var err error
	switch {
	case *asFindings:
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

	// Exit 0 whenever the probe ran. A monitoring wrapper that treats a WARN as
	// a broken check learns to ignore the check, so the threshold is opt-in.
	if *exitOn != "" {
		for _, r := range reps {
			if finding.AtLeast(r.Worst(), finding.Status(*exitOn)) {
				return 1
			}
		}
	}
	return 0
}

// run probes every target with every profile, bounded by concurrency.
//
// The profiles of one endpoint are dialled in sequence, deliberately: they are
// the same endpoint, and three connections landing at once is how a probe
// starts measuring a connection limit instead of a capability.
func run(ctx context.Context, d probe.Dialer, targets []probe.Target, profiles []clientprofile.Profile, opt verdict.Options, concurrency int) []verdict.Report {
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
			for _, p := range profiles {
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
func collect(args []string, listFile, invFile string, groups []string, port, sni string) ([]probe.Target, []error) {
	var all []probe.Target
	var errs []error

	ts, e := inventory.ParseAll(args)
	all, errs = append(all, ts...), append(errs, e...)
	if listFile != "" {
		ts, e = inventory.ReadListFile(listFile)
		all, errs = append(all, ts...), append(errs, e...)
	}
	if invFile != "" {
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

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			// A flag that takes a value may be written as two words. Only
			// consume the next word when this flag has no "=" in it and the
			// next word is not itself a flag.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && takesValue(a) {
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
		"baseline", "groups":
		return true
	}
	return false
}
