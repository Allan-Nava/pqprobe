package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// Go's flag package stops at the first operand, so `probe host --json` would
// otherwise parse as "no flags, two targets" — and "no such target: --json" is
// a confusing way to learn that.
func TestPermuteMovesFlagsAhead(t *testing.T) {
	got := permute([]string{"host.example", "--json", "--timeout", "3s", "other.example"})
	want := []string{"--json", "--timeout", "3s", "host.example", "other.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

// A boolean flag must not swallow the target that follows it.
func TestPermuteDoesNotConsumeATargetAfterABoolFlag(t *testing.T) {
	got := permute([]string{"--json", "host.example"})
	want := []string{"--json", "host.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

func TestPermuteStopsAtDoubleDash(t *testing.T) {
	got := permute([]string{"--json", "--", "--weird-host"})
	want := []string{"--json", "--weird-host"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

func TestValidStatus(t *testing.T) {
	for _, ok := range []string{"", "OK", "WARN", "BAD", "ERROR"} {
		if err := validStatus(ok); err != nil {
			t.Fatalf("validStatus(%q) = %v", ok, err)
		}
	}
	if err := validStatus("warn"); err == nil {
		t.Fatal("statuses are upper case; a silently accepted lower-case one filters nothing")
	}
}

// PQ-35. --socks5 takes an address, and the name of the flag is the promise:
// no --proxy, because HTTP CONNECT is a request and this tool does not send
// requests.
func TestSocks5TakesAValueAndIsNotCalledProxy(t *testing.T) {
	if !takesValue("--socks5") {
		t.Fatal("--socks5 takes host:port")
	}
	if takesValue("--proxy") {
		t.Fatal("there is no --proxy: CONNECT is a request, and the flag name has to say what is supported")
	}
	got := permute([]string{"origin.example", "--socks5", "127.0.0.1:1080"})
	want := []string{"--socks5", "127.0.0.1:1080", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

// PQ-27. --markdown is a boolean and one of the mutually exclusive renderers:
// two documents on one stdout is not a document.
func TestMarkdownIsABooleanFlag(t *testing.T) {
	if takesValue("--markdown") {
		t.Fatal("--markdown takes no value")
	}
	got := permute([]string{"--markdown", "origin.example"})
	if len(got) != 2 || got[1] != "origin.example" {
		t.Fatalf("permute = %v, want the target kept as an operand", got)
	}
}

// PQ-34. --groups takes a list, so permute has to consume the word after it —
// otherwise the group list becomes a target and pqprobe tries to resolve
// "X25519MLKEM768,X25519" as a hostname.
func TestGroupsTakesAValue(t *testing.T) {
	if !takesValue("--groups") {
		t.Fatal("--groups takes a list")
	}
	got := permute([]string{"origin.example", "--groups", "X25519MLKEM768,X25519"})
	want := []string{"--groups", "X25519MLKEM768,X25519", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

// --group (inventory groups) and --groups (key exchange groups) are one letter
// apart and mean completely different things. Both exist because both names are
// the obvious one for their job — so the difference is asserted, since a silent
// mix-up would probe the wrong hosts with the wrong hello.
func TestGroupAndGroupsAreBothFlagsAndBothTakeValues(t *testing.T) {
	if !takesValue("--group") || !takesValue("--groups") {
		t.Fatal("both take a value")
	}
}

// PQ-25. --alpn-check is a boolean: it adds exactly one handshake, the same
// client carrying a realistic protocol list.
func TestALPNCheckIsABooleanFlag(t *testing.T) {
	if takesValue("--alpn-check") {
		t.Fatal("--alpn-check takes no value")
	}
	got := permute([]string{"--alpn-check", "origin.example"})
	if len(got) != 2 || got[1] != "origin.example" {
		t.Fatalf("permute = %v, want the target kept as an operand", got)
	}
}

// PQ-11. --size-sweep is a boolean, and the sweep stops at the first size the
// peer will not answer: the bracket is the answer, and dialling four more sizes
// past a wall proves nothing.
func TestSizeSweepIsABooleanFlag(t *testing.T) {
	if takesValue("--size-sweep") {
		t.Fatal("--size-sweep takes no value")
	}
	got := permute([]string{"--size-sweep", "origin.example"})
	if len(got) != 2 || got[1] != "origin.example" {
		t.Fatalf("permute = %v, want the target kept as an operand", got)
	}
}

// PQ-24. --baseline takes a path, so permute must consume the word after it or
// the file name becomes a target and the run probes a JSON file.
func TestBaselineTakesAValue(t *testing.T) {
	if !takesValue("--baseline") {
		t.Fatal("--baseline takes a file")
	}
	got := permute([]string{"origin.example", "--baseline", "yesterday.json"})
	want := []string{"--baseline", "yesterday.json", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

// PQ-12. --per-address turns one name into one target per A/AAAA record, so it
// multiplies the connections a run makes: off by default, and a boolean.
func TestPerAddressIsABooleanFlag(t *testing.T) {
	if takesValue("--per-address") {
		t.Fatal("--per-address takes no value")
	}
	got := permute([]string{"--per-address", "origin.example"})
	if len(got) != 2 || got[1] != "origin.example" {
		t.Fatalf("permute = %v, want the target kept as an operand", got)
	}
}

// PQ-23. --confirm is a boolean too, and it defaults to on: the second dial
// only ever happens on an abrupt failure, so a healthy fleet pays nothing for
// it, and a BAD verdict nobody can reproduce costs an afternoon.
func TestConfirmIsABooleanFlag(t *testing.T) {
	if takesValue("--confirm") {
		t.Fatal("--confirm takes no value; it is turned off with --confirm=false")
	}
	got := permute([]string{"--confirm", "example.com"})
	if len(got) != 2 || got[1] != "example.com" {
		t.Fatalf("permute = %v, want the target kept as an operand", got)
	}
}

// PQ-22. --per-group is a boolean, so permute must not eat the target after it:
// `pqprobe probe --per-group example.com` has to stay a probe of example.com,
// not a probe of nothing with a value of "example.com".
func TestPerGroupIsABooleanFlag(t *testing.T) {
	if takesValue("--per-group") {
		t.Fatal("--per-group takes no value")
	}
	got := permute([]string{"--per-group", "example.com"})
	want := []string{"--per-group", "example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("permute = %v, want %v", got, want)
	}
}

// The flag has to be in --help. A capability nobody can find is not delivered:
// the same rule that puts a new profile in the README puts it here.
func TestUsageDocumentsEveryFlagTheProbeAccepts(t *testing.T) {
	var b strings.Builder
	usageTo(&b)
	for _, flag := range []string{
		"--profile", "--per-group", "--inventory", "--group", "--list", "--port",
		"--sni", "--alpn", "--timeout", "--concurrency", "--json", "--findings",
		"--min-severity", "--exit-on", "--expiry-warn", "--expiry-bad", "--confirm",
		"--per-address", "--baseline", "--size-sweep", "--alpn-check", "--groups",
		"--markdown", "--socks5", "--textfile",
	} {
		if !strings.Contains(b.String(), flag) {
			t.Errorf("%s is not in --help", flag)
		}
	}
}

// PQ-28. `explain` is the one command that needs no network, so it is also the
// one an operator can run while the incident is still on.
func TestExplainWritesTheClassOut(t *testing.T) {
	var b strings.Builder
	if code := explainTo(&b, []string{"pq-intolerant"}); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	out := b.String()
	for _, want := range []string{"pq-intolerant", "BAD", "Chrome", "size-sweep"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from the explanation:\n%s", want, out)
		}
	}
}

// No argument lists every class, so somebody who half-remembers the word can
// find it.
func TestExplainWithNoArgumentListsThemAll(t *testing.T) {
	var b strings.Builder
	if code := explainTo(&b, nil); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, c := range verdict.Classes() {
		if !strings.Contains(b.String(), string(c)) {
			t.Errorf("%s is not in the list", c)
		}
	}
}

// A word that is not a class is a usage error that says what the words are —
// not a shrug.
func TestExplainingNonsenseIsAUsageError(t *testing.T) {
	var b strings.Builder
	code := explainTo(&b, []string{"pq-maybe"})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(b.String(), "pq-intolerant") {
		t.Errorf("the error has to list the classes: %q", b.String())
	}
}

// A leading -- is what somebody types out of habit, and refusing it teaches
// nothing.
func TestExplainToleratesADashedClass(t *testing.T) {
	var b strings.Builder
	if code := explainTo(&b, []string{"--pq-blind"}); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(b.String(), "pq-blind") {
		t.Errorf("output = %q", b.String())
	}
}

// A fixed clock, so a transition line is assertable: the timestamp is what a
// reader uses to line the change up against whatever they were doing to the
// load balancer at the time.
var watchAt = time.Date(2026, 9, 3, 12, 34, 56, 0, time.UTC)

// PQ-15. --textfile is a side output, not a renderer: it writes a file for a
// node exporter and leaves stdout to whichever renderer was asked for, so it
// combines with all of them — including --watch, where a file rewritten on
// every tick is exactly what a scrape wants.
func TestTextfileTakesAPathAndIsNotARenderer(t *testing.T) {
	if !takesValue("--textfile") {
		t.Fatal("--textfile takes a path")
	}
	got := permute([]string{"origin.example", "--textfile", "/var/lib/node_exporter/pqprobe.prom"})
	want := []string{"--textfile", "/var/lib/node_exporter/pqprobe.prom", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}
	// It is not one of the document renderers, so --watch must not refuse it.
	if err := validWatchOutput(time.Minute, ""); err != nil {
		t.Errorf("--watch with a textfile and the text renderer has to be allowed: %v", err)
	}
}

// PQ-13. Watch mode exists for the window in which a CDN or a load balancer is
// being changed, and in that window the only interesting output is what moved.
// So a tick that found nothing prints nothing.
func TestAWatchTickPrintsOnlyWhatMoved(t *testing.T) {
	same := []verdict.Report{
		{Target: "a:443", Class: verdict.PQReady},
		{Target: "b:443", Class: verdict.PQBlind},
	}

	var b strings.Builder
	if n := watchTick(&b, same, same, watchAt); n != 0 {
		t.Errorf("printed %d transitions for an unchanged fleet", n)
	}
	if b.String() != "" {
		t.Errorf("a quiet tick has to be silent, got %q", b.String())
	}
}

func TestAWatchTickNamesTheChangeAndTheTime(t *testing.T) {
	before := []verdict.Report{{Target: "a:443", Class: verdict.PQReady}}
	after := []verdict.Report{{Target: "a:443", Class: verdict.PQIntolerant}}

	var b strings.Builder
	n := watchTick(&b, before, after, watchAt)
	if n != 1 {
		t.Fatalf("printed %d transitions, want 1", n)
	}
	out := b.String()
	for _, want := range []string{"a:443", "pq-ready", "pq-intolerant", "12:34:56"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from %q", want, out)
		}
	}
}

// An endpoint that appears or vanishes mid-watch is exactly the kind of thing
// somebody is watching for while a pool is being drained.
func TestAWatchTickReportsAppearanceAndDisappearance(t *testing.T) {
	var b strings.Builder
	n := watchTick(&b,
		[]verdict.Report{{Target: "gone:443", Class: verdict.PQReady}},
		[]verdict.Report{{Target: "new:443", Class: verdict.PQReady}},
		watchAt)
	if n != 2 {
		t.Fatalf("printed %d, want both the appearance and the disappearance", n)
	}
	if !strings.Contains(b.String(), "gone:443") || !strings.Contains(b.String(), "new:443") {
		t.Errorf("output = %q", b.String())
	}
}

// The interval is a rate against somebody's production endpoint. A floor is not
// paternalism: --watch 100ms is a mistake, and the tool should say so rather
// than obey.
func TestAWatchIntervalBelowTheFloorIsRefused(t *testing.T) {
	if err := validWatch(0); err != nil {
		t.Errorf("zero means no watch at all, not an error: %v", err)
	}
	if err := validWatch(100 * time.Millisecond); err == nil {
		t.Error("100ms against a production endpoint has to be refused")
	}
	if err := validWatch(watchFloor); err != nil {
		t.Errorf("the floor itself has to be allowed: %v", err)
	}
	if err := validWatch(5 * time.Minute); err != nil {
		t.Errorf("a sane interval was refused: %v", err)
	}
}

// A stream of documents is not a document: --watch prints transitions as lines,
// so combining it with a renderer that emits one whole document is a usage
// error rather than a surprise halfway through a pipe.
func TestWatchRefusesTheDocumentRenderers(t *testing.T) {
	if takesValue("--watch") != true {
		t.Fatal("--watch takes a duration")
	}
	for _, r := range []string{"json", "findings", "markdown"} {
		if err := validWatchOutput(time.Minute, r); err == nil {
			t.Errorf("--watch with --%s should be refused", r)
		}
	}
	if err := validWatchOutput(time.Minute, ""); err != nil {
		t.Errorf("--watch with the text renderer is the point: %v", err)
	}
	if err := validWatchOutput(0, "json"); err != nil {
		t.Errorf("without --watch every renderer is fine: %v", err)
	}
}

// PQ-38. `pqprobe version` prints name *and* version, so anybody embedding it
// in a generated header gets "pqprobe pqprobe 0.19.1" — and the subcommand
// ignored its flags, so there was no way to ask for less.
func TestVersionCanBeEmbedded(t *testing.T) {
	var b strings.Builder
	if code := versionTo(&b, nil, "1.2.3"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := strings.TrimSpace(b.String()); got != "pqprobe 1.2.3" {
		t.Errorf("bare version = %q, want the human form unchanged", got)
	}

	b.Reset()
	if code := versionTo(&b, []string{"--short"}, "1.2.3"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := strings.TrimSpace(b.String()); got != "1.2.3" {
		t.Errorf("--short = %q, want the version and nothing else", got)
	}

	// -s, because anybody typing this is embedding it in a script.
	b.Reset()
	versionTo(&b, []string{"-s"}, "1.2.3")
	if got := strings.TrimSpace(b.String()); got != "1.2.3" {
		t.Errorf("-s = %q", got)
	}
}

// Ignoring a flag is the bug: `version --help` printed the version and said
// nothing about what it accepts.
func TestVersionDoesNotIgnoreItsFlags(t *testing.T) {
	var b strings.Builder
	if code := versionTo(&b, []string{"--help"}, "1.2.3"); code != 0 {
		t.Fatalf("--help exit = %d, want 0", code)
	}
	if !strings.Contains(b.String(), "--short") {
		t.Errorf("--help has to say what version accepts: %q", b.String())
	}

	b.Reset()
	code := versionTo(&b, []string{"--sohrt"}, "1.2.3")
	if code != 2 {
		t.Errorf("exit = %d for an unknown flag, want 2 — silently printing the version is how the typo survives", code)
	}
	if !strings.Contains(b.String(), "--short") {
		t.Errorf("the error has to name the real flag: %q", b.String())
	}
}

// PQ-37. --findings has to keep working exactly as it did — a bare flag
// producing the flat array — while --findings=wrapped selects the wrapped
// shape. So it is a value that also answers to being used as a boolean.
func TestFindingsFlagKeepsWorkingAndTakesAShape(t *testing.T) {
	var f findingsFormat

	// Bare: what every existing caller writes.
	if err := f.Set("true"); err != nil {
		t.Fatalf("bare --findings: %v", err)
	}
	if !f.on || f.wrapped {
		t.Errorf("bare --findings = %+v, want the flat array", f)
	}
	if !f.IsBoolFlag() {
		t.Error("--findings has to be usable without a value, or every existing command line breaks")
	}

	f = findingsFormat{}
	if err := f.Set("wrapped"); err != nil {
		t.Fatalf("--findings=wrapped: %v", err)
	}
	if !f.on || !f.wrapped {
		t.Errorf("--findings=wrapped = %+v", f)
	}

	f = findingsFormat{}
	if err := f.Set("flat"); err != nil {
		t.Fatalf("--findings=flat: %v", err)
	}
	if !f.on || f.wrapped {
		t.Errorf("--findings=flat = %+v", f)
	}

	// A typo must name the choices rather than picking one.
	f = findingsFormat{}
	err := f.Set("wrappd")
	if err == nil {
		t.Fatal("a shape that does not exist has to be refused")
	}
	if !strings.Contains(err.Error(), "wrapped") || !strings.Contains(err.Error(), "flat") {
		t.Errorf("the error has to list the shapes: %v", err)
	}

	// And it must not eat the target after it: `--findings example.com`.
	if takesValue("--findings") {
		t.Error("--findings takes its value with an =, so permute must not consume the next word")
	}
	got := permute([]string{"--findings", "example.com"})
	if len(got) != 2 || got[1] != "example.com" {
		t.Fatalf("permute = %v, want the target kept as an operand", got)
	}
}

// PQ-20. --starttls names the protocol whose plaintext negotiation reaches TLS.
// An unknown one is a usage error: a plain TLS dial that fails on port 587 for
// a reason nobody can see is worse than being told now.
func TestStartTLSFlagTakesAProtocolAndValidatesIt(t *testing.T) {
	if !takesValue("--starttls") {
		t.Fatal("--starttls takes a protocol")
	}
	got := permute([]string{"mx.example:587", "--starttls", "smtp"})
	want := []string{"--starttls", "smtp", "mx.example:587"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}

	if !probe.ValidStartTLS("") {
		t.Error("no --starttls means implicit TLS, which is every other port")
	}
	for _, p := range probe.StartTLSProtocols() {
		if !probe.ValidStartTLS(p) {
			t.Errorf("%s is listed but not accepted", p)
		}
	}
	if probe.ValidStartTLS("gopher") {
		t.Error("gopher is not one of them")
	}

	var b strings.Builder
	usageTo(&b)
	if !strings.Contains(b.String(), "--starttls") {
		t.Error("--starttls is not in --help")
	}
	for _, p := range probe.StartTLSProtocols() {
		if !strings.Contains(b.String(), p) {
			t.Errorf("--help does not list %s", p)
		}
	}
}

// The gate for the mistake that actually happened twice in this repository: an
// edit that silently did not land. A flag declared and never mentioned in
// --help, or documented and never declared, is invisible until somebody tries
// to use it — so the correspondence is asserted in both directions, from the
// flag set itself rather than from a list a human keeps in step.
func TestEveryProbeFlagIsDocumentedAndEveryDocumentedFlagExists(t *testing.T) {
	fs, _ := newProbeFlags()

	var help strings.Builder
	usageTo(&help)
	text := help.String()

	declared := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		declared[f.Name] = true
		if !strings.Contains(text, "--"+f.Name) {
			t.Errorf("--%s is declared but absent from --help: nobody will find it", f.Name)
		}
	})
	if len(declared) < 20 {
		t.Fatalf("only %d flags enumerated; the flag set is not being read", len(declared))
	}

	// The other direction: every --flag the help promises has to exist, or the
	// help is a list of things that do nothing.
	for _, word := range strings.Fields(strings.ReplaceAll(text, "=", " ")) {
		name := strings.TrimPrefix(word, "--")
		if name == word || name == "" {
			continue
		}
		// The help writes optional values as --findings[=SHAPE]; the flag is
		// still called findings.
		name = strings.TrimRight(name, ".,:;")
		if i := strings.IndexAny(name, "[]="); i >= 0 {
			name = name[:i]
		}
		// The help also names flags of the subcommands, which have their own
		// sets; those are asserted where they live.
		if name == "short" || name == "help" || name == "version" {
			continue
		}
		if !declared[name] {
			t.Errorf("--help documents --%s, which the probe does not accept", name)
		}
	}
}

// PQ-46. --net takes an address family, and an unknown one is a usage error:
// a run that quietly used both families answers a different question from the
// one that was asked, and nothing in the output would say so.
func TestNetFlagTakesAFamilyAndValidatesIt(t *testing.T) {
	if !takesValue("--net") {
		t.Fatal("--net takes an address family")
	}
	got := permute([]string{"origin.example", "--net", "tcp6"})
	want := []string{"--net", "tcp6", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}

	var b strings.Builder
	usageTo(&b)
	if !strings.Contains(b.String(), "--net") {
		t.Error("--net is not in --help")
	}
	for _, n := range probe.Nets() {
		if !strings.Contains(b.String(), n) {
			t.Errorf("--help does not list %s", n)
		}
	}
}

// The family the run could use belongs in the report, not only in the flag: a
// run pinned to IPv4 that says nothing reads afterwards as "IPv6 is fine", and
// that is the reading this item exists to remove.
func TestTheSelectedFamilyIsStatedInTheReport(t *testing.T) {
	reps := []verdict.Report{{Target: "origin.example:443"}, {Target: "other.example:443"}}
	netFindings("tcp4", reps)

	for _, r := range reps {
		var f *finding.Finding
		for i := range r.Finding {
			if r.Finding[i].Check == "net" {
				f = &r.Finding[i]
			}
		}
		if f == nil {
			t.Fatalf("%s has no `net` finding: the pinned family is invisible in every renderer", r.Target)
		}
		if f.Status != finding.OK {
			t.Errorf("status = %s, want OK: a flag the operator passed is not a problem with the endpoint", f.Status)
		}
		if !strings.Contains(f.Message, "IPv4") {
			t.Errorf("message = %q, want the family in words", f.Message)
		}
	}

	// The default run is unpinned, and a finding on every endpoint of every run
	// saying "both families" is noise nobody reads.
	quiet := []verdict.Report{{Target: "origin.example:443"}}
	netFindings("", quiet)
	if len(quiet[0].Finding) != 0 {
		t.Fatalf("got %+v, want nothing said when no family was pinned", quiet[0].Finding)
	}
}

// PQ-47. A workstation without IPv6 egress produces one `unroutable` per AAAA
// record across the whole fleet: forty findings that are all the same local
// fact, burying the one finding that is about an endpoint. PQ-12 already
// refused to call those a property of the peer — this is the volume half.
func TestNoEgressIsStatedOnceAndTheEndpointsAreAttributedToIt(t *testing.T) {
	unroutable := []probe.Result{{Profile: "classic", Kind: probe.KindUnroutable, Err: "no route to host"}}
	reps := []verdict.Report{
		{Target: "[2001:db8::1]:443", Class: verdict.Unreachable, Results: unroutable,
			Finding: []finding.Finding{{Check: "verdict", Target: "[2001:db8::1]:443", Status: finding.ERROR, Hint: "an IPv6 address probed from a machine without IPv6 egress is the usual cause"}}},
		{Target: "[2001:db8::2]:443", Class: verdict.Unreachable, Results: unroutable,
			Finding: []finding.Finding{{Check: "verdict", Target: "[2001:db8::2]:443", Status: finding.ERROR, Hint: "an IPv6 address probed from a machine without IPv6 egress is the usual cause"}}},
		{Target: "192.0.2.9:443", Class: verdict.PQReady},
	}

	// No IPv6 egress from here, and the endpoints are somebody else's.
	egressFindings(reps, "", func(network string) bool { return network == "tcp4" })

	n := 0
	var note finding.Finding
	for _, r := range reps {
		for _, f := range r.Finding {
			if f.Check == "egress" {
				n++
				note = f
			}
		}
	}
	if n != 1 {
		t.Fatalf("got %d `egress` findings, want exactly one: saying the same local fact per endpoint is the noise this removes", n)
	}
	if note.Value == nil || *note.Value != 2 {
		t.Fatalf("value = %v, want 2 endpoints affected — a machine consumer must not parse the message", note.Value)
	}
	if note.Unit != "endpoints" {
		t.Errorf("unit = %q, want endpoints", note.Unit)
	}
	if !strings.Contains(note.Message, "IPv6") {
		t.Errorf("message = %q, want the family named", note.Message)
	}
	if note.Status != finding.ERROR {
		t.Errorf("status = %s, want ERROR: nothing could be concluded about those endpoints", note.Status)
	}

	// And the endpoints point at it instead of each guessing the cause again.
	for _, r := range reps[:2] {
		for _, f := range r.Finding {
			if f.Check == "verdict" && strings.Contains(f.Hint, "usual cause") {
				t.Errorf("%s still guesses at the cause: it is established now, and said once", r.Target)
			}
		}
	}

	// A prober that does have the route says nothing: the addresses are then
	// genuinely unreachable, which is a statement about them and already made.
	quiet := []verdict.Report{{Target: "[2001:db8::1]:443", Class: verdict.Unreachable, Results: unroutable}}
	egressFindings(quiet, "", func(string) bool { return true })
	for _, f := range quiet[0].Finding {
		if f.Check == "egress" {
			t.Fatal("the route exists here; blaming this prober would send somebody to fix the wrong machine")
		}
	}

	// A name dialled unpinned cannot be attributed to a family — Go tried every
	// address it resolved to — but with --net the family is known, so the same
	// fleet of names gets the note.
	names := []verdict.Report{
		{Target: "origin.example:443", Class: verdict.Unreachable, Results: unroutable},
		{Target: "other.example:443", Class: verdict.Unreachable, Results: unroutable},
	}
	egressFindings(names, "", func(string) bool { return false })
	for _, r := range names {
		for _, f := range r.Finding {
			if f.Check == "egress" {
				t.Fatal("an unpinned name says nothing about which family is missing; blaming one would be a guess in a report")
			}
		}
	}
	egressFindings(names, "tcp6", func(string) bool { return false })
	got := 0
	for _, r := range names {
		for _, f := range r.Finding {
			if f.Check == "egress" {
				got++
			}
		}
	}
	if got != 1 {
		t.Fatalf("got %d `egress` findings for a pinned run, want exactly one", got)
	}

	// A healthy fleet pays nothing at all — not even the local check.
	asked := false
	healthy := []verdict.Report{{Target: "192.0.2.9:443", Class: verdict.PQReady}}
	egressFindings(healthy, "", func(string) bool { asked = true; return true })
	if asked {
		t.Error("no target was unroutable; there is nothing to explain and nothing to check")
	}
	if len(healthy[0].Finding) != 0 {
		t.Errorf("got %+v, want silence", healthy[0].Finding)
	}
}

// PQ-48. The fleet that needs probing is usually the output of something else —
// a dig, a Consul query, an awk over a config — and today that has to become a
// temporary file first, which is the step people skip and how a stale list gets
// probed.
func TestTargetsComeFromStdin(t *testing.T) {
	// `-` is an operand, not a flag: permute must not file it with the flags,
	// and it must not be eaten as the value of the flag before it.
	got := permute([]string{"--json", "-"})
	if !reflect.DeepEqual(got, []string{"--json", "-"}) {
		t.Fatalf("permute = %v, want the dash kept as an operand", got)
	}
	got = permute([]string{"--port", "8443", "-"})
	if !reflect.DeepEqual(got, []string{"--port", "8443", "-"}) {
		t.Fatalf("permute = %v, want the dash kept as an operand", got)
	}

	// ...but it *is* a legitimate value for a flag that takes a file, and the
	// two spellings must not disagree about what they mean.
	got = permute([]string{"example.com", "--list", "-"})
	if !reflect.DeepEqual(got, []string{"--list", "-", "example.com"}) {
		t.Fatalf("permute = %v, want --list to keep its dash", got)
	}

	in := strings.NewReader("# a fleet\norigin.example:8443\n\n192.0.2.7=origin.example\n")
	targets, errs := collect([]string{"-"}, "", "", nil, "443", "", in)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(targets) != 2 {
		t.Fatalf("got %+v, want the two targets from the pipe", targets)
	}
	for _, tg := range targets {
		if tg.ServerName() != "origin.example" {
			t.Errorf("%s: server name = %q, want the same parsing as a file", tg, tg.ServerName())
		}
	}

	// The same through --list, because a pipe is a file that happens to have no
	// name and nobody should have to remember which spelling works.
	targets, errs = collect(nil, "-", "", nil, "443", "", strings.NewReader("origin.example\n"))
	if len(errs) != 0 || len(targets) != 1 {
		t.Fatalf("got %+v / %v, want the list read from stdin", targets, errs)
	}

	// And an inventory, which is the form a fleet actually arrives in.
	targets, errs = collect(nil, "", "-", []string{"web"}, "443", "",
		strings.NewReader("[web]\nnode1 ansible_host=192.0.2.10\n"))
	if len(errs) != 0 || len(targets) != 1 || targets[0].Host != "192.0.2.10" {
		t.Fatalf("got %+v / %v, want ansible_host from the piped inventory", targets, errs)
	}

	// Stdin is one stream: two readers of it would each get half a list, and
	// half a fleet probed is worse than an error.
	_, errs = collect([]string{"-"}, "-", "", nil, "443", "", strings.NewReader("origin.example\n"))
	if len(errs) == 0 {
		t.Fatal("two consumers of stdin must be an error, not a silently truncated fleet")
	}
	if !errors.Is(errs[0], errStdinTwice) {
		t.Fatalf("err = %v, want the usage sentinel: the command as written cannot do what it says, and a run that continued would look complete", errs[0])
	}
}

// PQ-50. --ech-config takes the base64 an HTTPS DNS record publishes. Its own
// input is the one thing pqprobe can validate before dialling, and a paste that
// is not an ECHConfigList must be a usage error: a handshake that fails for a
// reason nobody can see would be read as the endpoint's fault, which is the
// confusion this tool exists to prevent.
func TestECHConfigFlagTakesBase64AndValidatesIt(t *testing.T) {
	if !takesValue("--ech-config") {
		t.Fatal("--ech-config takes a value")
	}
	got := permute([]string{"origin.example", "--ech-config", "AEX+DQ=="})
	want := []string{"--ech-config", "AEX+DQ==", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}

	// A well-formed list: a two-byte length that covers the rest.
	list := []byte{0, 4, 0xfe, 0x0d, 0, 0}
	if _, err := parseECHConfig(base64.StdEncoding.EncodeToString(list)); err != nil {
		t.Errorf("a valid ECHConfigList was refused: %v", err)
	}
	if _, err := parseECHConfig(""); err != nil {
		t.Errorf("no flag is not an error: %v", err)
	}
	for _, bad := range []string{"not base64!", "AAAA", base64.StdEncoding.EncodeToString([]byte{0, 9, 1, 2})} {
		if _, err := parseECHConfig(bad); err == nil {
			t.Errorf("%q was accepted; a config that is not one fails later, where it reads as the endpoint's fault", bad)
		}
	}

	var b strings.Builder
	usageTo(&b)
	if !strings.Contains(b.String(), "--ech-config") {
		t.Error("--ech-config is not in --help")
	}
}

// PQ-51. `--ech` takes the config from the endpoint's own HTTPS record, which
// is the only spelling that works on a fleet. Giving both it and a pasted
// config is a usage error rather than a silent precedence rule: the two answer
// different questions, and a run that quietly picked one would be reported as
// if it had asked the other.
func TestECHLookupFlagsAreExclusiveAndDocumented(t *testing.T) {
	if takesValue("--ech") {
		t.Error("--ech takes no value: the config comes from the name being probed")
	}
	if !takesValue("--dns") {
		t.Error("--dns takes a resolver address")
	}
	got := permute([]string{"origin.example", "--ech", "--dns", "9.9.9.9:53"})
	want := []string{"--ech", "--dns", "9.9.9.9:53", "origin.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permute = %v, want %v", got, want)
	}

	if err := validECHFlags([]byte{0, 0}, true); err == nil {
		t.Error("--ech and --ech-config together must be an error")
	}
	if err := validECHFlags(nil, true); err != nil {
		t.Errorf("--ech alone: %v", err)
	}
	if err := validECHFlags([]byte{0, 0}, false); err != nil {
		t.Errorf("--ech-config alone: %v", err)
	}

	var b strings.Builder
	usageTo(&b)
	for _, f := range []string{"--ech", "--dns"} {
		if !strings.Contains(b.String(), f) {
			t.Errorf("%s is not in --help", f)
		}
	}
}
