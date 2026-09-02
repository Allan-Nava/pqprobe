package main

import (
	"reflect"
	"strings"
	"testing"

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
		"--markdown", "--socks5",
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
