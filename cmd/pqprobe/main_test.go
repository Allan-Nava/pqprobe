package main

import (
	"reflect"
	"strings"
	"testing"
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
		"--per-address", "--baseline", "--size-sweep",
	} {
		if !strings.Contains(b.String(), flag) {
			t.Errorf("%s is not in --help", flag)
		}
	}
}
