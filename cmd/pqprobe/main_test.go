package main

import (
	"reflect"
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
