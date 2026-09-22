package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PQ-78. `docs/schema.md` says what a document contract is and when its number
// moves. Nothing said the same for the rest of the surface — the flags, the exit
// codes, the class names, the check names, the `pq/` API — and a 1.0 is exactly
// a promise about those. A promise nobody wrote down is a promise nobody can
// hold you to, and one maintained by hand beside the code is a promise that is
// wrong by the second release.
//
// So the page is generated from the code it describes: the flag set as the
// binary declares it, the classes as the verdict names them, the checks as the
// findings carry them, and the exported surface of `pq/` as it is actually
// declared. The prose around them — what a major means, what is deliberately
// *not* stable, how long a deprecated flag keeps working — is the part a person
// writes, and it lives in the generator so half the page cannot go stale while
// the other half regenerates.

var updateCompat = flag.Bool("update", false, "rewrite docs/compatibility.md")

func TestTheCompatibilityPageMatchesTheCode(t *testing.T) {
	page, err := compatPage()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "compatibility.md")
	if *updateCompat {
		if err := os.WriteFile(path, []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v — run `go test ./cmd/pqprobe/ -update`", err)
	}
	if page != string(want) {
		t.Errorf("docs/compatibility.md no longer describes the code.\n"+
			"If the surface changed on purpose, re-run with -update and read the diff as\n"+
			"what it is: a change to what this tool promises not to break.\n\ngot:\n%s", page)
	}
}

// The generator walking nothing would produce a page that promises nothing and
// a golden that records the emptiness, which is the failure mode of every
// generated document in this repository.
func TestTheCompatibilityPageIsNotEmptyInAnySection(t *testing.T) {
	flags, classes, checks, api := compatFlags(), compatClasses(), compatChecks(), compatAPI()
	if len(flags) < 20 {
		t.Errorf("%d flags enumerated — the flag set is not being read", len(flags))
	}
	if len(classes) < 5 {
		t.Errorf("%d classes enumerated — verdict.Classes() is not being read", len(classes))
	}
	if len(checks) < 10 {
		t.Errorf("%d checks enumerated — the verdict source is not being read", len(checks))
	}
	if len(api) < 8 {
		t.Errorf("%d exported names in pq/ — the package is not being read", len(api))
	}
}

// The one that catches a real break: an exported name that disappears from
// `pq/` without the page changing would be a silent major.
func TestTheApiListIsTheApi(t *testing.T) {
	api := compatAPI()
	for _, want := range []string{"Probe", "Options", "Report", "Finding", "Classify", "Explain"} {
		found := false
		for _, got := range api {
			if got.Name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pq.%s is part of the public surface and the generator did not see it", want)
		}
	}
}

// The compatibility page promises the check names keep their meaning; the
// findings page says what each one means. Two hand-free lists that disagree
// would promise something nobody documented — the same two-way rule the flag
// set and --help already follow.
func TestEveryCheckTheToolEmitsIsDescribedInTheFindingsPage(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "findings.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range compatChecks() {
		if !strings.Contains(string(page), "`"+c+"`") {
			t.Errorf("the tool emits the check %q and docs/findings.md never mentions it", c)
		}
	}
}
