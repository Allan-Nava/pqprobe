package output

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/probe"
	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// PQ-69. Every shape here is somebody else's parser: checkfleet imports the
// reports, an aggregator deduplicates on the finding id, a node exporter
// scrapes the textfile, a CI job reads the findings array. None of it was
// asserted anywhere — renaming a field or reordering an object passed every
// gate in this repository and broke a consumer in silence.
//
// So the documents are compared byte for byte against a golden file. A
// deliberate change updates it in the same commit (`go test ./internal/output/
// -update`) and shows up in the diff as what it is: a change to somebody else's
// parser.

var update = flag.Bool("update", false, "rewrite the golden files")

// goldenRun is the fixture, and it exists to cover the shapes that actually
// vary rather than a plausible fleet: a healthy endpoint, one that was cut off,
// one nothing answered, a finding with value and unit, a finding with a hint,
// and a class that is not a grade.
func goldenRun(t *testing.T) []verdict.Report {
	t.Helper()
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	opt := verdict.DefaultOptions()
	opt.Now = at

	chain := []probe.Cert{{
		Subject:   "origin.example",
		Issuer:    "Example CA",
		NotBefore: at.Add(-30 * 24 * time.Hour),
		NotAfter:  at.Add(12 * 24 * time.Hour), // inside the WARN window
		DNSNames:  []string{"origin.example"},
		Bytes:     1200,
	}}

	ok := func(profile, group string, pq bool, hello int) probe.Result {
		return probe.Result{
			Profile: profile, OK: true, Kind: probe.KindOK,
			Version: "TLS 1.3", Group: group, PQ: pq,
			Cipher: "TLS_AES_128_GCM_SHA256", HelloBytes: hello, HelloCount: 1,
			Elapsed: 42 * time.Millisecond, Attempts: 1,
			Chain: chain, ChainVerified: true, ChainBytes: 1200, PeerChainLen: 1,
		}
	}

	healthy := verdict.Evaluate("origin.example:443", []probe.Result{
		ok("classic", "X25519", false, 285),
		ok("pq-preferred", "X25519MLKEM768", true, 1507),
		ok("pq-only", "X25519MLKEM768", true, 1439),
	}, opt)

	cut := verdict.Evaluate("wall.example:443", []probe.Result{
		ok("classic", "X25519", false, 285),
		{Profile: "pq-preferred", Kind: probe.KindTimeout, Err: "context deadline exceeded",
			HelloBytes: 1507, Elapsed: 5 * time.Second, Attempts: 2, Reproduced: true},
		{Profile: "pq-only", Kind: probe.KindTimeout, Err: "context deadline exceeded",
			HelloBytes: 1439, Elapsed: 5 * time.Second, Attempts: 2, Reproduced: true},
	}, opt)

	gone := verdict.Evaluate("gone.example:443", []probe.Result{
		{Profile: "classic", Kind: probe.KindRefused, Err: "connect: connection refused", Attempts: 1},
		{Profile: "pq-preferred", Kind: probe.KindRefused, Err: "connect: connection refused", Attempts: 1},
		{Profile: "pq-only", Kind: probe.KindRefused, Err: "connect: connection refused", Attempts: 1},
	}, opt)

	return []verdict.Report{healthy, cut, gone}
}

func compare(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v — run `go test ./internal/output/ -update` if this document is new", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s changed. If that was deliberate, re-run with -update and read the diff as what it is:\n"+
			"a change to the shape somebody else's parser depends on.\n\ngot:\n%s\nwant:\n%s", name, got, want)
	}
}

func TestTheMachineFacingDocumentsAreUnchanged(t *testing.T) {
	reps := goldenRun(t)

	var b bytes.Buffer
	if err := JSON(&b, reps); err != nil {
		t.Fatal(err)
	}
	compare(t, "run.json", b.Bytes())

	b.Reset()
	if err := Findings(&b, reps, ""); err != nil {
		t.Fatal(err)
	}
	compare(t, "findings.json", b.Bytes())

	b.Reset()
	if err := FindingsWrapped(&b, reps, ""); err != nil {
		t.Fatal(err)
	}
	compare(t, "findings-wrapped.json", b.Bytes())

	// The textfile is written to a path and renamed over it, so it is produced
	// through the real function rather than a renderer.
	dir := t.TempDir()
	path := filepath.Join(dir, "pqprobe.prom")
	if err := Textfile(path, reps, time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	prom, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, "metrics.prom", prom)

	// Markdown is read by people, but it is pasted into a pull request by a
	// machine and its table structure is what a job summary renders.
	b.Reset()
	if err := Markdown(&b, reps, ""); err != nil {
		t.Fatal(err)
	}
	compare(t, "report.md", b.Bytes())
}
