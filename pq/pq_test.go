package pq_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/pq"
)

// PQ-14. checkfleet cannot import internal/…, so embedding pqprobe needs a
// public surface. This is the contract an embedder gets: strings in, reports
// out, no internal types leaking — so the packages behind it stay free to move.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestProbeGivesAnEmbedderTheClassAndTheFindings(t *testing.T) {
	addr := serve(t, &tls.Config{MinVersion: tls.VersionTLS13})

	reps, err := pq.Probe(context.Background(), []string{addr}, pq.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(reps) != 1 {
		t.Fatalf("got %d reports, want 1", len(reps))
	}
	r := reps[0]
	if r.Class != "pq-ready" {
		t.Errorf("class = %q, want pq-ready", r.Class)
	}
	if r.Target == "" {
		t.Error("a report with no target cannot be correlated with anything")
	}
	// The listener is self-signed, so the chain does not verify against the
	// system roots and the run is a WARN — which is the documented behaviour and
	// exactly what an embedder has to be able to tell apart from a capability
	// problem: the class is still pq-ready.
	if r.Worst != "WARN" {
		t.Errorf("worst = %q, want WARN from the chain check", r.Worst)
	}
	var chainWarn bool
	for _, f := range r.Findings {
		if f.Check == "chain" && f.Status == "WARN" {
			chainWarn = true
		}
	}
	if !chainWarn {
		t.Error("the WARN has to come from the chain, not from the class")
	}

	var verdictSeen, handshakeSeen bool
	for _, f := range r.Findings {
		switch f.Check {
		case "verdict":
			verdictSeen = true
			if f.Hint == "" {
				t.Error("the verdict hint is the half that says what to do; an embedder needs it")
			}
		case "handshake":
			handshakeSeen = true
		}
		if f.Status == "" || f.Message == "" {
			t.Errorf("finding without status or message: %+v", f)
		}
	}
	if !verdictSeen || !handshakeSeen {
		t.Error("both the verdict and the per-profile handshakes have to be visible")
	}
}

// The numbers travel as numbers: an embedder must never parse the prose, which
// is the same rule the findings contract has always had.
func TestProbeCarriesValuesNotProse(t *testing.T) {
	addr := serve(t, &tls.Config{MinVersion: tls.VersionTLS13})
	reps, err := pq.Probe(context.Background(), []string{addr}, pq.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range reps[0].Findings {
		if f.Check == "expiry" {
			found = true
			if f.Value == nil || f.Unit != "days" {
				t.Errorf("expiry = %+v, want a value in days", f)
			}
		}
	}
	if !found {
		t.Error("no expiry finding")
	}
}

// A profile name that does not exist is a usage error at the boundary, not a
// silently smaller run — the same rule the CLI has.
func TestProbeRefusesAnUnknownProfile(t *testing.T) {
	_, err := pq.Probe(context.Background(), []string{"127.0.0.1:1"},
		pq.Options{Profiles: []string{"pq-preferred", "nonsense"}, Timeout: time.Second})
	if err == nil {
		t.Fatal("an unknown profile has to be refused")
	}
	if !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("the error has to name it: %v", err)
	}
}

// No target is a usage error too, rather than an empty slice that reads as
// "the fleet is fine".
func TestProbeRefusesNoTarget(t *testing.T) {
	if _, err := pq.Probe(context.Background(), nil, pq.Options{}); err == nil {
		t.Fatal("no target has to be an error")
	}
}

// An endpoint that is not there is a report, not an error: a fleet check must
// keep going and say `unreachable` for the one node that is down.
func TestProbeReportsAnUnreachableTargetInsteadOfFailing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing is listening now

	reps, err := pq.Probe(context.Background(), []string{addr}, pq.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("a dead endpoint is a finding, not an error: %v", err)
	}
	if len(reps) != 1 || reps[0].Class != "unreachable" {
		t.Fatalf("got %+v, want one unreachable report", reps)
	}
	if reps[0].Worst != "ERROR" {
		t.Errorf("worst = %q, want ERROR", reps[0].Worst)
	}
}

// The vocabulary an embedder needs to render or alert on, without a run.
func TestClassesAndExplainAreAvailableToEmbedders(t *testing.T) {
	classes := pq.Classes()
	if len(classes) < 8 {
		t.Fatalf("got %d classes, want the whole vocabulary", len(classes))
	}
	e, ok := pq.Explain("pq-intolerant")
	if !ok {
		t.Fatal("pq-intolerant has no explanation")
	}
	if e.Status != "BAD" || !strings.Contains(e.Affected, "Chrome") || e.Action == "" {
		t.Errorf("explanation = %+v", e)
	}
	if _, ok := pq.Explain("pq-maybe"); ok {
		t.Error("pq-maybe is not a class")
	}
}

// PQ-10 needs this before it needs anything else. A fingerprint probe dials
// with its own TLS stack, so it ends up holding an error — and the one thing
// this tool must never have two copies of is the judgement of what that error
// means. Exposing the classifier is what keeps "alert versus abrupt" in one
// place when the dialling happens outside this module.
func TestClassifyIsAvailableToAnEmbedderThatDialsItself(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		kind   string
		abrupt bool
	}{
		{"nothing went wrong", nil, "ok", false},
		{"a TLS alert", errors.New("remote error: tls: handshake failure"), "alert", false},
		// The real Go strings, checked against the toolchain source rather than
		// quoted from memory: both are locally generated refusals, so both are
		// civil — the peer and we understood each other and disagreed.
		{"no version in common", errors.New("tls: no mutually supported protocol versions"), "alert", false},
		{"the peer picked a group we did not offer", errors.New("tls: server selected unsupported group"), "alert", false},
		{"a reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, "reset", true},
		{"an EOF", io.ErrUnexpectedEOF, "eof", true},
		{"nothing listening", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "refused", false},
		{"no route from here", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, "unroutable", false},
	}
	for _, tc := range cases {
		kind, abrupt := pq.Classify(tc.err)
		if kind != tc.kind {
			t.Errorf("%s: kind = %q, want %q", tc.name, kind, tc.kind)
		}
		if abrupt != tc.abrupt {
			t.Errorf("%s: abrupt = %v, want %v — this is the distinction the whole tool rests on",
				tc.name, abrupt, tc.abrupt)
		}
	}
}

// PQ-46. An embedder pins the address family the same way the CLI does, and an
// unknown one is an error rather than a run over both families that looks like
// the one that was asked for.
func TestProbeTakesAnAddressFamily(t *testing.T) {
	addr := serve(t, &tls.Config{MinVersion: tls.VersionTLS13})

	reps, err := pq.Probe(context.Background(), []string{addr}, pq.Options{Net: "tcp4"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(reps) != 1 || reps[0].Class == "unreachable" {
		t.Fatalf("got %+v, want the v4 listener probed over IPv4", reps)
	}

	// The same listener asked for over IPv6: unreachable, and never a grade —
	// the family was excluded here, which says nothing about the endpoint.
	reps, err = pq.Probe(context.Background(), []string{addr}, pq.Options{Net: "tcp6"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(reps) != 1 || reps[0].Class != "unreachable" {
		t.Fatalf("got %+v, want unreachable: an excluded family is not a capability answer", reps)
	}

	if _, err := pq.Probe(context.Background(), []string{addr}, pq.Options{Net: "ipv4"}); err == nil {
		t.Fatal("an unknown address family must be an error, not a silently different run")
	}
}
