package verdict

import (
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// PQ-72. `chain-size` says what the chain costs today and *hints* that
// post-quantum authentication will cost more. A hint is prose: a machine
// consumer cannot threshold on it, and an operator planning the migration has
// to do the arithmetic by hand from a blog post.
//
// So the projection becomes a number. It is computed from what the peer
// actually sent — each certificate's signature and public key, replaced by the
// FIPS 204 sizes — because a leaf and two intermediates do not all move
// together, and the assumptions are stated in the finding rather than hidden in
// a constant.

// chain builds a result whose certificates carry the fields the projection
// needs. The numbers are deliberately round: an arithmetic test whose expected
// value has to be computed by the reader proves nothing.
func projectable() probe.Result {
	r := ok("classic", "TLS 1.3", "X25519", false)
	r.ChainVerified = true
	r.PeerChainLen = 2
	r.Chain = []probe.Cert{
		// An ECDSA P-256 leaf: a 91-byte subjectPublicKeyInfo and a 71-byte
		// signature are what those look like in DER.
		{Subject: "leaf", NotAfter: opts().Now.Add(60 * 24 * time.Hour),
			Bytes: 1000, KeyBytes: 91, SigBytes: 71},
		{Subject: "intermediate", IsCA: true, NotAfter: opts().Now.Add(600 * 24 * time.Hour),
			Bytes: 1500, KeyBytes: 91, SigBytes: 71},
	}
	r.ChainBytes = 2500
	return r
}

// The number a planner needs: what this chain weighs once every certificate in
// it is signed post-quantum. ML-DSA-65 is the one that travels as `Value`,
// because it is the parameter set a public CA is most likely to land on and
// the conservative half of the answer.
func TestTheChainProjectionCarriesTheNumber(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{projectable()}, opts())
	f := find(t, rep, "chain-projection")

	// Per certificate: the current key and signature come out, ML-DSA-65's
	// 1952-byte key and 3309-byte signature go in.
	// leaf:         1000 - 91 - 71 + 1952 + 3309 = 6099
	// intermediate: 1500 - 91 - 71 + 1952 + 3309 = 6599
	const want = 6099 + 6599
	if f.Value == nil || *f.Value != want {
		t.Errorf("value = %v, want %d (ML-DSA-65 across both certificates)", f.Value, want)
	}
	if f.Unit != "bytes" {
		t.Errorf("unit = %q, want bytes", f.Unit)
	}
	// Both parameter sets are in the message, because the smaller one is the
	// answer for an internal PKI that gets to choose.
	for _, want := range []string{"ML-DSA-44", "ML-DSA-65"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message = %q, want it to name %s", f.Message, want)
		}
	}
	if !strings.Contains(f.Message, "2500") {
		t.Errorf("message = %q, want the chain's size today in it for comparison", f.Message)
	}
}

// ML-DSA-44 is the other half of the answer and has to be right too, or the
// smaller parameter set becomes a number nobody checked.
func TestTheSmallerParameterSetIsProjectedToo(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{projectable()}, opts())
	f := find(t, rep, "chain-projection")

	// leaf:         1000 - 91 - 71 + 1312 + 2420 = 4570
	// intermediate: 1500 - 91 - 71 + 1312 + 2420 = 5070
	if !strings.Contains(f.Message, "9640") {
		t.Errorf("message = %q, want the ML-DSA-44 total (9640) in it", f.Message)
	}
}

// PQ-74. The threshold PQ-72 deliberately left out. A projected chain past
// roughly 14 KB no longer fits the ten-segment initial congestion window most
// stacks still ship, which is where a handshake stops costing one round trip and
// starts costing two — or stops working, on a path that already dislikes large
// flights.
func TestTheProjectionWarnsWhenTheHeadroomIsGone(t *testing.T) {
	r := projectable()
	r.Chain[1].Bytes = 6000
	r.ChainBytes = 7000
	// leaf 6099 + intermediate 11099 = 17198, past the 14000-byte default.
	rep := Evaluate("h:443", []probe.Result{r}, opts())

	f := find(t, rep, "chain-projection")
	if f.Status != finding.WARN {
		t.Errorf("status = %s, want WARN: 17198 projected bytes is past the headroom", f.Status)
	}
	// Worded as the conditional it is, or it reads as a problem the endpoint
	// has today rather than one it would have after a migration nobody has
	// started.
	if !strings.Contains(f.Message, "would") {
		t.Errorf("message = %q: a projection has to be worded as a condition", f.Message)
	}
	if !strings.Contains(f.Message+f.Hint, "14000") {
		t.Errorf("neither message nor hint names the threshold: %s / %s", f.Message, f.Hint)
	}
}

// An ordinary chain stays quiet. A WARN on every endpoint is a WARN nobody
// reads, and most chains today project to well under the line.
func TestTheProjectionStaysQuietWithHeadroomLeft(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{projectable()}, opts())
	f := find(t, rep, "chain-projection")
	if f.Status != finding.OK {
		t.Errorf("status = %s, want OK: 12698 projected bytes still fits", f.Status)
	}
}

// 14 KB is a default, not a law: an operator who knows their path knows better,
// and zero turns the threshold off for somebody who does not want the question
// asked at all.
func TestTheHeadroomThresholdCanBeMovedOrTurnedOff(t *testing.T) {
	tight := opts()
	tight.CertHeadroomWarn = 5000
	f := find(t, Evaluate("h:443", []probe.Result{projectable()}, tight), "chain-projection")
	if f.Status != finding.WARN {
		t.Errorf("status = %s with a 5000-byte threshold, want WARN", f.Status)
	}
	if !strings.Contains(f.Message+f.Hint, "5000") {
		t.Errorf("the finding names the default rather than the threshold in force: %s / %s", f.Message, f.Hint)
	}

	off := opts()
	off.CertHeadroomWarn = 0
	r := projectable()
	r.Chain[1].Bytes = 60000
	r.ChainBytes = 61000
	f = find(t, Evaluate("h:443", []probe.Result{r}, off), "chain-projection")
	if f.Status != finding.OK {
		t.Errorf("status = %s with the threshold off, want OK", f.Status)
	}
}

// The invariant PQ-72 stated and PQ-74 must not break: the threshold grades the
// *finding*, never the endpoint. An endpoint whose post-quantum key exchange
// works is pq-ready whatever its certificates would weigh after a migration
// that has not started — turning that into a failure is how a monitoring system
// becomes one nobody reads.
func TestTheHeadroomWarningNeverChangesTheClass(t *testing.T) {
	healthy := []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		ok("pq-preferred", "TLS 1.3", "X25519MLKEM768", true),
		ok("pq-only", "TLS 1.3", "X25519MLKEM768", true),
	}
	for i := range healthy {
		healthy[i].ChainVerified = true
		healthy[i].PeerChainLen = 2
		healthy[i].Chain = projectable().Chain
		healthy[i].Chain[1].Bytes = 60000
		healthy[i].ChainBytes = 61000
	}

	rep := Evaluate("h:443", healthy, opts())
	if rep.Class != PQReady {
		t.Errorf("class = %s, want pq-ready: the projection must not grade the endpoint", rep.Class)
	}
	if f := find(t, rep, "chain-projection"); f.Status != finding.WARN {
		t.Errorf("the finding itself should still warn: %s", f.Status)
	}
}

// The per-certificate breakdown is where the actionable part is: one fat
// intermediate is a different problem from three ordinary certificates, and the
// hint is what gets pasted into the ticket.
func TestTheHintBreaksTheProjectionDownPerCertificate(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{projectable()}, opts())
	f := find(t, rep, "chain-projection")
	for _, want := range []string{"leaf", "intermediate"} {
		if !strings.Contains(f.Hint, want) {
			t.Errorf("hint = %q, want the %s in the breakdown", f.Hint, want)
		}
	}
}

// A baseline written before the sizes were recorded, or a peer whose chain we
// only have byte totals for, must produce **no** projection rather than one
// computed from zeros — which would claim a chain grows by the full ML-DSA
// weight with nothing coming out, and be wrong by kilobytes in the alarming
// direction.
func TestNoProjectionWithoutTheSizesItIsComputedFrom(t *testing.T) {
	r := projectable()
	for i := range r.Chain {
		r.Chain[i].KeyBytes, r.Chain[i].SigBytes = 0, 0
	}
	rep := Evaluate("h:443", []probe.Result{r}, opts())
	for _, f := range rep.Finding {
		if f.Check == "chain-projection" {
			t.Fatalf("a projection was computed from nothing: %+v", f)
		}
	}
}

// No handshake, no chain, no projection.
func TestNoProjectionWithoutAHandshake(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{fail("classic", probe.KindRefused)}, opts())
	for _, f := range rep.Finding {
		if f.Check == "chain-projection" {
			t.Fatalf("unexpected finding: %+v", f)
		}
	}
}
