package verdict

import (
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// PQ-73. PQ-72 says what this chain costs once it moves; this says what it is
// today. A migration is planned against that inventory — how many endpoints are
// RSA-2048, how many ECDSA P-256, which ones are cross-signed — and the
// certificates were already in hand with nobody writing it down.
//
// It stays on the right side of the boundary with checkfleet: not lifecycle,
// not renewal, not issuer policy. What the peer sent, and what it costs when
// the signature changes.

func signed() probe.Result {
	r := ok("classic", "TLS 1.3", "X25519", false)
	r.ChainVerified = true
	r.PeerChainLen = 2
	r.Chain = []probe.Cert{
		{Subject: "leaf.example", NotAfter: opts().Now.Add(60 * 24 * time.Hour),
			Bytes: 1000, KeyBytes: 91, SigBytes: 71,
			KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "SHA256-RSA"},
		{Subject: "Example CA", IsCA: true, NotAfter: opts().Now.Add(600 * 24 * time.Hour),
			Bytes: 1500, KeyBytes: 270, SigBytes: 256,
			KeyAlg: "RSA", KeyBits: 2048, SigAlg: "SHA256-RSA"},
	}
	r.ChainBytes = 2500
	return r
}

func TestTheChainSaysWhatSignsIt(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{signed()}, opts())
	f := find(t, rep, "signatures")

	// Both certificates, each with its key and what signed it: an inventory
	// that named only the leaf would miss the intermediate that is the reason
	// half these chains are RSA.
	for _, want := range []string{"leaf.example", "ECDSA", "256", "Example CA", "RSA", "2048"} {
		if !strings.Contains(f.Message+f.Hint, want) {
			t.Errorf("neither the message nor the hint mentions %q:\n  %s\n  %s", want, f.Message, f.Hint)
		}
	}

	// The number a fleet query groups by is the leaf's key size — "how many
	// endpoints are still 2048" is the question this finding exists to answer.
	if f.Value == nil || *f.Value != 256 {
		t.Errorf("value = %v, want the leaf's key size", f.Value)
	}
	if f.Unit != "bits" {
		t.Errorf("unit = %q, want bits", f.Unit)
	}
}

// Inventory, not grading — the same rule PQ-72 follows. Whether RSA-2048 is
// good enough is a configuration opinion, and a configuration opinion is
// testssl.sh's job, not this tool's.
func TestTheSignatureInventoryDoesNotGrade(t *testing.T) {
	r := signed()
	r.Chain[0].KeyAlg, r.Chain[0].KeyBits = "RSA", 1024
	r.Chain[0].SigAlg = "SHA1-RSA"
	rep := Evaluate("h:443", []probe.Result{r}, opts())

	f := find(t, rep, "signatures")
	if f.Status != finding.OK {
		t.Errorf("status = %s: this finding states what is there, it does not grade it", f.Status)
	}
	if !strings.Contains(f.Message+f.Hint, "SHA1") {
		t.Errorf("the inventory dropped the algorithm it was asked to record: %s / %s", f.Message, f.Hint)
	}
}

// A report from before the fields existed says nothing rather than saying
// "unknown" three times — an inventory of blanks is worse than no row.
func TestNoSignatureFindingWithoutTheFields(t *testing.T) {
	r := signed()
	for i := range r.Chain {
		r.Chain[i].KeyAlg, r.Chain[i].KeyBits, r.Chain[i].SigAlg = "", 0, ""
	}
	rep := Evaluate("h:443", []probe.Result{r}, opts())
	for _, f := range rep.Finding {
		if f.Check == "signatures" {
			t.Fatalf("an inventory was written from nothing: %+v", f)
		}
	}
}

func TestNoSignatureFindingWithoutAHandshake(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{fail("classic", probe.KindRefused)}, opts())
	for _, f := range rep.Finding {
		if f.Check == "signatures" {
			t.Fatalf("unexpected finding: %+v", f)
		}
	}
}
