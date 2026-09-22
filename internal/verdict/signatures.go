package verdict

import (
	"fmt"
	"strings"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// The signature inventory (PQ-73).
//
// PQ-72 says what this chain costs once it is signed post-quantum. This says
// what it is signed with today — which is what the migration gets planned
// against: how many endpoints are RSA-2048, how many ECDSA P-256, which ones
// carry an intermediate from a different era than their leaf.
//
// It records and does not grade. Whether RSA-2048 is good enough, or SHA-1
// unacceptable, is a configuration opinion, and configuration opinions belong
// to testssl.sh — the boundary INTENT.md draws. What belongs here is what the
// peer sent, because it is in hand and because it decides what the chain costs
// when the signature changes.

// signatureInventory is one finding naming every certificate's key and what
// signed it. Silent when the fields were never recorded: an inventory of blanks
// is worse than no row at all.
func signatureInventory(target string, src *probe.Result) (finding.Finding, bool) {
	if len(src.Chain) == 0 {
		return finding.Finding{}, false
	}
	for _, c := range src.Chain {
		if c.KeyAlg == "" && c.SigAlg == "" {
			return finding.Finding{}, false
		}
	}

	leaf := src.Chain[0]
	msg := fmt.Sprintf("leaf %s signed %s", keyDescription(leaf), algOrUnknown(leaf.SigAlg))
	if n := len(src.Chain) - 1; n > 0 {
		msg = fmt.Sprintf("%s, with %d issuer certificate(s) in the chain", msg, n)
	}

	var b strings.Builder
	for i, c := range src.Chain {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s: %s, signed %s", certLabel(c, i), keyDescription(c), algOrUnknown(c.SigAlg))
	}
	b.WriteString(". This is the inventory a certificate migration is planned against, " +
		"not a judgement of it — what it costs when the signature changes is the chain-projection finding")

	return finding.Finding{
		Check: "signatures", Target: target, Status: finding.OK,
		Message: msg,
		Value:   finding.Num(float64(leaf.KeyBits)), Unit: "bits",
		Hint: b.String(),
	}, true
}

// keyDescription is "ECDSA 256" or "RSA 2048" — the algorithm and the number a
// fleet query groups by, with the number left out when this build could not
// work it out rather than printed as a zero.
func keyDescription(c probe.Cert) string {
	alg := algOrUnknown(c.KeyAlg)
	if c.KeyBits <= 0 {
		return alg
	}
	return fmt.Sprintf("%s %d", alg, c.KeyBits)
}

func algOrUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "an algorithm this build does not name"
	}
	return s
}
