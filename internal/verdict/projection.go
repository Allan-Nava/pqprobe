package verdict

import (
	"fmt"
	"strings"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// The post-quantum authentication projection (PQ-72).
//
// Key exchange is the migration happening now. Authentication is the next one,
// and it fails in the same shape for the same reason: an ML-DSA signature is
// measured in kilobytes where an ECDSA one is measured in tens of bytes, so the
// server's flight stops fitting where the ClientHello stopped fitting before.
//
// The difference is that nothing has to be sent to know what it costs. The
// chain arrived in the handshake, and a post-quantum certificate is the same
// certificate with two fields replaced: the subjectPublicKeyInfo and the
// signature. So the projection is arithmetic over numbers already in hand, and
// the arithmetic is stated in the finding rather than hidden in a constant — a
// projection whose assumptions are not visible is a number nobody trusts twice.
//
// What it deliberately does not model: the AlgorithmIdentifier around each
// field (tens of bytes against thousands), a chain that gains or loses a
// certificate in the migration, and any certificate whose key stays classical
// in a hybrid deployment. Those are decisions somebody makes; this is what the
// chain in front of you weighs if all of it moves.

// mldsaParams is a FIPS 204 parameter set: the sizes of a public key and a
// signature, in bytes, as the standard specifies them.
type mldsaParams struct {
	Name string
	Key  int
	Sig  int
}

// The three parameter sets. ML-DSA-87 is here because the table is the answer
// to "what if we need the big one" and a table with a hole in it gets guessed
// at; the finding projects the two a certificate authority is actually choosing
// between today.
var mldsaSets = []mldsaParams{
	{"ML-DSA-44", 1312, 2420},
	{"ML-DSA-65", 1952, 3309},
	{"ML-DSA-87", 2592, 4627},
}

func mldsaSet(name string) mldsaParams {
	for _, p := range mldsaSets {
		if p.Name == name {
			return p
		}
	}
	panic("verdict: no such ML-DSA parameter set: " + name)
}

// projectChain returns what the chain would weigh under one parameter set, and
// the per-certificate figures behind that total.
//
// It reports ok=false when any certificate is missing the sizes the arithmetic
// consumes. That happens for a report written before those were recorded, and
// the alternative — treating a missing size as zero — would claim the chain
// grows by the full ML-DSA weight with nothing coming out: wrong by kilobytes,
// in the alarming direction, on a document that reads like a measurement.
func projectChain(chain []probe.Cert, p mldsaParams) (total int, per []int, ok bool) {
	if len(chain) == 0 {
		return 0, nil, false
	}
	per = make([]int, len(chain))
	for i, c := range chain {
		if c.Bytes <= 0 || c.KeyBytes <= 0 || c.SigBytes <= 0 {
			return 0, nil, false
		}
		per[i] = c.Bytes - c.KeyBytes - c.SigBytes + p.Key + p.Sig
		total += per[i]
	}
	return total, per, true
}

// chainProjection is the finding. It states a number and does not grade: an
// endpoint that works today must not acquire a warning over a migration nobody
// has started. The threshold, and the flag that moves it, are PQ-74's.
func chainProjection(target string, src *probe.Result) (finding.Finding, bool) {
	small, _, ok := projectChain(src.Chain, mldsaSet("ML-DSA-44"))
	if !ok {
		return finding.Finding{}, false
	}
	large, perLarge, ok := projectChain(src.Chain, mldsaSet("ML-DSA-65"))
	if !ok {
		return finding.Finding{}, false
	}

	now := src.ChainBytes
	if now <= 0 {
		for _, c := range src.Chain {
			now += c.Bytes
		}
	}

	msg := fmt.Sprintf("signed with ML-DSA-44 this chain would be %d bytes, with ML-DSA-65 %d (%d today, ×%.1f)",
		small, large, now, float64(large)/float64(now))

	var b strings.Builder
	b.WriteString("per certificate under ML-DSA-65: ")
	for i, c := range src.Chain {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s %d → %d B", certLabel(c, i), c.Bytes, perLarge[i])
	}
	b.WriteString(". The projection replaces each certificate's public key and signature " +
		"with the FIPS 204 sizes and changes nothing else, so it is what this chain weighs " +
		"if all of it moves; value is the ML-DSA-65 total")

	return finding.Finding{
		Check: "chain-projection", Target: target, Status: finding.OK,
		Message: msg,
		Value:   finding.Num(float64(large)), Unit: "bytes",
		Hint: b.String(),
	}, true
}

// certLabel names a certificate in the breakdown. The subject is what an
// operator recognises; the position is the fallback, because a certificate with
// an empty common name is ordinary and "  1200 → 6099 B" is not a line anybody
// can act on.
func certLabel(c probe.Cert, i int) string {
	if s := strings.TrimSpace(c.Subject); s != "" {
		return s
	}
	if i == 0 {
		return "leaf"
	}
	return fmt.Sprintf("certificate %d", i+1)
}
