//go:build go1.27

package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// PQ-76 found this, and it changes what M15 can assert. As of Go 1.27 the
// standard library has `crypto/mldsa`, `crypto/x509` names the ML-DSA signature
// algorithms, and `crypto/tls` has signature schemes for them — so a
// post-quantum *certificate* is something a Go server can serve and a Go client
// can accept, today, in a real TLS 1.3 handshake.
//
// Which means the projection no longer has to be taken on trust. The same
// certificate template, signed two ways: the projection computed from the ECDSA
// one is compared against the ML-DSA one that actually exists. Before this, the
// model's accuracy was a claim in a comment.
//
// Behind a build tag because crypto/mldsa does not exist in Go 1.26, the floor
// go.mod declares. The `test-current` CI job is where this runs.

func sameTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "same-template.example"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"same-template.example"},
	}
}

func cert(t *testing.T, pub, priv any) probe.Cert {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, sameTemplate(), sameTemplate(), pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return probe.Cert{
		Subject: c.Subject.CommonName, Bytes: len(c.Raw),
		KeyBytes: len(c.RawSubjectPublicKeyInfo), SigBytes: len(c.Signature),
		KeyAlg: c.PublicKeyAlgorithm.String(), SigAlg: c.SignatureAlgorithm.String(),
	}
}

// The model is within a few tens of bytes of a real ML-DSA certificate, and the
// difference is the AlgorithmIdentifier the page says is not modelled. This
// turns that caveat from a claim into a measured bound: 2% is generous enough
// not to be brittle and tight enough that a change in the model, or in how Go
// encodes these, fails here.
func TestTheProjectionMatchesARealMLDSACertificate(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	classical := cert(t, &ec.PublicKey, ec)

	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	real44 := cert(t, key.Public(), key)

	projected, _, ok := projectChain([]probe.Cert{classical}, mldsaSet("ML-DSA-44"))
	if !ok {
		t.Fatal("the classical certificate produced no projection")
	}

	off := projected - real44.Bytes
	if off < 0 {
		off = -off
	}
	tolerance := real44.Bytes / 50 // 2%
	t.Logf("projected %d, real %d, off by %d bytes (%.1f%%)",
		projected, real44.Bytes, projected-real44.Bytes,
		100*float64(projected-real44.Bytes)/float64(real44.Bytes))
	if off > tolerance {
		t.Errorf("the projection is off by %d bytes against a real ML-DSA-44 certificate (tolerance %d): "+
			"either the model drifted or Go encodes these differently now", off, tolerance)
	}

	// And the sizes the model puts *in* are the FIPS 204 ones, which is the
	// other half of why it lands: the signature is exact, the key carries the
	// AlgorithmIdentifier the model ignores.
	if real44.SigBytes != mldsaSet("ML-DSA-44").Sig {
		t.Errorf("a real ML-DSA-44 signature is %d bytes, the table says %d",
			real44.SigBytes, mldsaSet("ML-DSA-44").Sig)
	}
}

// What the tool reports for such a certificate, today. The inventory names the
// algorithm from the peer's own words, so an ML-DSA chain is described rather
// than reported as unknown — and `key_bits` stays absent, because a parameter
// set is not a number of bits and inventing one would be the guess the
// signatures finding exists not to make.
func TestTheInventoryNamesARealMLDSACertificate(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	c := cert(t, key.Public(), key)

	r := ok("classic", "TLS 1.3", "X25519", false)
	r.ChainVerified = true
	r.PeerChainLen = 1
	r.Chain = []probe.Cert{c}
	r.ChainBytes = c.Bytes

	f := find(t, Evaluate("h:443", []probe.Result{r}, opts()), "signatures")
	for _, want := range []string{"ML-DSA"} {
		if !strings.Contains(f.Message+f.Hint, want) {
			t.Errorf("the inventory does not name %s: %s / %s", want, f.Message, f.Hint)
		}
	}
	if f.Value != nil && *f.Value != 0 {
		t.Errorf("value = %v: a parameter set is not a number of bits, so there is none to report", *f.Value)
	}
}
