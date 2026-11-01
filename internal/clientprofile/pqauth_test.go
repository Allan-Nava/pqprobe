package clientprofile

import (
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"
)

// PQ-76. The obvious profile in the certificate milestone is a `pq-auth-only`
// client — one that offers only post-quantum *signature* algorithms, the
// authentication twin of `pq-only`. It is not shippable, and this is the test
// that will say when it becomes shippable, rather than somebody re-checking by
// hand every toolchain upgrade.
//
// What the standard library already has, as of Go 1.27 — and this is a
// correction of what the backlog item first claimed:
//
//   - `crypto/mldsa`: FIPS 204 keys and verification.
//   - `crypto/x509.SignatureAlgorithm`: ML-DSA-44, ML-DSA-65 and ML-DSA-87, so
//     a certificate signed with one is *parsed* and named — which is why the
//     `signatures` finding would already report it.
//
//   - `crypto/tls.SignatureScheme`: MLDSA44, MLDSA65 and MLDSA87, so TLS can
//     negotiate one — a Go server serves such a certificate and a Go client
//     accepts it, in a real TLS 1.3 handshake. internal/verdict checks the
//     projection against one.
//
// What is still missing, and it is the only thing:
//
//   - any way for a *client* to pin the signature algorithms it offers, the way
//     `CurvePreferences` pins the groups. A profile that could not pin them
//     would fall back to the toolchain's defaults and prove something different
//     after every upgrade, which is the first principle in INTENT.md.
//
// A profile that cannot pin what it is testing is not a capability class. So
// this stays a decision rather than a gap, and these assertions are the alarm
// on it: the day either one fails, PQ-76 is unblocked and the next steps are a
// profile, a class and a red test, in that order.

// pqAuthStillImpossible is the message both halves print, because whoever sees
// it will not have this file in mind.
const pqAuthStillImpossible = "PQ-76 is unblocked: the standard library has gained what a " +
	"post-quantum authentication profile needs. Next: a `pq-auth-only` profile pinning the " +
	"ML-DSA signature schemes, a class saying what to do about an endpoint that refuses it, " +
	"and a red test first. Update INTENT.md and the backlog item before writing any of it."

// The half that is already there, asserted so the reasoning cannot rot the
// other way: TLS knows the ML-DSA signature schemes. The day it stops, the
// `signatures` finding and the projection's real-certificate check lose their
// footing and this item needs rethinking rather than unblocking.
func TestTLSAlreadyKnowsTheMLDSASignatureSchemes(t *testing.T) {
	found := 0
	for i := 0; i <= 0xffff; i++ {
		name := strings.ToUpper(tls.SignatureScheme(i).String())
		if strings.Contains(name, "MLDSA") || strings.Contains(name, "ML-DSA") {
			found++
		}
	}
	if found < 3 {
		t.Errorf("crypto/tls names %d ML-DSA signature schemes, want the three FIPS 204 sets: "+
			"PQ-76's reasoning rests on TLS being able to negotiate one", found)
	}
}

func TestAClientStillCannotPinItsSignatureAlgorithms(t *testing.T) {
	ty := reflect.TypeOf(tls.Config{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if f.PkgPath != "" { // unexported: not a knob a profile can turn
			continue
		}
		if strings.Contains(f.Name, "Signature") {
			t.Fatalf("tls.Config now has %s %s — %s", f.Name, f.Type, pqAuthStillImpossible)
		}
	}
}

// The other half of the correction, asserted so it cannot rot the other way:
// x509 *does* know the ML-DSA algorithms, which is why `signatures` would name
// one today if a peer served such a certificate. If this ever stops being true,
// the backlog item's reasoning has to change again.
func TestX509AlreadyNamesTheMLDSAAlgorithms(t *testing.T) {
	found := map[string]bool{}
	for i := 0; i < 64; i++ {
		name := x509.SignatureAlgorithm(i).String()
		if strings.HasPrefix(name, "ML-DSA") {
			found[name] = true
		}
	}
	for _, want := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if !found[want] {
			t.Errorf("crypto/x509 no longer names %s: PQ-76's reasoning rests on it doing so", want)
		}
	}
}
