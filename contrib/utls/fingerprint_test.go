package utls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/contrib/utls"
)

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
			go func() { _ = c.(*tls.Conn).HandshakeContext(context.Background()); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// PQ-10. The capability classes in the main binary pin groups and versions and
// never claim to be a browser. This module is the other half: a real
// ClientHello, so a report may say "Chrome 131 could not connect here" instead
// of "a client that offers ML-KEM could not".
func TestTheFingerprintsAreRealBrowsersAndSayWhichVersion(t *testing.T) {
	fps := utls.Fingerprints()
	if len(fps) < 3 {
		t.Fatalf("got %d fingerprints, want at least Chrome, Firefox and Safari", len(fps))
	}
	seen := map[string]bool{}
	for _, f := range fps {
		if f.Name == "" || f.Client == "" {
			t.Errorf("%+v: a fingerprint has to name itself and the client it imitates", f)
		}
		if seen[f.Name] {
			t.Errorf("%s appears twice", f.Name)
		}
		seen[f.Name] = true
		// The whole point is a claim about a named client, so the text has to
		// carry the version — "Chrome" alone is what the capability classes
		// already say.
		if !strings.ContainsAny(f.Client, "0123456789") {
			t.Errorf("%s: client = %q, want a version in it", f.Name, f.Client)
		}
	}
	if _, ok := utls.ByName("chrome"); !ok {
		t.Error("chrome has to be reachable by name, since that is what a flag passes")
	}
	if _, ok := utls.ByName("netscape"); ok {
		t.Error("netscape is not a fingerprint this module has")
	}
}

// A handshake with a real browser hello, against a server that has ML-KEM.
func TestAModernBrowserHelloCompletes(t *testing.T) {
	addr := serve(t, &tls.Config{MinVersion: tls.VersionTLS13})

	f, ok := utls.ByName("chrome")
	if !ok {
		t.Fatal("no chrome fingerprint")
	}
	res := utls.Probe(context.Background(), addr, "localhost", f, 5*time.Second)

	if !res.OK {
		t.Fatalf("the handshake failed: %s (%s)", res.Error, res.Kind)
	}
	if res.Group == "" || res.Version == "" {
		t.Errorf("result = %+v, want the negotiated version and group", res)
	}
	// The reason this module exists: a real hello is bigger than a Go one and
	// carries the extensions a browser sends.
	if res.HelloBytes < 500 {
		t.Errorf("hello = %d bytes, which is not a browser ClientHello", res.HelloBytes)
	}
	if res.Fingerprint != f.Name {
		t.Errorf("fingerprint = %q, want %q", res.Fingerprint, f.Name)
	}
}

// A server without ML-KEM still takes a browser hello, by falling back — and
// the refusal, when there is one, is classified by pqprobe's own classifier
// rather than by a second opinion living here.
func TestAClassicalServerIsAFallbackNotAFailure(t *testing.T) {
	addr := serve(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	f, _ := utls.ByName("chrome")
	res := utls.Probe(context.Background(), addr, "localhost", f, 5*time.Second)

	if !res.OK {
		t.Fatalf("a browser falls back to X25519: %s (%s)", res.Error, res.Kind)
	}
	if res.PQ {
		t.Errorf("group = %q, and the server has no ML-KEM", res.Group)
	}
}

// Nothing listening: the kind and the abrupt flag come from pqprobe, which is
// the only place that judgement is allowed to live.
func TestAFailureIsClassifiedByPqprobeNotHere(t *testing.T) {
	f, _ := utls.ByName("chrome")
	res := utls.Probe(context.Background(), "127.0.0.1:1", "localhost", f, 2*time.Second)

	if res.OK {
		t.Fatal("nothing is listening on port 1")
	}
	if res.Kind != "refused" {
		t.Errorf("kind = %q, want refused", res.Kind)
	}
	if res.Abrupt {
		t.Error("a refused connection is not the peer cutting us off mid-hello")
	}
}

// Found by running it: HelloSafari_16_0 and HelloIOS_14 fail against modern
// servers with "invalid signature by the server certificate", which is uTLS
// verifying the handshake signature *itself* — a fault of the preset, not of
// the endpoint. Reporting that as "example.com refuses Safari" would be the
// exact lie this toolchain exists to avoid, so it has to be flagged as local.
func TestAPresetThatFailsAgainstAnyServerIsFlaggedAsLocal(t *testing.T) {
	addr := serve(t, &tls.Config{MinVersion: tls.VersionTLS13})

	var sawLocal bool
	for _, f := range utls.Fingerprints() {
		res := utls.Probe(context.Background(), addr, "localhost", f, 5*time.Second)
		if res.OK {
			if res.Local {
				t.Errorf("%s: a successful handshake cannot be a local failure", f.Name)
			}
			continue
		}
		if !res.Local {
			t.Errorf("%s: failed against a plain TLS 1.3 server with %q — if that is the preset's own doing it has to say so, or the endpoint gets blamed",
				f.Name, res.Error)
			continue
		}
		sawLocal = true
		if !strings.Contains(strings.ToLower(res.Note), "preset") &&
			!strings.Contains(strings.ToLower(res.Note), "local") {
			t.Errorf("%s: note = %q, want it to say the failure is on this side", f.Name, res.Note)
		}
	}
	if !sawLocal {
		t.Log("every preset completed against a local server; nothing to flag on this toolchain")
	}
}
