package quic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	pqquic "github.com/Allan-Nava/pqprobe/contrib/quic"
	quicgo "github.com/quic-go/quic-go"
)

// serve starts a QUIC listener with the given TLS settings and returns its
// address. The certificate is self-signed: the probe never verifies, for the
// same reason the main tool does not — an expiry problem must not be reported
// as a capability problem.
func serve(t *testing.T, curves []tls.CurveID) string {
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
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:       []string{"h3"},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}
	ln, err := quicgo.ListenAddr("127.0.0.1:0", cfg, &quicgo.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-c.Context().Done() }()
		}
	}()
	return ln.Addr().String()
}

// PQ-19. The same question over HTTP/3. What makes it worth a separate probe is
// that the ClientHello has to fit QUIC's Initial packet, and when something on
// the path cannot cope the failure is *quieter* than over TCP: UDP has no
// reset, so there is nothing to receive at all.
func TestAHybridClientCompletesOverQUIC(t *testing.T) {
	addr := serve(t, nil) // the stack's defaults, which include ML-KEM

	res := pqquic.Probe(context.Background(), addr, "localhost",
		pqquic.Profile{Name: "pq-only", Groups: []tls.CurveID{tls.X25519MLKEM768}}, 5*time.Second)

	if !res.OK {
		t.Fatalf("handshake failed: %s (%s)", res.Error, res.Kind)
	}
	if res.Group != "X25519MLKEM768" {
		t.Errorf("group = %q, want the hybrid one", res.Group)
	}
	if !res.PQ {
		t.Error("the negotiated group is post-quantum and the result should say so")
	}
	if res.ALPN != "h3" {
		t.Errorf("alpn = %q, want h3 — a QUIC probe that negotiates nothing is not probing HTTP/3", res.ALPN)
	}
}

// A server without ML-KEM refuses a post-quantum-only client, and QUIC carries
// that refusal as a CRYPTO_ERROR: the peer answered, so it is civil — the same
// judgement pqprobe makes over TCP, not a second opinion invented here.
func TestARefusalOverQUICIsCivilNotAbrupt(t *testing.T) {
	addr := serve(t, []tls.CurveID{tls.X25519})

	res := pqquic.Probe(context.Background(), addr, "localhost",
		pqquic.Profile{Name: "pq-only", Groups: []tls.CurveID{tls.X25519MLKEM768}}, 5*time.Second)

	if res.OK {
		t.Fatal("the server has no ML-KEM; the handshake must not complete")
	}
	if res.Abrupt {
		t.Errorf("kind = %q: the peer sent a CRYPTO_ERROR, which is an answer, not a disappearance", res.Kind)
	}
	if res.Kind != "alert" {
		t.Errorf("kind = %q, want alert", res.Kind)
	}
}

// Nothing listening on a UDP port: no reset comes back, because UDP has none.
// This is the failure mode the item is about — over TCP the same situation is a
// refusal, and here it can only be a timeout.
func TestNothingListeningOverUDPIsAQuietTimeout(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()

	start := time.Now()
	res := pqquic.Probe(context.Background(), addr, "localhost",
		pqquic.Profile{Name: "classic", Groups: []tls.CurveID{tls.X25519}}, 2*time.Second)
	elapsed := time.Since(start)

	if res.OK {
		t.Fatal("nothing is listening there")
	}
	if !res.Abrupt {
		t.Errorf("kind = %q: over UDP an unanswered handshake is exactly the abrupt case", res.Kind)
	}
	if res.Kind != "timeout" {
		t.Errorf("kind = %q, want timeout", res.Kind)
	}
	// It has to give up on the deadline rather than on some internal default,
	// or a fleet run would take as long as the slowest firewall.
	if elapsed > 4*time.Second {
		t.Errorf("took %s for a 2s timeout", elapsed)
	}
}

// The profiles are the same capability classes the main tool dials, so the two
// answers are comparable rather than merely adjacent.
func TestTheProfilesMirrorTheMainTool(t *testing.T) {
	names := map[string]bool{}
	for _, p := range pqquic.Profiles() {
		names[p.Name] = true
		if len(p.Groups) == 0 {
			t.Errorf("%s pins no groups: it would inherit whatever the stack defaults to", p.Name)
		}
	}
	for _, want := range []string{"classic", "pq-preferred", "pq-only"} {
		if !names[want] {
			t.Errorf("no %s profile", want)
		}
	}
	if _, ok := pqquic.ByName("pq-only"); !ok {
		t.Error("pq-only has to be reachable by name")
	}
	if _, ok := pqquic.ByName("nonsense"); ok {
		t.Error("an unknown profile must not resolve")
	}
	// ALPN matters here in a way it does not over TCP: a QUIC server answers
	// only what it speaks, and every one of these is asking about HTTP/3.
	for _, p := range pqquic.Profiles() {
		if len(p.ALPN) == 0 || !strings.Contains(strings.Join(p.ALPN, ","), "h3") {
			t.Errorf("%s does not offer h3", p.Name)
		}
	}
}
