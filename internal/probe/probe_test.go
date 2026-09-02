package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
)

// selfSigned makes a certificate for 127.0.0.1. The tests never verify it —
// pqprobe verifies the chain separately and these servers exist to answer a
// capability question — but a handshake still needs one.
func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqprobe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS starts a TLS server with cfg and returns its target.
func serveTLS(t *testing.T, cfg *tls.Config) Target {
	t.Helper()
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
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}()
		}
	}()
	return targetOf(t, ln.Addr().String())
}

func targetOf(t *testing.T, addr string) Target {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return Target{Host: host, Port: port}
}

func dial(t *testing.T, tg Target, profile string) Result {
	t.Helper()
	p, ok := clientprofile.ByName(profile)
	if !ok {
		t.Fatalf("no such profile %q", profile)
	}
	d := Dialer{Timeout: 5 * time.Second}
	return d.Do(context.Background(), tg, p)
}

// A server on a current stack accepts the hybrid group, and a client that
// offers nothing else gets it.
func TestModernServerIsPostQuantumReady(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})

	res := dial(t, tg, "pq-only")
	if !res.OK {
		t.Fatalf("pq-only handshake failed: %s (%s)", res.Err, res.Kind)
	}
	if !res.PQ || res.Group != "X25519MLKEM768" {
		t.Fatalf("expected a post-quantum group, got %q (pq=%v)", res.Group, res.PQ)
	}
}

// A server without ML-KEM refuses the post-quantum-only client *civilly* — an
// alert, not a reset. That difference is the whole point of Kind.
func TestClassicalServerRefusesPQOnlyWithAnAlert(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	if res := dial(t, tg, "pq-only"); res.OK {
		t.Fatal("pq-only should not complete against a server without ML-KEM")
	} else if res.Kind.Abrupt() {
		t.Fatalf("a server that says no politely must not be reported as abrupt: kind=%s err=%s", res.Kind, res.Err)
	}

	// The same server must still take the realistic client, by falling back.
	res := dial(t, tg, "pq-preferred")
	if !res.OK {
		t.Fatalf("pq-preferred must fall back to a classical group: %s (%s)", res.Err, res.Kind)
	}
	if res.PQ {
		t.Fatal("no post-quantum group can have been negotiated here")
	}
	if res.Group != "X25519" {
		t.Fatalf("negotiated group = %q, want X25519", res.Group)
	}
}

// intolerantServer reproduces the failure this tool exists for: a stack that
// copes with a small ClientHello and dies on the ~1.2 KB one that carries an
// ML-KEM key share. It is a real TLS server for anything under limit bytes and
// a closed connection above it.
func intolerantServer(t *testing.T, cfg *tls.Config, limit int) Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				defer c.Close()
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				// TLS record header: type, version, 16-bit length.
				if n := int(hdr[3])<<8 | int(hdr[4]); n > limit {
					return // the whole point: no alert, just gone
				}
				srv := tls.Server(&prefixConn{Conn: c, pre: bytes.NewReader(hdr)}, cfg)
				_ = srv.HandshakeContext(context.Background())
				srv.Close()
			}()
		}
	}()
	return targetOf(t, ln.Addr().String())
}

// prefixConn replays bytes already read from the connection before continuing
// with the connection itself.
type prefixConn struct {
	net.Conn
	pre *bytes.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.pre.Len() > 0 {
		return c.pre.Read(b)
	}
	return c.Conn.Read(b)
}

func TestIntolerantServerBreaksOnlyThePostQuantumClient(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	// 600 bytes sits above a classical ClientHello (~250-400 B) and well below
	// one carrying an ML-KEM key share.
	tg := intolerantServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, 600)

	classic := dial(t, tg, "classic")
	if !classic.OK {
		t.Fatalf("the classical client must still connect — that is what makes this bug invisible: %s (%s)", classic.Err, classic.Kind)
	}
	pref := dial(t, tg, "pq-preferred")
	if pref.OK {
		t.Fatal("pq-preferred must fail against a size-intolerant server")
	}
	if !pref.Kind.Abrupt() {
		t.Fatalf("kind = %s, want an abrupt kind (reset/eof/timeout): %s", pref.Kind, pref.Err)
	}
}

func TestTLS12OnlyServer(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	res := dial(t, tg, "classic")
	if !res.OK {
		t.Fatalf("classic must connect over TLS 1.2: %s", res.Err)
	}
	if res.Version != "TLS 1.2" {
		t.Fatalf("version = %q, want TLS 1.2", res.Version)
	}
	if res := dial(t, tg, "pq-only"); res.OK {
		t.Fatal("post-quantum key exchange cannot happen over TLS 1.2")
	}
}

// Nothing listening is not a TLS verdict. The kind has to say so, or a fleet
// run reports every unreachable host as post-quantum intolerant.
func TestClosedPortIsRefusedNotIntolerant(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := targetOf(t, ln.Addr().String())
	ln.Close()

	res := dial(t, tg, "classic")
	if res.OK {
		t.Fatal("a closed port cannot complete a handshake")
	}
	if res.Kind != KindRefused && res.Kind != KindTimeout {
		t.Fatalf("kind = %s, want refused", res.Kind)
	}
}

// A plaintext service on the probed port answers with something that is not a
// TLS record. It must not be confused with a capability problem.
func TestPlaintextServerIsARecordError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()

	res := dial(t, targetOf(t, ln.Addr().String()), "classic")
	if res.OK {
		t.Fatal("plaintext is not a handshake")
	}
	if res.Kind != KindRecord && res.Kind != KindEOF {
		t.Fatalf("kind = %s, want record", res.Kind)
	}
}

func TestChainVerificationIsSeparateFromTheHandshake(t *testing.T) {
	// An expired certificate must not stop the capability answer: the
	// handshake completes, and the chain is graded on its own.
	cert := selfSigned(t, time.Now().Add(-24*time.Hour))
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})

	res := dial(t, tg, "pq-preferred")
	if !res.OK {
		t.Fatalf("an expired certificate must not fail the capability probe: %s", res.Err)
	}
	if res.ChainVerified {
		t.Fatal("an expired self-signed certificate cannot verify against the system roots")
	}
	if res.PeerChainLen != 1 {
		t.Fatalf("peer chain length = %d, want 1", res.PeerChainLen)
	}
}

func TestTargetStringShowsSNIOnlyWhenItDiffers(t *testing.T) {
	if got := (Target{Host: "h", Port: "443"}).String(); got != "h:443" {
		t.Fatalf("got %q", got)
	}
	if got := (Target{Host: "1.2.3.4", Port: "443", SNI: "www.example.com"}).String(); got != "1.2.3.4:443 (sni www.example.com)" {
		t.Fatalf("got %q", got)
	}
}

// PQ-22, against a real listener: a server pinned to X25519 accepts exactly one
// group when each is offered alone, and says no to the others *civilly*. The
// point of the per-group pass is that the accepted set is read off the wire
// rather than inferred from a profile that offered three groups at once.
func TestGroupProbesReadTheAcceptedSetOffTheWire(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	d := Dialer{Timeout: 5 * time.Second}
	got := map[string]Result{}
	for _, p := range clientprofile.GroupProbes() {
		got[p.Name] = d.Do(context.Background(), tg, p)
	}

	x := got[clientprofile.GroupProbeName(tls.X25519)]
	if !x.OK {
		t.Fatalf("X25519 was pinned on the server and must be accepted: %s (%s)", x.Err, x.Kind)
	}
	if x.Group != "X25519" {
		t.Fatalf("negotiated %q, want X25519 — a group probe offers one group, so the answer is unambiguous", x.Group)
	}

	pq := got[clientprofile.GroupProbeName(tls.X25519MLKEM768)]
	if pq.OK {
		t.Fatal("the server has no ML-KEM; the hybrid group probe must not complete")
	}
	if pq.Kind.Abrupt() {
		t.Fatalf("a group the peer merely does not have must be a civil refusal, not abrupt: kind=%s err=%s", pq.Kind, pq.Err)
	}

	for _, id := range []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		if r := got[clientprofile.GroupProbeName(id)]; r.OK {
			t.Errorf("%s completed against a server pinned to X25519", clientprofile.GroupName(id))
		}
	}
}

// flakyServer drops the first `bad` connections without a word and serves TLS
// normally afterwards. A half-closed conntrack entry, a load balancer being
// reconfigured and a genuinely intolerant middlebox all look identical on one
// dial; they stop looking identical on two.
func flakyServer(t *testing.T, cfg *tls.Config, bad int) Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	seen := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			seen++
			n := seen
			mu.Unlock()
			go func() {
				if n <= bad {
					// A reset rather than a polite close: no alert, nothing to log.
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetLinger(0)
					}
					c.Close()
					return
				}
				defer c.Close()
				srv := tls.Server(c, cfg)
				_ = srv.HandshakeContext(context.Background())
				srv.Close()
			}()
		}
	}()
	return targetOf(t, ln.Addr().String())
}

// PQ-23. pq-intolerant is the finding somebody takes to a CDN vendor. One reset
// can also be a stale conntrack entry, so an abrupt result is dialled a second
// time before it is believed — and when the second dial connects, the endpoint
// is flapping, not walled.
func TestAnAbruptResultIsConfirmedBeforeItIsBelieved(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := flakyServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, 1)

	p, _ := clientprofile.ByName("pq-preferred")
	d := Dialer{Timeout: 5 * time.Second, Confirm: true}
	res := d.DoConfirmed(context.Background(), tg, p)

	if !res.OK {
		t.Fatalf("the second dial should have connected: %s (%s)", res.Err, res.Kind)
	}
	if res.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", res.Attempts)
	}
	if !res.Flapped {
		t.Error("a result that failed abruptly and then connected has to say so: this is a flap, not a wall")
	}
	if res.FirstKind != KindReset && res.FirstKind != KindEOF {
		t.Errorf("first kind = %q, want the abrupt failure that was retried", res.FirstKind)
	}
}

// The wall: both dials end the same way, and the result says the refusal
// reproduced — which is what makes it quotable.
func TestAReproducibleWallSaysSo(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := intolerantServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, 400)

	p, _ := clientprofile.ByName("pq-preferred")
	d := Dialer{Timeout: 5 * time.Second, Confirm: true}
	res := d.DoConfirmed(context.Background(), tg, p)

	if res.OK {
		t.Fatal("the hybrid hello is over the limit; it must not complete")
	}
	if res.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", res.Attempts)
	}
	if !res.Reproduced {
		t.Error("both dials failed abruptly, so the refusal reproduced and the finding has to say it")
	}
	if res.Flapped {
		t.Error("nothing flapped here")
	}
}

// A civil refusal is a decision the peer made, not a network event: re-dialling
// it would double the connections against every endpoint with a policy, and
// prove nothing.
func TestACivilRefusalIsNotRetried(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	p, _ := clientprofile.ByName("pq-only")
	d := Dialer{Timeout: 5 * time.Second, Confirm: true}
	res := d.DoConfirmed(context.Background(), tg, p)

	if res.OK {
		t.Fatal("a server without ML-KEM must not complete pq-only")
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 — an alert is an answer, not a flap", res.Attempts)
	}
	if res.Reproduced {
		t.Error("nothing was reproduced: there was one dial")
	}
}

// Off by default is not the question — the question is that it can be turned
// off, for a run where a second connection per abrupt result is not welcome.
func TestConfirmCanBeTurnedOff(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := flakyServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, 1)

	p, _ := clientprofile.ByName("pq-preferred")
	d := Dialer{Timeout: 5 * time.Second}
	res := d.DoConfirmed(context.Background(), tg, p)

	if res.OK {
		t.Fatal("without confirmation the first dial is the answer, and it failed")
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
}

// PQ-26. A mutual-TLS origin is not a peer that refuses post-quantum clients.
// On TLS 1.3 its rejection arrives *after* the client's Finished, so the
// handshake completes and the key exchange answer is sound — but a report that
// said nothing would let somebody read "pq-ready" as "usable". The peer's
// CertificateRequest is recorded instead.
func TestMutualTLSIsRecordedNotMistakenForARefusal(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
	})

	p, _ := clientprofile.ByName("pq-only")
	d := Dialer{Timeout: 5 * time.Second}
	res := d.Do(context.Background(), tg, p)

	if !res.OK {
		t.Fatalf("on TLS 1.3 the handshake completes before the peer can object: %s (%s)", res.Err, res.Kind)
	}
	if !res.ClientCertRequested {
		t.Error("the peer sent a CertificateRequest and the result has to say so")
	}
	if res.Group != "X25519MLKEM768" {
		t.Errorf("group = %q — the key exchange still happened and is still the answer", res.Group)
	}
}

// An endpoint that asks for nothing must not grow a mutual-TLS note.
func TestNoCertificateRequestIsNotRecorded(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})

	p, _ := clientprofile.ByName("pq-preferred")
	res := Dialer{Timeout: 5 * time.Second}.Do(context.Background(), tg, p)
	if res.ClientCertRequested {
		t.Error("nothing asked for a client certificate")
	}
}

// TLS 1.2 is where it actually bites: client auth happens inside the handshake,
// so the peer's alert is indistinguishable from "no mutually supported group" by
// its error string alone. The recorded request is what tells them apart.
func TestMutualTLSOnTLS12IsDistinguishableFromAGroupRefusal(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAnyClientCert,
	})

	p, _ := clientprofile.ByName("tls12")
	res := Dialer{Timeout: 5 * time.Second}.Do(context.Background(), tg, p)

	if res.OK {
		t.Fatal("the peer wanted a certificate pqprobe does not have")
	}
	if res.Kind.Abrupt() {
		t.Errorf("this is a civil refusal: kind = %s", res.Kind)
	}
	if !res.ClientCertRequested {
		t.Error("without this the failure is indistinguishable from a group refusal, which is the whole point")
	}
}
