package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
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

// fakeResolver answers from a table, so the expansion can be asserted without
// DNS — which is both flaky and somebody else's infrastructure.
type fakeResolver struct {
	table map[string][]string
	err   error
	calls int
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []net.IPAddr
	for _, s := range f.table[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// PQ-12. A hostname behind several A/AAAA records is several stacks, and one bad
// node out of six is exactly the shape that survives a manual check. Each
// address is probed by address while the name still travels as the SNI — the
// `1.2.3.4=origin.example` form the tool already had, applied automatically.
func TestExpandAddressesProbesEveryStackByAddress(t *testing.T) {
	r := &fakeResolver{table: map[string][]string{
		"origin.example": {"192.0.2.1", "192.0.2.2", "2001:db8::1"},
	}}

	got, errs := ExpandAddresses(context.Background(), r, []Target{
		{Host: "origin.example", Port: "443"},
	}, "")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 3 {
		t.Fatalf("got %d targets, want one per address: %+v", len(got), got)
	}
	for _, tg := range got {
		if net.ParseIP(tg.Host) == nil {
			t.Errorf("%s is not an address — the point is to dial the stack, not the name", tg.Host)
		}
		if tg.SNI != "origin.example" {
			t.Errorf("sni = %q, want the name: dialling an address with the wrong server name probes a different vhost", tg.SNI)
		}
		if tg.Port != "443" {
			t.Errorf("port = %q, want 443", tg.Port)
		}
	}
}

// An explicit SNI must survive: `1.2.3.4=origin.example` and `--sni` exist
// because the name being sent is the interesting variable.
func TestExpandAddressesKeepsAnExplicitSNI(t *testing.T) {
	r := &fakeResolver{table: map[string][]string{"lb.example": {"192.0.2.9"}}}

	got, _ := ExpandAddresses(context.Background(), r, []Target{
		{Host: "lb.example", Port: "443", SNI: "origin.example"},
	}, "")
	if len(got) != 1 || got[0].SNI != "origin.example" {
		t.Fatalf("got %+v, want the SNI preserved", got)
	}
}

// An address needs no resolving, and resolving it would be a DNS lookup nobody
// asked for.
func TestExpandAddressesLeavesLiteralsAlone(t *testing.T) {
	r := &fakeResolver{}
	got, _ := ExpandAddresses(context.Background(), r, []Target{
		{Host: "192.0.2.5", Port: "8443", SNI: "origin.example"},
	}, "")
	if len(got) != 1 || got[0].Host != "192.0.2.5" || got[0].Port != "8443" {
		t.Fatalf("got %+v, want the literal untouched", got)
	}
	if r.calls != 0 {
		t.Errorf("resolver was called %d times for an address literal", r.calls)
	}
}

// A name that does not resolve keeps its target: the normal dial then reports it
// as a DNS failure, with the same wording as every other run. Dropping it would
// make an endpoint vanish from a fleet report, which is the one thing a
// monitoring tool must never do.
func TestExpandAddressesKeepsATargetThatDoesNotResolve(t *testing.T) {
	r := &fakeResolver{err: errors.New("no such host")}
	got, errs := ExpandAddresses(context.Background(), r, []Target{
		{Host: "gone.example", Port: "443"},
	}, "")
	if len(got) != 1 || got[0].Host != "gone.example" {
		t.Fatalf("got %+v, want the target kept for the dialler to report", got)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want the resolution failure reported once", errs)
	}
}

// PQ-12, found by running --per-address on a host with no IPv6 route: an
// address that cannot be reached *from here* was classified as "other", which
// the verdict then read as tls-broken — "the port answered but no profile
// completed a handshake". The port never answered. A local routing gap must
// never be reported as a property of somebody else's endpoint.
func TestNoRouteIsItsOwnKindNotAnEndpointProblem(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"host unreachable", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}},
		{"network unreachable", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}},
	} {
		kind, _ := classify(tc.err)
		if kind != KindUnroutable {
			t.Errorf("%s: kind = %q, want %q", tc.name, kind, KindUnroutable)
		}
		if kind.Abrupt() {
			t.Errorf("%s: a route that does not exist is not a peer cutting us off", tc.name)
		}
	}
}

// A refused connection still means something is there to refuse: the two must
// not collapse into one word.
func TestRefusedIsNotUnroutable(t *testing.T) {
	kind, _ := classify(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	if kind != KindRefused {
		t.Errorf("kind = %q, want %q", kind, KindRefused)
	}
}

// PQ-9. Go does not expose HelloRetryRequest, and the backlog assumed a
// hand-parsed ServerHello. There is a simpler signal that needs no parsing of
// somebody else's message: an HRR is precisely the case where *we* send a second
// ClientHello. Counting the ClientHellos we write is deterministic, and it also
// gives the size of the first one for free.
//
// What the first run of this test taught, and what the finding therefore has to
// mean: Go's client sends **two** key shares — the hybrid one and X25519 — so a
// classical server picking X25519 costs no retry at all. An HRR happens when
// the only group in common is one no key share was offered for, which in
// practice means P-256 or P-384. That is a narrower, more interesting state
// than "the peer has no ML-KEM".
func TestHelloRetryRequestIsVisibleFromOurOwnWrites(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))

	// Only P-256, which pq-preferred lists but sends no key share for: the peer
	// has to ask for another group, and the round trip is real.
	p256 := serveTLS(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	})
	res := dial(t, p256, "pq-preferred")
	if !res.OK {
		t.Fatalf("the realistic client must still connect: %s (%s)", res.Err, res.Kind)
	}
	if res.Group != "P-256" {
		t.Fatalf("group = %q, want P-256", res.Group)
	}
	if !res.HRR {
		t.Error("this handshake cost a HelloRetryRequest and the result has to say so")
	}
	if res.HelloCount != 2 {
		t.Errorf("hello count = %d, want 2: the client hello was sent again", res.HelloCount)
	}

	// X25519 needs no retry, because a key share for it went out with the
	// hybrid one. Asserted so the day Go stops doing that, this says so.
	x25519 := serveTLS(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	if res := dial(t, x25519, "pq-preferred"); res.HRR || res.HelloCount != 1 {
		t.Errorf("falling back to X25519 costs no retry: hrr=%v count=%d", res.HRR, res.HelloCount)
	}

	// A server that has ML-KEM answers the first hello, and nothing is retried.
	modern := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	res = dial(t, modern, "pq-preferred")
	if !res.OK {
		t.Fatalf("handshake failed: %s", res.Err)
	}
	if res.HRR || res.HelloCount != 1 {
		t.Errorf("nothing was retried: hrr=%v count=%d", res.HRR, res.HelloCount)
	}
}

// The size of the ClientHello is the number the size-intolerance conversation
// actually turns on, and it is measured rather than estimated: these are the
// bytes we put on the wire.
func TestTheClientHelloSizeIsMeasured(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})

	small := dial(t, tg, "classic")
	large := dial(t, tg, "pq-preferred")

	if small.HelloBytes <= 0 || large.HelloBytes <= 0 {
		t.Fatalf("no hello size recorded: classic=%d pq-preferred=%d", small.HelloBytes, large.HelloBytes)
	}
	// The ML-KEM key share is roughly 1.2 KB. The exact numbers move with the
	// toolchain, so the assertion is the gap, which is the whole story.
	if large.HelloBytes-small.HelloBytes < 800 {
		t.Errorf("the hybrid hello is only %d bytes bigger than the classical one (%d vs %d) — that gap is the reason this tool exists",
			large.HelloBytes-small.HelloBytes, large.HelloBytes, small.HelloBytes)
	}
	if small.HelloBytes > 1000 {
		t.Errorf("the classical hello is %d bytes, which is implausible", small.HelloBytes)
	}
}

// PQ-11. The point of the sweep is a number an operator can put in a ticket
// instead of an argument. Against a listener that serves TLS below a hello size
// limit and vanishes above it, the sweep has to bracket that limit — and the
// size it reports is measured on the wire, not the size it asked for.
func TestTheSizeSweepBracketsARealLimit(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	const limit = 3000
	tg := intolerantServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, limit)

	d := Dialer{Timeout: 5 * time.Second}
	var lastOK, firstBad int
	for _, p := range clientprofile.SizeProbes() {
		res := d.Do(context.Background(), tg, p)
		if res.HelloBytes == 0 {
			t.Fatalf("%s: no hello size measured", p.Name)
		}
		// The measured size is what gets reported, and it has to be close to
		// the size the probe was asking for or the sweep means nothing.
		if diff := res.HelloBytes - p.Pad - 1500; diff > 400 || diff < -400 {
			t.Errorf("%s: measured %d bytes, which is %d off the target", p.Name, res.HelloBytes, diff)
		}
		if res.OK {
			lastOK = res.HelloBytes
			continue
		}
		if !res.Kind.Abrupt() {
			t.Errorf("%s: the listener vanishes rather than declining: kind=%s", p.Name, res.Kind)
		}
		firstBad = res.HelloBytes
		break
	}

	if lastOK == 0 || firstBad == 0 {
		t.Fatalf("the sweep did not bracket the limit: last ok %d, first bad %d", lastOK, firstBad)
	}
	if lastOK >= firstBad {
		t.Fatalf("the bracket is inverted: %d then %d", lastOK, firstBad)
	}
	if lastOK > limit || firstBad < limit {
		t.Errorf("the limit is %d and the bracket is %d..%d, which does not contain it", limit, lastOK, firstBad)
	}
}

// PQ-25, against a real listener with a threshold between the two hellos: bare
// connects, the same client carrying h2,http/1.1 does not. Without the pair
// this is indistinguishable from a flap, which is why the two are dialled
// together.
func TestALPNBytesCanBeWhatTipsAPeerOver(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	// Measure the bare hybrid hello first, then plant the limit just above it.
	bareSize := dial(t, serveTLS(t, cfg), "pq-preferred").HelloBytes
	if bareSize == 0 {
		t.Fatal("no hello size measured")
	}
	tg := intolerantServer(t, cfg, bareSize+4)

	d := Dialer{Timeout: 5 * time.Second}
	pref, _ := clientprofile.ByName("pq-preferred")
	bare := d.Do(context.Background(), tg, pref)
	withALPN := d.Do(context.Background(), tg, clientprofile.ALPNProbe())

	if !bare.OK {
		t.Fatalf("the bare hello is under the limit and must connect: %s (%s)", bare.Err, bare.Kind)
	}
	if withALPN.OK {
		t.Fatalf("the ALPN list pushed the hello to %d bytes, over the limit of %d, and it must not connect",
			withALPN.HelloBytes, bareSize+4)
	}
	if !withALPN.Kind.Abrupt() {
		t.Errorf("this listener vanishes rather than declining: kind=%s", withALPN.Kind)
	}
	if withALPN.HelloBytes <= bare.HelloBytes {
		t.Errorf("the ALPN hello (%d B) is not larger than the bare one (%d B), so nothing was tested",
			withALPN.HelloBytes, bare.HelloBytes)
	}
}

// socks5Server is a minimal RFC 1928 proxy for the tests: it negotiates
// no-auth, CONNECTs to `to`, and splices. `auth` makes it demand a method
// pqprobe does not have; `reply` makes it answer CONNECT with a failure.
// asked records the address the client asked for, which is how the test proves
// the *name* went to the proxy rather than an address resolved here.
type socks5Server struct {
	to    string
	auth  bool
	reply byte
	asked chan string
}

func startSocks5(t *testing.T, s *socks5Server) string {
	t.Helper()
	s.asked = make(chan string, 4)
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
			go s.serve(c)
		}
	}()
	return ln.Addr().String()
}

func (s *socks5Server) serve(c net.Conn) {
	defer c.Close()

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if s.auth {
		_, _ = c.Write([]byte{5, 2}) // username/password, which pqprobe has none of
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		b := make([]byte, int(l[0]))
		io.ReadFull(c, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	}
	port := make([]byte, 2)
	io.ReadFull(c, port)
	select {
	case s.asked <- net.JoinHostPort(host, fmt.Sprint(int(port[0])<<8|int(port[1]))):
	default:
	}

	if s.reply != 0 {
		_, _ = c.Write([]byte{5, s.reply, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.Dial("tcp", s.to)
	if err != nil {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go io.Copy(up, c)
	io.Copy(c, up)
}

// PQ-35. From many networks the only way out is a proxy. SOCKS5 is a handshake
// on a raw socket and fits; HTTP CONNECT is a *request* and would trade away
// the property that makes this binary safe to point at production.
func TestAHandshakeThroughASocks5Proxy(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	origin := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	srv := &socks5Server{to: origin.Addr()}
	proxy := startSocks5(t, srv)

	p, _ := clientprofile.ByName("pq-only")
	d := Dialer{Timeout: 5 * time.Second, Socks5: proxy}
	res := d.Do(context.Background(), Target{Host: "origin.example", Port: origin.Port, SNI: "origin.example"}, p)

	if !res.OK {
		t.Fatalf("the handshake has to complete through the proxy: %s (%s)", res.Err, res.Kind)
	}
	if res.Group != "X25519MLKEM768" {
		t.Errorf("group = %q — the proxy carries bytes, it does not change the key exchange", res.Group)
	}
	if res.HelloBytes == 0 {
		t.Error("the hello is still measured through a proxy")
	}

	// The name has to travel to the proxy: inside a network it is often the only
	// place it resolves at all.
	select {
	case asked := <-srv.asked:
		if !strings.HasPrefix(asked, "origin.example:") {
			t.Errorf("the proxy was asked for %q, want the name", asked)
		}
	default:
		t.Error("the proxy recorded no request")
	}
}

// A proxy that wants credentials, a proxy that refuses, and a proxy that is not
// there: none of those is the endpoint cutting us off, and none may ever read as
// abrupt — that is what turns into a pq-intolerant verdict about somebody
// else's endpoint.
func TestProxyFailuresAreNeverTheEndpointsFault(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	origin := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	p, _ := clientprofile.ByName("pq-preferred")
	tg := Target{Host: "origin.example", Port: origin.Port, SNI: "origin.example"}

	cases := []struct {
		name  string
		proxy string
		want  string
	}{
		{"wants credentials", startSocks5(t, &socks5Server{to: origin.Addr(), auth: true}), "auth"},
		{"refuses the connection", startSocks5(t, &socks5Server{to: origin.Addr(), reply: 5}), "refused"},
		{"host unreachable", startSocks5(t, &socks5Server{to: origin.Addr(), reply: 4}), "unreachable"},
		{"not listening", "127.0.0.1:1", "proxy"},
	}
	for _, tc := range cases {
		d := Dialer{Timeout: 3 * time.Second, Socks5: tc.proxy}
		res := d.Do(context.Background(), tg, p)

		if res.OK {
			t.Errorf("%s: the handshake must not complete", tc.name)
			continue
		}
		if res.Kind != KindProxy {
			t.Errorf("%s: kind = %q, want %q — this happened at the proxy, before the endpoint saw anything",
				tc.name, res.Kind, KindProxy)
		}
		if res.Kind.Abrupt() {
			t.Errorf("%s: a proxy failure must never read as the peer cutting us off", tc.name)
		}
		if !strings.Contains(strings.ToLower(res.Err), tc.want) {
			t.Errorf("%s: error = %q, want it to mention %q", tc.name, res.Err, tc.want)
		}
		if !strings.Contains(strings.ToLower(res.Err), "socks5") {
			t.Errorf("%s: error = %q, want the proxy named so nobody debugs the wrong host", tc.name, res.Err)
		}
	}
}

// starttlsServer speaks just enough of a protocol's plaintext negotiation to
// reach TLS, then hands the connection to tls.Server. `refuse` makes it answer
// the upgrade request with a refusal, which is what a relay with TLS switched
// off does.
func starttlsServer(t *testing.T, proto string, cfg *tls.Config, refuse bool) Target {
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
				br := bufio.NewReader(c)
				switch proto {
				case "smtp":
					fmt.Fprint(c, "220 mx.example ESMTP ready\r\n")
					line, _ := br.ReadString('\n')
					if !strings.HasPrefix(strings.ToUpper(line), "EHLO") {
						return
					}
					fmt.Fprint(c, "250-mx.example\r\n250-SIZE 10240000\r\n")
					if refuse {
						fmt.Fprint(c, "250 PIPELINING\r\n")
					} else {
						fmt.Fprint(c, "250 STARTTLS\r\n")
					}
					line, _ = br.ReadString('\n')
					if !strings.HasPrefix(strings.ToUpper(line), "STARTTLS") {
						return
					}
					if refuse {
						fmt.Fprint(c, "454 TLS not available\r\n")
						return
					}
					fmt.Fprint(c, "220 ready to start TLS\r\n")
				case "imap":
					fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
					line, _ := br.ReadString('\n')
					if !strings.Contains(strings.ToUpper(line), "STARTTLS") {
						return
					}
					if refuse {
						fmt.Fprint(c, "a1 NO starttls not supported\r\n")
						return
					}
					fmt.Fprint(c, "a1 OK begin TLS negotiation now\r\n")
				case "ldap":
					// The StartTLS extended request, and an extendedResp whose
					// resultCode is the whole answer: 0 success, 53 unwilling
					// to perform — with the server's own words attached, which
					// is what sends an operator to the right file.
					head := make([]byte, 2)
					if _, err := io.ReadFull(br, head); err != nil {
						return
					}
					body := make([]byte, int(head[1]))
					if _, err := io.ReadFull(br, body); err != nil {
						return
					}
					if !strings.Contains(string(body), "1.3.6.1.4.1.1466.20037") {
						t.Error("ldap: the request does not carry the StartTLS OID")
						return
					}
					if refuse {
						msg := "TLS not enabled"
						resp := []byte{0x30, 0, 0x02, 0x01, 0x01, 0x78, 0, 0x0a, 0x01, 53, 0x04, 0x00, 0x04, byte(len(msg))}
						resp = append(resp, msg...)
						resp[6] = byte(len(resp) - 7)
						resp[1] = byte(len(resp) - 2)
						_, _ = c.Write(resp)
						return
					}
					_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
				case "xmpp-split":
					// The same exchange, with the proceed element split across
					// two writes — which is all a TCP segment boundary is. A
					// client that stops reading at `<proceed` leaves the tail
					// in the socket, and tls.Client then reads `xmlns=...` as a
					// TLS record: a healthy endpoint graded pq-intolerant.
					open := make([]byte, 512)
					n, _ := br.Read(open)
					_ = n
					fmt.Fprint(c, "<?xml version='1.0'?><stream:stream id='1' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>")
					req := make([]byte, 256)
					if _, err := br.Read(req); err != nil {
						return
					}
					fmt.Fprint(c, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-t")
					time.Sleep(50 * time.Millisecond)
					fmt.Fprint(c, "ls'/>")
				case "xmpp":
					open := make([]byte, 512)
					n, _ := br.Read(open)
					if !strings.Contains(string(open[:n]), "to=") {
						t.Error("xmpp: the stream header carries no to=, so a virtual host would answer for the wrong name")
					}
					features := "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>"
					if refuse {
						features = "<stream:features><mechanisms/></stream:features>"
					}
					fmt.Fprint(c, "<?xml version='1.0'?><stream:stream id='1' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"+features)
					if refuse {
						return
					}
					req := make([]byte, 256)
					n, _ = br.Read(req)
					if !strings.Contains(string(req[:n]), "starttls") {
						return
					}
					fmt.Fprint(c, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
				case "ftp":
					// The real shape, from a public server: a dash on the
					// first line and then lines with no code at all.
					fmt.Fprint(c, "220-Welcome to files.example\r\n")
					fmt.Fprint(c, "See https://files.example/ for the terms of use.\r\n")
					fmt.Fprint(c, "220 ready\r\n")
					line, _ := br.ReadString('\n')
					if !strings.HasPrefix(strings.ToUpper(line), "AUTH TLS") {
						return
					}
					if refuse {
						fmt.Fprint(c, "500 AUTH not understood\r\n")
						return
					}
					fmt.Fprint(c, "234 AUTH TLS successful\r\n")
				case "nntp":
					// 201 rather than 200: posting is not allowed here, and that
					// is a healthy server, not a refusal.
					fmt.Fprint(c, "201 news.example ready - no posting allowed\r\n")
					line, _ := br.ReadString('\n')
					if !strings.HasPrefix(strings.ToUpper(line), "STARTTLS") {
						return
					}
					if refuse {
						fmt.Fprint(c, "580 Can not initiate TLS negotiation\r\n")
						return
					}
					fmt.Fprint(c, "382 Continue with TLS negotiation\r\n")
				case "mysql":
					// The server speaks first: a handshake packet whose
					// capability flags say whether CLIENT_SSL is on offer.
					caps := 0x0200 // CLIENT_PROTOCOL_41
					if !refuse {
						caps |= 0x0800 // CLIENT_SSL
					}
					payload := []byte{10}
					payload = append(payload, "8.0.36-pqprobe-test\x00"...)
					payload = append(payload, 1, 0, 0, 0)             // connection id
					payload = append(payload, 1, 2, 3, 4, 5, 6, 7, 8) // auth-plugin-data-part-1
					payload = append(payload, 0)                      // filler
					payload = append(payload, byte(caps), byte(caps>>8))
					payload = append(payload, 45)   // charset
					payload = append(payload, 2, 0) // status flags
					payload = append(payload, 0, 0) // capability flags, upper
					payload = append(payload, 21)   // auth-plugin-data length
					payload = append(payload, make([]byte, 10)...)
					payload = append(payload, "123456789012\x00"...)
					payload = append(payload, "mysql_native_password\x00"...)
					pkt := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 0}
					if _, err := c.Write(append(pkt, payload...)); err != nil {
						return
					}
					if refuse {
						// A server without CLIENT_SSL waits for a login packet
						// it will never get; the client has already given up.
						return
					}
					// The SSLRequest packet: a 4-byte header and 32 bytes.
					hdr := make([]byte, 4)
					if _, err := io.ReadFull(br, hdr); err != nil {
						return
					}
					if n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16; n != 32 {
						t.Errorf("mysql: SSLRequest payload is %d bytes, want 32", n)
						return
					}
					if hdr[3] != 1 {
						t.Errorf("mysql: SSLRequest sequence id = %d, want 1 (the greeting was 0)", hdr[3])
						return
					}
					body := make([]byte, 32)
					if _, err := io.ReadFull(br, body); err != nil {
						return
					}
					if body[1]&0x08 == 0 {
						t.Error("mysql: the client did not set CLIENT_SSL, so the server would expect a login packet")
						return
					}
				case "postgres":
					// The SSLRequest packet: 8 bytes, length then the magic code.
					hdr := make([]byte, 8)
					if _, err := io.ReadFull(br, hdr); err != nil {
						return
					}
					if refuse {
						_, _ = c.Write([]byte("N"))
						return
					}
					_, _ = c.Write([]byte("S"))
				}
				// Whatever the reader pulled in past the negotiation is the
				// start of the ClientHello: MySQL's client does not wait for a
				// reply before sending it, so one Read can hold both. Dropping
				// those bytes deadlocks the handshake — which is how this was
				// found, under -race.
				buffered := make([]byte, br.Buffered())
				if len(buffered) > 0 {
					_, _ = io.ReadFull(br, buffered)
				}
				srv := tls.Server(&prefixConn{Conn: c, pre: bytes.NewReader(buffered)}, cfg)
				_ = srv.HandshakeContext(context.Background())
				srv.Close()
			}()
		}
	}()
	return targetOf(t, ln.Addr().String())
}

// PQ-20. An SMTP relay, an IMAP server and a Postgres instance all speak TLS,
// and none of them on 443: the handshake is reached through a plaintext
// negotiation first. Implicit TLS on any port already worked — this is the
// half that did not.
func TestSTARTTLSReachesTheHandshakeOnEveryProtocol(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	for _, proto := range StartTLSProtocols() {
		tg := starttlsServer(t, proto, cfg, false)
		p, _ := clientprofile.ByName("pq-only")
		d := Dialer{Timeout: 5 * time.Second, StartTLS: proto}
		res := d.Do(context.Background(), tg, p)

		if !res.OK {
			t.Errorf("%s: handshake failed after the upgrade: %s (%s)", proto, res.Err, res.Kind)
			continue
		}
		if res.Group != "X25519MLKEM768" {
			t.Errorf("%s: group = %q — the negotiation carries bytes, it does not change the key exchange", proto, res.Group)
		}
		// The ClientHello is still measured, and the plaintext chatter before it
		// must not be counted as one.
		if res.HelloBytes < 1000 {
			t.Errorf("%s: hello = %d bytes, want the hybrid hello measured after the upgrade", proto, res.HelloBytes)
		}
		if res.HelloCount != 1 {
			t.Errorf("%s: hello count = %d, want 1", proto, res.HelloCount)
		}
	}
}

// A relay with TLS switched off has not refused a post-quantum client: it has
// refused *TLS*, and reading that as an abrupt end would file it as
// pq-intolerant.
func TestASTARTTLSRefusalIsNotAPostQuantumVerdict(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	for _, proto := range StartTLSProtocols() {
		tg := starttlsServer(t, proto, cfg, true)
		p, _ := clientprofile.ByName("pq-preferred")
		res := Dialer{Timeout: 5 * time.Second, StartTLS: proto}.Do(context.Background(), tg, p)

		if res.OK {
			t.Errorf("%s: the server refused the upgrade; the handshake must not complete", proto)
		}
		if res.Kind != KindStartTLS {
			t.Errorf("%s: kind = %q, want %q", proto, res.Kind, KindStartTLS)
		}
		if res.Kind.Abrupt() {
			t.Errorf("%s: a refused upgrade must never read as the peer cutting us off", proto)
		}
		if !strings.Contains(strings.ToLower(res.Err), "starttls") &&
			!strings.Contains(strings.ToLower(res.Err), "tls") {
			t.Errorf("%s: error = %q, want it to say what was refused", proto, res.Err)
		}
	}
}

// An unknown protocol is a usage error at the boundary, not a plain TLS dial
// that happens to fail on port 587 for a reason nobody can see.
func TestAnUnknownSTARTTLSProtocolIsRefused(t *testing.T) {
	if StartTLSProtocols() == nil {
		t.Fatal("the supported protocols have to be listable, for the error message and the docs")
	}
	if !ValidStartTLS("smtp") || !ValidStartTLS("") {
		t.Error("smtp and the empty value (no negotiation) are both valid")
	}
	if ValidStartTLS("gopher") {
		t.Error("gopher is not a STARTTLS protocol this tool speaks")
	}
}

// PQ-44. Post-quantum *authentication* is the next migration, and its failure
// will be a size failure again — an ML-DSA signature is about 3.3 KB where an
// ECDSA one is 64 bytes, so the chain a server sends grows from roughly 3 KB to
// well past 10. The number to watch is therefore what the chain costs today,
// measured on the wire rather than guessed.
func TestTheCertificateChainIsMeasured(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})

	res := dial(t, tg, "classic")
	if !res.OK {
		t.Fatalf("handshake failed: %s", res.Err)
	}
	if res.ChainBytes <= 0 {
		t.Fatal("no chain size recorded")
	}
	// One self-signed P-256 leaf: a few hundred bytes, and certainly not the
	// kilobytes an ML-DSA chain will cost.
	if res.ChainBytes < 200 || res.ChainBytes > 2000 {
		t.Errorf("chain = %d bytes, which is implausible for a single ECDSA leaf", res.ChainBytes)
	}
	// It has to be the sum of what the peer actually sent, not a re-encoding.
	sum := 0
	for _, c := range res.Chain {
		if c.Bytes <= 0 {
			t.Errorf("a certificate with no size: %+v", c)
		}
		sum += c.Bytes
	}
	if sum != res.ChainBytes {
		t.Errorf("chain bytes = %d but the certificates add up to %d", res.ChainBytes, sum)
	}
}

// A failed handshake has no chain, and reporting zero as if it were a
// measurement is how a dashboard grows a cliff nobody can explain.
func TestNoChainNoMeasurement(t *testing.T) {
	res := Dialer{Timeout: 2 * time.Second}.Do(context.Background(),
		Target{Host: "127.0.0.1", Port: "1"}, mustProfile(t, "classic"))
	if res.OK {
		t.Fatal("nothing is listening on port 1")
	}
	if res.ChainBytes != 0 {
		t.Errorf("chain bytes = %d for a handshake that never happened", res.ChainBytes)
	}
}

func mustProfile(t *testing.T, name string) clientprofile.Profile {
	t.Helper()
	p, ok := clientprofile.ByName(name)
	if !ok {
		t.Fatalf("no profile %q", name)
	}
	return p
}

// PQ-46. --net pins the address family, because today the resolver chooses and
// the run does not say so. A dual-stack name that answers on A and dies on AAAA
// reports whichever address the resolver felt like handing over that minute.
func TestNetPinsTheAddressFamily(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	p, _ := clientprofile.ByName("classic")

	ok := Dialer{Timeout: 5 * time.Second, Net: "tcp4"}.Do(context.Background(), tg, p)
	if !ok.OK {
		t.Fatalf("--net tcp4 against a v4 listener failed: %s (%s)", ok.Err, ok.Kind)
	}

	// The same listener, asked for over IPv6 only: it cannot be reached, and
	// that is a fact about this prober's choice — never a property of the peer.
	res := Dialer{Timeout: 5 * time.Second, Net: "tcp6"}.Do(context.Background(), tg, p)
	if res.OK {
		t.Fatal("a v4 listener answered a tcp6-only dial; the family is not being pinned")
	}
	if res.Kind != KindUnroutable {
		t.Fatalf("kind = %q, want %q: an address family this run excluded says nothing about the endpoint", res.Kind, KindUnroutable)
	}
	if res.Kind.Abrupt() {
		t.Fatal("an excluded address family must never be abrupt: that would grade the peer for our own flag")
	}
}

// The empty value is the default and means what the tool did before: whatever
// the resolver hands over. Anything that is not a family Go dials is a usage
// error rather than a silently different run.
func TestValidNet(t *testing.T) {
	if !ValidNet("") {
		t.Error("no --net is the default: whatever the resolver hands over")
	}
	for _, n := range Nets() {
		if !ValidNet(n) {
			t.Errorf("%s is listed but not accepted", n)
		}
	}
	for _, bad := range []string{"tcp", "udp", "ipv4", "4"} {
		if ValidNet(bad) {
			t.Errorf("%q is not an address family this dials", bad)
		}
	}
}

// PQ-46. --per-address is where the family blindness is worst: a name behind an
// A and an AAAA is two stacks, and a run pinned to one family must probe only
// the addresses of that family — otherwise every excluded record comes back as
// a failure the operator has to read past.
func TestExpandAddressesHonoursTheAddressFamily(t *testing.T) {
	r := &fakeResolver{table: map[string][]string{
		"origin.example": {"192.0.2.1", "2001:db8::1"},
	}}

	v4, errs := ExpandAddresses(context.Background(), r, []Target{{Host: "origin.example", Port: "443"}}, "tcp4")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(v4) != 1 || v4[0].Host != "192.0.2.1" {
		t.Fatalf("got %+v, want only the A record under --net tcp4", v4)
	}

	v6, errs := ExpandAddresses(context.Background(), r, []Target{{Host: "origin.example", Port: "443"}}, "tcp6")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(v6) != 1 || v6[0].Host != "2001:db8::1" {
		t.Fatalf("got %+v, want only the AAAA record under --net tcp6", v6)
	}
	if v6[0].SNI != "origin.example" {
		t.Fatalf("sni = %q, want the name", v6[0].SNI)
	}

	// A name with nothing in the selected family keeps its target and says why:
	// an endpoint must never vanish from a fleet report, and "no AAAA record"
	// is a different sentence from "did not resolve".
	only4 := &fakeResolver{table: map[string][]string{"v4.example": {"192.0.2.7"}}}
	got, errs := ExpandAddresses(context.Background(), only4, []Target{{Host: "v4.example", Port: "443"}}, "tcp6")
	if len(got) != 1 || got[0].Host != "v4.example" {
		t.Fatalf("got %+v, want the target kept", got)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want one explanation of the empty family", errs)
	}
	if !strings.Contains(errs[0].Error(), "tcp6") {
		t.Fatalf("errs = %v, want the family named: without it this reads as a DNS failure", errs)
	}
}

// PQ-45. MySQL is the one protocol here where the *server* speaks first, and a
// port that accepts the connection and then says nothing is its common failure
// — a blocked host, an instance still starting, a firewall that completes the
// handshake for you. Without a deadline on the plaintext negotiation the probe
// waits for ever: --timeout covers the TLS handshake, and there was no TLS
// handshake yet.
func TestAPlaintextNegotiationThatHangsIsBoundedAndIsNotAVerdict(t *testing.T) {
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
			// Accepted, and then nothing at all.
			t.Cleanup(func() { c.Close() })
		}
	}()

	p, _ := clientprofile.ByName("pq-preferred")
	done := make(chan Result, 1)
	go func() {
		done <- Dialer{Timeout: 300 * time.Millisecond, StartTLS: "mysql"}.
			Do(context.Background(), targetOf(t, ln.Addr().String()), p)
	}()

	select {
	case res := <-done:
		if res.OK {
			t.Fatal("nothing was ever sent; there is no handshake to have completed")
		}
		if res.Kind != KindStartTLS {
			t.Fatalf("kind = %q, want %q: the upgrade never happened, and a timeout waiting for a greeting is not the peer cutting off a post-quantum hello", res.Kind, KindStartTLS)
		}
		if res.Kind.Abrupt() {
			t.Fatal("a silent greeting must never read as abrupt: that is the pq-intolerant bucket")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe did not return: --timeout does not bound the plaintext negotiation")
	}
}

// The MySQL X Protocol on 33060 is a different negotiation — protobuf-framed,
// not this packet exchange — and it is left out on purpose, the same way MySQL
// itself was left out of PQ-20. The list is the promise, so it is asserted.
func TestStartTLSListIsExactlyWhatIsSpoken(t *testing.T) {
	want := map[string]bool{"smtp": true, "imap": true, "postgres": true, "mysql": true,
		"ftp": true, "nntp": true, "ldap": true, "xmpp": true}
	got := StartTLSProtocols()
	if len(got) != len(want) {
		t.Fatalf("StartTLSProtocols() = %v, want exactly %d protocols", got, len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("%s is offered but not in the list this test knows about", p)
		}
		if !ValidStartTLS(p) {
			t.Errorf("%s is listed but not accepted", p)
		}
	}
	if ValidStartTLS("mysqlx") {
		t.Error("the X Protocol is a different negotiation and must not be silently accepted as mysql")
	}
}

// PQ-47. What this prober can reach at all, established locally: a UDP "dial"
// performs the route lookup and sends nothing, which is the only way to ask the
// question without traffic. The answer must be cheap and stable — it is
// consulted once per run, after something has already failed.
func TestHasEgressIsLocalCheapAndStable(t *testing.T) {
	start := time.Now()
	first4, first6 := HasEgress("tcp4"), HasEgress("tcp6")
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the egress check took %s: it is a route lookup, not a probe", d)
	}
	if HasEgress("tcp4") != first4 || HasEgress("tcp6") != first6 {
		t.Fatal("two calls disagreed; a run would report a different local fact each time")
	}
	// Whatever this machine has, it has to have one of them: these tests dial.
	if !first4 && !first6 {
		t.Fatal("neither family has a route, yet this suite is dialling listeners")
	}
	if HasEgress("tcp") || HasEgress("") {
		t.Error("only a pinned family can be answered; anything else has to be false rather than a guess")
	}
}

// echConfig builds an ECHConfigList and the matching server key, by hand.
//
// There is no helper for this anywhere: the wire format is the whole contract
// between a client and a server that have never met, so it is written out here
// — version 0xfe0d, an X25519 HPKE key, one cipher suite — exactly as a DNS
// HTTPS record would carry it. Building it is also what makes ECH assertable
// offline, which is the bar every profile in this repository has had to clear.
func echConfig(t testing.TB) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()

	var cfg []byte
	be16 := func(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) }

	contents := []byte{1}               // config_id
	contents = be16(contents, 0x0020)   // kem_id: DHKEM(X25519, HKDF-SHA256)
	contents = be16(contents, len(pub)) // public_key
	contents = append(contents, pub...)
	contents = be16(contents, 4)      // cipher_suites: one suite
	contents = be16(contents, 0x0001) // kdf_id: HKDF-SHA256
	contents = be16(contents, 0x0001) // aead_id: AES-128-GCM
	contents = append(contents, 0)    // maximum_name_length
	name := "public.example"
	contents = append(contents, byte(len(name)))
	contents = append(contents, name...)
	contents = be16(contents, 0) // extensions

	cfg = be16(cfg, 0xfe0d) // version, draft-ietf-tls-esni-17 / final
	cfg = be16(cfg, len(contents))
	cfg = append(cfg, contents...)

	var list []byte
	list = be16(list, len(cfg))
	list = append(list, cfg...)

	return list, tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: key.Bytes()}
}

// PQ-50. The question ECH asks is the one this tool always asks, one layer out:
// it is a client capability that makes the ClientHello bigger, on top of a
// hybrid hello already sitting near the MTU. Whether the peer *accepted* it is
// read from the connection state, never inferred from the handshake having
// worked — a server that ignores ECH completes a handshake too.
func TestECHIsOfferedAndItsAcceptanceIsRead(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	list, key := echConfig(t)
	tg := serveTLS(t, &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
	})

	ps := clientprofile.ECHProbes(list)
	d := Dialer{Timeout: 5 * time.Second}
	off := d.Do(context.Background(), tg, ps[0])
	on := d.Do(context.Background(), tg, ps[1])

	if !off.OK {
		t.Fatalf("the control handshake failed: %s (%s)", off.Err, off.Kind)
	}
	if !on.OK {
		t.Fatalf("the ECH handshake failed against a server holding the key: %s (%s)", on.Err, on.Kind)
	}
	if !on.ECHAccepted {
		t.Fatal("the server holds the key and the handshake completed, but acceptance was not recorded")
	}
	if off.ECHAccepted {
		t.Fatal("the control offered no ECH; it cannot have been accepted")
	}
	if on.HelloBytes <= off.HelloBytes {
		t.Fatalf("ECH hello = %d B, control = %d B: the extra bytes are the whole point of measuring this", on.HelloBytes, off.HelloBytes)
	}
}

// A server that does not hold the key rejects ECH and offers a retry config.
// That is a *negotiation*: the peer parsed the hello and answered. Reading it
// as the peer cutting us off would file an endpoint that simply does not do ECH
// as intolerant of large hellos.
func TestAnECHRejectionIsCivil(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	list, _ := echConfig(t)
	tg := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})

	on := clientprofile.ECHProbes(list)[1]
	res := Dialer{Timeout: 5 * time.Second}.Do(context.Background(), tg, on)

	if res.OK || res.ECHAccepted {
		t.Fatal("no key on that server; ECH cannot have been accepted")
	}
	if res.Kind != KindECHReject {
		t.Fatalf("kind = %q, want %q", res.Kind, KindECHReject)
	}
	if res.Kind.Abrupt() {
		t.Fatal("an ECH rejection is an answer the peer chose to give; abrupt is the pq-intolerant bucket")
	}
}

// PQ-59. A server that speaks only the P-256 hybrid is post-quantum, and until
// this it came out `tls-broken` — the port answered and nothing completed. The
// condition is planted here rather than described: a listener whose only group
// is SecP256r1MLKEM768.
func TestAPeerThatOnlySpeaksAnotherHybridIsStillPostQuantum(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	tg := serveTLS(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.SecP256r1MLKEM768},
	})

	// The group probe --per-group dials for it has to exist and to connect.
	var probeFor *clientprofile.Profile
	for _, p := range clientprofile.GroupProbes() {
		if len(p.Groups) == 1 && p.Groups[0] == tls.SecP256r1MLKEM768 {
			probeFor = &p
			break
		}
	}
	if probeFor == nil {
		t.Fatal("--per-group has no probe for SecP256r1MLKEM768, so nothing would ever ask")
	}

	res := Dialer{Timeout: 5 * time.Second}.Do(context.Background(), tg, *probeFor)
	if !res.OK {
		t.Fatalf("the handshake failed: %s (%s)", res.Err, res.Kind)
	}
	if !res.PQ {
		t.Fatal("a completed SecP256r1MLKEM768 handshake is post-quantum; grading it classical is how a capable endpoint becomes pq-blind")
	}
	if res.Group != "SecP256r1MLKEM768" {
		t.Fatalf("group = %q, want the name a report prints", res.Group)
	}

	// And what browsers send still fails here, which is the true half of the
	// old answer and must not be softened.
	browser, _ := clientprofile.ByName("pq-only")
	if b := (Dialer{Timeout: 5 * time.Second}).Do(context.Background(), tg, browser); b.OK {
		t.Fatal("this peer offers no X25519MLKEM768; a browser cannot reach it, and the report must keep saying so")
	}
}

// Audit. The XMPP reader stopped at the literal `<proceed`, mid-element. When
// the rest of the element arrives in a later TCP segment those plaintext bytes
// are still in the socket when the TLS handshake starts, tls.Client reads them
// as a record header, and the result is KindRecord — abrupt — which grades a
// perfectly healthy XMPP server `pq-intolerant`.
func TestXMPPConsumesTheWholeProceedElement(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(90*24*time.Hour))
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	tg := starttlsServer(t, "xmpp-split", cfg, false)

	p, _ := clientprofile.ByName("pq-preferred")
	res := Dialer{Timeout: 5 * time.Second, StartTLS: "xmpp"}.Do(context.Background(), tg, p)
	if !res.OK {
		t.Fatalf("handshake failed after a split <proceed/>: %s (%s)", res.Err, res.Kind)
	}
	if res.Kind.Abrupt() {
		t.Fatal("the tail of an XML element is not the peer cutting us off")
	}
}
