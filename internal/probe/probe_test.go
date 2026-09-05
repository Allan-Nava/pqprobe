package probe

import (
	"bufio"
	"bytes"
	"context"
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
	})
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
	})
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
	})
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
	})
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
				srv := tls.Server(&prefixConn{Conn: c, pre: bytes.NewReader(nil)}, cfg)
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

	for _, proto := range []string{"smtp", "imap", "postgres"} {
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

	for _, proto := range []string{"smtp", "imap", "postgres"} {
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
