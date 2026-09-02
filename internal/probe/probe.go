// Package probe dials one endpoint with one client profile and reports what
// happened, in enough detail to tell two very different refusals apart.
//
// The distinction the whole tool rests on: a peer that answers a
// post-quantum ClientHello with a TLS alert has *understood* it and declined
// the group — a clean, survivable "no". A peer that resets the connection,
// times out, or closes without a record has choked on the ClientHello itself,
// and every client that offers ML-KEM will fail against it regardless of
// whether that client would have been happy with X25519. Only the second is an
// outage waiting for a CDN to flip a default.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
)

// Kind classifies how a handshake ended.
type Kind string

const (
	KindOK Kind = "ok"
	// KindDNS: the name did not resolve. Nothing about TLS was learned.
	KindDNS Kind = "dns"
	// KindRefused: nothing is listening.
	KindRefused Kind = "refused"
	// KindUnroutable: this host has no route to the address. It says nothing
	// about the endpoint — an AAAA record probed from a machine with no IPv6
	// egress is the usual case — so it must never be reported as a property of
	// the peer.
	KindUnroutable Kind = "unroutable"
	// KindTimeout: no answer inside the deadline. On a profile with a large
	// ClientHello this is a classic intolerance symptom — a middlebox that
	// drops the second TCP segment leaves the handshake hanging forever.
	KindTimeout Kind = "timeout"
	// KindReset: the peer killed the connection.
	KindReset Kind = "reset"
	// KindEOF: the peer closed without saying anything.
	KindEOF Kind = "eof"
	// KindAlert: a TLS alert. The peer parsed the ClientHello and said no.
	KindAlert Kind = "alert"
	// KindRecord: the answer was not a TLS record at all (a plaintext HTTP
	// error page on 443 is the usual case).
	KindRecord Kind = "record"
	KindOther  Kind = "other"
)

// Abrupt reports whether a failure of this kind means the peer never managed a
// civil refusal. These are the kinds that turn a post-quantum ClientHello into
// an outage rather than a negotiation.
func (k Kind) Abrupt() bool {
	switch k {
	case KindTimeout, KindReset, KindEOF, KindRecord:
		return true
	}
	return false
}

// Target is one endpoint to probe. SNI defaults to Host but is kept separate:
// probing an origin by IP while sending the public hostname is exactly what a
// CDN does, and it is the only way to reproduce a CDN-only failure from a
// workstation.
type Target struct {
	Host string
	Port string
	SNI  string
}

// Addr is the dial address.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, t.Port) }

// String identifies the target in reports; the SNI is shown only when it is
// not the host, because that is when it changes the meaning of the result.
func (t Target) String() string {
	if t.SNI != "" && t.SNI != t.Host {
		return t.Addr() + " (sni " + t.SNI + ")"
	}
	return t.Addr()
}

// ServerName is what goes in the SNI extension.
func (t Target) ServerName() string {
	if t.SNI != "" {
		return t.SNI
	}
	return t.Host
}

// Cert is the part of a peer certificate a report can use.
type Cert struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotAfter  time.Time `json:"not_after"`
	NotBefore time.Time `json:"not_before"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	IsCA      bool      `json:"is_ca"`
}

// Result is one (target, profile) handshake attempt.
type Result struct {
	Profile string        `json:"profile"`
	OK      bool          `json:"ok"`
	Kind    Kind          `json:"kind"`
	Err     string        `json:"error,omitempty"`
	Version string        `json:"tls_version,omitempty"`
	Group   string        `json:"group,omitempty"`
	Cipher  string        `json:"cipher,omitempty"`
	ALPN    string        `json:"alpn,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns,omitempty"`
	// PQ is true when the negotiated key exchange was a post-quantum hybrid.
	PQ bool `json:"pq,omitempty"`
	// Chain is the certificate chain as the peer sent it, leaf first. It is
	// recorded on every successful handshake and read once, from the baseline.
	Chain []Cert `json:"chain,omitempty"`
	// ChainVerified is the result of verifying that chain against the system
	// roots, done here rather than by the dialler — see clientprofile.TLSConfig.
	ChainVerified bool   `json:"chain_verified"`
	ChainError    string `json:"chain_error,omitempty"`
	// Attempts is how many handshakes this result is based on: two when an
	// abrupt failure was re-dialled to confirm it. See DoConfirmed.
	Attempts int `json:"attempts,omitempty"`
	// FirstKind is how the first attempt ended, when there was more than one.
	FirstKind Kind `json:"first_kind,omitempty"`
	// Reproduced is true when both attempts ended abruptly: the refusal is a
	// wall rather than a flap, and the finding may say so.
	Reproduced bool `json:"reproduced,omitempty"`
	// Flapped is true when the first attempt ended abruptly and the second
	// connected. The endpoint works and is unstable, which is a third state and
	// must not render as either of the other two.
	Flapped bool `json:"flapped,omitempty"`
	// ClientCertRequested is true when the peer sent a CertificateRequest: this
	// endpoint is mutual TLS. On TLS 1.3 that does not stop the handshake —
	// the peer's objection arrives after the client is finished, and pqprobe
	// never reads — so the key exchange answer stands and this is the note that
	// keeps "pq-ready" from being read as "usable". On TLS 1.2 client auth
	// happens inside the handshake, and then this is the only thing that tells
	// the failure apart from "no mutually supported group".
	ClientCertRequested bool `json:"client_cert_requested,omitempty"`
	// PeerChainLen is how many certificates the peer sent. One means the peer
	// sent the leaf alone: browsers with a cached intermediate will be fine and
	// a fresh client will not, which is the most confusing class of bug there
	// is.
	PeerChainLen int `json:"peer_chain_len,omitempty"`
}

// Resolver is the DNS lookup ExpandAddresses needs. *net.Resolver satisfies it;
// the tests pass a table, because DNS is flaky and belongs to somebody else.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ExpandAddresses turns each named target into one target per A/AAAA record,
// dialling the address while still sending the name (PQ-12).
//
// A hostname behind six records is six stacks, and the failure that survives a
// manual check is one of them being different: probe the name and you hit
// whichever address the resolver felt like handing over, six times if you are
// unlucky, and the broken node stays invisible. This is the
// `1.2.3.4=origin.example` form the tool already had, applied automatically.
//
// An address literal is left alone — there is nothing to resolve, and looking
// it up would be a DNS query nobody asked for. A name that does not resolve
// keeps its target and the error is returned as well: the dialler then reports
// it as a DNS failure in the usual words, and no endpoint silently disappears
// from a fleet report.
func ExpandAddresses(ctx context.Context, r Resolver, targets []Target) ([]Target, []error) {
	var out []Target
	var errs []error
	for _, t := range targets {
		if net.ParseIP(t.Host) != nil {
			out = append(out, t)
			continue
		}
		addrs, err := r.LookupIPAddr(ctx, t.Host)
		if err != nil || len(addrs) == 0 {
			if err == nil {
				err = fmt.Errorf("%s: no A or AAAA record", t.Host)
			} else {
				err = fmt.Errorf("%s: %w", t.Host, err)
			}
			errs = append(errs, err)
			out = append(out, t)
			continue
		}
		sni := t.ServerName()
		for _, a := range addrs {
			out = append(out, Target{Host: a.IP.String(), Port: t.Port, SNI: sni})
		}
	}
	return out, errs
}

// Dialer performs one handshake. It exists so tests can drive the classifier
// without a network, and so a caller can inject a proxy-aware dialler later.
type Dialer struct {
	Timeout time.Duration
	ALPN    []string
	// Confirm re-dials an abrupt failure once before it is believed. See
	// DoConfirmed.
	Confirm bool
	// ConfirmDelay is the pause between the two dials. Zero means a short
	// default; tests set it to nothing.
	ConfirmDelay time.Duration
	// Now is the clock used for expiry arithmetic; tests set it.
	Now func() time.Time
}

// DoConfirmed dials once and, when the failure was abrupt and Confirm is set,
// dials a second time before the result is believed.
//
// pq-intolerant is the finding somebody takes to a CDN vendor, and one reset is
// not only a middlebox: it is also a stale conntrack entry, a load balancer
// mid-reconfiguration, a node that had just been drained. Those flap; a wall
// does not. So the second dial decides which word the report gets to use, and
// the result carries both attempts either way — Reproduced when the refusal
// happened twice, Flapped when the retry connected.
//
// Only abrupt failures are retried. An alert is an answer the peer chose to
// give, and re-dialling it would double the connections against every endpoint
// with a group policy while proving nothing.
func (d Dialer) DoConfirmed(ctx context.Context, t Target, p clientprofile.Profile) Result {
	first := d.Do(ctx, t, p)
	first.Attempts = 1
	if !d.Confirm || first.OK || !first.Kind.Abrupt() {
		return first
	}

	// A pause, because the failure being ruled out is often a connection state
	// that clears in milliseconds. Immediately reusing the same four-tuple is
	// the one way to reproduce it on purpose.
	delay := d.ConfirmDelay
	if delay == 0 {
		delay = 250 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return first
	case <-time.After(delay):
	}

	second := d.Do(ctx, t, p)
	second.Attempts = 2
	second.FirstKind = first.Kind
	if second.OK {
		// The endpoint answered the same hello a moment later: real, and not the
		// wall the first dial looked like.
		second.Flapped = true
		return second
	}
	// Still gone. Report the second failure — it is the one that was confirmed —
	// and say that it reproduced, which is what makes it quotable.
	second.Reproduced = second.Kind.Abrupt()
	return second
}

// Do dials target with profile and reports what happened.
func (d Dialer) Do(ctx context.Context, t Target, p clientprofile.Profile) Result {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res := Result{Profile: p.Name}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.Addr())
	if err != nil {
		res.Kind, res.Err = classify(err)
		res.Elapsed = time.Since(start)
		return res
	}
	defer raw.Close()

	cfg := p.TLSConfig(t.ServerName(), d.ALPN)

	// GetClientCertificate is called exactly when the peer sends a
	// CertificateRequest, which is the only reliable way to know an endpoint is
	// mutual TLS: the alert a TLS 1.2 server sends afterwards is
	// indistinguishable from "no mutually supported group" by its text, and on
	// TLS 1.3 there is no error at all. Returning an empty certificate is what
	// Go's own default does, so recording this changes nothing about the
	// handshake — and pqprobe still holds no key material of any kind.
	requested := false
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		requested = true
		return &tls.Certificate{}, nil
	}

	conn := tls.Client(raw, cfg)
	err = conn.HandshakeContext(ctx)
	res.ClientCertRequested = requested
	res.Elapsed = time.Since(start)
	if err != nil {
		res.Kind, res.Err = classify(err)
		return res
	}
	defer conn.Close()

	st := conn.ConnectionState()
	res.OK = true
	res.Kind = KindOK
	res.Version = versionName(st.Version)
	res.Group = clientprofile.GroupName(st.CurveID)
	res.PQ = clientprofile.IsPQ(st.CurveID)
	res.Cipher = tls.CipherSuiteName(st.CipherSuite)
	res.ALPN = st.NegotiatedProtocol
	res.PeerChainLen = len(st.PeerCertificates)
	for _, c := range st.PeerCertificates {
		res.Chain = append(res.Chain, Cert{
			Subject:   c.Subject.CommonName,
			Issuer:    c.Issuer.CommonName,
			NotAfter:  c.NotAfter,
			NotBefore: c.NotBefore,
			DNSNames:  c.DNSNames,
			IsCA:      c.IsCA,
		})
	}
	res.ChainVerified, res.ChainError = verifyChain(st.PeerCertificates, t.ServerName(), d.now())
	return res
}

func (d Dialer) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// verifyChain checks the certificates the peer sent against the system roots.
// It is deliberately separate from the handshake: a capability answer must not
// change because a certificate expired, and an expiry must not be reported as
// "the endpoint refused post-quantum clients".
func verifyChain(certs []*x509.Certificate, serverName string, now time.Time) (bool, string) {
	if len(certs) == 0 {
		return false, "peer sent no certificate"
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       serverName,
		Intermediates: inter,
		CurrentTime:   now,
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// classify turns a dial or handshake error into a Kind plus the message a
// report shows. The order matters: a timeout arrives wrapped in an OpError, and
// a reset arrives wrapped twice, so the specific tests come before the general
// ones.
func classify(err error) (Kind, string) {
	msg := err.Error()

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return KindDNS, msg
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return KindTimeout, msg
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return KindRefused, msg
	}
	// A route that does not exist is a fact about the prober, not the peer.
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return KindUnroutable, msg
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return KindReset, msg
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return KindEOF, msg
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return KindAlert, msg
	}
	var rec tls.RecordHeaderError
	if errors.As(err, &rec) {
		return KindRecord, msg
	}
	// Go reports a locally generated alert (no mutually supported group, no
	// protocol version in common) as a plain error string rather than an
	// AlertError, and that is still a civil refusal: both sides parsed, one
	// said no.
	switch {
	case strings.Contains(msg, "handshake failure"),
		strings.Contains(msg, "protocol version not supported"),
		strings.Contains(msg, "no cipher suite supported"),
		strings.Contains(msg, "no supported versions"),
		strings.Contains(msg, "illegal parameter"),
		strings.Contains(msg, "insufficient security"),
		strings.Contains(msg, "unexpected message"):
		return KindAlert, msg
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "broken pipe"):
		return KindReset, msg
	case strings.Contains(msg, "EOF"):
		return KindEOF, msg
	case strings.Contains(msg, "first record does not look like a TLS handshake"):
		return KindRecord, msg
	}
	return KindOther, msg
}

// isTimeout keeps the net.Error timeout test in one place; a bare
// errors.As on net.Error would also match non-timeout network errors.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
