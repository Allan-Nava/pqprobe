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
	// PeerChainLen is how many certificates the peer sent. One means the peer
	// sent the leaf alone: browsers with a cached intermediate will be fine and
	// a fresh client will not, which is the most confusing class of bug there
	// is.
	PeerChainLen int `json:"peer_chain_len,omitempty"`
}

// Dialer performs one handshake. It exists so tests can drive the classifier
// without a network, and so a caller can inject a proxy-aware dialler later.
type Dialer struct {
	Timeout time.Duration
	ALPN    []string
	// Now is the clock used for expiry arithmetic; tests set it.
	Now func() time.Time
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

	conn := tls.Client(raw, p.TLSConfig(t.ServerName(), d.ALPN))
	err = conn.HandshakeContext(ctx)
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
