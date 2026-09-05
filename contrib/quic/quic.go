// Package quic asks pqprobe's question over HTTP/3 (PQ-19).
//
// The distinction the main tool rests on is *how* a refusal arrives, and QUIC
// changes what that looks like. A peer that declines a group answers with a
// CRYPTO_ERROR carrying the TLS alert — civil, the same as over TCP. A path
// that cannot carry the handshake gives nothing at all: UDP has no reset, so
// where TCP would produce a connection reset there is only silence until the
// deadline. That is the failure this module exists for, and it is quieter than
// the one that already costs people afternoons.
//
// It also matters more here. The ClientHello has to fit QUIC's Initial packet,
// a hybrid ML-KEM key share is roughly 1.2 KB, and middleboxes and UDP filters
// have opinions about large Initials that they never had to have about TCP
// segments.
//
// A module of its own because a QUIC stack is a dependency and the root module
// has none. Like everything else here: it completes handshakes and closes them,
// and it never sends a request — not even an HTTP/3 one.
package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/Allan-Nava/pqprobe/pq"
	quicgo "github.com/quic-go/quic-go"
)

// Profile is a capability class, exactly as in the main tool: pinned groups, so
// a toolchain upgrade cannot quietly change what a run proves.
type Profile struct {
	Name   string
	Groups []tls.CurveID
	// ALPN is what the QUIC handshake offers. Unlike TCP TLS this is not
	// optional in practice: a QUIC server answers only protocols it speaks.
	ALPN []string
}

// Result is one QUIC handshake.
type Result struct {
	Profile string        `json:"profile"`
	Target  string        `json:"target"`
	OK      bool          `json:"ok"`
	Kind    string        `json:"kind"`
	Abrupt  bool          `json:"abrupt"`
	Error   string        `json:"error,omitempty"`
	Version string        `json:"tls_version,omitempty"`
	Group   string        `json:"group,omitempty"`
	Cipher  string        `json:"cipher,omitempty"`
	ALPN    string        `json:"alpn,omitempty"`
	PQ      bool          `json:"pq,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns,omitempty"`
}

// Profiles mirrors the main tool's default set, so the two answers are
// comparable rather than merely adjacent. Every one offers h3.
func Profiles() []Profile {
	h3 := []string{"h3"}
	return []Profile{
		{"classic", []tls.CurveID{tls.X25519, tls.CurveP256}, h3},
		{"pq-preferred", []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}, h3},
		{"pq-only", []tls.CurveID{tls.X25519MLKEM768}, h3},
	}
}

// ByName resolves what a flag passed.
func ByName(name string) (Profile, bool) {
	for _, p := range Profiles() {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Probe performs one QUIC handshake and reports what happened.
func Probe(ctx context.Context, addr, serverName string, p Profile, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res := Result{Profile: p.Name, Target: addr}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	alpn := p.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}

	// InsecureSkipVerify for the main tool's reason: the question is whether the
	// handshake completes, and a certificate problem answering "no" would make a
	// capability report say something untrue.
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // see above
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   p.Groups,
		NextProtos:         alpn,
	}

	start := time.Now()
	conn, err := quicgo.DialAddr(ctx, addr, cfg, &quicgo.Config{
		// The handshake deadline is the caller's: without this quic-go would
		// keep retransmitting Initials on its own schedule, and a fleet run
		// would take as long as the slowest firewall.
		HandshakeIdleTimeout: timeout,
	})
	res.Elapsed = time.Since(start)
	if err != nil {
		res.Kind, res.Abrupt = classify(err)
		res.Error = err.Error()
		return res
	}
	defer conn.CloseWithError(0, "")

	st := conn.ConnectionState().TLS
	res.OK = true
	res.Kind, _ = pq.Classify(nil)
	res.Version = versionName(st.Version)
	res.Cipher = tls.CipherSuiteName(st.CipherSuite)
	res.ALPN = st.NegotiatedProtocol
	res.Group = groupName(st.CurveID)
	res.PQ = st.CurveID == tls.X25519MLKEM768
	return res
}

// classify maps a QUIC failure onto the vocabulary pqprobe already uses, and
// defers to pqprobe wherever the error is TLS-shaped — the judgement of what an
// alert means has to live in one place.
//
// The QUIC-specific part is the transport error: codes from 0x100 up are
// CRYPTO_ERROR, which carries the TLS alert the peer sent. That is an answer,
// so it is civil, exactly as an alert is over TCP. Everything that ends in
// silence — no response, an idle handshake, a cancelled context — is abrupt,
// and over UDP that is the *only* way a broken path can present itself.
func classify(err error) (kind string, abrupt bool) {
	var te *quicgo.TransportError
	if errors.As(err, &te) {
		if te.ErrorCode >= 0x100 {
			// A CRYPTO_ERROR: the peer parsed the hello and declined.
			return "alert", false
		}
		return "other", false
	}

	var ie *quicgo.IdleTimeoutError
	if errors.As(err, &ie) {
		return "timeout", true
	}
	var he *quicgo.HandshakeTimeoutError
	if errors.As(err, &he) {
		return "timeout", true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", true
	}
	// quic-go reports a path that never answered as a timeout in words before
	// it does in types, depending on where the deadline lands.
	if msg := err.Error(); strings.Contains(msg, "timeout") || strings.Contains(msg, "no recent network activity") {
		return "timeout", true
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout", true
	}
	// Anything left is a plain dial or TLS error, and pqprobe already knows what
	// those mean.
	return pq.Classify(err)
}

func versionName(v uint16) string {
	if v == tls.VersionTLS13 {
		return "TLS 1.3"
	}
	// QUIC requires TLS 1.3; anything else is a stack doing something strange.
	return ""
}

func groupName(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case 0:
		return ""
	}
	return id.String()
}
