// Package utls probes an endpoint with a *real* browser ClientHello (PQ-10).
//
// The main binary dials capability classes: it pins groups and versions, and it
// never claims to be Chrome, because Go's crypto/tls cannot reproduce a
// browser's extension order, its GREASE values or its padding. That honesty is
// worth keeping, and it leaves a question unanswered — "would Chrome 131
// actually connect here?" — which is what this module answers.
//
// It lives in a module of its own because uTLS is a dependency and the root
// module has none. That is enforced in CI and stated in INTENT.md: it is what
// makes the default binary reasonable to run inside somebody else's production
// network. Nobody gets a dependency by accident; you build this on purpose.
//
// What it does not do is judge. Whether a failure was a civil refusal or the
// peer choking on the hello is pqprobe's judgement, taken from
// pqprobe/pq.Classify — two copies of that distinction is exactly one too many.
package utls

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Allan-Nava/pqprobe/pq"
	tls "github.com/refraction-networking/utls"
)

// Fingerprint is one real client shape.
type Fingerprint struct {
	// Name is what a flag passes: chrome, firefox, safari, edge, ios.
	Name string
	// Client is the software it imitates, with its version — the whole point of
	// this module is a claim about a named client, and "Chrome" without a
	// version is what the capability classes already say.
	Client string
	id     tls.ClientHelloID
}

// Result is one handshake with one fingerprint.
type Result struct {
	Fingerprint string `json:"fingerprint"`
	Client      string `json:"client"`
	Target      string `json:"target"`
	OK          bool   `json:"ok"`
	Kind        string `json:"kind"`
	Abrupt      bool   `json:"abrupt"`
	Error       string `json:"error,omitempty"`
	Version     string `json:"tls_version,omitempty"`
	Group       string `json:"group,omitempty"`
	Cipher      string `json:"cipher,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	PQ          bool   `json:"pq,omitempty"`
	HelloBytes  int    `json:"hello_bytes,omitempty"`
	// HRR is true when the peer answered with a HelloRetryRequest: an extra
	// round trip on every connection, and a different state from never having
	// seen ML-KEM.
	HRR bool `json:"hrr,omitempty"`
	// Local is true when the failure happened inside *this* client rather than
	// at the peer: an old uTLS preset that cannot verify a modern server's
	// handshake signature, for instance. It is the difference between "the
	// endpoint refuses Safari" and "this Safari preset refuses everything", and
	// reporting the first when it is the second is the exact mistake this
	// toolchain exists to avoid.
	Local bool `json:"local,omitempty"`
	// Note says, in words, what a reader should conclude — set only when there
	// is something they would otherwise get wrong.
	Note    string        `json:"note,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns,omitempty"`
}

// Fingerprints is the set this module offers, newest-behaving first. Each one
// is a uTLS preset: the extension order and the GREASE that browser actually
// sends, which is the part Go cannot reproduce.
func Fingerprints() []Fingerprint {
	return []Fingerprint{
		{"chrome", "Chrome 131 (post-quantum by default)", tls.HelloChrome_131},
		{"firefox", "Firefox 120+", tls.HelloFirefox_120},
		{"safari", "Safari 16.0", tls.HelloSafari_16_0},
		{"edge", "Edge 106", tls.HelloEdge_106},
		{"ios", "iOS 14 Safari", tls.HelloIOS_14},
	}
}

// ByName resolves what a flag passed.
func ByName(name string) (Fingerprint, bool) {
	for _, f := range Fingerprints() {
		if f.Name == name {
			return f, true
		}
	}
	return Fingerprint{}, false
}

// Probe dials one endpoint with one fingerprint and reports what happened.
//
// serverName is sent as the SNI, so probing an address while claiming a
// hostname works here as it does in the main tool — it is the only way to
// reproduce a CDN-only failure from a workstation.
//
// Like pqprobe: the handshake completes and the connection closes. No request.
func Probe(ctx context.Context, addr, serverName string, f Fingerprint, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res := Result{Fingerprint: f.Name, Client: f.Client, Target: addr}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Kind, res.Abrupt = pq.Classify(err)
		res.Error = err.Error()
		res.Elapsed = time.Since(start)
		return res
	}
	defer raw.Close()

	wire := &wireConn{Conn: raw}

	// InsecureSkipVerify for the same reason the main tool sets it: the question
	// is whether the handshake completes, and an expired certificate answering
	// "no" would make a capability report say something untrue. The chain is not
	// this module's business at all.
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true} //nolint:gosec // see above
	conn := tls.UClient(wire, cfg, f.id)
	err = conn.HandshakeContext(ctx)
	res.HelloBytes = wire.helloBytes
	res.Elapsed = time.Since(start)

	if err != nil {
		res.Kind, res.Abrupt = pq.Classify(err)
		res.Error = err.Error()
		markLocal(&res)
		return res
	}

	st := conn.ConnectionState()
	res.OK = true
	res.Kind, _ = pq.Classify(nil)
	res.Version = versionName(st.Version)
	res.Cipher = tls.CipherSuiteName(st.CipherSuite)
	res.ALPN = st.NegotiatedProtocol

	// uTLS is forked from a crypto/tls that predates ConnectionState.CurveID,
	// so the negotiated group is not there. It does expose the handshake state
	// for fingerprinting, and the ServerHello's key share is the group the peer
	// picked — which is the number this whole tool is about.
	if sh := conn.HandshakeState.ServerHello; sh != nil {
		group := sh.ServerShare.Group
		if sh.SelectedGroup != 0 {
			// A HelloRetryRequest: the peer asked for another group, so that is
			// the one it settled on, and the round trip is real.
			group = sh.SelectedGroup
			res.HRR = true
		}
		res.Group = groupName(group)
		res.PQ = group == tls.X25519MLKEM768
	}
	return res
}

// markLocal flags a failure that happened inside this client.
//
// Some uTLS presets — HelloSafari_16_0 and HelloIOS_14 at the time of writing —
// cannot verify a modern server's handshake signature and fail against
// *everything*, including a plain local TLS 1.3 listener. That is a property of
// the preset, and a report that read "the endpoint refuses Safari" would send
// somebody to look at an endpoint that is fine. The abrupt flag is left alone:
// this is not the peer cutting anybody off.
func markLocal(res *Result) {
	for _, sig := range []string{
		"invalid signature by the server certificate",
		"failed to verify certificate",
		"x509:",
		"tls: failed to parse certificate",
	} {
		if strings.Contains(res.Error, sig) {
			res.Local = true
			res.Note = "this failed inside the client, not at the peer: the " + res.Fingerprint +
				" preset cannot complete a handshake with a modern server at all, so it says nothing about this endpoint"
			return
		}
	}
}

// wireConn records the size of the first ClientHello, the way the main tool
// does: a handshake record whose first message is a client_hello.
type wireConn struct {
	net.Conn
	helloBytes int
}

func (c *wireConn) Write(b []byte) (int, error) {
	if c.helloBytes == 0 && len(b) >= 6 && b[0] == 22 && b[5] == 1 {
		c.helloBytes = len(b)
	}
	return c.Conn.Write(b)
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
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
	case tls.CurveID(0x6399):
		return "X25519Kyber768Draft00"
	case 0:
		return ""
	}
	return id.String()
}
