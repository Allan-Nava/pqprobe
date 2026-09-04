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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
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
	// KindStartTLS: the plaintext upgrade never reached TLS — the peer does not
	// advertise STARTTLS, or refused it. Never abrupt: the peer refused *TLS*,
	// not a post-quantum client, and reading it as abrupt would file a relay
	// with TLS switched off as pq-intolerant.
	KindStartTLS Kind = "starttls"
	// KindProxy: the SOCKS5 proxy failed before the endpoint saw anything — it
	// wanted credentials, refused, or was not there. Never abrupt: it is not the
	// peer cutting us off, and treating it as one would put somebody else's
	// endpoint in the pq-intolerant bucket for a fault on this side.
	KindProxy Kind = "proxy"
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
	// HelloBytes is the size on the wire of the first ClientHello record,
	// measured rather than estimated. It is the number the whole
	// size-intolerance conversation turns on: the hybrid hello is roughly
	// 1.2 KB larger than the classical one, which is what stops it fitting a
	// single TCP segment.
	HelloBytes int `json:"hello_bytes,omitempty"`
	// HelloCount is how many ClientHellos went out. Two means the peer sent a
	// HelloRetryRequest.
	HelloCount int `json:"hello_count,omitempty"`
	// HRR is true when the peer answered with a HelloRetryRequest: it did not
	// take the key share offered and asked for another group, which costs a
	// round trip and is a different state from never having seen ML-KEM.
	HRR bool `json:"hrr,omitempty"`
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

// StartTLSProtocols is what --starttls accepts, in the order the help lists
// them.
func StartTLSProtocols() []string { return []string{"smtp", "imap", "postgres"} }

// ValidStartTLS reports whether the protocol is one of them. The empty string
// is valid and means no negotiation: implicit TLS, which is every other port.
func ValidStartTLS(proto string) bool {
	if proto == "" {
		return true
	}
	for _, p := range StartTLSProtocols() {
		if p == proto {
			return true
		}
	}
	return false
}

// startTLS performs a protocol's plaintext upgrade so the TLS handshake can
// happen at all (PQ-20).
//
// What goes on the wire is negotiation and nothing else — a greeting is read,
// an EHLO or a STARTTLS or an eight-byte SSLRequest is written — and no
// application data, no mail, no query, no credential. That distinction is the
// whole reason this is acceptable in a tool whose contract is "handshake and
// close": without it these ports cannot be probed at all, and with anything
// more it would be a different tool.
func startTLS(c net.Conn, proto, serverName string) error {
	br := bufio.NewReader(c)
	switch proto {
	case "smtp":
		// 220 greeting, EHLO, then STARTTLS. The capability list is read but
		// not required: a relay that answers 220 to STARTTLS without having
		// advertised it is still upgrading.
		if err := expectSMTP(br, "220"); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		if _, err := fmt.Fprintf(c, "EHLO %s\r\n", ehloName(serverName)); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		if err := expectSMTP(br, "250"); err != nil {
			return fmt.Errorf("smtp: EHLO: %w", err)
		}
		if _, err := fmt.Fprint(c, "STARTTLS\r\n"); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		if err := expectSMTP(br, "220"); err != nil {
			return fmt.Errorf("smtp: STARTTLS refused: %w", err)
		}
		return nil

	case "imap":
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("imap: reading the greeting: %w", err)
		}
		if !strings.HasPrefix(line, "* OK") {
			return fmt.Errorf("imap: greeting was %q, not * OK", strings.TrimSpace(line))
		}
		if _, err := fmt.Fprint(c, "a1 STARTTLS\r\n"); err != nil {
			return fmt.Errorf("imap: %w", err)
		}
		for {
			line, err = br.ReadString('\n')
			if err != nil {
				return fmt.Errorf("imap: reading the STARTTLS reply: %w", err)
			}
			// Untagged lines may precede the tagged answer.
			if strings.HasPrefix(line, "a1 ") {
				if !strings.HasPrefix(line, "a1 OK") {
					return fmt.Errorf("imap: STARTTLS refused: %s", strings.TrimSpace(line))
				}
				return nil
			}
		}

	case "postgres":
		// SSLRequest: length 8, then the magic 80877103. One byte comes back:
		// 'S' to continue in TLS, 'N' to say the server has none.
		req := []byte{0, 0, 0, 8, 4, 210, 22, 47}
		if _, err := c.Write(req); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		b, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("postgres: reading the SSLRequest reply: %w", err)
		}
		switch b {
		case 'S':
			return nil
		case 'N':
			return errors.New("postgres: the server answered N to SSLRequest — TLS is not enabled on it")
		default:
			return fmt.Errorf("postgres: unexpected SSLRequest reply %q", b)
		}
	}
	return fmt.Errorf("unknown starttls protocol %q (have: %s)", proto, strings.Join(StartTLSProtocols(), ", "))
}

// expectSMTP reads a possibly multi-line reply and checks its code. SMTP marks
// continuation with a dash after the code, so the last line is the one whose
// fourth byte is a space.
func expectSMTP(br *bufio.Reader, code string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading a %s reply: %w", code, err)
		}
		if len(line) < 4 {
			return fmt.Errorf("short reply %q", strings.TrimSpace(line))
		}
		if line[:3] != code {
			return fmt.Errorf("answered %s", strings.TrimSpace(line))
		}
		if line[3] == ' ' {
			return nil
		}
	}
}

// ehloName is what to put after EHLO. The server name is a reasonable, honest
// answer; an address literal has to be bracketed per the grammar.
func ehloName(serverName string) string {
	if serverName == "" {
		return "[127.0.0.1]"
	}
	if net.ParseIP(serverName) != nil {
		return "[" + serverName + "]"
	}
	return serverName
}

// socks5Connect opens a connection to host:port through a SOCKS5 proxy
// (RFC 1928), with no authentication (PQ-35).
//
// The host is sent as a name whenever it is one, so the proxy resolves it: from
// inside a network that is frequently the only place it resolves at all, and it
// is also what a CDN does.
//
// No authentication, deliberately: pqprobe holds no credentials by design, and
// a flag that took a proxy password would be the first secret this tool ever
// asked for. A proxy that demands one says so, in those words.
func socks5Connect(ctx context.Context, proxy, host, port string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	if deadline, has := ctx.Deadline(); has {
		_ = c.SetDeadline(deadline)
	}

	// Greeting: version 5, one method, "no authentication".
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
	}
	if reply[0] != 5 {
		return nil, fmt.Errorf("socks5 proxy %s: answered version %d, not 5 — is that a SOCKS5 proxy?", proxy, reply[0])
	}
	if reply[1] != 0 {
		return nil, fmt.Errorf("socks5 proxy %s: wants auth method %#x; pqprobe holds no credentials by design and only speaks no-auth SOCKS5", proxy, reply[1])
	}

	// CONNECT.
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5 proxy %s: the host name is %d bytes; SOCKS5 allows 255", proxy, len(host))
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return nil, fmt.Errorf("socks5 proxy %s: %q is not a port", proxy, port)
	}
	req = append(req, byte(p>>8), byte(p))
	if _, err := c.Write(req); err != nil {
		return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
	}
	if head[1] != 0 {
		return nil, fmt.Errorf("socks5 proxy %s: %s (reply %#x) for %s",
			proxy, socks5Reply(head[1]), head[1], net.JoinHostPort(host, port))
	}
	// The bound address, which is of no interest but has to be consumed before
	// the TLS bytes start.
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
		}
		skip = int(l[0])
	case 4:
		skip = 16
	default:
		return nil, fmt.Errorf("socks5 proxy %s: unknown address type %#x in the reply", proxy, head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return nil, fmt.Errorf("socks5 proxy %s: %w", proxy, err)
	}

	// The deadline was the proxy handshake's; the TLS handshake sets its own.
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

// socks5Reply is RFC 1928's reply code in words an operator can act on.
func socks5Reply(code byte) string {
	switch code {
	case 1:
		return "general failure at the proxy"
	case 2:
		return "the proxy is configured not to allow this connection"
	case 3:
		return "the proxy says the network is unreachable"
	case 4:
		return "the proxy says the host is unreachable"
	case 5:
		return "the endpoint refused the connection"
	case 6:
		return "the proxy timed out reaching the endpoint"
	case 7:
		return "the proxy does not support CONNECT"
	case 8:
		return "the proxy does not support that address type"
	}
	return "the proxy refused"
}

// wireConn counts the ClientHellos written to the peer and records the size of
// the first one.
//
// It reads only the record header and the handshake type — five bytes and one
// byte, of our own outgoing data — and never buffers or alters anything. A TLS
// handshake record can in principle carry several handshake messages, and a
// ClientHello can in principle be fragmented across records; neither happens in
// what Go's client writes, and if it ever did, the count would be low rather
// than wrong, so nothing here can turn into a false HelloRetryRequest.
type wireConn struct {
	net.Conn
	helloBytes int
	helloCount int
}

func (c *wireConn) Write(b []byte) (int, error) {
	// A handshake record (22) whose first message is a client_hello (1).
	if len(b) >= 6 && b[0] == 22 && b[5] == 1 {
		c.helloCount++
		if c.helloBytes == 0 {
			c.helloBytes = len(b)
		}
	}
	return c.Conn.Write(b)
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
	// StartTLS, when set, is the protocol whose plaintext negotiation gets to
	// TLS before the handshake: smtp, imap or postgres. Implicit TLS on any
	// port needs none of this — `host:465` is already just TLS.
	StartTLS string
	// Socks5, when set, is the `host:port` of a SOCKS5 proxy every connection
	// goes through. SOCKS5 and nothing else: HTTP CONNECT is a *request*, and
	// sending one would trade away the property that makes this binary safe to
	// point at production. The target name is passed to the proxy unresolved,
	// because inside a network that is often the only place it resolves.
	Socks5 string
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
	var raw net.Conn
	var err error
	if d.Socks5 != "" {
		raw, err = socks5Connect(ctx, d.Socks5, t.Host, t.Port)
		if err != nil {
			// Attributed to the proxy on purpose: the endpoint has not been
			// reached, so nothing here is a statement about it.
			res.Kind, res.Err = KindProxy, err.Error()
			res.Elapsed = time.Since(start)
			return res
		}
	} else {
		raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", t.Addr())
		if err != nil {
			res.Kind, res.Err = classify(err)
			res.Elapsed = time.Since(start)
			return res
		}
	}
	defer raw.Close()

	// The plaintext negotiation happens on the raw connection, before anything
	// is measured: an SMTP relay answers TLS on 587 only after being asked in
	// its own protocol (PQ-20).
	if d.StartTLS != "" {
		if err := startTLS(raw, d.StartTLS, t.ServerName()); err != nil {
			// The peer refused *TLS*, which says nothing about post-quantum
			// clients — hence its own kind, and not an abrupt one.
			res.Kind, res.Err = KindStartTLS, err.Error()
			res.Elapsed = time.Since(start)
			return res
		}
	}

	// Everything written to the peer passes through here, which is how the
	// ClientHello gets measured and how a HelloRetryRequest becomes visible
	// without parsing somebody else's message: an HRR is exactly the case where
	// we send a second ClientHello.
	wire := &wireConn{Conn: raw}
	raw = wire

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
	res.HelloBytes, res.HelloCount = wire.helloBytes, wire.helloCount
	res.HRR = wire.helloCount > 1
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
// Classify is classify, exported so the public facade can offer it to an
// embedder that dials with its own TLS stack (PQ-10). The judgement of what an
// error means has to stay in one place; a fingerprint probe holding its own
// error must reach *this* answer, not a second opinion.
func Classify(err error) (Kind, string) { return classify(err) }

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
		// Go's own wording, verified in crypto/tls rather than remembered: the
		// brief used to quote "no mutually supported group", which the
		// toolchain has never produced. These two it does.
		strings.Contains(msg, "mutually supported protocol versions"),
		strings.Contains(msg, "server selected unsupported group"),
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
