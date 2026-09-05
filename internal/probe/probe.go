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
	// KindECHReject: the peer declined Encrypted Client Hello and answered with
	// a retry config. Never abrupt: it parsed the hello, found no key of its own
	// for it, and said so — an endpoint that simply does not do ECH, which is
	// most of them, and not one that chokes on a larger hello.
	KindECHReject Kind = "ech-reject"
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
	// Bytes is the DER length the peer sent for this certificate. Post-quantum
	// *authentication* is the next migration and its failure will be a size
	// failure again — an ML-DSA signature is around 3.3 KB where an ECDSA one
	// is 64 — so what a chain costs today is worth having in hand.
	Bytes     int       `json:"bytes,omitempty"`
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
	// ECHAccepted is true when the peer accepted Encrypted Client Hello. Read
	// from the connection state and never inferred: a server that ignores ECH
	// completes the handshake too, and calling that acceptance would be a claim
	// about privacy that is not true (PQ-50).
	ECHAccepted bool `json:"ech_accepted,omitempty"`
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
	// ChainBytes is what the whole chain cost on the wire, in bytes of DER. It
	// is the headroom number for post-quantum authentication: a chain that is
	// already 6 KB has a different future from one that is 2.
	ChainBytes int `json:"chain_bytes,omitempty"`
	// PeerChainLen is how many certificates the peer sent. One means the peer
	// sent the leaf alone: browsers with a cached intermediate will be fine and
	// a fresh client will not, which is the most confusing class of bug there
	// is.
	PeerChainLen int `json:"peer_chain_len,omitempty"`
}

// StartTLSProtocols is what --starttls accepts, in the order the help lists
// them.
func StartTLSProtocols() []string {
	return []string{"smtp", "imap", "postgres", "mysql", "ftp", "nntp", "ldap", "xmpp"}
}

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

// Nets is what --net accepts: the two address families Go dials, in the order
// the help lists them.
func Nets() []string { return []string{"tcp4", "tcp6"} }

// ValidNet reports whether n is one of them. The empty string is valid and is
// the default: whatever the resolver hands over, which is what every run did
// before PQ-46 — and which is exactly why a dual-stack name could answer on one
// stack and die on the other without the report ever saying which was dialled.
func ValidNet(n string) bool {
	if n == "" {
		return true
	}
	for _, v := range Nets() {
		if v == n {
			return true
		}
	}
	return false
}

// NetName is the family in the words an operator uses. It exists so no renderer
// has to translate "tcp6" itself, and so the two spellings cannot drift.
func NetName(n string) string {
	switch n {
	case "tcp4":
		return "IPv4"
	case "tcp6":
		return "IPv6"
	}
	return "IPv4 and IPv6"
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

	case "ftp":
		// RFC 4217. The greeting and the reply use SMTP's grammar exactly — a
		// three-digit code, a dash for continuation — so the same reader serves
		// both, and 234 is the only answer that means "start now".
		if err := expectFTP(br, "220"); err != nil {
			return fmt.Errorf("ftp: %w", err)
		}
		if _, err := fmt.Fprint(c, "AUTH TLS\r\n"); err != nil {
			return fmt.Errorf("ftp: %w", err)
		}
		if err := expectFTP(br, "234"); err != nil {
			return fmt.Errorf("ftp: AUTH TLS refused: %w", err)
		}
		return nil

	case "nntp":
		// RFC 4642. The greeting is 200 or 201 — the difference is whether
		// posting is allowed, which is not a fact about TLS, and reading 201 as
		// a failure would report a perfectly healthy news server as broken.
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("nntp: reading the greeting: %w", err)
		}
		if !strings.HasPrefix(line, "200") && !strings.HasPrefix(line, "201") {
			return fmt.Errorf("nntp: greeting was %q, not 200 or 201", strings.TrimSpace(line))
		}
		if _, err := fmt.Fprint(c, "STARTTLS\r\n"); err != nil {
			return fmt.Errorf("nntp: %w", err)
		}
		if err := expectSMTP(br, "382"); err != nil {
			return fmt.Errorf("nntp: STARTTLS refused: %w", err)
		}
		return nil

	case "ldap":
		return startTLSLDAP(br, c)

	case "xmpp":
		return startTLSXMPP(br, c, serverName)

	case "mysql":
		return startTLSMySQL(br, c)

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

// startTLSLDAP performs the StartTLS extended operation of RFC 4511 §4.14
// (PQ-54).
//
// A directory server is the most likely thing in a fleet to be running a TLS
// stack nobody has touched in a decade, on a port no browser will ever complain
// about. The request is one fixed BER-encoded message carrying the StartTLS
// OID and no credentials of any kind — a bind is what would carry those, and
// pqprobe never sends one.
func startTLSLDAP(br *bufio.Reader, c net.Conn) error {
	// LDAPMessage ::= SEQUENCE { messageID 1, ExtendedRequest [APPLICATION 23]
	// { requestName [0] "1.3.6.1.4.1.1466.20037" } }
	oid := "1.3.6.1.4.1.1466.20037"
	// The lengths are arithmetic rather than constants so the OID and the
	// message cannot drift apart: 3 bytes of messageID, then the request's own
	// two-byte header around its contents.
	req := []byte{0x30, byte(3 + 2 + 2 + len(oid)), 0x02, 0x01, 0x01, 0x77, byte(2 + len(oid)), 0x80, byte(len(oid))}
	req = append(req, oid...)
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}

	body, err := berValue(br, 0x30)
	if err != nil {
		return fmt.Errorf("ldap: reading the response: %w", err)
	}
	// messageID, then the ExtendedResponse.
	i := 0
	if _, i, err = berField(body, i); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	resp, _, err := berField(body, i)
	if err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	// resultCode ENUMERATED, matchedDN, diagnosticMessage.
	code, j, err := berField(resp, 0)
	if err != nil || len(code) != 1 {
		return errors.New("ldap: the response carries no result code")
	}
	if code[0] == 0 {
		return nil
	}
	msg := ""
	if _, j, err = berField(resp, j); err == nil {
		if diag, _, err := berField(resp, j); err == nil {
			msg = strings.TrimSpace(string(diag))
		}
	}
	if msg == "" {
		msg = "no diagnostic message"
	}
	// The server's own words, quoted: "unwilling to perform" and "protocol
	// error" send an operator to two different files.
	return fmt.Errorf("ldap: StartTLS refused with result code %d: %s", code[0], msg)
}

// berValue reads one BER element of the expected tag and returns its contents.
func berValue(br *bufio.Reader, tag byte) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, err
	}
	if head[0] != tag {
		return nil, fmt.Errorf("expected tag %#x, got %#x — this does not look like LDAP", tag, head[0])
	}
	n := int(head[1])
	if n&0x80 != 0 {
		// Long form: the low bits say how many length bytes follow.
		count := n & 0x7f
		if count == 0 || count > 3 {
			return nil, errors.New("a length this shape is not an LDAP response")
		}
		lb := make([]byte, count)
		if _, err := io.ReadFull(br, lb); err != nil {
			return nil, err
		}
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	if n > 65535 {
		return nil, fmt.Errorf("a %d-byte LDAP response is not one", n)
	}
	out := make([]byte, n)
	_, err := io.ReadFull(br, out)
	return out, err
}

// berField returns the contents of the element at off and the offset after it.
func berField(b []byte, off int) ([]byte, int, error) {
	if off+2 > len(b) {
		return nil, 0, errors.New("a field runs past the end of the message")
	}
	n := int(b[off+1])
	start := off + 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 || start+count > len(b) {
			return nil, 0, errors.New("a length this shape is not LDAP")
		}
		n = 0
		for _, x := range b[start : start+count] {
			n = n<<8 | int(x)
		}
		start += count
	}
	if start+n > len(b) {
		return nil, 0, errors.New("a field claims more data than the message holds")
	}
	return b[start : start+n], start + n, nil
}

// startTLSXMPP opens a stream and asks for TLS, per RFC 6120 (PQ-55).
//
// The `to` attribute is the server name pqprobe is already sending as SNI, and
// it is not decoration: a virtual host answers for whatever it is asked about,
// so a stream opened without it probes a different service — the same reason
// the `1.2.3.4=origin.example` form exists.
//
// The reply is scanned for the elements that decide it rather than parsed:
// there is no XML document here yet, only the opening of one, and a parser
// waiting for a close tag that will never come is a hang rather than an answer.
func startTLSXMPP(br *bufio.Reader, c net.Conn, serverName string) error {
	if serverName == "" {
		return errors.New("xmpp: no server name to open a stream to — dial the name, or use the address=name form")
	}
	open := "<?xml version='1.0'?><stream:stream to='" + serverName +
		"' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
	if _, err := fmt.Fprint(c, open); err != nil {
		return fmt.Errorf("xmpp: %w", err)
	}

	seen, err := readUntil(br, "</stream:features>", "<stream:error", "</stream:stream>")
	if err != nil {
		return fmt.Errorf("xmpp: reading the stream features: %w", err)
	}
	if !strings.Contains(seen, "<starttls") {
		return errors.New("xmpp: the stream features do not offer STARTTLS — TLS is not enabled on this service")
	}
	if _, err := fmt.Fprint(c, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"); err != nil {
		return fmt.Errorf("xmpp: %w", err)
	}
	seen, err = readUntil(br, "<proceed", "<failure", "</stream:stream>")
	if err != nil {
		return fmt.Errorf("xmpp: reading the STARTTLS reply: %w", err)
	}
	if !strings.Contains(seen, "<proceed") {
		return errors.New("xmpp: the server answered <failure/> to STARTTLS")
	}
	return nil
}

// readUntil reads until one of the markers appears, bounded so a peer that
// talks for ever cannot make a fleet run wait for it. The deadline set before
// the negotiation is what stops one that says nothing at all.
func readUntil(br *bufio.Reader, markers ...string) (string, error) {
	var b strings.Builder
	for b.Len() < 16384 {
		ch, err := br.ReadByte()
		if err != nil {
			return b.String(), err
		}
		b.WriteByte(ch)
		for _, m := range markers {
			if strings.HasSuffix(b.String(), m) {
				return b.String(), nil
			}
		}
	}
	return b.String(), errors.New("the peer sent 16 KB without answering")
}

// MySQL capability bits, from the connection phase. Only these three are ever
// set: CLIENT_SSL is the request, and the other two say which dialect of the
// packet the server should read it as.
const (
	mysqlClientSSL       = 0x00000800
	mysqlClientProto41   = 0x00000200
	mysqlClientSecureCon = 0x00008000
)

// startTLSMySQL performs MySQL's upgrade to TLS (PQ-45).
//
// MySQL is the protocol PQ-20 left out, and the reason is visible here: the
// upgrade is not a line somebody types. The server speaks first with a handshake
// packet, and the client answers with a **SSLRequest** — the first 32 bytes of a
// login packet and nothing after them, which is precisely where the credentials
// would have gone. Nothing else is sent: no user, no password, no database, no
// query. That is what keeps this inside "pqprobe handshakes and closes".
//
// The X Protocol on 33060 is a different negotiation, protobuf-framed rather
// than this exchange, and it is deliberately not spoken.
func startTLSMySQL(br *bufio.Reader, c net.Conn) error {
	payload, seq, err := mysqlPacket(br)
	if err != nil {
		return fmt.Errorf("mysql: reading the server greeting: %w", err)
	}
	if len(payload) == 0 {
		return errors.New("mysql: the server greeting was empty")
	}
	// An ERR packet instead of a greeting is the server refusing the connection
	// before TLS was ever on the table — a blocked host is the usual case, and
	// reporting it as "TLS is off here" would send somebody to the wrong file.
	if payload[0] == 0xff {
		return fmt.Errorf("mysql: the server refused the connection: %s", mysqlErrText(payload))
	}
	if payload[0] != 10 {
		return fmt.Errorf("mysql: protocol version %d, not 10 — this does not look like a MySQL server", payload[0])
	}

	// Skip to the capability flags: the null-terminated server version, the
	// connection id, eight bytes of auth-plugin data and a filler byte.
	i := 1
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	i++ // the terminator
	i += 4 + 8 + 1
	if i+1 >= len(payload) {
		return errors.New("mysql: the greeting ended before the capability flags")
	}
	caps := int(payload[i]) | int(payload[i+1])<<8
	if caps&mysqlClientSSL == 0 {
		// The server has TLS switched off. It has refused *TLS*, not a
		// post-quantum client, which is the whole reason KindStartTLS exists.
		return errors.New("mysql: the server does not advertise CLIENT_SSL — TLS is not enabled on it")
	}

	// The SSLRequest packet: 32 bytes, and the TLS handshake starts straight
	// after it. The sequence id continues the greeting's, or the server drops
	// the connection as out of order.
	body := make([]byte, 32)
	flags := mysqlClientSSL | mysqlClientProto41 | mysqlClientSecureCon
	body[0], body[1] = byte(flags), byte(flags>>8)
	body[2], body[3] = byte(flags>>16), byte(flags>>24)
	body[7] = 1 // max_allowed_packet: 16 MiB, which nothing here will approach
	body[8] = 45
	out := []byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), seq + 1}
	if _, err := c.Write(append(out, body...)); err != nil {
		return fmt.Errorf("mysql: sending SSLRequest: %w", err)
	}
	return nil
}

// mysqlPacket reads one packet: a three-byte little-endian length, a sequence
// id, then the payload.
func mysqlPacket(br *bufio.Reader) ([]byte, byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, 0, err
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	// A greeting is a few hundred bytes; anything else is not one, and reading
	// 16 MiB to find that out is a denial of service against ourselves.
	if n > 4096 {
		return nil, 0, fmt.Errorf("a %d-byte first packet is not a MySQL greeting", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, 0, err
	}
	return payload, head[3], nil
}

// mysqlErrText is the human half of an ERR packet: a two-byte code, then an
// optional `#` and five-byte SQL state, then the message.
func mysqlErrText(payload []byte) string {
	msg := payload[1:]
	if len(msg) > 2 {
		msg = msg[2:]
	}
	if len(msg) > 6 && msg[0] == '#' {
		msg = msg[6:]
	}
	return strings.TrimSpace(string(msg))
}

// expectFTP reads an FTP reply, whose multi-line rule is *not* SMTP's.
//
// Found by running it against a real server: RFC 959 marks continuation with a
// dash on the first line and then says nothing about the lines that follow —
// they carry banners, terms of use, a user count, and no code at all — until a
// line beginning with the code and a space. Reading them with SMTP's rule
// turned "220-Welcome" into "the server answered See https://…", a refusal that
// never happened, on an endpoint that was fine.
func expectFTP(br *bufio.Reader, code string) error {
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
	if line[3] != '-' {
		return fmt.Errorf("answered %s", strings.TrimSpace(line))
	}
	// A banner, bounded: a peer that never closes the reply would otherwise be
	// a hang, and the deadline on the negotiation is the other half of this.
	for i := 0; i < 100; i++ {
		if line, err = br.ReadString('\n'); err != nil {
			return fmt.Errorf("reading the rest of a %s reply: %w", code, err)
		}
		if len(line) >= 4 && line[:3] == code && line[3] == ' ' {
			return nil
		}
	}
	return fmt.Errorf("the %s reply did not end after 100 lines", code)
}

// expectSMTP reads a possibly multi-line reply and checks its code. SMTP marks
// continuation with a dash after the code and **every** line carries the code —
// which is exactly where FTP differs, and why expectFTP exists.
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
func socks5Connect(ctx context.Context, network, proxy, host, port string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, proxy)
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
// network is the family the run is pinned to (PQ-46): "tcp4", "tcp6", or ""
// for both. Records outside it are dropped here rather than dialled and
// reported as failures — a run pinned to one family that still probes the other
// produces a page of results the operator has to learn to read past, which is
// the same noise --per-address was built to cut.
func ExpandAddresses(ctx context.Context, r Resolver, targets []Target, network string) ([]Target, []error) {
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
		kept := 0
		for _, a := range addrs {
			if !inFamily(a.IP, network) {
				continue
			}
			kept++
			out = append(out, Target{Host: a.IP.String(), Port: t.Port, SNI: sni})
		}
		if kept == 0 {
			// The name resolved; it simply has nothing in the family this run
			// was pinned to. Said in those words, because "no AAAA record" and
			// "did not resolve" send an operator to two different places — and
			// the target is kept, so no endpoint vanishes from a fleet report.
			errs = append(errs, fmt.Errorf("%s: resolved, but no address in the %s family (--net %s)",
				t.Host, NetName(network), network))
			out = append(out, t)
		}
	}
	return out, errs
}

// egressProbe is the address the route lookup is made against, per family:
// documentation ranges (RFC 5737, RFC 3849) that are routed nowhere and belong
// to nobody, so nothing can be reached even by accident.
var egressProbe = map[string]string{
	"tcp4": "192.0.2.1:53",
	"tcp6": "[2001:db8::1]:53",
}

// HasEgress reports whether this machine has a route for an address family
// (PQ-47).
//
// A UDP "dial" is a route lookup and a local bind: no packet is sent, nothing
// is contacted, and the address it is made against is a documentation prefix
// that is routed nowhere. That matters twice over — this is a tool whose
// contract is that it never sends anything it did not say it would, and the
// answer has to be available on a fleet run where forty endpoints have just
// failed for what is probably one local reason.
//
// It answers only for a pinned family. "tcp" is not a question that has an
// answer here, and guessing one would be worse than the silence.
func HasEgress(network string) bool {
	addr, ok := egressProbe[network]
	if !ok {
		return false
	}
	c, err := net.Dial("udp"+strings.TrimPrefix(network, "tcp"), addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// inFamily reports whether ip belongs to the pinned family. An empty network
// pins nothing, which is the default and takes both.
func inFamily(ip net.IP, network string) bool {
	switch network {
	case "tcp4":
		return ip.To4() != nil
	case "tcp6":
		return ip.To4() == nil && ip.To16() != nil
	}
	return true
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
	// Net pins the address family every connection uses: "tcp4", "tcp6", or ""
	// for whatever the resolver hands over. Pinning it is what makes an
	// IPv6-only failure reproducible on demand — unpinned, a dual-stack name
	// answers on whichever address the resolver felt like handing over, and two
	// runs can disagree with nothing having changed on the endpoint.
	Net string
	// Confirm re-dials an abrupt failure once before it is believed. See
	// DoConfirmed.
	Confirm bool
	// ConfirmDelay is the pause between the two dials. Zero means a short
	// default; tests set it to nothing.
	ConfirmDelay time.Duration
	// Now is the clock used for expiry arithmetic; tests set it.
	Now func() time.Time
}

// network is the dial network: the pinned family, or "tcp" for both.
func (d Dialer) network() string {
	if d.Net == "" {
		return "tcp"
	}
	return d.Net
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
		// Through a proxy the family is the *proxy's* to choose for the second
		// hop; here it can only govern the hop to the proxy itself.
		raw, err = socks5Connect(ctx, d.network(), d.Socks5, t.Host, t.Port)
		if err != nil {
			// Attributed to the proxy on purpose: the endpoint has not been
			// reached, so nothing here is a statement about it.
			res.Kind, res.Err = KindProxy, err.Error()
			res.Elapsed = time.Since(start)
			return res
		}
	} else {
		raw, err = (&net.Dialer{}).DialContext(ctx, d.network(), t.Addr())
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
		// Bounded by the same deadline as everything else: --timeout covers the
		// TLS handshake, and until the upgrade lands there is no TLS handshake
		// to cover. A port that accepts the connection and then says nothing —
		// which for MySQL, where the server speaks first, is the ordinary
		// failure — would otherwise wait for ever.
		if deadline, has := ctx.Deadline(); has {
			_ = raw.SetDeadline(deadline)
		}
		if err := startTLS(raw, d.StartTLS, t.ServerName()); err != nil {
			// The peer refused *TLS*, which says nothing about post-quantum
			// clients — hence its own kind, and not an abrupt one.
			res.Kind, res.Err = KindStartTLS, err.Error()
			res.Elapsed = time.Since(start)
			return res
		}
		// The TLS handshake sets its own; leaving this one on would stop the
		// measurement at whatever was left of it.
		_ = raw.SetDeadline(time.Time{})
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
		// Found by running it: when a peer declines ECH, Go verifies its
		// certificate against the *public name* in the config before it will
		// trust the retry configs — and `InsecureSkipVerify` does not disable
		// that path. So a peer behind a private CA answers the ECH probe with a
		// verification error rather than a rejection, and reading that as
		// "something is wrong with this endpoint" would be exactly the
		// capability-versus-certificate confusion this tool exists to avoid.
		// It is the same event: the peer declined ECH.
		if len(cfg.EncryptedClientHelloConfigList) > 0 && res.Kind == KindOther &&
			strings.Contains(res.Err, "failed to verify certificate") {
			res.Kind = KindECHReject
			res.Err = "the peer declined ECH, and Go verified its certificate against the config's public name before trusting the retry configs (InsecureSkipVerify does not disable that): " + res.Err
		}
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
	res.ECHAccepted = st.ECHAccepted
	res.PeerChainLen = len(st.PeerCertificates)
	for _, c := range st.PeerCertificates {
		// len(c.Raw) is the DER the peer actually sent, not a re-encoding of the
		// parsed structure — the number that has to travel, which is what the
		// size question is about (PQ-44).
		res.ChainBytes += len(c.Raw)
		res.Chain = append(res.Chain, Cert{
			Subject:   c.Subject.CommonName,
			Issuer:    c.Issuer.CommonName,
			NotAfter:  c.NotAfter,
			NotBefore: c.NotBefore,
			DNSNames:  c.DNSNames,
			IsCA:      c.IsCA,
			Bytes:     len(c.Raw),
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
	// An address family this run excluded (--net, PQ-46): Go answers "no
	// suitable address found", which is our own flag talking. Unroutable, for
	// the same reason an AAAA record probed without IPv6 egress is: it is a
	// fact about the prober, and grading the peer on it would be a lie.
	if strings.Contains(msg, "no suitable address found") {
		return KindUnroutable, msg
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return KindReset, msg
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return KindEOF, msg
	}
	// An ECH rejection is a negotiation, not a wall: the peer parsed the hello
	// and answered with a retry config. It is checked before the alert cases
	// because it arrives wrapped in one.
	var echErr *tls.ECHRejectionError
	if errors.As(err, &echErr) {
		return KindECHReject, msg
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
