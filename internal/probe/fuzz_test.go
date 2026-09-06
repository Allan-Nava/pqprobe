package probe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// PQ-66. Three of these parsers read bytes an *endpoint* chose — a DNS answer,
// an LDAP response, a MySQL greeting — and one reads an XML fragment from a
// chat server. A wrong answer there is a bug; a panic is a monitoring tool that
// dies halfway through somebody's fleet, which is the property INTENT.md calls
// "safe to point at production".
//
// The fuzzer does not share the author's assumptions, which is the whole reason
// it is here: the audit (PQ-65) found seven bugs in code every gate called
// green, and three of them were the same mistake written three times.

// discardConn is a net.Conn that reads from r and throws writes away: these
// parsers write a request and read an answer, and only the reading is under
// test.
type discardConn struct {
	net.Conn
	r *bufio.Reader
}

func (c discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (c discardConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c discardConn) Close() error                { return nil }
func (c discardConn) SetDeadline(time.Time) error { return nil }
func (c discardConn) LocalAddr() net.Addr         { return nil }
func (c discardConn) RemoteAddr() net.Addr        { return nil }

// FuzzECHAnswer walks a DNS answer for the HTTPS record's ech= parameter, with
// compression pointers and lengths that came from somebody else.
func FuzzECHAnswer(f *testing.F) {
	list, _ := echConfig(f)
	query, err := dnsQuery("origin.example")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(dnsAnswer(f, query, list, false))
	f.Add(dnsAnswer(f, query, nil, false))
	f.Add([]byte{})
	f.Add(make([]byte, 12))

	f.Fuzz(func(t *testing.T, msg []byte) {
		got, err := echFromAnswer(msg, "origin.example")
		if err != nil {
			return
		}
		// A config it returns has to be bytes that were actually in the answer:
		// a parser that can invent one would hand a client a key nobody
		// published.
		if len(got) > 0 && !bytes.Contains(msg, got) {
			t.Fatalf("returned %d bytes that are not in the answer", len(got))
		}
	})
}

// FuzzLDAPResponse reads the BER a directory server sent back.
func FuzzLDAPResponse(f *testing.F) {
	f.Add([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	f.Add([]byte{0x30, 0x84, 0, 0, 0, 12, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x35})
	f.Add([]byte{0x30})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, resp []byte) {
		br := bufio.NewReader(bytes.NewReader(resp))
		_ = startTLSLDAP(br, discardConn{r: br})
	})
}

// FuzzMySQLGreeting reads the packet a database server speaks first.
func FuzzMySQLGreeting(f *testing.F) {
	payload := []byte{10}
	payload = append(payload, "8.0.36-test\x00"...)
	payload = append(payload, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0)
	payload = append(payload, 0x00, 0x0a, 45, 2, 0, 0, 0, 21)
	payload = append(payload, make([]byte, 10)...)
	pkt := []byte{byte(len(payload)), 0, 0, 0}
	f.Add(append(pkt, payload...))
	f.Add([]byte{0xff, 0, 0, 0, 0xff, 0x15, 0x04, 'b', 'a', 'd'})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, greeting []byte) {
		br := bufio.NewReader(bytes.NewReader(greeting))
		_ = startTLSMySQL(br, discardConn{r: br})
	})
}

// FuzzXMPPReply reads the stream features and the answer to <starttls/>.
func FuzzXMPPReply(f *testing.F) {
	f.Add([]byte("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
	f.Add([]byte("<stream:features><mechanisms/></stream:features>"))
	f.Add([]byte("<proceed"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, reply []byte) {
		br := bufio.NewReader(bytes.NewReader(reply))
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = startTLSXMPP(br, discardConn{r: br}, "origin.example")
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// There is no deadline on a bufio.Reader over bytes, so a reader
			// that can loop for ever on some input shows up here.
			t.Fatal("the XMPP reader did not return")
		}
	})
}

// FuzzDNSCheck is the header check every answer passes through first.
func FuzzDNSCheck(f *testing.F) {
	query, _ := dnsQuery("origin.example")
	f.Add(query)
	f.Add([]byte{1, 2, 3})

	f.Fuzz(func(t *testing.T, resp []byte) {
		q := make([]byte, 12)
		binary.BigEndian.PutUint16(q, 0x1234)
		_, _, _ = dnsCheck(resp, q)
	})
}
