package probe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
)

// dnsAnswer builds a response carrying one HTTPS record whose `ech=` parameter
// is list, for the question in the query. The wire format is written out here
// for the same reason the ECHConfigList is in probe_test.go: it is the contract
// with something that is not us, and a fixture that agrees with our own parser
// by construction would assert nothing.
func dnsAnswer(t *testing.T, query, list []byte, truncated bool) []byte {
	t.Helper()
	if len(query) < 12 {
		t.Fatal("query is not a DNS message")
	}
	// The question, verbatim, is what a response has to echo.
	qEnd := 12
	for query[qEnd] != 0 {
		qEnd += 1 + int(query[qEnd])
	}
	qEnd += 1 + 4

	msg := make([]byte, 0, 128)
	msg = append(msg, query[0], query[1]) // id
	flags := uint16(0x8180)               // response, recursion available
	if truncated {
		flags |= 0x0200
	}
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, 1) // qdcount
	msg = binary.BigEndian.AppendUint16(msg, 1) // ancount
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, query[12:qEnd]...)

	// The answer, with a compression pointer to the question's name.
	msg = append(msg, 0xc0, 0x0c)
	msg = binary.BigEndian.AppendUint16(msg, 65) // HTTPS
	msg = binary.BigEndian.AppendUint16(msg, 1)  // IN
	msg = binary.BigEndian.AppendUint32(msg, 300)

	rdata := []byte{0, 1, 0} // priority 1, root target (".")
	rdata = binary.BigEndian.AppendUint16(rdata, 1)
	rdata = binary.BigEndian.AppendUint16(rdata, 3)
	rdata = append(rdata, 2, 'h', '2') // alpn=h2, a param before the one we want
	rdata = binary.BigEndian.AppendUint16(rdata, 5)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(list)))
	rdata = append(rdata, list...)

	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	msg = append(msg, rdata...)
	if truncated {
		// A truncated answer is the header and the question: the client has to
		// ask again over TCP rather than believe half a record.
		return msg[:qEnd]
	}
	return msg
}

// fakeDNS serves one canned HTTPS record over UDP and TCP and returns its
// address. udpTruncates makes it set TC, which is how a real resolver says the
// answer did not fit — the case that matters here, because an ECH config is
// hundreds of bytes and pushes an answer past 512 easily.
func fakeDNS(t *testing.T, list []byte, udpTruncates bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte{}, buf[:n]...)
			_, _ = pc.WriteTo(dnsAnswer(t, q, list, udpTruncates), addr)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				q := make([]byte, int(head[0])<<8|int(head[1]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				a := dnsAnswer(t, q, list, false)
				_, _ = c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
			}()
		}
	}()
	return pc.LocalAddr().String()
}

// PQ-51. Pasting base64 is not a fleet workflow: the config lives in the HTTPS
// record of the name being probed, and Go's resolver exposes no arbitrary
// record type — so the query is written here, with no dependency.
func TestLookupECHConfigReadsTheHTTPSRecord(t *testing.T) {
	list, _ := echConfig(t)
	at := fakeDNS(t, list, false)

	got, err := LookupECHConfig(context.Background(), at, "origin.example")
	if err != nil {
		t.Fatalf("LookupECHConfig: %v", err)
	}
	if string(got) != string(list) {
		t.Fatalf("got %d bytes, want the %d-byte config list from the record", len(got), len(list))
	}
}

// An answer that did not fit is the ordinary case for a record carrying an ECH
// config, and half a record parsed as a whole one would be a config that fails
// in the handshake — where it reads as the endpoint's fault.
func TestLookupECHConfigRetriesOverTCPWhenTruncated(t *testing.T) {
	list, _ := echConfig(t)
	at := fakeDNS(t, list, true)

	got, err := LookupECHConfig(context.Background(), at, "origin.example")
	if err != nil {
		t.Fatalf("LookupECHConfig: %v", err)
	}
	if string(got) != string(list) {
		t.Fatal("the TCP retry did not produce the record")
	}
}

// A name with no ECH to offer is not a failure and must not read as one: it is
// most of the internet today.
func TestLookupECHConfigSaysWhenThereIsNone(t *testing.T) {
	at := fakeDNS(t, nil, false)
	_, err := LookupECHConfig(context.Background(), at, "origin.example")
	if err == nil {
		t.Fatal("an empty ech= parameter is no config at all")
	}
	if !strings.Contains(err.Error(), "origin.example") {
		t.Errorf("err = %v, want the name in it: a fleet run reports one of these per target", err)
	}
}

// A resolver that is not there must fail inside the run's own patience rather
// than hanging a fleet report on a UDP packet nobody will answer.
func TestLookupECHConfigIsBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := LookupECHConfig(ctx, "127.0.0.1:1", "origin.example"); err == nil {
		t.Fatal("nothing is listening there")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %s: a DNS query has to be bounded by the caller's deadline", d)
	}
}

// PQ-58. --dns was introduced for the ECH record and governed only that, so a
// run could ask one resolver about ECH and another about addresses without
// saying so. From inside a network where the interesting answer is the internal
// one, that is not a preference — it is a wrong answer.
func TestResolverAtIsUsedForEveryLookup(t *testing.T) {
	if ResolverAt("") != nil {
		t.Fatal("no --dns means the machine's own resolver, which is a nil *net.Resolver")
	}
	r := ResolverAt("127.0.0.1:1")
	if r == nil || !r.PreferGo {
		t.Fatal("a pinned resolver has to be Go's own: the cgo one asks whatever the system is configured with")
	}

	// Nothing is listening there, so the lookup must fail rather than quietly
	// falling back to the resolver the flag exists to replace.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := r.LookupIPAddr(ctx, "localhost.test.invalid"); err == nil {
		t.Fatal("the lookup succeeded with nothing at the pinned resolver: something else answered it")
	}

	// And the dialler carries it, or a target named rather than addressed would
	// still be resolved by the machine.
	d := Dialer{Timeout: time.Second, Resolver: r}
	res := d.Do(ctx, Target{Host: "origin.test.invalid", Port: "443"}, classicProfile(t))
	if res.OK {
		t.Fatal("that name cannot resolve anywhere")
	}
}

func classicProfile(t *testing.T) clientprofile.Profile {
	t.Helper()
	p, ok := clientprofile.ByName("classic")
	if !ok {
		t.Fatal("no classic profile")
	}
	return p
}
