package probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"
)

// The ECH config travels in the HTTPS resource record (type 65) of the name
// being probed, as SvcParamKey 5. Go's resolver exposes no arbitrary record
// type, so the query is written here (PQ-51).
//
// This is the same kind of lookup ExpandAddresses already performs and it is
// still not a *request* in the sense INTENT.md means: a DNS question about the
// name, asked of the resolver this machine already uses, with no application
// data and no dependency added to a module that has none.
const (
	dnsTypeHTTPS  = 65
	dnsClassIN    = 1
	dnsParamECH   = 5
	dnsFlagTrunc  = 0x0200
	dnsRcodeMask  = 0x000f
	dnsUDPMaxSize = 1232 // the EDNS-free ceiling everything agrees on
)

// ResolverAt returns the resolver every lookup in a run should use (PQ-58).
//
// An empty address means the machine's own, which is a nil *net.Resolver — the
// zero value every net API already understands as "the default". A pinned one
// is Go's own resolver rather than the system's, because the cgo path asks
// whatever the host is configured with and would ignore the flag.
//
// It is used for *every* question pqprobe asks, the dialler's own name
// resolution included: a run that asked one resolver about ECH and another
// about addresses would be reporting on two different networks, and from inside
// one where the interesting answer is the internal one that is not a preference
// but a wrong answer.
func ResolverAt(at string) *net.Resolver {
	if at == "" {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, at)
		},
	}
}

// LookupECHConfig returns the ECHConfigList published for name, asking at.
//
// at is a `host:port` resolver; empty means the ones this machine uses. A name
// with no HTTPS record, or one without an `ech=` parameter, is an error naming
// the name — most of the internet is in that state today, and a fleet run says
// so per target rather than silently probing without ECH.
func LookupECHConfig(ctx context.Context, at, name string) ([]byte, error) {
	servers := []string{at}
	if at == "" {
		var err error
		if servers, err = systemResolvers(); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}

	query, err := dnsQuery(name)
	if err != nil {
		return nil, err
	}

	var last error
	for _, server := range servers {
		resp, truncated, err := dnsExchangeUDP(ctx, server, query)
		if err != nil {
			last = err
			continue
		}
		if truncated {
			// An answer that did not fit. A record carrying an ECH config is
			// hundreds of bytes, so this is ordinary rather than exotic — and
			// half a record parsed as a whole one is a config that fails inside
			// the handshake, where it reads as the endpoint's fault.
			if resp, err = dnsExchangeTCP(ctx, server, query); err != nil {
				last = err
				continue
			}
		}
		list, err := echFromAnswer(resp, name)
		if err != nil {
			return nil, err
		}
		return list, nil
	}
	if last == nil {
		last = errors.New("no resolver answered")
	}
	return nil, fmt.Errorf("%s: %w", name, last)
}

// systemResolvers reads /etc/resolv.conf. Go keeps its own copy of this
// parsing unexported, and a tool with no dependencies cannot borrow one — so a
// platform without the file says so plainly instead of dialling a guess.
func systemResolvers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("cannot read the system resolvers (%w) — pass --dns HOST:PORT, or --ech-config with the value from DNS", err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, net.JoinHostPort(fields[1], "53"))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no nameserver in /etc/resolv.conf — pass --dns HOST:PORT")
	}
	return out, nil
}

// dnsQuery builds a recursion-desired question for the HTTPS record of name.
func dnsQuery(name string) ([]byte, error) {
	msg := make([]byte, 0, 64)
	msg = binary.BigEndian.AppendUint16(msg, uint16(rand.N(1<<16))) //nolint:gosec // a query id, not a secret
	msg = binary.BigEndian.AppendUint16(msg, 0x0100)                // recursion desired
	msg = binary.BigEndian.AppendUint16(msg, 1)                     // qdcount
	msg = binary.BigEndian.AppendUint16(msg, 0)                     // ancount
	msg = binary.BigEndian.AppendUint16(msg, 0)                     // nscount
	msg = binary.BigEndian.AppendUint16(msg, 0)                     // arcount

	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("%q is not a name a DNS query can carry", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeHTTPS)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg, nil
}

func dnsDeadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(5 * time.Second)
}

func dnsExchangeUDP(ctx context.Context, server string, query []byte) ([]byte, bool, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	_ = c.SetDeadline(dnsDeadline(ctx))

	if _, err := c.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, dnsUDPMaxSize)
	n, err := c.Read(buf)
	if err != nil {
		return nil, false, err
	}
	return dnsCheck(buf[:n], query)
}

func dnsExchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(dnsDeadline(ctx))

	framed := append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
	if _, err := c.Write(framed); err != nil {
		return nil, err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, err
	}
	resp := make([]byte, int(head[0])<<8|int(head[1]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	out, _, err := dnsCheck(resp, query)
	return out, err
}

// dnsCheck rejects an answer to somebody else's question and turns the response
// code into words.
func dnsCheck(resp, query []byte) ([]byte, bool, error) {
	if len(resp) < 12 {
		return nil, false, errors.New("the resolver answered with a message too short to be one")
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		return nil, false, errors.New("the resolver answered a different query")
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	switch flags & dnsRcodeMask {
	case 0:
	case 3:
		return nil, false, errors.New("no such name")
	default:
		return nil, false, fmt.Errorf("the resolver answered rcode %d", flags&dnsRcodeMask)
	}
	return resp, flags&dnsFlagTrunc != 0, nil
}

// echFromAnswer walks the answer section for an HTTPS record carrying `ech=`.
//
// Every record is scanned rather than only the one whose owner matches: an
// answer routinely arrives as a CNAME followed by the record for the canonical
// name, and refusing that would mean no ECH for every endpoint behind a CDN —
// which is nearly every endpoint that has ECH at all.
func echFromAnswer(msg []byte, name string) ([]byte, error) {
	if len(msg) < 12 {
		return nil, errors.New("short answer")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		off += 4
	}

	for i := 0; i < an && off < len(msg); i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("answer ends inside a record")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("a record claims more data than the answer holds")
		}
		if typ == dnsTypeHTTPS {
			if list, ok := echFromSVCB(msg, msg[off:off+rdlen]); ok {
				return list, nil
			}
		}
		off += rdlen
	}
	return nil, fmt.Errorf("%s: no ECH config in DNS (no HTTPS record, or one without an ech= parameter) — most endpoints are in that state today", name)
}

// echFromSVCB reads the SvcParams of an HTTPS record and returns the ech= value.
// Priority 0 is AliasMode, which carries no parameters at all.
func echFromSVCB(msg, rdata []byte) ([]byte, bool) {
	if len(rdata) < 3 {
		return nil, false
	}
	if binary.BigEndian.Uint16(rdata[0:2]) == 0 {
		return nil, false // AliasMode: the parameters live at the target name
	}
	// The target name is inside the rdata and may itself be compressed, so it
	// is skipped against the whole message.
	off, err := skipNameIn(msg, rdata, 2)
	if err != nil {
		return nil, false
	}
	for off+4 <= len(rdata) {
		key := binary.BigEndian.Uint16(rdata[off : off+2])
		n := int(binary.BigEndian.Uint16(rdata[off+2 : off+4]))
		off += 4
		if off+n > len(rdata) {
			return nil, false
		}
		if key == dnsParamECH && n > 0 {
			return append([]byte{}, rdata[off:off+n]...), true
		}
		off += n
	}
	return nil, false
}

// skipName advances past a name, following a compression pointer once — which
// is all a pointer may do, and a bounded loop is what keeps a malformed answer
// from spinning here for ever.
func skipName(msg []byte, off int) (int, error) {
	for off < len(msg) {
		n := int(msg[off])
		switch {
		case n == 0:
			return off + 1, nil
		case n&0xc0 == 0xc0:
			return off + 2, nil
		case n > 63:
			return 0, errors.New("bad label in a name")
		default:
			off += 1 + n
		}
	}
	return 0, errors.New("a name runs past the end of the answer")
}

// skipNameIn is skipName over a record's rdata rather than the message.
func skipNameIn(msg, rdata []byte, off int) (int, error) {
	for off < len(rdata) {
		n := int(rdata[off])
		switch {
		case n == 0:
			return off + 1, nil
		case n&0xc0 == 0xc0:
			return off + 2, nil
		case n > 63:
			return 0, errors.New("bad label in a name")
		default:
			off += 1 + n
		}
	}
	return 0, errors.New("a name runs past the end of a record")
}
