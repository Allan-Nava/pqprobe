// pqprobe-quic asks pqprobe's question over HTTP/3 (PQ-19).
//
// Same capability classes, different transport — and a different failure. Over
// TCP a path that cannot carry a hybrid ClientHello resets the connection, and
// pqprobe calls that abrupt. Over QUIC there is no reset to send: the Initial
// packet goes into UDP and nothing comes back, so the same fault presents as
// silence until the deadline. That is the quieter half of the same problem.
//
// A separate binary in a separate module because a QUIC stack is a dependency
// and pqprobe has none. Handshakes only: it never sends an HTTP/3 request.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pqquic "github.com/Allan-Nava/pqprobe/contrib/quic"
)

func main() {
	var (
		asJSON  = flag.Bool("json", false, "emit the results as JSON")
		which   = flag.String("profile", "", "only this profile (default: all of them)")
		sni     = flag.String("sni", "", "server name to send (default: the target host)")
		timeout = flag.Duration("timeout", 10*time.Second, "per-handshake timeout")
	)
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	target := withDefaultPort(flag.Arg(0))

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe-quic:", err)
		os.Exit(2)
	}
	serverName := host
	if *sni != "" {
		serverName = *sni
	}

	profiles := pqquic.Profiles()
	if *which != "" {
		p, ok := pqquic.ByName(*which)
		if !ok {
			names := make([]string, 0, len(profiles))
			for _, x := range profiles {
				names = append(names, x.Name)
			}
			fmt.Fprintf(os.Stderr, "pqprobe-quic: unknown profile %q (have: %s)\n",
				*which, strings.Join(names, ", "))
			os.Exit(2)
		}
		profiles = []pqquic.Profile{p}
	}

	// Sequential, like pqprobe: several handshakes at once measures a
	// connection limit instead of a capability.
	results := make([]pqquic.Result, 0, len(profiles))
	for _, p := range profiles {
		results = append(results, pqquic.Probe(context.Background(), target, serverName, p, *timeout))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintln(os.Stderr, "pqprobe-quic:", err)
			os.Exit(1)
		}
		return
	}

	for _, r := range results {
		mark, detail := "OK  ", fmt.Sprintf("%s, %s, alpn %s", r.Version, r.Group, r.ALPN)
		if !r.OK {
			mark = "FAIL"
			detail = fmt.Sprintf("%s: %s", r.Kind, r.Error)
			if r.Abrupt {
				// Worth spelling out: over UDP this is what a broken path looks
				// like, and it looks the same as an endpoint that is simply not
				// there.
				detail += "  (nothing came back — over QUIC there is no reset to receive)"
			}
		}
		fmt.Printf("%s  %-13s %s\n", mark, r.Profile, detail)
	}

	// Exit 0 whenever the probe ran, as everywhere else in this toolchain.
}

func withDefaultPort(t string) string {
	if _, _, err := net.SplitHostPort(t); err != nil {
		return net.JoinHostPort(t, "443")
	}
	return t
}

func usage() {
	fmt.Fprint(os.Stderr, `pqprobe-quic — the same question over HTTP/3

usage:
  pqprobe-quic [flags] <host[:port]>

flags:
  --profile NAME   only this one: classic, pq-preferred, pq-only
  --sni NAME       server name to send (default: the target host)
  --timeout D      per-handshake timeout (default 10s)
  --json           emit the results as JSON

The ClientHello has to fit QUIC's Initial packet, and a hybrid ML-KEM key share
is about 1.2 KB. When something on the path cannot carry it, UDP gives no reset:
the handshake simply never completes, which reads exactly like an endpoint that
is not there. Handshakes only — no HTTP/3 request is ever sent.
`)
}
