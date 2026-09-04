// pqprobe-utls dials an endpoint with real browser ClientHellos (PQ-10).
//
// The main pqprobe binary answers "which capability classes can still
// handshake here", and says so without ever claiming to be a browser, because
// Go's crypto/tls cannot reproduce one. This answers the narrower, noisier
// question — "would Chrome 131 actually connect?" — and it is a separate
// binary in a separate module for one reason: uTLS is a dependency, and the
// default pqprobe has none.
//
// Read the two together. This tool cannot tell you *why* a client class fails,
// which is what the classes are for; pqprobe cannot tell you that a specific
// browser build fails, which is this.
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

	"github.com/Allan-Nava/pqprobe/contrib/utls"
)

func main() {
	var (
		asJSON  = flag.Bool("json", false, "emit the results as JSON")
		which   = flag.String("fingerprint", "", "only this fingerprint (default: all of them)")
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
		fmt.Fprintln(os.Stderr, "pqprobe-utls:", err)
		os.Exit(2)
	}
	serverName := host
	if *sni != "" {
		serverName = *sni
	}

	fps := utls.Fingerprints()
	if *which != "" {
		f, ok := utls.ByName(*which)
		if !ok {
			names := make([]string, 0, len(fps))
			for _, x := range fps {
				names = append(names, x.Name)
			}
			fmt.Fprintf(os.Stderr, "pqprobe-utls: unknown fingerprint %q (have: %s)\n",
				*which, strings.Join(names, ", "))
			os.Exit(2)
		}
		fps = []utls.Fingerprint{f}
	}

	// Sequential, like pqprobe: several handshakes landing at once measures a
	// connection limit instead of a capability.
	results := make([]utls.Result, 0, len(fps))
	for _, f := range fps {
		results = append(results, utls.Probe(context.Background(), target, serverName, f, *timeout))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintln(os.Stderr, "pqprobe-utls:", err)
			os.Exit(1)
		}
		return
	}

	for _, r := range results {
		mark := "OK  "
		detail := fmt.Sprintf("%s, %s, hello %d B", r.Version, r.Group, r.HelloBytes)
		if r.HRR {
			detail += " after a hello retry"
		}
		if !r.OK {
			mark = "FAIL"
			detail = fmt.Sprintf("%s: %s", r.Kind, r.Error)
			if r.Abrupt {
				detail += "  (abrupt: no alert — it choked on the hello)"
			}
			// A preset that fails against everything says nothing about this
			// endpoint, and must not be read as if it did.
			if r.Local {
				mark = "SKIP"
			}
		}
		fmt.Printf("%s  %-9s %-38s %s\n", mark, r.Fingerprint, r.Client, detail)
		if r.Note != "" {
			fmt.Printf("      ↳ %s\n", r.Note)
		}
	}

	// Exit 0 whenever the probe ran, as everywhere else in this toolchain:
	// findings are output, not an error.
}

func withDefaultPort(t string) string {
	if _, _, err := net.SplitHostPort(t); err != nil {
		return net.JoinHostPort(t, "443")
	}
	return t
}

func usage() {
	fmt.Fprint(os.Stderr, `pqprobe-utls — does a real browser ClientHello get through?

usage:
  pqprobe-utls [flags] <host[:port]>

flags:
  --fingerprint NAME   only this one: chrome, firefox, safari, edge, ios
  --sni NAME           server name to send (default: the target host)
  --timeout D          per-handshake timeout (default 10s)
  --json               emit the results as JSON

This is deliberately a separate binary: it depends on uTLS, and the default
pqprobe depends on nothing. It claims a fingerprint, which pqprobe never does —
and it cannot tell you which *class* of client is affected, which is what
pqprobe is for. Handshakes only: no request, no application data.
`)
}
