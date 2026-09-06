package inventory

import (
	"net"
	"strings"
	"testing"
)

// PQ-68. The `?q=1` bug lives here: a query string contains an `=`, and reading
// it as a server name is a silently wrong probe rather than an error. That one
// was caught by a table case written before the parser. These are the
// properties that hold however the target was written — including the two the
// audit turned up, which no table case had thought to state.
func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{
		"origin.example", "origin.example:8443", "[::1]:443",
		"https://origin.example/path?q=1", "1.2.3.4=origin.example",
		"https://origin.example:8443/x?a=b=lb.example", "", ":", "=", "[", "]:",
		"origin.example:", ":443", "a=b=c", "http://[::1]:443/x",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, word string) {
		tg, err := Parse(word)
		if err != nil {
			return
		}

		// 1. A target that parsed has a host and a port, or the dialler has
		//    nothing to dial.
		if tg.Host == "" || tg.Port == "" {
			t.Fatalf("%q parsed to %+v", word, tg)
		}
		if strings.ContainsAny(tg.Host, " \t") {
			t.Fatalf("%q parsed to a host with whitespace: %q", word, tg.Host)
		}

		// 2. A port nobody wrote is never marked as written — this is what
		//    --port reads, and getting it wrong probed an endpoint the operator
		//    had not named (PQ-65).
		if tg.PortWritten && !strings.Contains(word, ":") {
			t.Fatalf("%q has no colon and claims a written port", word)
		}
		if !tg.PortWritten && tg.Port != DefaultPort {
			t.Fatalf("%q was given port %q without anybody writing one", word, tg.Port)
		}

		// 3. The server name never comes from a path or a query string. The
		//    URL form is parsed before the `=sni` form precisely so that
		//    `https://h/x?q=1` cannot become a probe of h with server name 1.
		if tg.SNI != "" {
			if strings.ContainsAny(tg.SNI, "/?#") {
				t.Fatalf("%q took a server name out of a URL: %q", word, tg.SNI)
			}
			if i := strings.Index(word, "://"); i >= 0 {
				rest := word[i+3:]
				if j := strings.IndexAny(rest, "/?#"); j >= 0 && !strings.Contains(rest[:j], "=") {
					t.Fatalf("%q has no `=` in its authority, so %q is not a server name", word, tg.SNI)
				}
			}
		}

		// 4. The address round-trips: whatever was written, Addr() is something
		//    net.Dial can take apart again.
		if _, _, err := net.SplitHostPort(tg.Addr()); err != nil {
			t.Fatalf("%q produced the unsplittable address %q", word, tg.Addr())
		}
	})
}
