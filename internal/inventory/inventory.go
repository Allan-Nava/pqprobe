// Package inventory reads the list of endpoints to probe.
//
// Three shapes, because those are the three that already exist in an ops
// repository: arguments on the command line, a flat list in a file, and an
// Ansible INI inventory. Nothing here resolves anything or opens a socket —
// parsing the list is separate from probing it so that a typo in a group name
// is a parse error rather than a run of misleading results.
package inventory

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// DefaultPort is used for a target written without one.
const DefaultPort = "443"

// Parse turns one target word into a Target. Accepted: "host", "host:port",
// "[::1]:443", "https://host/path" (the path is dropped), and any of those
// followed by "=sni" to send a different server name — the form that probes an
// origin by address the way a CDN does.
func Parse(word string) (probe.Target, error) {
	word = strings.TrimSpace(word)
	if word == "" {
		return probe.Target{}, fmt.Errorf("empty target")
	}
	// A URL is accepted because people paste them, but only the authority is
	// used: pqprobe never sends a request, so a path would be a lie. This runs
	// *before* the "=sni" split, because a query string has an "=" in it and
	// reading "?q=1" as a server name is a silently wrong probe rather than an
	// error.
	if i := strings.Index(word, "://"); i >= 0 {
		word = word[i+3:]
		if j := strings.IndexAny(word, "/?#"); j >= 0 {
			word = word[:j]
		}
	}
	sni := ""
	if i := strings.LastIndex(word, "="); i > 0 {
		sni = strings.TrimSpace(word[i+1:])
		word = strings.TrimSpace(word[:i])
	}
	host, port, written := word, DefaultPort, false
	if h, p, err := net.SplitHostPort(word); err == nil {
		host, port, written = h, p, true
	} else if strings.HasPrefix(word, "[") && strings.HasSuffix(word, "]") {
		host = strings.Trim(word, "[]")
	}
	if host == "" {
		return probe.Target{}, fmt.Errorf("no host in %q", word)
	}
	if strings.ContainsAny(host, " \t") {
		return probe.Target{}, fmt.Errorf("host %q contains whitespace", host)
	}
	return probe.Target{Host: host, Port: port, SNI: sni, PortWritten: written}, nil
}

// ParseAll parses every word, collecting errors rather than stopping at the
// first: a fleet run should report all the malformed lines in one go.
func ParseAll(words []string) ([]probe.Target, []error) {
	var ts []probe.Target
	var errs []error
	for _, w := range words {
		t, err := Parse(w)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ts = append(ts, t)
	}
	return ts, errs
}

// ReadList reads a flat list: one target per line, "#" and ";" comments and
// blank lines ignored.
func ReadList(r io.Reader) ([]probe.Target, []error) {
	var words []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		words = append(words, line)
	}
	ts, errs := ParseAll(words)
	if err := sc.Err(); err != nil {
		errs = append(errs, err)
	}
	return ts, errs
}

// ReadListFile is ReadList over a path.
func ReadListFile(path string) ([]probe.Target, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{err}
	}
	defer f.Close()
	return ReadList(f)
}

// ReadAnsibleINI reads hosts out of an Ansible INI inventory.
//
// Two rules earn their place here. A `[group:vars]` section holds variables,
// not hosts, and reading it as hosts is how a probe list acquires entries like
// "ansible_user". And `ansible_host=` wins over the inventory name, because
// the name is frequently an alias that does not resolve outside the control
// node — the sort of thing that turns a fleet run into a page of DNS errors.
//
// groups filters by section name; empty means every group. A host in several
// groups is returned once.
func ReadAnsibleINI(r io.Reader, groups []string) ([]probe.Target, []error) {
	want := map[string]bool{}
	for _, g := range groups {
		want[strings.TrimSpace(g)] = true
	}
	var errs []error
	seen := map[string]probe.Target{}
	section := "ungrouped"
	skip := false

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			// [g:vars] carries variables; [g:children] carries group names,
			// not hosts. Both would otherwise be read as endpoints.
			skip = strings.Contains(section, ":")
			continue
		}
		if skip {
			continue
		}
		if len(want) > 0 && !want[section] {
			continue
		}
		fields := strings.Fields(line)
		name := fields[0]
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(f, "ansible_host="); ok {
				name = v
			}
		}
		t, err := Parse(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		seen[t.Addr()] = t
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, err)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]probe.Target, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out, errs
}

// ReadAnsibleINIFile is ReadAnsibleINI over a path.
func ReadAnsibleINIFile(path string, groups []string) ([]probe.Target, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{err}
	}
	defer f.Close()
	return ReadAnsibleINI(f, groups)
}
