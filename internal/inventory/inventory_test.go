package inventory

import (
	"strings"
	"testing"
)

func TestParseForms(t *testing.T) {
	cases := []struct {
		in, host, port, sni string
	}{
		{"example.com", "example.com", "443", ""},
		{"example.com:8443", "example.com", "8443", ""},
		{"https://example.com/path?q=1", "example.com", "443", ""},
		{"http://example.com:8080/x", "example.com", "8080", ""},
		{"10.0.0.1=origin.example.com", "10.0.0.1", "443", "origin.example.com"},
		{"[2001:db8::1]:443", "2001:db8::1", "443", ""},
		{"[2001:db8::1]", "2001:db8::1", "443", ""},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if got.Host != c.host || got.Port != c.port || got.SNI != c.sni {
			t.Fatalf("Parse(%q) = %+v, want %s/%s/%s", c.in, got, c.host, c.port, c.sni)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "   ", "host name"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("Parse(%q) should fail", in)
		}
	}
}

func TestReadListSkipsCommentsAndReportsEveryBadLine(t *testing.T) {
	in := strings.NewReader(`
# the public endpoints
a.example.com
; another comment
b.example.com:8443
bad host name
also bad name
`)
	ts, errs := ReadList(in)
	if len(ts) != 2 {
		t.Fatalf("targets = %d, want 2: %+v", len(ts), ts)
	}
	if len(errs) != 2 {
		t.Fatalf("errors = %d, want both bad lines reported: %v", len(errs), errs)
	}
}

// The two rules that make an Ansible inventory usable as a probe list: a
// `:vars` section is not a list of hosts, and `ansible_host` is the address
// that actually resolves.
func TestReadAnsibleINI(t *testing.T) {
	in := strings.NewReader(`
[edge]
edge-01 ansible_host=10.11.10.5
edge-02

[edge:vars]
ansible_user=hwm
ansible_python_interpreter=/usr/bin/python3

[origin]
origin-01 ansible_host=10.11.20.9 ansible_port=22

[all:children]
edge
origin
`)
	ts, errs := ReadAnsibleINI(in, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	var hosts []string
	for _, tg := range ts {
		hosts = append(hosts, tg.Host)
	}
	got := strings.Join(hosts, ",")
	if strings.Contains(got, "ansible_user") || strings.Contains(got, "hwm") {
		t.Fatalf("a [group:vars] section was read as hosts: %s", got)
	}
	if strings.Contains(got, "edge-01") {
		t.Fatalf("ansible_host must win over the inventory alias: %s", got)
	}
	if len(ts) != 3 {
		t.Fatalf("hosts = %d (%s), want 3", len(ts), got)
	}
}

func TestReadAnsibleINIFiltersGroupsAndDeduplicates(t *testing.T) {
	in := strings.NewReader(`
[edge]
10.0.0.1

[cdn]
10.0.0.1
10.0.0.2
`)
	ts, _ := ReadAnsibleINI(in, []string{"cdn"})
	if len(ts) != 2 {
		t.Fatalf("targets = %+v, want the two cdn hosts", ts)
	}
	all, _ := ReadAnsibleINI(strings.NewReader("[a]\n10.0.0.1\n[b]\n10.0.0.1\n"), nil)
	if len(all) != 1 {
		t.Fatalf("a host in two groups is one endpoint, got %d", len(all))
	}
}
