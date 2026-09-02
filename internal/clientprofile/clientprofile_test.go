package clientprofile

import (
	"crypto/tls"
	"testing"
)

func TestSelectKeepsCanonicalOrder(t *testing.T) {
	sel, unknown := Select([]string{"pq-only", "classic"})
	if len(unknown) != 0 {
		t.Fatalf("unknown = %v", unknown)
	}
	if sel[0].Name != "classic" {
		t.Fatalf("a report reads baseline-first whatever the flag order: got %s", sel[0].Name)
	}
}

func TestSelectReportsUnknownNames(t *testing.T) {
	sel, unknown := Select([]string{"classic", "pq-maybe"})
	if len(sel) != 1 || len(unknown) != 1 || unknown[0] != "pq-maybe" {
		t.Fatalf("sel=%v unknown=%v", sel, unknown)
	}
}

// Every profile pins its groups. A profile that fell back to Go's defaults
// would change what a run proves when the toolchain is upgraded.
func TestEveryProfilePinsItsGroups(t *testing.T) {
	for _, p := range All {
		if len(p.Groups) == 0 {
			t.Fatalf("profile %s has no explicit group list", p.Name)
		}
		if p.MinVersion == 0 || p.MaxVersion == 0 {
			t.Fatalf("profile %s does not pin its TLS versions", p.Name)
		}
		if p.Clients == "" {
			t.Fatalf("profile %s does not say which real clients it stands for", p.Name)
		}
	}
}

func TestPQFlagsMatchTheGroupLists(t *testing.T) {
	for _, p := range All {
		var hasPQ, hasClassical bool
		for _, g := range p.Groups {
			if IsPQ(g) {
				hasPQ = true
			} else {
				hasClassical = true
			}
		}
		if p.OffersPQ != hasPQ {
			t.Fatalf("profile %s: OffersPQ=%v but groups say %v", p.Name, p.OffersPQ, hasPQ)
		}
		if p.RequiresPQ && hasClassical {
			t.Fatalf("profile %s claims to require post-quantum but offers a classical fallback", p.Name)
		}
	}
}

// The config never verifies the certificate: the chain is graded separately so
// an expired certificate cannot be reported as a capability failure.
func TestTLSConfigLeavesVerificationToTheCaller(t *testing.T) {
	p, _ := ByName("classic")
	cfg := p.TLSConfig("example.com", nil)
	if !cfg.InsecureSkipVerify {
		t.Fatal("handshake and chain verification must stay separate")
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.CurvePreferences) != len(p.Groups) {
		t.Fatal("the group list must reach the config")
	}
}

func TestGroupNameNeverEmptyForAKnownGroup(t *testing.T) {
	for _, g := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519MLKEM768} {
		if GroupName(g) == "" {
			t.Fatalf("no name for group %v", g)
		}
	}
	if GroupName(0) != "" {
		t.Fatal("an unset group has no name")
	}
}

// PQ-22. `pq-preferred` says a hybrid handshake works; it does not say *which*
// hybrid group. The group probes answer that: one group per ClientHello, so an
// accepted set can be read off the results instead of inferred.
func TestGroupProbesOfferExactlyOneGroupEach(t *testing.T) {
	probes := GroupProbes()
	if len(probes) < 3 {
		t.Fatalf("got %d group probes, want at least X25519MLKEM768, X25519 and P-256", len(probes))
	}
	seen := map[string]bool{}
	for _, p := range probes {
		if len(p.Groups) != 1 {
			t.Errorf("%s offers %d groups; a group probe offers exactly one, or the answer is about the set",
				p.Name, len(p.Groups))
		}
		// Post-quantum key exchange lives in the TLS 1.3 key_share extension, and
		// a group probe that fell back to 1.2 would report "refused" for a group
		// the peer never got the chance to pick.
		if p.MinVersion != tls.VersionTLS13 || p.MaxVersion != tls.VersionTLS13 {
			t.Errorf("%s is not pinned to TLS 1.3", p.Name)
		}
		if !IsGroupProbe(p.Name) {
			t.Errorf("%s is not recognisable as a group probe", p.Name)
		}
		if seen[p.Name] {
			t.Errorf("%s appears twice", p.Name)
		}
		seen[p.Name] = true
		if want := IsPQ(p.Groups[0]); p.OffersPQ != want {
			t.Errorf("%s: OffersPQ = %v, want %v", p.Name, p.OffersPQ, want)
		}
		if p.Clients == "" || p.Summary == "" {
			t.Errorf("%s has no summary or clients text", p.Name)
		}
	}
	if !seen[GroupProbeName(tls.X25519MLKEM768)] {
		t.Errorf("the hybrid group is the one anybody is asking about, and it is missing: %v", seen)
	}
}

// The real profiles must never be mistaken for group probes: the verdict reads
// them, and a class derived from a single-group hello would be a different
// statement entirely.
func TestRealProfilesAreNotGroupProbes(t *testing.T) {
	for _, p := range All {
		if IsGroupProbe(p.Name) {
			t.Errorf("%s reads as a group probe", p.Name)
		}
	}
}

// PQ-11. The sweep answers "at what size does this peer stop answering" with a
// number instead of an argument. Go exposes no padding, and in TLS 1.3 the
// cipher list is fixed, so the only client-controlled field that can grow
// arbitrarily without changing what the handshake means is the ALPN list.
func TestSizeProbesGrowAndAreRecognisable(t *testing.T) {
	probes := SizeProbes()
	if len(probes) < 3 {
		t.Fatalf("got %d size probes, want a sweep", len(probes))
	}

	last := 0
	for _, p := range probes {
		if !IsSizeProbe(p.Name) {
			t.Errorf("%s is not recognisable as a size probe", p.Name)
		}
		if p.Pad <= last {
			t.Errorf("%s pads to %d, which is not larger than the previous %d — a sweep has to climb",
				p.Name, p.Pad, last)
		}
		last = p.Pad
		// The realistic hybrid client is what a middlebox is choking on, so
		// that is the shape being grown.
		if !p.OffersPQ {
			t.Errorf("%s does not offer the hybrid group: the size question is about that hello", p.Name)
		}
		if p.MinVersion != tls.VersionTLS13 {
			t.Errorf("%s is not pinned to TLS 1.3", p.Name)
		}
	}

	for _, p := range All {
		if IsSizeProbe(p.Name) {
			t.Errorf("%s reads as a size probe", p.Name)
		}
	}
}

// The padding has to land in the ALPN list and be roughly the size asked for —
// the exact hello is measured on the wire, but a config that padded nothing
// would make the whole sweep report the same number.
func TestPaddingLandsInTheALPNList(t *testing.T) {
	p := Profile{Name: "size:4096", Groups: []tls.CurveID{tls.X25519MLKEM768}, Pad: 2000}
	cfg := p.TLSConfig("origin.example", []string{"h2"})

	if len(cfg.NextProtos) < 2 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("the ALPN the caller asked for has to come first: %v", cfg.NextProtos)
	}
	total := 0
	for _, s := range cfg.NextProtos {
		total += len(s) + 1
		if len(s) > 255 {
			t.Errorf("an ALPN entry is %d bytes; the wire format allows 255", len(s))
		}
	}
	if total < 2000 || total > 2000+300 {
		t.Errorf("the padded ALPN list is %d bytes, want about 2000", total)
	}
}

// No padding, no filler: every other profile must produce exactly the ALPN it
// was given.
func TestUnpaddedProfilesKeepTheirALPN(t *testing.T) {
	p, _ := ByName("pq-preferred")
	cfg := p.TLSConfig("origin.example", []string{"h2", "http/1.1"})
	if len(cfg.NextProtos) != 2 {
		t.Fatalf("NextProtos = %v, want exactly what was passed", cfg.NextProtos)
	}
}
