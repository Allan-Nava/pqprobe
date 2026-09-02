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
