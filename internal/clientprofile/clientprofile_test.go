package clientprofile

import (
	"crypto/tls"
	"strings"
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

// PQ-25. ALPN is bytes in the same hello, and a CDN offers h2,http/1.1 where a
// health check offers nothing. If a peer takes the hybrid hello bare and drops
// it with ALPN, it is size-intolerant with a threshold in between — and today
// that reads as a flap.
func TestTheALPNProbePinsItsProtocolList(t *testing.T) {
	p := ALPNProbe()

	if !IsALPNProbe(p.Name) {
		t.Errorf("%s is not recognisable as the ALPN probe", p.Name)
	}
	if !p.OffersPQ {
		t.Error("the question is about the hybrid hello, so it has to offer the hybrid group")
	}
	if len(p.ALPN) == 0 {
		t.Fatal("the probe exists to carry an ALPN list")
	}

	// A profile that pins its ALPN pins it: the caller's list would make the
	// comparison meaningless, since the difference *is* the variable.
	cfg := p.TLSConfig("origin.example", []string{"whatever-the-caller-said"})
	if len(cfg.NextProtos) != len(p.ALPN) || cfg.NextProtos[0] != p.ALPN[0] {
		t.Fatalf("NextProtos = %v, want the pinned list %v", cfg.NextProtos, p.ALPN)
	}
	if cfg.NextProtos[0] != "h2" {
		t.Errorf("the realistic list starts with h2, not %q", cfg.NextProtos[0])
	}

	// The bare profile it is compared against must not carry ALPN of its own.
	bare, _ := ByName("pq-preferred")
	if len(bare.ALPN) != 0 {
		t.Error("pq-preferred has to stay bare, or there is nothing to compare")
	}
	for _, x := range All {
		if IsALPNProbe(x.Name) {
			t.Errorf("%s reads as the ALPN probe", x.Name)
		}
	}
}

// One variable. The first ALPN probe pinned TLS 1.3 while pq-preferred allows
// 1.2, so it offered fewer cipher suites and produced a *smaller* hello: the
// pair measured two differences at once, which measures nothing. This asserts
// the shapes stay identical apart from the ALPN list.
func TestTheALPNProbeDiffersFromItsPairInExactlyOneWay(t *testing.T) {
	bare, _ := ByName("pq-preferred")
	probe := ALPNProbe()

	if probe.MinVersion != bare.MinVersion || probe.MaxVersion != bare.MaxVersion {
		t.Errorf("version window differs: %x-%x against %x-%x",
			probe.MinVersion, probe.MaxVersion, bare.MinVersion, bare.MaxVersion)
	}
	if len(probe.Groups) != len(bare.Groups) {
		t.Fatalf("group list differs: %v against %v", probe.Groups, bare.Groups)
	}
	for i := range probe.Groups {
		if probe.Groups[i] != bare.Groups[i] {
			t.Errorf("group %d differs: %v against %v", i, probe.Groups[i], bare.Groups[i])
		}
	}
	if probe.OffersPQ != bare.OffersPQ || probe.RequiresPQ != bare.RequiresPQ || probe.Pad != bare.Pad {
		t.Error("the flags have to match: the ALPN list is the only variable")
	}
}

// PQ-34. The profiles fix three group sets and --per-group asks about one group
// at a time. Neither answers "what about exactly the set my CDN offers", which
// is the question somebody planning a migration actually has.
func TestCustomProfileTakesTheSetItIsGiven(t *testing.T) {
	p, unknown := CustomProfile([]string{"X25519MLKEM768", "X25519"})
	if len(unknown) != 0 {
		t.Fatalf("unknown = %v, want none", unknown)
	}
	if !IsCustomProfile(p.Name) {
		t.Errorf("%s is not recognisable as the custom profile", p.Name)
	}
	if len(p.Groups) != 2 || p.Groups[0] != tls.X25519MLKEM768 || p.Groups[1] != tls.X25519 {
		t.Fatalf("groups = %v, want the two asked for, in that order", p.Groups)
	}
	// The order is the client's preference and it is the caller's to choose:
	// reordering it would answer a different question.
	if !p.OffersPQ {
		t.Error("a set containing ML-KEM offers post-quantum")
	}
	if p.RequiresPQ {
		t.Error("X25519 is a fallback, so this set does not require post-quantum")
	}
	// The same version window as the realistic client, so the result is
	// comparable with pq-preferred rather than with nothing.
	bare, _ := ByName("pq-preferred")
	if p.MinVersion != bare.MinVersion || p.MaxVersion != bare.MaxVersion {
		t.Errorf("version window %x-%x, want the same as pq-preferred", p.MinVersion, p.MaxVersion)
	}
	if !strings.Contains(p.Name, "X25519MLKEM768") {
		t.Errorf("the name has to say what was dialled, since nothing else will: %q", p.Name)
	}
}

// A set of only post-quantum groups requires it, exactly as pq-only does.
func TestACustomPostQuantumOnlySetRequiresIt(t *testing.T) {
	p, _ := CustomProfile([]string{"X25519MLKEM768"})
	if !p.OffersPQ || !p.RequiresPQ {
		t.Errorf("offers=%v requires=%v, want both", p.OffersPQ, p.RequiresPQ)
	}
}

// A name Go cannot offer is a usage error, not a silently smaller set: a run
// that quietly dropped a group would prove something other than what was asked.
func TestUnknownGroupNamesAreReturnedNotDropped(t *testing.T) {
	p, unknown := CustomProfile([]string{"X25519", "kyber1024", "P-256"})
	if len(unknown) != 1 || unknown[0] != "kyber1024" {
		t.Fatalf("unknown = %v, want [kyber1024]", unknown)
	}
	if len(p.Groups) != 2 {
		t.Errorf("groups = %v: the known ones are still resolved so the caller can report both", p.Groups)
	}
}

// Group names are how they are printed, and nobody types them twice the same
// way: the spelling in the report is what the flag accepts, case aside.
func TestGroupNamesRoundTripThroughTheFlag(t *testing.T) {
	for _, id := range Probed {
		name := GroupName(id)
		p, unknown := CustomProfile([]string{strings.ToLower(name)})
		if len(unknown) != 0 || len(p.Groups) != 1 || p.Groups[0] != id {
			t.Errorf("%q did not resolve back to itself: groups=%v unknown=%v", name, p.Groups, unknown)
		}
	}
}

// PQ-50. ECH is offered as a *pair*, and the pair is the whole point: PQ-25
// learned this the hard way, when an ALPN probe that also pinned a TLS version
// produced a smaller hello than the bare one and compared two variables at
// once. ECH requires TLS 1.3, so its twin has to require it too.
func TestECHProbesDifferOnlyInECH(t *testing.T) {
	list := []byte{0xde, 0xad, 0xbe, 0xef}
	ps := ECHProbes(list)
	if len(ps) != 2 {
		t.Fatalf("got %d profiles, want the pair", len(ps))
	}
	off, on := ps[0], ps[1]

	for _, p := range ps {
		if !IsECHProbe(p.Name) {
			t.Errorf("%s is not recognised as an ECH probe, so the verdict would grade on it", p.Name)
		}
		if p.MinVersion != tls.VersionTLS13 || p.MaxVersion != tls.VersionTLS13 {
			t.Errorf("%s: versions %x..%x, want TLS 1.3 pinned on both halves", p.Name, p.MinVersion, p.MaxVersion)
		}
	}
	if off.Name == on.Name {
		t.Fatal("the two halves need different names, or one result overwrites the other")
	}

	base, _ := ByName("pq-preferred")
	if len(off.Groups) != len(base.Groups) {
		t.Errorf("the twin must offer the same groups as pq-preferred, or it is measuring something else")
	}

	cfgOff := off.TLSConfig("origin.example", nil)
	cfgOn := on.TLSConfig("origin.example", nil)
	if len(cfgOff.EncryptedClientHelloConfigList) != 0 {
		t.Error("the twin must not carry an ECH config: it is the control")
	}
	if string(cfgOn.EncryptedClientHelloConfigList) != string(list) {
		t.Errorf("the ECH half carries %v, want the config list it was given", cfgOn.EncryptedClientHelloConfigList)
	}
}

// PQ-59. Go exposes three hybrid groups and pqprobe offered one, which is not a
// limitation of the language: a server configured with SecP256r1MLKEM768 alone
// completes a handshake with Go today, and pqprobe called it tls-broken.
func TestEveryHybridGoCanNegotiateIsKnown(t *testing.T) {
	hybrids := []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}

	// The names a report prints, pinned here rather than taken from the
	// toolchain: what a run says must not change when Go's String() does.
	names := map[tls.CurveID]string{
		tls.X25519MLKEM768:     "X25519MLKEM768",
		tls.SecP256r1MLKEM768:  "SecP256r1MLKEM768",
		tls.SecP384r1MLKEM1024: "SecP384r1MLKEM1024",
	}
	for _, id := range hybrids {
		if !IsPQ(id) {
			t.Errorf("%s is a hybrid ML-KEM group and IsPQ says otherwise — a handshake on it would be graded classical", GroupName(id))
		}
		name := GroupName(id)
		if name != names[id] {
			t.Errorf("group %d is printed %q, want %q", id, name, names[id])
		}
		back, ok := GroupByName(strings.ToLower(name))
		if !ok || back != id {
			t.Errorf("%s does not round-trip through GroupByName (--groups takes the name a report prints)", name)
		}
		found := false
		for _, p := range Probed {
			if p == id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not in Probed, so --per-group never asks about it", name)
		}
	}

	// The classical groups are not hybrids, and nothing above may blur that.
	for _, id := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		if IsPQ(id) {
			t.Errorf("%s is classical", GroupName(id))
		}
	}
}

// What must not change: pq-preferred and pq-only offer what Chrome and Firefox
// offer. A peer that speaks only another hybrid is still unreachable for them,
// and widening the browser profiles to hide that would be the same lie in the
// other direction.
func TestTheBrowserProfilesStillOfferWhatBrowsersOffer(t *testing.T) {
	for _, name := range []string{"pq-preferred", "pq-only"} {
		p, ok := ByName(name)
		if !ok {
			t.Fatalf("no %s profile", name)
		}
		for _, g := range p.Groups {
			if IsPQ(g) && g != tls.X25519MLKEM768 {
				t.Errorf("%s offers %s, which no browser sends: this profile stands for real clients",
					name, GroupName(g))
			}
		}
	}
}
