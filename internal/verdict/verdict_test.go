package verdict

import (
	"strings"
	"testing"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

func ok(profile, version, group string, pq bool) probe.Result {
	return probe.Result{Profile: profile, OK: true, Kind: probe.KindOK, Version: version, Group: group, PQ: pq, Cipher: "TLS_AES_128_GCM_SHA256"}
}

func fail(profile string, k probe.Kind) probe.Result {
	return probe.Result{Profile: profile, Kind: k, Err: string(k)}
}

func opts() Options {
	o := DefaultOptions()
	o.Now = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	return o
}

func find(t *testing.T, rep Report, check string) finding.Finding {
	t.Helper()
	for _, f := range rep.Finding {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("no %q finding in %+v", check, rep.Finding)
	return finding.Finding{}
}

// The asymmetry the tool exists for: classical connects, post-quantum-capable
// is cut off. That is BAD, and it is BAD *because* the classical probe passed.
func TestIntolerantIsBadOnlyAgainstAWorkingBaseline(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		fail("pq-preferred", probe.KindReset),
		fail("pq-only", probe.KindReset),
	}, opts())

	if rep.Class != PQIntolerant {
		t.Fatalf("class = %s, want %s", rep.Class, PQIntolerant)
	}
	v := find(t, rep, "verdict")
	if v.Status != finding.BAD {
		t.Fatalf("status = %s, want BAD", v.Status)
	}
	if !strings.Contains(v.Hint, "curl") {
		t.Fatalf("the hint must say that existing checks keep passing: %q", v.Hint)
	}
}

// Same asymmetry, civil refusal: a different diagnosis and a different fix.
func TestAlertRefusalIsRefusingNotIntolerant(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		fail("pq-preferred", probe.KindAlert),
	}, opts())
	if rep.Class != PQRefusing {
		t.Fatalf("class = %s, want %s", rep.Class, PQRefusing)
	}
	if find(t, rep, "verdict").Status != finding.BAD {
		t.Fatal("a client class that cannot connect is BAD however politely it was told")
	}
}

// No post-quantum support, but everything still connects: a WARN with a date
// attached to it, not a failure.
func TestFallbackIsWarnNotBad(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		ok("pq-preferred", "TLS 1.3", "X25519", false),
		fail("pq-only", probe.KindAlert),
	}, opts())
	if rep.Class != PQBlind {
		t.Fatalf("class = %s, want %s", rep.Class, PQBlind)
	}
	if got := find(t, rep, "verdict").Status; got != finding.WARN {
		t.Fatalf("status = %s, want WARN", got)
	}
}

func TestReadyIsQuiet(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		ok("pq-preferred", "TLS 1.3", "X25519MLKEM768", true),
		ok("pq-only", "TLS 1.3", "X25519MLKEM768", true),
	}, opts())
	if rep.Class != PQReady {
		t.Fatalf("class = %s, want %s", rep.Class, PQReady)
	}
	if rep.Worst() != finding.OK {
		t.Fatalf("a ready endpoint must produce nothing above OK, got %s", rep.Worst())
	}
}

// An endpoint nobody reached is not an endpoint that failed a post-quantum
// probe. Grading it would put every firewalled host in the "intolerant" bucket.
func TestUnreachableIsNotAGrade(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		fail("classic", probe.KindRefused),
		fail("pq-preferred", probe.KindRefused),
	}, opts())
	if rep.Class != Unreachable {
		t.Fatalf("class = %s, want %s", rep.Class, Unreachable)
	}
	if rep.Worst() != finding.ERROR {
		t.Fatalf("worst = %s, want ERROR", rep.Worst())
	}
	for _, f := range rep.Finding {
		if f.Check == "verdict" && f.Status != finding.ERROR {
			t.Fatal("the verdict of an unreachable endpoint must be ERROR, never BAD")
		}
	}
}

func TestTLS12CeilingIsItsOwnClass(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.2", "X25519", false),
		fail("pq-preferred", probe.KindAlert),
	}, opts())
	if rep.Class != NoTLS13 {
		t.Fatalf("class = %s, want %s", rep.Class, NoTLS13)
	}
}

func TestExpiryThresholds(t *testing.T) {
	now := opts().Now
	mk := func(days int) Report {
		r := ok("classic", "TLS 1.3", "X25519", false)
		r.Chain = []probe.Cert{{Subject: "leaf", NotAfter: now.AddDate(0, 0, days)}}
		r.ChainVerified = true
		r.PeerChainLen = 2
		return Evaluate("h:443", []probe.Result{r}, opts())
	}
	if got := find(t, mk(60), "expiry").Status; got != finding.OK {
		t.Fatalf("60 days = %s, want OK", got)
	}
	if got := find(t, mk(10), "expiry").Status; got != finding.WARN {
		t.Fatalf("10 days = %s, want WARN", got)
	}
	if got := find(t, mk(2), "expiry").Status; got != finding.BAD {
		t.Fatalf("2 days = %s, want BAD", got)
	}
	if got := find(t, mk(-1), "expiry"); !strings.Contains(got.Message, "expired") {
		t.Fatalf("an expired leaf must say so: %q", got.Message)
	}
}

func TestLeafOnlyChainIsReported(t *testing.T) {
	r := ok("classic", "TLS 1.3", "X25519", false)
	r.Chain = []probe.Cert{{Subject: "leaf", NotAfter: opts().Now.AddDate(1, 0, 0)}}
	r.ChainVerified = true
	r.PeerChainLen = 1
	rep := Evaluate("h:443", []probe.Result{r}, opts())
	if got := find(t, rep, "chain"); got.Status != finding.WARN || !strings.Contains(got.Message, "alone") {
		t.Fatalf("expected a leaf-only warning, got %+v", got)
	}
}

// Every conclusion has to be traceable to the attempt behind it.
func TestEveryProfileGetsItsOwnFinding(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		fail("pq-preferred", probe.KindReset),
	}, opts())
	var handshakes int
	for _, f := range rep.Finding {
		if f.Check == "handshake" {
			handshakes++
		}
	}
	if handshakes != 2 {
		t.Fatalf("handshake findings = %d, want one per profile", handshakes)
	}
}

// PQ-22. The group map is a report, not a grade: it says which groups the peer
// accepted, and it must not move the class — a single-group ClientHello says
// nothing about what a realistic client can do.
func TestGroupMapReportsWithoutChangingTheClass(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		ok("pq-preferred", "TLS 1.3", "X25519MLKEM768", true),
		ok("pq-only", "TLS 1.3", "X25519MLKEM768", true),
		ok("group:X25519MLKEM768", "TLS 1.3", "X25519MLKEM768", true),
		ok("group:X25519", "TLS 1.3", "X25519", false),
		fail("group:P-384", probe.KindAlert),
		fail("group:P-521", probe.KindReset),
	}, opts())

	if rep.Class != PQReady {
		t.Fatalf("class = %s, want %s — the group probes must not decide the class", rep.Class, PQReady)
	}

	g := find(t, rep, "groups")
	if !strings.Contains(g.Message, "X25519MLKEM768") || !strings.Contains(g.Message, "X25519") {
		t.Errorf("the accepted groups have to be named: %q", g.Message)
	}
	if !strings.Contains(g.Message, "P-384") || !strings.Contains(g.Message, "P-521") {
		t.Errorf("the refused groups have to be named too: %q", g.Message)
	}
	if g.Value == nil || *g.Value != 2 {
		t.Errorf("value = %v, want 2 accepted groups", g.Value)
	}
	if g.Unit != "groups" {
		t.Errorf("unit = %q, want groups", g.Unit)
	}
	// A group refused with an alert is a policy; a group whose hello vanished is
	// the failure this whole tool exists for. One message must not blur them.
	if !strings.Contains(g.Message, "alert") || !strings.Contains(g.Message, "cut off") {
		t.Errorf("the two kinds of refusal must stay apart: %q", g.Message)
	}
}

// One `groups` finding, not five handshake findings: the per-group pass would
// otherwise treble the output of every run that used it.
func TestGroupProbesDoNotEmitHandshakeFindings(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		fail("group:P-521", probe.KindAlert),
	}, opts())

	for _, f := range rep.Finding {
		if f.Check == "handshake" && strings.Contains(f.Target, "group:") {
			t.Fatalf("a group probe got its own handshake finding: %+v", f)
		}
	}
}

// Without the flag there are no group results, and then there is nothing to say.
func TestNoGroupFindingWhenNoGroupWasProbed(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
	}, opts())

	for _, f := range rep.Finding {
		if f.Check == "groups" {
			t.Fatalf("a groups finding with no group probes: %+v", f)
		}
	}
}

// PQ-23. A flap is a third state: the endpoint works, and it is unstable. It
// must not be graded as the wall it looked like on the first dial, and it must
// not be silent either.
func TestAFlapIsReportedButDoesNotCondemn(t *testing.T) {
	flapped := ok("pq-preferred", "TLS 1.3", "X25519MLKEM768", true)
	flapped.Attempts = 2
	flapped.FirstKind = probe.KindReset
	flapped.Flapped = true

	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		flapped,
		ok("pq-only", "TLS 1.3", "X25519MLKEM768", true),
	}, opts())

	if rep.Class != PQReady {
		t.Fatalf("class = %s, want %s — it connected, on the second dial", rep.Class, PQReady)
	}

	var hs finding.Finding
	for _, f := range rep.Finding {
		if f.Check == "handshake" && strings.Contains(f.Target, "pq-preferred") {
			hs = f
		}
	}
	if hs.Status != finding.WARN {
		t.Errorf("status = %s, want WARN: a connection that needed two attempts is not OK", hs.Status)
	}
	if !strings.Contains(hs.Message, "second") {
		t.Errorf("the message has to say it took a second attempt: %q", hs.Message)
	}
	if !strings.Contains(hs.Hint, "flap") && !strings.Contains(hs.Hint, "unstable") {
		t.Errorf("the hint has to name the state: %q", hs.Hint)
	}
}

// The wall, confirmed: the verdict is the same BAD it always was, and the hint
// says the refusal reproduced — because that is the sentence that survives
// being forwarded to whoever owns the middlebox.
func TestAConfirmedWallSaysItReproduced(t *testing.T) {
	wall := fail("pq-preferred", probe.KindReset)
	wall.Attempts = 2
	wall.FirstKind = probe.KindReset
	wall.Reproduced = true
	only := fail("pq-only", probe.KindReset)
	only.Attempts = 2
	only.Reproduced = true

	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		wall, only,
	}, opts())

	if rep.Class != PQIntolerant {
		t.Fatalf("class = %s, want %s", rep.Class, PQIntolerant)
	}
	v := find(t, rep, "verdict")
	if !strings.Contains(v.Hint, "twice") && !strings.Contains(v.Hint, "reproduced") {
		t.Errorf("the hint has to say the refusal reproduced: %q", v.Hint)
	}
}

// One dial and no confirmation: nothing about attempts belongs in the output,
// or every finding grows a clause that means nothing.
func TestASingleAttemptSaysNothingAboutAttempts(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		ok("classic", "TLS 1.3", "X25519", false),
		fail("pq-preferred", probe.KindReset),
		fail("pq-only", probe.KindReset),
	}, opts())

	v := find(t, rep, "verdict")
	if strings.Contains(v.Hint, "twice") || strings.Contains(v.Hint, "reproduced") {
		t.Errorf("nothing was confirmed, so the hint must not claim it was: %q", v.Hint)
	}
	for _, f := range rep.Finding {
		if strings.Contains(f.Message, "second attempt") {
			t.Errorf("a single-dial result mentions a second attempt: %+v", f)
		}
	}
}

// PQ-26. Mutual TLS does not change what the key exchange proved, so the class
// stands — and the report says the peer asked, because "pq-ready" alone would
// be read as "usable".
func TestMutualTLSIsANoteNotAGrade(t *testing.T) {
	mark := func(r probe.Result) probe.Result { r.ClientCertRequested = true; return r }
	rep := Evaluate("h:443", []probe.Result{
		mark(ok("classic", "TLS 1.3", "X25519", false)),
		mark(ok("pq-preferred", "TLS 1.3", "X25519MLKEM768", true)),
		mark(ok("pq-only", "TLS 1.3", "X25519MLKEM768", true)),
	}, opts())

	if rep.Class != PQReady {
		t.Fatalf("class = %s, want %s: the key exchange completed", rep.Class, PQReady)
	}
	f := find(t, rep, "client-auth")
	if f.Status != finding.OK {
		t.Errorf("status = %s: a deliberate mutual-TLS origin is a fact, not a problem", f.Status)
	}
	if !strings.Contains(f.Message, "client certificate") {
		t.Errorf("message = %q", f.Message)
	}
}

// When the certificate request is what broke every handshake, the endpoint has
// not refused post-quantum clients — it has refused *pqprobe*, and saying
// anything about capability would be a fabrication.
func TestNothingIsGradedWhenTheClientCertificateIsWhatFailed(t *testing.T) {
	mark := func(r probe.Result) probe.Result { r.ClientCertRequested = true; return r }
	rep := Evaluate("h:443", []probe.Result{
		mark(fail("classic", probe.KindAlert)),
		mark(fail("pq-preferred", probe.KindAlert)),
		mark(fail("pq-only", probe.KindAlert)),
	}, opts())

	if rep.Class != MTLSRequired {
		t.Fatalf("class = %s, want %s", rep.Class, MTLSRequired)
	}
	v := find(t, rep, "verdict")
	if v.Status != finding.ERROR {
		t.Errorf("status = %s, want ERROR — this is not a grade", v.Status)
	}
	if !strings.Contains(v.Hint, "certificate") {
		t.Errorf("the hint has to name what to do: %q", v.Hint)
	}
}

// A plain alert with no certificate request is still tls-broken: the new class
// must not swallow the old one.
func TestAlertsWithoutACertificateRequestStayTLSBroken(t *testing.T) {
	rep := Evaluate("h:443", []probe.Result{
		fail("classic", probe.KindAlert),
		fail("pq-preferred", probe.KindAlert),
	}, opts())

	if rep.Class != TLSBroken {
		t.Fatalf("class = %s, want %s", rep.Class, TLSBroken)
	}
}

// PQ-12. Six addresses behind one name, one of them different: that is the
// shape that survives a manual check, and naming the odd one out is the whole
// value of probing by address.
func TestTheInconsistentAddressIsNamed(t *testing.T) {
	reps := []Report{
		{Target: "192.0.2.1:443 (sni origin.example)", Class: PQReady},
		{Target: "192.0.2.2:443 (sni origin.example)", Class: PQReady},
		{Target: "192.0.2.3:443 (sni origin.example)", Class: PQIntolerant},
	}

	f, idx, ok := AddressConsistency("origin.example", reps)
	if !ok {
		t.Fatal("three addresses that disagree must produce a finding")
	}
	if idx != 2 {
		t.Errorf("index = %d, want the finding attached to the address that differs", idx)
	}
	if f.Status != finding.BAD {
		t.Errorf("status = %s, want BAD: the worst class in the group decides", f.Status)
	}
	if !strings.Contains(f.Message, "192.0.2.3") {
		t.Errorf("the odd address has to be named: %q", f.Message)
	}
	if !strings.Contains(f.Message, "pq-intolerant") || !strings.Contains(f.Message, "pq-ready") {
		t.Errorf("both sides of the disagreement have to be in the message: %q", f.Message)
	}
	if f.Value == nil || *f.Value != 3 {
		t.Errorf("value = %v, want the number of addresses behind the name", f.Value)
	}
	if f.Unit != "addresses" {
		t.Errorf("unit = %q, want addresses", f.Unit)
	}
	if !strings.Contains(f.Hint, "one node") && !strings.Contains(f.Hint, "pool") {
		t.Errorf("the hint has to say what to do with an inconsistent pool: %q", f.Hint)
	}
}

// Every address agreeing is worth saying once: it is the difference between "we
// checked the pool" and "we checked whatever DNS handed us".
func TestAConsistentPoolIsStatedOnce(t *testing.T) {
	reps := []Report{
		{Target: "192.0.2.1:443 (sni origin.example)", Class: PQReady},
		{Target: "192.0.2.2:443 (sni origin.example)", Class: PQReady},
	}
	f, idx, ok := AddressConsistency("origin.example", reps)
	if !ok {
		t.Fatal("a consistent pool still deserves the one line that says so")
	}
	if f.Status != finding.OK {
		t.Errorf("status = %s, want OK", f.Status)
	}
	if idx != 0 {
		t.Errorf("index = %d, want the first report", idx)
	}
	if !strings.Contains(f.Message, "2 addresses") || !strings.Contains(f.Message, "pq-ready") {
		t.Errorf("message = %q", f.Message)
	}
}

// One address is not a pool, and a finding about its consistency would be noise
// on every single-homed endpoint in the fleet.
func TestASingleAddressGetsNoConsistencyFinding(t *testing.T) {
	if _, _, ok := AddressConsistency("origin.example", []Report{{Target: "192.0.2.1:443", Class: PQReady}}); ok {
		t.Fatal("a single address must not produce a consistency finding")
	}
}

// An unreachable node in a pool of working ones is the same story with a
// different word: ERROR sorts above BAD, so it must not be diluted into it.
func TestAnUnreachableNodeInAPoolIsAnError(t *testing.T) {
	reps := []Report{
		{Target: "192.0.2.1:443 (sni origin.example)", Class: PQReady},
		{Target: "192.0.2.9:443 (sni origin.example)", Class: Unreachable},
	}
	f, idx, ok := AddressConsistency("origin.example", reps)
	if !ok {
		t.Fatal("want a finding")
	}
	if f.Status != finding.ERROR {
		t.Errorf("status = %s, want ERROR", f.Status)
	}
	if idx != 1 {
		t.Errorf("index = %d, want the unreachable node", idx)
	}
}

// PQ-12. An address this host has no route to says nothing about the endpoint,
// so it is unreachable — never tls-broken, which claims the port answered.
func TestUnroutableIsUnreachableNotBroken(t *testing.T) {
	rep := Evaluate("[2001:db8::1]:443 (sni origin.example)", []probe.Result{
		fail("classic", probe.KindUnroutable),
		fail("pq-preferred", probe.KindUnroutable),
		fail("pq-only", probe.KindUnroutable),
	}, opts())

	if rep.Class != Unreachable {
		t.Fatalf("class = %s, want %s", rep.Class, Unreachable)
	}
	v := find(t, rep, "verdict")
	if !strings.Contains(v.Hint, "route") {
		t.Errorf("the hint has to raise the likeliest cause — no route from this host: %q", v.Hint)
	}
	if !strings.Contains(v.Hint, "IPv6") {
		t.Errorf("and name the case that produces it in practice: %q", v.Hint)
	}
}

// The pool finding must not tell somebody to drain a node that is only
// unreachable from the machine running the probe.
func TestAPoolWithAnUnreachableNodeBlamesTheRouteFirst(t *testing.T) {
	f, _, ok := AddressConsistency("origin.example", []Report{
		{Target: "192.0.2.1:443 (sni origin.example)", Class: PQReady},
		{Target: "[2001:db8::1]:443 (sni origin.example)", Class: Unreachable},
	})
	if !ok {
		t.Fatal("want a finding")
	}
	if !strings.Contains(f.Hint, "route") {
		t.Errorf("the hint has to offer the local route as the first explanation: %q", f.Hint)
	}
	if strings.Contains(f.Hint, "take it out of rotation") {
		t.Errorf("draining a node you simply cannot reach is the wrong advice: %q", f.Hint)
	}
}

// PQ-24. The transition is the news. An endpoint that was already broken
// yesterday is not, and it must not be at the top of the output every morning.
func TestTransitionsAreTheNews(t *testing.T) {
	old := []Report{
		{Target: "a:443", Class: PQReady},
		{Target: "b:443", Class: PQIntolerant},
		{Target: "c:443", Class: PQBlind},
	}
	now := []Report{
		{Target: "a:443", Class: PQIntolerant}, // regression: the news
		{Target: "b:443", Class: PQIntolerant}, // still broken: not news
		{Target: "c:443", Class: PQReady},      // fixed: worth saying, quietly
		{Target: "d:443", Class: PQReady},      // new endpoint
	}

	fs := Transitions(old, now)

	byTarget := map[string]finding.Finding{}
	for _, f := range fs {
		if f.Check != "transition" {
			t.Errorf("unexpected check %q", f.Check)
		}
		byTarget[f.Target] = f
	}

	if _, ok := byTarget["b:443"]; ok {
		t.Error("an endpoint that has not changed must produce nothing at all")
	}

	a, ok := byTarget["a:443"]
	if !ok {
		t.Fatal("a regression has to be reported")
	}
	if a.Status != finding.BAD {
		t.Errorf("status = %s, want BAD: it got worse", a.Status)
	}
	if !strings.Contains(a.Message, "pq-ready") || !strings.Contains(a.Message, "pq-intolerant") {
		t.Errorf("both classes have to be in the message: %q", a.Message)
	}

	c, ok := byTarget["c:443"]
	if !ok {
		t.Fatal("an improvement is a transition too")
	}
	if c.Status != finding.OK {
		t.Errorf("status = %s, want OK: it got better", c.Status)
	}

	d, ok := byTarget["d:443"]
	if !ok {
		t.Fatal("an endpoint the baseline never saw has to be flagged as new")
	}
	if !strings.Contains(d.Message, "new") {
		t.Errorf("message = %q, want it to say the baseline had never seen it", d.Message)
	}
	if d.Status != finding.OK {
		t.Errorf("status = %s: a new endpoint is not by itself a problem", d.Status)
	}
}

// An endpoint that vanished is a question about the inventory, and silence
// would hide a target somebody deleted by accident.
func TestAVanishedEndpointIsReported(t *testing.T) {
	fs := Transitions(
		[]Report{{Target: "gone:443", Class: PQReady}},
		[]Report{{Target: "here:443", Class: PQReady}},
	)
	var found bool
	for _, f := range fs {
		if f.Target == "gone:443" {
			found = true
			if f.Status != finding.WARN {
				t.Errorf("status = %s, want WARN", f.Status)
			}
			if !strings.Contains(f.Message, "not in this run") {
				t.Errorf("message = %q", f.Message)
			}
			// It has nowhere of its own to be printed, so it is filed under
			// another endpoint. The message has to name the endpoint it is
			// about, or it reads as a statement about the wrong one.
			if !strings.Contains(f.Message, "gone:443") {
				t.Errorf("a transition with no report of its own must name its target: %q", f.Message)
			}
		}
	}
	if !found {
		t.Error("an endpoint in the baseline and not in the run has to be reported")
	}
}

// Two identical runs say nothing. A diff that always has something in it is a
// diff nobody reads.
func TestIdenticalRunsProduceNoTransitions(t *testing.T) {
	reps := []Report{{Target: "a:443", Class: PQReady}, {Target: "b:443", Class: PQBlind}}
	if fs := Transitions(reps, reps); len(fs) != 0 {
		t.Fatalf("got %d findings for two identical runs: %+v", len(fs), fs)
	}
}
