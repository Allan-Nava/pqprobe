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
