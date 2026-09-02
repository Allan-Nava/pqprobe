// Package verdict turns a set of per-profile handshake results into the two
// things an operator needs: a class for the endpoint, and findings that say
// which real clients are affected and why.
//
// The class is decided against the baseline. "The post-quantum probe failed"
// on its own means nothing — the endpoint might be down — so every conclusion
// about post-quantum is conditional on the classical profile having worked. An
// endpoint that answered nothing is unreachable, and unreachable is not a
// grade.
package verdict

import (
	"fmt"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// Class is the endpoint's post-quantum readiness.
type Class string

const (
	// PQReady: the endpoint completed a handshake with a client that offered
	// nothing but hybrid ML-KEM.
	PQReady Class = "pq-ready"
	// PQCapable: hybrid ML-KEM was negotiated when offered alongside classical
	// groups, but the post-quantum-only profile did not complete. Usually a
	// TLS 1.3 restriction on the pq-only profile rather than a real limit.
	PQCapable Class = "pq-capable"
	// PQBlind: no post-quantum support, but a client that offers it still
	// connects on a classical group. Works today; the clock is running.
	PQBlind Class = "pq-blind"
	// PQIntolerant: the classical client connects and the post-quantum-capable
	// client does not, and the refusal was abrupt — a reset, a timeout, a
	// closed connection. This is the failure that looks like "the origin is
	// fine, curl works" while a CDN in front of it serves errors.
	PQIntolerant Class = "pq-intolerant"
	// PQRefusing: same asymmetry, but the peer refused with a TLS alert. It
	// parsed a ClientHello that offered classical groups too and still said no,
	// so the cause is policy or a broken group list rather than size.
	PQRefusing Class = "pq-refusing"
	// NoTLS13: the endpoint serves TLS 1.2 and nothing newer. Post-quantum key
	// exchange is a TLS 1.3 feature, so this is a ceiling, not a setting.
	NoTLS13 Class = "no-tls13"
	// Unreachable: nothing answered. No TLS conclusion is available.
	Unreachable Class = "unreachable"
	// TLSBroken: something answered and no profile completed a handshake.
	TLSBroken Class = "tls-broken"
)

// Options are the thresholds a report is graded against.
type Options struct {
	// ExpiryWarnDays and ExpiryBadDays grade the leaf certificate.
	ExpiryWarnDays int
	ExpiryBadDays  int
	// Now is the clock for expiry arithmetic.
	Now time.Time
}

// DefaultOptions are the thresholds used when a caller passes none.
func DefaultOptions() Options {
	return Options{ExpiryWarnDays: 21, ExpiryBadDays: 7, Now: time.Now()}
}

// Report is everything pqprobe concluded about one endpoint.
type Report struct {
	Target  string            `json:"target"`
	Class   Class             `json:"class"`
	Results []probe.Result    `json:"results"`
	Finding []finding.Finding `json:"findings"`
}

// Worst is the highest severity in the report.
func (r Report) Worst() finding.Status { return finding.Worst(r.Finding) }

// Describe is the one-line meaning of a class.
func Describe(c Class) string {
	switch c {
	case PQReady:
		return "post-quantum key exchange works, including for a client that requires it"
	case PQCapable:
		return "hybrid ML-KEM is negotiated when offered, but a post-quantum-only client did not connect"
	case PQBlind:
		return "no post-quantum support, but post-quantum-capable clients still connect on a classical group"
	case PQIntolerant:
		return "post-quantum-capable clients cannot connect at all, while classical clients can"
	case PQRefusing:
		return "post-quantum-capable clients are refused with an alert, while classical clients connect"
	case NoTLS13:
		return "TLS 1.2 is the ceiling, so post-quantum key exchange is not reachable here"
	case Unreachable:
		return "nothing answered; no TLS conclusion available"
	case TLSBroken:
		return "the port answered but no client profile completed a handshake"
	}
	return string(c)
}

// Evaluate grades one endpoint. results may hold any subset of the profiles;
// a conclusion that needs a profile which was not dialled is simply not made.
func Evaluate(target string, results []probe.Result, opt Options) Report {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	rep := Report{Target: target, Results: results}
	by := map[string]probe.Result{}
	for _, r := range results {
		by[r.Profile] = r
	}

	// Every handshake attempt is a finding of its own: the class is a summary,
	// and a summary that cannot be traced back to the attempt behind it is not
	// evidence.
	for _, r := range results {
		rep.Finding = append(rep.Finding, handshakeFinding(target, r))
	}

	classic, haveClassic := by["classic"]
	pref, havePref := by["pq-preferred"]
	only, haveOnly := by["pq-only"]

	// No baseline, nothing reachable: say so and stop. Grading post-quantum
	// support on an endpoint that never answered is how a monitoring system
	// starts lying.
	if !anyOK(results) {
		rep.Class = TLSBroken
		if allKinds(results, probe.KindDNS, probe.KindRefused) {
			rep.Class = Unreachable
		}
		rep.Finding = append(rep.Finding, finding.Finding{
			Check:   "verdict",
			Target:  target,
			Status:  finding.ERROR,
			Message: Describe(rep.Class),
			Hint:    "fix reachability first — no statement about post-quantum readiness can be made from a probe that never completed a handshake",
		})
		finding.SortWorstFirst(rep.Finding)
		return rep
	}

	switch {
	case haveClassic && classic.OK && classic.Version == "TLS 1.2":
		// A 1.2-only endpoint cannot do hybrid key exchange at all, whatever
		// the group list says: ML-KEM lives in the TLS 1.3 key_share.
		rep.Class = NoTLS13
		rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class,
			"post-quantum key exchange requires TLS 1.3; enable it before anything else here"))
	case havePref && !pref.OK && haveClassic && classic.OK:
		if pref.Kind.Abrupt() {
			rep.Class = PQIntolerant
			rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class, fmt.Sprintf(
				"the classical client connected and the post-quantum-capable one was cut off (%s): every client that merely *offers* ML-KEM fails here — Chrome and Edge 131+, Firefox 132+, a CDN with post-quantum enabled — while curl and your existing health checks keep passing",
				pref.Kind)))
		} else {
			rep.Class = PQRefusing
			rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class,
				"the peer parsed a ClientHello that also offered X25519 and P-256 and still refused: look for a pinned group list or a TLS policy, not for a size problem"))
		}
	case havePref && pref.OK && pref.PQ:
		if haveOnly && only.OK {
			rep.Class = PQReady
			rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class,
				"nothing to do; re-run after any TLS stack or load balancer change"))
		} else {
			rep.Class = PQCapable
			hint := "hybrid ML-KEM works when offered alongside classical groups"
			if haveOnly {
				hint += fmt.Sprintf("; the post-quantum-only profile ended in %s (%s)", only.Kind, only.Err)
			} else {
				hint += "; dial --profile pq-only to find out whether a client that requires it can connect"
			}
			rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class, hint))
		}
	case havePref && pref.OK && !pref.PQ:
		rep.Class = PQBlind
		hint := "the endpoint fell back to " + orUnknown(pref.Group) +
			", so post-quantum-capable clients work today. It stops working the day a client requires ML-KEM, or the day something on the path stops tolerating the larger ClientHello"
		if haveOnly && only.OK {
			// Contradiction worth surfacing rather than resolving silently.
			hint += ". Note the post-quantum-only profile *did* connect — re-run, the two results disagree"
		}
		rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class, hint))
	case haveOnly && only.OK:
		rep.Class = PQReady
		rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class,
			"graded from the post-quantum-only profile alone; dial the classical profile too for a baseline"))
	default:
		rep.Class = PQBlind
		rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class,
			"no post-quantum profile was dialled — this is a classical-only result"))
	}

	// TLS 1.3 availability, when both edges were dialled: an endpoint that
	// answers 1.2 but not 1.3 is one where post-quantum is unreachable, and it
	// is worth saying even when the class is about something else.
	if v13, ok := by["tls13-only"]; ok {
		if v12, ok12 := by["tls12"]; ok12 && !v13.OK && v12.OK {
			rep.Finding = append(rep.Finding, finding.Finding{
				Check:   "tls-version",
				Target:  target,
				Status:  finding.WARN,
				Message: "TLS 1.3 did not complete while TLS 1.2 did",
				Hint:    "post-quantum key exchange is a TLS 1.3 feature: until 1.3 works, pq readiness is out of reach",
			})
		}
	}

	rep.Finding = append(rep.Finding, chainFindings(target, results, opt)...)
	finding.SortWorstFirst(rep.Finding)
	return rep
}

// handshakeFinding states one attempt. A refused post-quantum handshake is a
// WARN on its own, never a BAD: whether it matters is the class's job to say,
// and a per-profile BAD would double-count the same fact.
func handshakeFinding(target string, r probe.Result) finding.Finding {
	f := finding.Finding{
		Check:  "handshake",
		Target: target + "/" + r.Profile,
	}
	if r.OK {
		f.Status = finding.OK
		f.Message = fmt.Sprintf("%s, %s, %s", r.Version, orUnknown(r.Group), r.Cipher)
		if r.ALPN != "" {
			f.Message += ", alpn " + r.ALPN
		}
		f.Value = finding.Num(float64(r.Elapsed.Milliseconds()))
		f.Unit = "ms"
		return f
	}
	f.Status = finding.WARN
	f.Message = fmt.Sprintf("no handshake (%s): %s", r.Kind, r.Err)
	if r.Kind.Abrupt() {
		f.Hint = "an abrupt end means the peer never sent a TLS alert: it choked on the ClientHello rather than declining it"
	}
	return f
}

func verdictFinding(target string, c Class, hint string) finding.Finding {
	st := finding.OK
	switch c {
	case PQBlind, PQCapable, NoTLS13:
		st = finding.WARN
	case PQIntolerant, PQRefusing:
		st = finding.BAD
	}
	return finding.Finding{
		Check:   "verdict",
		Target:  target,
		Status:  st,
		Message: string(c) + " — " + Describe(c),
		Hint:    hint,
	}
}

// chainFindings grade the certificate, from the first successful handshake
// that carried a chain. They are separate from the capability verdict on
// purpose: an expiring certificate and a post-quantum problem are different
// work for different people.
func chainFindings(target string, results []probe.Result, opt Options) []finding.Finding {
	var src *probe.Result
	for i := range results {
		if results[i].OK && len(results[i].Chain) > 0 {
			src = &results[i]
			break
		}
	}
	if src == nil {
		return nil
	}
	var out []finding.Finding
	leaf := src.Chain[0]
	days := leaf.NotAfter.Sub(opt.Now).Hours() / 24
	st := finding.OK
	switch {
	case days <= float64(opt.ExpiryBadDays):
		st = finding.BAD
	case days <= float64(opt.ExpiryWarnDays):
		st = finding.WARN
	}
	msg := fmt.Sprintf("leaf expires %s (%.0f days)", leaf.NotAfter.UTC().Format("2006-01-02"), days)
	if days < 0 {
		msg = fmt.Sprintf("leaf expired %s (%.0f days ago)", leaf.NotAfter.UTC().Format("2006-01-02"), -days)
	}
	out = append(out, finding.Finding{
		Check: "expiry", Target: target, Status: st, Message: msg,
		Value: finding.Num(days), Unit: "days",
	})

	if !src.ChainVerified {
		out = append(out, finding.Finding{
			Check: "chain", Target: target, Status: finding.WARN,
			Message: "chain does not verify against the system roots: " + src.ChainError,
			Hint:    "expected when probing an origin by IP or behind a private CA; a real finding when this is the public endpoint",
		})
	}
	if src.PeerChainLen == 1 && !leaf.IsCA {
		out = append(out, finding.Finding{
			Check: "chain", Target: target, Status: finding.WARN,
			Message: "the peer sent the leaf certificate alone, with no intermediate",
			Value:   finding.Num(1), Unit: "certs",
			Hint: "browsers that cached the intermediate will not notice and a fresh client will fail — the most confusing class of TLS bug there is",
		})
	}
	return out
}

func anyOK(rs []probe.Result) bool {
	for _, r := range rs {
		if r.OK {
			return true
		}
	}
	return false
}

func allKinds(rs []probe.Result, kinds ...probe.Kind) bool {
	if len(rs) == 0 {
		return false
	}
	for _, r := range rs {
		match := false
		for _, k := range kinds {
			if r.Kind == k {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func orUnknown(s string) string {
	if s == "" {
		return "group unknown"
	}
	return s
}
