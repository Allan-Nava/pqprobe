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
	"sort"
	"strings"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
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
	// NoTLS: the plaintext upgrade never reached TLS — the peer does not offer
	// STARTTLS, or refused it. Not a grade: it refused TLS, not post-quantum
	// clients, and a relay with TLS switched off filed as pq-intolerant would
	// send somebody looking for a middlebox that does not exist.
	NoTLS Class = "no-tls"
	// MTLSRequired: the peer asked for a client certificate and no handshake
	// survived it. pqprobe has no certificate to offer and never will, so
	// nothing about post-quantum capability can be concluded — the endpoint
	// refused the prober, not post-quantum clients.
	MTLSRequired Class = "mtls-required"
	// TLSBroken: something answered and no profile completed a handshake.
	TLSBroken Class = "tls-broken"
	// PQOtherHybrid: no ordinary client profile completed a handshake, and a
	// single-group probe shows the peer doing hybrid ML-KEM in a group no
	// browser sends — SecP256r1MLKEM768 or SecP384r1MLKEM1024, which is what a
	// FIPS-shaped stack has. It is post-quantum and unreachable for real
	// clients at the same time, and calling it `tls-broken` said the port was
	// faulty when it is merely configured for somebody else (PQ-60).
	PQOtherHybrid Class = "pq-other-hybrid"
)

// Classes is every class, in the order a reader should meet them: the good news
// first, then the two that are somebody's outage, then the ceilings, then the
// three that are not grades at all.
func Classes() []Class {
	return []Class{
		PQReady, PQCapable, PQBlind, PQIntolerant, PQRefusing,
		NoTLS13, NoTLS, MTLSRequired, Unreachable, TLSBroken, PQOtherHybrid,
	}
}

// Explanation is a class, out of context: what it means, who it affects and
// what to do about it (PQ-28).
//
// The hints inside a report are written for the endpoint in front of you. This
// is the same knowledge without a run, because at 03:00 the alternative is
// reproducing the failure to find out what the word meant.
type Explanation struct {
	Class    Class          `json:"class"`
	Status   finding.Status `json:"status"`
	Meaning  string         `json:"meaning"`
	Affected string         `json:"affected,omitempty"`
	Action   string         `json:"action"`
}

// Topics is the vocabulary `explain` answers for that is *not* a class (PQ-52).
//
// ECH is the reason it exists: it is reported and deliberately never graded, so
// it has no class to look up — and a finding nobody can look up is a finding
// nobody acts on. A topic is a word that appears in a report; nothing in the
// grading reads this list.
func Topics() []string { return []string{"ech", "ech-reject"} }

// ExplainTopic answers for a topic. The Class field carries the topic's name so
// one renderer serves both — a topic has no status, and an empty one is what
// says so.
func ExplainTopic(name string) (Explanation, bool) {
	e := Explanation{Class: Class(name)}
	switch name {
	case "ech":
		e.Meaning = "Encrypted Client Hello: the client encrypts the real server name to a public key the endpoint publishes in DNS, so only the public name travels in the clear. pqprobe dials it as a pair — the same client with and without — and reports whether the peer accepted it and what it cost in bytes"
		e.Affected = "nobody, in the sense of a client class: no real client requires ECH, and one that offers it falls back where a config is not published. It is reported and never graded"
		e.Action = "read it as a size number first. ECH adds a few hundred bytes to a hybrid ClientHello already near the 1500-byte MTU, so the case worth acting on is the one where the control connects and the ECH twin is cut off — that is a threshold on the path, not an ECH policy, and --size-sweep finds where it sits"
	case "ech-reject":
		e.Meaning = "the peer declined Encrypted Client Hello and answered with a retry config. It parsed the hello and said no: a negotiation, which is why it is never counted as the peer cutting us off"
		e.Affected = "nobody. Most endpoints are in this state, and a browser that offers ECH connects to them perfectly well"
		e.Action = "check the config is the one this endpoint publishes — `--ech` takes it from the endpoint's own HTTPS record, and a config from somewhere else says nothing about it. Note that when a peer declines ECH, Go verifies its certificate against the config's public name, so an endpoint behind a private CA arrives here with a certificate error rather than a clean rejection"
	default:
		return Explanation{}, false
	}
	return e, true
}

// Explain returns the explanation for a class.
func Explain(c Class) (Explanation, bool) {
	e := Explanation{Class: c, Status: StatusOf(c), Meaning: Describe(c)}
	switch c {
	case PQReady:
		e.Affected = "nobody: a client that offers hybrid ML-KEM, one that requires it, and one that has never heard of it all connect"
		e.Action = "nothing. Re-run after a change to the TLS stack, the load balancer or the CDN in front of it — this is a property of the path, and paths change without anybody touching the origin"
	case PQCapable:
		e.Affected = "a client configured to *require* post-quantum key exchange, which is rare today and is where the defaults are going"
		e.Action = "find out why the post-quantum-only handshake did not complete: usually a TLS 1.3 restriction rather than a group policy. Everything in use today works"
	case PQBlind:
		e.Affected = "nobody today. Tomorrow: any client that requires post-quantum key exchange, and Chrome, Edge and Firefox already offer it by default"
		e.Action = "plan the ML-KEM rollout on this endpoint. It works now because capable clients fall back to X25519, and it stops working the day one of them stops offering the fallback — or the day something on the path stops tolerating the larger hello"
	case PQIntolerant:
		e.Affected = "every client that merely *offers* ML-KEM: Chrome and Edge 131+, Firefox 132+, Go 1.24+, OpenSSL 3.5+, and any CDN with post-quantum enabled. curl and your existing health checks keep passing"
		e.Action = "look at what the ClientHello has to cross, not at the TLS configuration: an old TLS library, a middlebox that reads the hello, a load balancer with its own parser, anything that assumes a handshake fits one packet. Run --size-sweep to get the byte size to quote, and --per-address in case it is one node of a pool"
	case PQRefusing:
		e.Affected = "the same clients as pq-intolerant, but here the peer answered: Chrome, Edge, Firefox and post-quantum-enabled CDNs are declined rather than dropped"
		e.Action = "look at the configuration, not at the path: a pinned group list, a TLS policy, a FIPS mode, an accelerator with a fixed algorithm set. The peer parsed a hello that also offered X25519 and P-256 and still said no"
	case NoTLS13:
		e.Affected = "any client that requires TLS 1.3, and every post-quantum client — the key exchange lives in the 1.3 key_share extension"
		e.Action = "enable TLS 1.3 before anything else here. This is a ceiling, not a setting: no group list can get post-quantum key exchange onto a 1.2 handshake"
	case NoTLS:
		e.Affected = "not a grade — nothing about post-quantum support can be said, because there was no TLS handshake at all"
		e.Action = "not a grade: the peer would not upgrade to TLS. Either it does not advertise STARTTLS (a relay with TLS switched off, a Postgres without ssl=on), or --starttls named the wrong protocol for that port. Implicit TLS ports need no --starttls at all"
	case MTLSRequired:
		e.Affected = "not a grade — the endpoint refused the prober, not post-quantum clients"
		e.Action = "not a grade: pqprobe holds no key material by design, so probe this leg from somewhere that has a client certificate, or probe the front door instead"
	case Unreachable:
		e.Affected = "not a grade — nothing answered, so nothing is known about any client"
		e.Action = "not a grade: fix reachability first. If this came from --per-address, check the route from this host before blaming the node — an IPv6 address probed without IPv6 egress fails exactly like this"
	case TLSBroken:
		e.Affected = "not a grade — the port answered and no client shape completed a handshake, so no capability conclusion is available"
		e.Action = "not a grade: something is listening and it is not serving TLS the way any of these clients speak it. Look at the port and the terminator before reading anything about post-quantum support. Run --per-group before concluding anything: a peer that speaks only a P-curve hybrid looks exactly like this and is not broken at all"
	case PQOtherHybrid:
		e.Affected = "every ordinary client: browsers send X25519MLKEM768, and the classical shapes were refused too. Only a client configured for this endpoint's hybrid group reaches it"
		e.Action = "this is a group policy, not a fault. The peer does hybrid ML-KEM in a group no browser sends — SecP256r1MLKEM768 or SecP384r1MLKEM1024, which is what a FIPS-shaped stack has. Either add X25519MLKEM768 to the endpoint, or accept that only clients you configure will reach it; the `groups` finding says exactly which one it took"
	default:
		return Explanation{}, false
	}
	return e, true
}

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
	case NoTLS:
		return "the plaintext upgrade to TLS was refused, so there was no handshake to grade"
	case MTLSRequired:
		return "the peer requires a client certificate, so no capability conclusion is available"
	case TLSBroken:
		return "the port answered but no client profile completed a handshake"
	case PQOtherHybrid:
		return "post-quantum key exchange works here, but only in a hybrid group no browser sends"
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

	// The per-group pass (PQ-22) is held apart from the classification. A
	// single-group ClientHello answers "does the peer accept this group", which
	// is not the question the class answers — no realistic client dials that
	// way, and grading on it would call a peer intolerant for declining P-521.
	var client, groups, sizes, ech []probe.Result
	var alpnPair *probe.Result
	for i, r := range results {
		switch {
		case clientprofile.IsGroupProbe(r.Profile):
			groups = append(groups, r)
		case clientprofile.IsSizeProbe(r.Profile):
			sizes = append(sizes, r)
		case clientprofile.IsALPNProbe(r.Profile):
			alpnPair = &results[i]
		case clientprofile.IsECHProbe(r.Profile):
			ech = append(ech, r)
		default:
			client = append(client, r)
		}
	}

	by := map[string]probe.Result{}
	for _, r := range client {
		by[r.Profile] = r
	}

	// Every handshake attempt is a finding of its own: the class is a summary,
	// and a summary that cannot be traced back to the attempt behind it is not
	// evidence. The group probes are the exception — five more handshake
	// findings per endpoint would bury the three that carry the answer, so they
	// arrive as one map instead.
	for _, r := range client {
		rep.Finding = append(rep.Finding, handshakeFinding(target, r))
	}
	if f, ok := groupsFinding(target, groups); ok {
		rep.Finding = append(rep.Finding, f)
	}
	// Said wherever the probes saw it, not only where it changes the class: an
	// endpoint whose browsers fall back to a classical handshake is graded
	// pq-blind correctly, and "there is no post-quantum here" would still be the
	// wrong thing to read into it (PQ-60).
	if g, ok := otherHybrid(groups); ok && anyOK(client) {
		rep.Finding = append(rep.Finding, hybridFinding(target, g, true))
	}
	if f, ok := clientAuthFinding(target, client); ok {
		rep.Finding = append(rep.Finding, f)
	}
	if f, ok := sizeFinding(target, sizes); ok {
		rep.Finding = append(rep.Finding, f)
	}

	if f, ok := echFinding(target, ech); ok {
		rep.Finding = append(rep.Finding, f)
	}

	if alpnPair != nil {
		if bare, ok := by["pq-preferred"]; ok {
			if f, ok := alpnFinding(target, bare, *alpnPair); ok {
				rep.Finding = append(rep.Finding, f)
			}
		}
	}

	classic, haveClassic := by["classic"]
	pref, havePref := by["pq-preferred"]
	only, haveOnly := by["pq-only"]

	// No baseline, nothing reachable: say so and stop. Grading post-quantum
	// support on an endpoint that never answered is how a monitoring system
	// starts lying.
	if !anyOK(client) {
		rep.Class = TLSBroken
		if allKinds(client, probe.KindStartTLS) {
			// The peer refused TLS itself. Saying anything about post-quantum
			// clients from that would be a fabrication.
			rep.Class = NoTLS
		}
		if anyClientCertRequested(client) {
			// The peer asked for something pqprobe does not have. Grading
			// post-quantum support on that would be a fabrication.
			rep.Class = MTLSRequired
		}
		if allKinds(client, probe.KindDNS, probe.KindRefused, probe.KindUnroutable) {
			rep.Class = Unreachable
		}
		// The single-group probes are the one thing allowed to move this class,
		// and only in this direction: they are evidence that the peer is not
		// broken. They may never *create* a grade — no real client dials one
		// group at a time, and grading on that would call a peer intolerant for
		// declining P-521 (PQ-22, PQ-60).
		if rep.Class == TLSBroken {
			if g, ok := otherHybrid(groups); ok {
				rep.Class = PQOtherHybrid
				rep.Finding = append(rep.Finding, hybridFinding(target, g, false))
			}
		}
		hint := "fix reachability first — no statement about post-quantum readiness can be made from a probe that never completed a handshake"
		if rep.Class == TLSBroken && len(groups) == 0 {
			// The one run that can tell "faulty" from "configured for somebody
			// else" apart, and it costs nothing to name it here (PQ-60).
			hint += ". Before concluding it is broken, run --per-group: a peer that speaks only a P-curve hybrid — what a FIPS-shaped stack has — looks exactly like this"
		}
		if rep.Class == PQOtherHybrid {
			hint = "not a fault: the peer negotiates hybrid ML-KEM in a group no browser sends, so every ordinary client is refused while post-quantum key exchange works. See the `hybrid` finding for the group it took"
		}
		if allKinds(client, probe.KindUnroutable) {
			// The prober's own connectivity, not the endpoint's: usually an AAAA
			// record reached from a host with no IPv6 egress.
			hint = "this host has no route to that address, so nothing here is a statement about the endpoint — an IPv6 address probed from a machine without IPv6 egress is the usual cause. Fix the route, or probe the addresses you can actually reach"
		}
		if rep.Class == NoTLS {
			hint = "the plaintext upgrade to TLS was refused, so there was no handshake to grade: either the peer does not advertise STARTTLS — a relay with TLS off, a Postgres without ssl=on — or --starttls named the wrong protocol for this port. Nothing here is a statement about post-quantum support"
		}
		if rep.Class == MTLSRequired {
			// A different failure and a different next step: the endpoint is
			// working, it just will not talk to a client without a certificate.
			hint = "the peer requested a client certificate and pqprobe has none — it holds no key material by design. Probe this leg from somewhere that has a certificate, or probe the front door instead; nothing here says anything about post-quantum support"
		}
		// ERROR is what this branch means — nothing was concluded — with one
		// exception it now has: pq-other-hybrid *is* a conclusion, and grading
		// it ERROR would put a working endpoint in the bucket for the ones that
		// never answered (PQ-60).
		status := finding.ERROR
		if rep.Class == PQOtherHybrid {
			status = StatusOf(rep.Class)
		}
		rep.Finding = append(rep.Finding, finding.Finding{
			Check:   "verdict",
			Target:  target,
			Status:  status,
			Message: Describe(rep.Class),
			Hint:    hint,
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
			// Say it reproduced only when it did. A clause that is always there
			// stops being read, and this one is the difference between a finding
			// a vendor accepts and one they ask you to re-run.
			confirmed := ""
			if pref.Reproduced {
				confirmed = ", reproduced on a second dial"
			}
			rep.Finding = append(rep.Finding, verdictFinding(target, rep.Class, fmt.Sprintf(
				"the classical client connected and the post-quantum-capable one was cut off (%s%s): every client that merely *offers* ML-KEM fails here — Chrome and Edge 131+, Firefox 132+, a CDN with post-quantum enabled — while curl and your existing health checks keep passing",
				pref.Kind, confirmed)))
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

	rep.Finding = append(rep.Finding, chainFindings(target, client, opt)...)
	finding.SortWorstFirst(rep.Finding)
	return rep
}

// Transitions compares a run against a baseline and reports what *changed*
// (PQ-24).
//
// The transition is the news. An endpoint that was already intolerant yesterday
// is not news, and putting it at the top of the output every morning is how a
// daily check becomes a daily thing people close. So an unchanged endpoint
// produces nothing at all, a regression is graded by the class it fell to, an
// improvement is stated quietly, and an endpoint that appeared or vanished is
// mentioned because both are usually somebody editing an inventory.
func Transitions(baseline, current []Report) []finding.Finding {
	was := make(map[string]Class, len(baseline))
	for _, r := range baseline {
		was[r.Target] = r.Class
	}
	seen := make(map[string]bool, len(current))

	var out []finding.Finding
	for _, r := range current {
		seen[r.Target] = true
		before, known := was[r.Target]
		if !known {
			out = append(out, finding.Finding{
				Check:   "transition",
				Target:  r.Target,
				Status:  finding.OK,
				Message: fmt.Sprintf("new since the baseline: %s", r.Class),
				Hint:    "the baseline had never seen this endpoint — expected after an inventory change, worth a look otherwise",
			})
			continue
		}
		if before == r.Class {
			continue
		}

		st := StatusOf(r.Class)
		hint := "this endpoint changed class since the baseline: whatever changed on the path or in the TLS configuration did it, and the time between the two runs is the window to look in"
		if !finding.AtLeast(StatusOf(r.Class), StatusOf(before)) {
			// It got better. Still a transition — somebody should know a fix
			// landed — but not something to page about.
			st = finding.OK
			hint = "this endpoint improved since the baseline: if nobody meant to change it, find out who did"
		}
		out = append(out, finding.Finding{
			Check:   "transition",
			Target:  r.Target,
			Status:  st,
			Message: fmt.Sprintf("%s → %s", before, r.Class),
			Hint:    hint,
		})
	}

	for _, r := range baseline {
		if seen[r.Target] {
			continue
		}
		out = append(out, finding.Finding{
			Check:  "transition",
			Target: r.Target,
			Status: finding.WARN,
			// Named, because this finding has no report of its own: it is filed
			// under another endpoint, where an unqualified sentence would read
			// as a statement about that one.
			Message: fmt.Sprintf("%s was %s in the baseline and is not in this run", r.Target, r.Class),
			Hint:    "an endpoint that disappeared is usually an inventory edit, and occasionally a target somebody deleted by accident",
		})
	}

	finding.SortWorstFirst(out)
	return out
}

// AddressConsistency compares the reports for the addresses behind one name
// (PQ-12) and returns the finding, the index of the report it belongs next to,
// and whether there is anything to say.
//
// One bad node out of six is the failure that survives a manual check: probe
// the name and the resolver hands over whichever address it likes, so the
// broken stack stays invisible. The finding is attached to the report of the
// address that differs, because that is where somebody reading the output is
// already looking.
//
// A single address gets nothing: a consistency finding on every single-homed
// endpoint in a fleet is noise, and noise is what teaches people to skim.
func AddressConsistency(name string, reps []Report) (finding.Finding, int, bool) {
	if len(reps) < 2 {
		return finding.Finding{}, 0, false
	}

	// The worst class in the group decides the severity, and its report is where
	// the finding goes. finding.Worst orders ERROR above BAD deliberately.
	worst := 0
	counts := map[Class]int{}
	for i, r := range reps {
		counts[r.Class]++
		if cur, best := StatusOf(r.Class), StatusOf(reps[worst].Class); cur != best && finding.AtLeast(cur, best) {
			worst = i
		}
	}

	if len(counts) == 1 {
		c := reps[0].Class
		return finding.Finding{
			Check:   "addresses",
			Target:  name,
			Status:  StatusOf(c),
			Message: fmt.Sprintf("%d addresses, all %s", len(reps), c),
			Value:   finding.Num(float64(len(reps))),
			Unit:    "addresses",
			Hint:    "the whole pool answers the same way, which is what probing by address rather than by name is for",
		}, 0, true
	}

	// Name the classes, commonest first, so the message reads as "mostly this,
	// except that one".
	var classes []Class
	for c := range counts {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool {
		if counts[classes[i]] != counts[classes[j]] {
			return counts[classes[i]] > counts[classes[j]]
		}
		return classes[i] < classes[j]
	})
	parts := make([]string, 0, len(classes))
	for _, c := range classes {
		parts = append(parts, fmt.Sprintf("%d %s", counts[c], c))
	}

	odd := addressOf(reps[worst].Target)
	hint := "one node in the pool answers differently from the others: take it out of rotation, then compare its TLS terminator with a healthy one. A name-only probe would have hit whichever address the resolver felt like handing over, and this is the shape of failure that survives a manual check"
	if reps[worst].Class == Unreachable {
		// Draining a node you cannot reach is the wrong advice, and reaching an
		// AAAA record from a host with no IPv6 egress is the common false alarm.
		hint = "before blaming the node: check the route to it from here — an IPv6 address probed from a machine without IPv6 egress fails exactly like this. If the route is fine, then that address is down while the rest of the pool serves"
	}
	return finding.Finding{
		Check:  "addresses",
		Target: name,
		Status: StatusOf(reps[worst].Class),
		Message: fmt.Sprintf("%d addresses disagree: %s — worst is %s (%s)",
			len(reps), strings.Join(parts, ", "), odd, reps[worst].Class),
		Value: finding.Num(float64(len(reps))),
		Unit:  "addresses",
		Hint:  hint,
	}, worst, true
}

// addressOf is the dial address out of a report target, without the SNI note.
func addressOf(target string) string {
	if i := strings.Index(target, " ("); i > 0 {
		return target[:i]
	}
	return target
}

// echFinding reports what Encrypted Client Hello costs here and whether the
// peer took it (PQ-50).
//
// It is never a grade. No real client requires ECH — a browser offers it where
// DNS advertises a config and connects perfectly well where it does not — so an
// endpoint that declines has failed no class of client, and moving it to a
// worse bucket would be a claim about capability that is not true. What the
// pair *can* say is a size sentence: ECH adds a few hundred bytes to a hybrid
// hello already near the MTU, and a peer that takes the control and drops the
// ECH twin has a threshold sitting between the two.
func echFinding(target string, results []probe.Result) (finding.Finding, bool) {
	var off, on *probe.Result
	for i, r := range results {
		switch r.Profile {
		case clientprofile.ECHPrefix + "off":
			off = &results[i]
		case clientprofile.ECHPrefix + "on":
			on = &results[i]
		}
	}
	if off == nil || on == nil {
		return finding.Finding{}, false
	}

	sizes := ""
	if off.HelloBytes > 0 && on.HelloBytes > 0 {
		sizes = fmt.Sprintf(" (%d B against %d B)", off.HelloBytes, on.HelloBytes)
	}

	switch {
	case on.OK && on.ECHAccepted:
		if off.HelloBytes == 0 || on.HelloBytes == 0 {
			// Acceptance is still true and still worth saying; the cost is not,
			// because half the pair never went out and the "difference" would
			// be the whole hello.
			return finding.Finding{
				Check:   "ech",
				Target:  target,
				Status:  finding.OK,
				Message: "Encrypted Client Hello accepted; what it costs was not measured, because the control hello never went out",
				Hint:    "the pair is what makes the byte count mean anything, and one half of it did not reach the wire. Re-run to get the number",
			}, true
		}
		diff := on.HelloBytes - off.HelloBytes
		return finding.Finding{
			Check:   "ech",
			Target:  target,
			Status:  finding.OK,
			Message: fmt.Sprintf("Encrypted Client Hello accepted, %d bytes larger than the same hello without it%s", diff, sizes),
			Value:   finding.Num(float64(diff)),
			Unit:    "bytes",
			Hint:    "the server name is no longer in the clear for clients that offer ECH, and this is what it costs on the wire — the number to watch as the hybrid key share and the certificate chain grow into the same 1500-byte budget",
		}, true

	case off.OK && !on.OK && on.Kind.Abrupt():
		diff := on.HelloBytes - off.HelloBytes
		f := finding.Finding{
			Check:   "ech",
			Target:  target,
			Status:  finding.WARN,
			Message: fmt.Sprintf("the same client connects without ECH and is cut off with it%s", sizes),
			Unit:    "bytes",
			Hint:    "that is a size threshold, not an ECH policy: the peer answered the smaller hello and never answered the larger one. Chrome and Firefox send ECH wherever DNS advertises a config, so this breaks real browsers while a bare probe keeps saying the endpoint is fine — run --size-sweep to find where the MTU or the middlebox draws the line",
		}
		if diff > 0 {
			f.Value = finding.Num(float64(diff))
		}
		return f, true

	case !on.OK:
		// Declined, which is most endpoints today: the peer parsed the hello
		// and said it holds no key for that config. An answer, not a fault.
		return finding.Finding{
			Check:   "ech",
			Target:  target,
			Status:  finding.OK,
			Message: fmt.Sprintf("Encrypted Client Hello was declined by the peer (%s)", on.Kind),
			Hint:    "nothing is wrong: no client requires ECH, and one that offers it falls back. The config offered here has to be the one this endpoint publishes in DNS, or a rejection says nothing about the endpoint at all",
		}, true

	case on.OK && !on.ECHAccepted:
		return finding.Finding{
			Check:   "ech",
			Target:  target,
			Status:  finding.OK,
			Message: fmt.Sprintf("the handshake completed but Encrypted Client Hello was not accepted%s", sizes),
			Hint:    "the peer ignored the extension rather than refusing it, so the server name still travelled in the clear — read from the connection state, because a completed handshake is not acceptance",
		}, true
	}
	return finding.Finding{}, false
}

// alpnFinding compares the same client with and without an ALPN list (PQ-25).
//
// ALPN is a couple of dozen bytes in the same ClientHello — nothing, unless the
// peer has a threshold in between. Then the endpoint takes the hybrid hello
// bare and drops it with ALPN, every browser and CDN fails while a bare probe
// says the endpoint is fine, and without the pair the two results look like a
// flap. The measured sizes are in the message because the smallness of the
// difference is the point.
func alpnFinding(target string, bare, withALPN probe.Result) (finding.Finding, bool) {
	sizes := ""
	if bare.HelloBytes > 0 && withALPN.HelloBytes > 0 {
		sizes = fmt.Sprintf(" (%d B against %d B)", bare.HelloBytes, withALPN.HelloBytes)
	}

	switch {
	case bare.OK && !withALPN.OK:
		// Only when both hellos were measured: a dial that failed before
		// writing one gives a negative "difference", and a report that says
		// "-1519 bytes of ALPN" is worse than one that says nothing.
		if withALPN.HelloBytes == 0 || bare.HelloBytes == 0 {
			return finding.Finding{
				Check:   "alpn",
				Target:  target,
				Status:  finding.WARN,
				Message: "the same client connects without ALPN and did not with h2,http/1.1, but its hello never went out",
				Hint:    "nothing was measured on the second dial — no hello left the machine — so this is not the size story it usually is. Re-run: a connection that failed before the handshake is more often a flap than a threshold",
			}, true
		}
		diff := withALPN.HelloBytes - bare.HelloBytes
		return finding.Finding{
			Check:   "alpn",
			Target:  target,
			Status:  finding.BAD,
			Message: fmt.Sprintf("the same client connects without ALPN and is refused with h2,http/1.1%s", sizes),
			Value:   finding.Num(float64(diff)),
			Unit:    "bytes",
			Hint: fmt.Sprintf("%d bytes of ALPN is the difference between working and not, so this peer has a size threshold sitting between the two — every browser and every CDN sends ALPN, and a bare probe like a health check will keep saying the endpoint is fine. Run --size-sweep to find where the threshold is",
				diff),
		}, true

	case !bare.OK && withALPN.OK:
		return finding.Finding{
			Check:   "alpn",
			Target:  target,
			Status:  finding.WARN,
			Message: fmt.Sprintf("the same client is refused without ALPN and connects with h2,http/1.1%s", sizes),
			Hint:    "that is the opposite of a size problem: the peer appears to require an ALPN list, which some terminators do when they route by protocol. Worth knowing before a health check without one is trusted",
		}, true

	case bare.OK && withALPN.OK:
		return finding.Finding{
			Check:   "alpn",
			Target:  target,
			Status:  finding.OK,
			Message: fmt.Sprintf("ALPN makes no difference%s", sizes),
			Hint:    "the answer does not depend on whether the client offers a protocol list, which is one fewer thing between a health check and a browser",
		}, true
	}

	// Both failed: the verdict already says what happened, and a second sentence
	// about ALPN would be a claim nobody measured.
	return finding.Finding{}, false
}

// sizeFinding brackets the ClientHello size at which the peer stopped
// answering (PQ-11).
//
// The sizes are the ones measured on the wire, never the ones the sweep asked
// for: an operator taking this to a vendor needs the number that was actually
// sent. The class is left alone — a padded hello answers "how big is too big",
// which is not the question the class answers.
func sizeFinding(target string, results []probe.Result) (finding.Finding, bool) {
	if len(results) == 0 {
		return finding.Finding{}, false
	}

	// A result whose hello never left the machine — a dial that failed, an
	// address with no route — carries HelloBytes 0. It is not a small hello
	// that was answered, and it is not a small hello that was refused: it is
	// no evidence either way, and a sweep made only of those proves nothing
	// about size. Grading it would report headroom on a host nothing answered.
	wrote := false
	for _, r := range results {
		if r.HelloBytes > 0 {
			wrote = true
			break
		}
	}
	if !wrote {
		return finding.Finding{}, false
	}

	lastOK, firstBad, unsent := 0, 0, 0
	for _, r := range results {
		if r.OK {
			if r.HelloBytes > lastOK {
				lastOK = r.HelloBytes
			}
			continue
		}
		// A step that failed *before* its hello left the machine measures
		// nothing: 0 is a real byte count here, and reading it as one made a
		// refused connection mid-sweep look like proof there is no wall. Same
		// rule as the `wrote` guard above, applied per step instead of per run.
		if r.HelloBytes == 0 {
			unsent++
			continue
		}
		if firstBad == 0 || r.HelloBytes < firstBad {
			firstBad = r.HelloBytes
		}
	}

	// The honesty clause: the filler is ALPN, because Go offers no padding
	// extension. A peer that inspects ALPN may treat these differently from a
	// hello made large by a key share, and a number quoted without that is a
	// number that will be argued with.
	const how = "the hello was padded with ALPN entries, which is the only field Go lets a client grow — a peer that inspects ALPN may treat that differently from a hello made large by a key share, so quote the number with the method"

	if firstBad == 0 {
		hint := "no size limit found in the swept range; " + how
		status := finding.OK
		if unsent > 0 {
			// Some of the sweep never reached the wire, so "no limit" is a
			// claim about sizes nobody tried.
			status = finding.WARN
			hint = fmt.Sprintf("%d step(s) of the sweep never sent their hello, so the sizes above %d B were not tried at all — re-run before reading this as headroom; ",
				unsent, lastOK) + how
			return finding.Finding{
				Check:   "size-limit",
				Target:  target,
				Status:  status,
				Message: fmt.Sprintf("answered a ClientHello of %d B; %d larger step(s) never sent one", lastOK, unsent),
				Value:   finding.Num(float64(lastOK)),
				Unit:    "bytes",
				Hint:    hint,
			}, true
		}
		return finding.Finding{
			Check:   "size-limit",
			Target:  target,
			Status:  status,
			Message: fmt.Sprintf("answered a ClientHello of %d B, the largest tried", lastOK),
			Value:   finding.Num(float64(lastOK)),
			Unit:    "bytes",
			Hint:    hint,
		}, true
	}

	msg := fmt.Sprintf("answered up to %d B and stopped answering at %d B", lastOK, firstBad)
	if lastOK == 0 {
		msg = fmt.Sprintf("did not answer a ClientHello of %d B, the smallest tried", firstBad)
	}
	return finding.Finding{
		Check:   "size-limit",
		Target:  target,
		Status:  finding.BAD,
		Message: msg,
		Value:   finding.Num(float64(lastOK)),
		Unit:    "bytes",
		Hint: "that is a hello size this peer will not answer, which is an outage for every client whose hello reaches it — a hybrid ML-KEM hello is already around 1.5 KB and a client certificate or a long ALPN list adds more. " + how +
			". Take the two numbers to whoever owns the middlebox or the terminator",
	}, true
}

// chainBytesWarn is where a chain stops having room for post-quantum
// authentication. It is not a limit anybody enforces today: an ML-DSA-65
// signature is roughly 3.3 KB against 64 bytes for ECDSA, and its public key
// about 2 KB, so a two-certificate chain gains something like 8 KB when it
// migrates. A chain already at 8 KB lands past 16 — the largest handshake
// message many stacks will accept, and well past what fits the initial flight
// somebody's middlebox is willing to reassemble.
const chainBytesWarn = 8000

func chainSizeHint(src *probe.Result) string {
	base := "post-quantum authentication is the next migration and it is a size problem again: an ML-DSA signature is around 3.3 KB where an ECDSA one is 64 bytes, so this chain grows by roughly 4 KB per certificate when it moves. This is the headroom you have today"
	if src.ChainBytes >= chainBytesWarn {
		return "this chain is already large, and post-quantum certificates will roughly double it: an ML-DSA signature is around 3.3 KB where an ECDSA one is 64 bytes. " +
			"Shortening the chain — one intermediate rather than two, no unnecessary cross-signs — is the cheap thing to do now, while it is a choice rather than an outage"
	}
	return base
}

// anyClientCertRequested reports whether the peer asked for a client
// certificate on any attempt.
func anyClientCertRequested(rs []probe.Result) bool {
	for _, r := range rs {
		if r.ClientCertRequested {
			return true
		}
	}
	return false
}

// clientAuthFinding says the endpoint is mutual TLS (PQ-26).
//
// It is a fact rather than a problem, so it is an OK finding when the
// handshakes completed: the key exchange is what pqprobe grades, and it
// happened. What it prevents is somebody reading "pq-ready" as "usable", since
// a client without a certificate is rejected right after the handshake that
// pqprobe just called successful — on TLS 1.3 the objection arrives after the
// client is finished, and pqprobe never reads.
func clientAuthFinding(target string, results []probe.Result) (finding.Finding, bool) {
	if !anyClientCertRequested(results) {
		return finding.Finding{}, false
	}

	completed := anyOK(results)
	f := finding.Finding{
		Check:   "client-auth",
		Target:  target,
		Status:  finding.OK,
		Message: "mutual TLS: the peer requested a client certificate",
		Hint:    "the key exchange is what pqprobe grades and it completed, so the class stands. A client with no certificate is still rejected immediately after this handshake — on TLS 1.3 that objection arrives after the client is finished, which is why nothing failed here",
	}
	if !completed {
		f.Status = finding.WARN
		f.Message = "mutual TLS: the peer requested a client certificate and no handshake survived it"
		f.Hint = "pqprobe holds no key material and never will, so this endpoint cannot be graded from outside: probe it from somewhere with a client certificate, or probe the front door instead of the mutual-TLS leg"
	}
	return f, true
}

// otherHybrid returns the hybrid group the peer accepted that browsers do not
// send, if the single-group probes found one (PQ-60).
//
// X25519MLKEM768 is what Chrome and Firefox offer; the other two are the same
// ML-KEM with a NIST curve, which is what a FIPS-shaped stack has. A peer that
// takes one of those is doing post-quantum key exchange — the fact the report
// could not state before, because nothing in the client profiles can see it.
func otherHybrid(groups []probe.Result) (string, bool) {
	for _, r := range groups {
		if !r.OK || !r.PQ {
			continue
		}
		name := strings.TrimPrefix(r.Profile, clientprofile.GroupPrefix)
		if name != "X25519MLKEM768" {
			return name, true
		}
	}
	return "", false
}

// hybridFinding says which hybrid the peer took and who that leaves out.
//
// browsersToo is set when the ordinary profiles connected: there the class is
// already right — a browser gets a classical handshake — and what is missing is
// only that the migration here is a *group policy* rather than switching
// post-quantum on at all.
func hybridFinding(target, group string, browsersToo bool) finding.Finding {
	status := finding.WARN
	msg := fmt.Sprintf("hybrid ML-KEM works here, in %s — a group no browser sends", group)
	hint := fmt.Sprintf("Chrome and Firefox offer X25519MLKEM768 and nothing else post-quantum, so they fall back to a classical handshake with this endpoint. The work here is adding X25519MLKEM768 to the group list, not enabling post-quantum key exchange: it is already on. %s is what a FIPS-shaped stack has", group)
	if !browsersToo {
		msg = fmt.Sprintf("post-quantum key exchange works, but only in %s — a group no browser sends", group)
		hint = fmt.Sprintf("nothing here is broken: the peer negotiates hybrid ML-KEM in %s and refused every shape an ordinary client sends, X25519MLKEM768 included. Either add X25519MLKEM768 to the endpoint, or accept that only clients configured for this group reach it", group)
	}
	return finding.Finding{
		Check:   "hybrid",
		Target:  target,
		Status:  status,
		Message: msg,
		Hint:    hint,
	}
}

// groupsFinding is the per-group capability map: which key exchange groups the
// peer accepted when each was offered alone, and how it refused the others.
//
// The two refusals stay apart here as they do everywhere else. A group declined
// with an alert is a policy — a pinned list, a FIPS mode, an accelerator with a
// fixed algorithm set. A group whose hello was cut off is the failure this tool
// exists for, and on a single-group hello it is also a size signal: the hybrid
// one is 1.2 KB larger than the rest.
func groupsFinding(target string, results []probe.Result) (finding.Finding, bool) {
	if len(results) == 0 {
		return finding.Finding{}, false
	}

	var accepted, byAlert, cutOff []string
	for _, r := range results {
		name := strings.TrimPrefix(r.Profile, clientprofile.GroupPrefix)
		switch {
		case r.OK:
			accepted = append(accepted, name)
		case r.Kind.Abrupt():
			cutOff = append(cutOff, name)
		default:
			byAlert = append(byAlert, name)
		}
	}

	var parts []string
	if len(accepted) > 0 {
		parts = append(parts, "accepted: "+strings.Join(accepted, ", "))
	} else {
		parts = append(parts, "no group was accepted on its own")
	}
	if len(byAlert) > 0 {
		parts = append(parts, "declined with an alert: "+strings.Join(byAlert, ", "))
	}
	if len(cutOff) > 0 {
		parts = append(parts, "cut off: "+strings.Join(cutOff, ", "))
	}

	status := finding.OK
	hint := "one TLS 1.3 handshake per group, in sequence — this is what the peer accepts when a group is the only one offered, which is what a migration has to be planned against"
	if len(accepted) == 0 {
		status = finding.WARN
		hint = "no single-group handshake completed: either TLS 1.3 is not reachable here (see the verdict) or the peer needs a choice of groups to negotiate at all"
	}
	if len(cutOff) > 0 {
		status = finding.WARN
		hint = "a group whose hello was cut off was not declined, it was mishandled — on the hybrid group that is the 1.2 KB ClientHello, and it is the same failure the verdict describes"
	}

	return finding.Finding{
		Check:   "groups",
		Target:  target,
		Status:  status,
		Message: strings.Join(parts, " · "),
		Value:   finding.Num(float64(len(accepted))),
		Unit:    "groups",
		Hint:    hint,
	}, true
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
		if r.HelloBytes > 0 {
			f.Message += fmt.Sprintf(", hello %d B", r.HelloBytes)
		}
		// An HRR is a round trip the peer imposed (PQ-9). Said only when it
		// happened: "no HelloRetryRequest" on every healthy handshake is noise.
		if r.HRR {
			f.Message += " after a hello retry"
			f.Hint = "the peer did not take either key share offered and asked for another group, which costs an extra round trip on every connection. Go sends key shares for the hybrid group and X25519, so this means the only group in common was a third one — usually P-256 or P-384 on an older or policy-restricted stack"
		}
		f.Value = finding.Num(float64(r.Elapsed.Milliseconds()))
		f.Unit = "ms"
		// A handshake that needed a second dial is a third state (PQ-23): the
		// endpoint works and it is unstable. Silence would file it as healthy,
		// and the class would file it as a wall — both are wrong.
		if r.Flapped {
			f.Status = finding.WARN
			f.Message += fmt.Sprintf(" — but only on the second attempt (the first ended %s)", r.FirstKind)
			f.Hint = "this endpoint is flapping, not walled: the same hello was cut off and then accepted a moment later. Look for a node being drained, a load balancer mid-reconfiguration or a stale connection-tracking entry — and re-run before concluding anything"
		}
		return f
	}
	f.Status = finding.WARN
	f.Message = fmt.Sprintf("no handshake (%s): %s", r.Kind, r.Err)
	if r.Reproduced {
		f.Message += " — twice"
	}
	if r.Kind.Abrupt() {
		f.Hint = "an abrupt end means the peer never sent a TLS alert: it choked on the ClientHello rather than declining it"
	}
	return f
}

// StatusOf is the severity a class carries. Exported because a fleet-level
// finding has to agree with the endpoint-level one — two tables would drift,
// and the day they did the wrong one would be the one an alert read.
func StatusOf(c Class) finding.Status {
	switch c {
	case PQBlind, PQCapable, NoTLS13:
		return finding.WARN
	case PQIntolerant, PQRefusing, PQOtherHybrid:
		return finding.BAD
	case Unreachable, TLSBroken, MTLSRequired, NoTLS:
		return finding.ERROR
	}
	return finding.OK
}

func verdictFinding(target string, c Class, hint string) finding.Finding {
	st := StatusOf(c)
	if c == Unreachable || c == TLSBroken || c == MTLSRequired || c == NoTLS {
		// Those are raised by the branch that returns early, with their own
		// wording; keep this function's behaviour unchanged for them.
		st = finding.ERROR
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

	// What the chain costs on the wire (PQ-44). Reported on every run because
	// post-quantum *authentication* is the next migration and it will fail the
	// same way key exchange did — by being too big — so the useful moment to
	// know the headroom is before anybody enables it.
	if src.ChainBytes > 0 {
		st, hint := finding.OK, chainSizeHint(src)
		if src.ChainBytes >= chainBytesWarn {
			st = finding.WARN
		}
		out = append(out, finding.Finding{
			Check: "chain-size", Target: target, Status: st,
			Message: fmt.Sprintf("the peer sent %d certificate(s), %d bytes of chain",
				src.PeerChainLen, src.ChainBytes),
			Value: finding.Num(float64(src.ChainBytes)), Unit: "bytes",
			Hint: hint,
		})
	}

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
