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
	// MTLSRequired: the peer asked for a client certificate and no handshake
	// survived it. pqprobe has no certificate to offer and never will, so
	// nothing about post-quantum capability can be concluded — the endpoint
	// refused the prober, not post-quantum clients.
	MTLSRequired Class = "mtls-required"
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
	case MTLSRequired:
		return "the peer requires a client certificate, so no capability conclusion is available"
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

	// The per-group pass (PQ-22) is held apart from the classification. A
	// single-group ClientHello answers "does the peer accept this group", which
	// is not the question the class answers — no realistic client dials that
	// way, and grading on it would call a peer intolerant for declining P-521.
	var client, groups []probe.Result
	for _, r := range results {
		if clientprofile.IsGroupProbe(r.Profile) {
			groups = append(groups, r)
			continue
		}
		client = append(client, r)
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
	if f, ok := clientAuthFinding(target, client); ok {
		rep.Finding = append(rep.Finding, f)
	}

	classic, haveClassic := by["classic"]
	pref, havePref := by["pq-preferred"]
	only, haveOnly := by["pq-only"]

	// No baseline, nothing reachable: say so and stop. Grading post-quantum
	// support on an endpoint that never answered is how a monitoring system
	// starts lying.
	if !anyOK(client) {
		rep.Class = TLSBroken
		if anyClientCertRequested(client) {
			// The peer asked for something pqprobe does not have. Grading
			// post-quantum support on that would be a fabrication.
			rep.Class = MTLSRequired
		}
		if allKinds(client, probe.KindDNS, probe.KindRefused, probe.KindUnroutable) {
			rep.Class = Unreachable
		}
		hint := "fix reachability first — no statement about post-quantum readiness can be made from a probe that never completed a handshake"
		if allKinds(client, probe.KindUnroutable) {
			// The prober's own connectivity, not the endpoint's: usually an AAAA
			// record reached from a host with no IPv6 egress.
			hint = "this host has no route to that address, so nothing here is a statement about the endpoint — an IPv6 address probed from a machine without IPv6 egress is the usual cause. Fix the route, or probe the addresses you can actually reach"
		}
		if rep.Class == MTLSRequired {
			// A different failure and a different next step: the endpoint is
			// working, it just will not talk to a client without a certificate.
			hint = "the peer requested a client certificate and pqprobe has none — it holds no key material by design. Probe this leg from somewhere that has a certificate, or probe the front door instead; nothing here says anything about post-quantum support"
		}
		rep.Finding = append(rep.Finding, finding.Finding{
			Check:   "verdict",
			Target:  target,
			Status:  finding.ERROR,
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
	case PQIntolerant, PQRefusing:
		return finding.BAD
	case Unreachable, TLSBroken, MTLSRequired:
		return finding.ERROR
	}
	return finding.OK
}

func verdictFinding(target string, c Class, hint string) finding.Finding {
	st := StatusOf(c)
	if c == Unreachable || c == TLSBroken || c == MTLSRequired {
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
