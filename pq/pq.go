// Package pq is the public surface of pqprobe: strings in, reports out (PQ-14).
//
// Everything that does the work lives under internal/, which no other module
// can import — deliberately, so those packages stay free to move. This is the
// contract an embedder gets instead: target strings, a few options, and reports
// carrying the class and the findings with their values. Nothing internal
// leaks through it, and nothing here parses prose.
//
// It exists because a fleet already described in somebody's inventory should
// gain this check without a second inventory and without a second copy of the
// alert-versus-reset classification, which is the one thing in this tool that
// must live in exactly one place.
//
// Like the binary: it completes TLS handshakes and closes them. No request, no
// application data, no credentials.
package pq

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/inventory"
	"github.com/Allan-Nava/pqprobe/internal/probe"
	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// Finding is one statement about one endpoint. Value and Unit carry the number
// wherever there is one, so a consumer never has to read Message.
type Finding struct {
	Check   string   `json:"check"`
	Target  string   `json:"target"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Value   *float64 `json:"value,omitempty"`
	Unit    string   `json:"unit,omitempty"`
	Hint    string   `json:"hint,omitempty"`
}

// Report is everything concluded about one endpoint. Worst is the highest
// severity among the findings, which is what an aggregator grades on.
type Report struct {
	Target   string    `json:"target"`
	Class    string    `json:"class"`
	Worst    string    `json:"worst"`
	Findings []Finding `json:"findings"`
}

// Explanation is a class out of context: what it means, who it affects, what to
// do. Available without a run, for rendering and for alert text.
type Explanation struct {
	Class    string `json:"class"`
	Status   string `json:"status"`
	Meaning  string `json:"meaning"`
	Affected string `json:"affected,omitempty"`
	Action   string `json:"action"`
}

// Options are what an embedder may vary. The zero value is the default run:
// the three profiles the CLI dials, a ten-second handshake timeout, and an
// abrupt failure confirmed by a second dial.
type Options struct {
	// Profiles by name; empty means classic, pq-preferred and pq-only. An
	// unknown name is an error rather than a smaller run.
	Profiles []string
	// Timeout per handshake. Zero means ten seconds.
	Timeout time.Duration
	// ALPN protocols to offer. Empty means none.
	ALPN []string
	// Socks5 is a no-auth SOCKS5 proxy to reach the endpoints through.
	Socks5 string
	// Net pins the address family: "tcp4", "tcp6", or empty for whatever the
	// resolver hands over. Unpinned, a dual-stack name is graded on whichever
	// address the resolver chose that minute, and two runs can disagree with
	// nothing having changed on the endpoint. An unknown value is an error.
	Net string
	// NoConfirm turns off the second dial after an abrupt failure. The default
	// is to confirm, because "cut off" is a claim somebody takes to a vendor.
	NoConfirm bool
	// Concurrency is how many endpoints are in flight. Zero means eight. The
	// profiles of one endpoint are always dialled in sequence.
	Concurrency int
	// ExpiryWarnDays and ExpiryBadDays grade the leaf certificate. Zero means
	// 21 and 7.
	ExpiryWarnDays, ExpiryBadDays int
	// DefaultPort for targets written without one. Empty means 443.
	DefaultPort string
	// SNI overrides the server name sent to every target. Empty keeps each
	// target's own — including the `1.2.3.4=origin.example` form.
	SNI string
}

// Probe dials every target and returns one report each.
//
// A target that cannot be reached is a report with class `unreachable`, not an
// error: a fleet check has to keep going and name the node that is down. An
// error comes back only for something the caller got wrong — no targets, an
// unknown profile, a target that cannot be parsed at all.
func Probe(ctx context.Context, targets []string, opt Options) ([]Report, error) {
	if len(targets) == 0 {
		return nil, errors.New("pq: no target to probe")
	}

	names := opt.Profiles
	if len(names) == 0 {
		names = clientprofile.Default
	}
	sel, unknown := clientprofile.Select(names)
	if len(unknown) > 0 {
		return nil, fmt.Errorf("pq: unknown profile(s): %v (have: %v)", unknown, clientprofile.Names())
	}

	parsed, errs := inventory.ParseAll(targets)
	if len(parsed) == 0 {
		return nil, fmt.Errorf("pq: no target could be parsed: %v", errs)
	}
	// The same overrides the CLI applies, in the same order: a port only
	// replaces the default one, and an SNI replaces every target's — including
	// the `1.2.3.4=origin.example` form, which is the whole point of having it.
	for i := range parsed {
		if opt.DefaultPort != "" && parsed[i].Port == inventory.DefaultPort {
			parsed[i].Port = opt.DefaultPort
		}
		if opt.SNI != "" {
			parsed[i].SNI = opt.SNI
		}
	}

	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	concurrency := opt.Concurrency
	if concurrency < 1 {
		concurrency = 8
	}

	if !probe.ValidNet(opt.Net) {
		return nil, fmt.Errorf("unknown address family %q (have: %s)", opt.Net, strings.Join(probe.Nets(), ", "))
	}
	d := probe.Dialer{
		Timeout: timeout,
		ALPN:    opt.ALPN,
		Socks5:  opt.Socks5,
		Net:     opt.Net,
		Confirm: !opt.NoConfirm,
	}
	vopt := verdict.DefaultOptions()
	if opt.ExpiryWarnDays > 0 {
		vopt.ExpiryWarnDays = opt.ExpiryWarnDays
	}
	if opt.ExpiryBadDays > 0 {
		vopt.ExpiryBadDays = opt.ExpiryBadDays
	}
	vopt.Now = time.Now()

	out := make([]Report, len(parsed))
	sem := make(chan struct{}, concurrency)
	done := make(chan struct{})
	for i, t := range parsed {
		go func(i int, t probe.Target) {
			sem <- struct{}{}
			defer func() { <-sem; done <- struct{}{} }()
			var results []probe.Result
			for _, p := range sel {
				results = append(results, d.DoConfirmed(ctx, t, p))
			}
			out[i] = convert(verdict.Evaluate(t.String(), results, vopt))
		}(i, t)
	}
	for range parsed {
		<-done
	}
	return out, nil
}

// Classes is every class pqprobe can conclude, in the order a reader should
// meet them.
func Classes() []string {
	cs := verdict.Classes()
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c))
	}
	return out
}

// Explain is what a class means, who it affects and what to do about it — with
// no network call, so an embedder can render it before anything goes wrong.
func Explain(class string) (Explanation, bool) {
	e, ok := verdict.Explain(verdict.Class(class))
	if !ok {
		return Explanation{}, false
	}
	return Explanation{
		Class:    string(e.Class),
		Status:   string(e.Status),
		Meaning:  e.Meaning,
		Affected: e.Affected,
		Action:   e.Action,
	}, true
}

// Classify says how a failed handshake ended and whether that ending was
// **abrupt** — the distinction the whole tool rests on (PQ-10).
//
// A TLS alert means the peer parsed the ClientHello and declined a group: a
// policy, a pinned group list, a negotiation that worked. A reset, a timeout,
// an EOF or a non-TLS record means it choked on the hello itself, and is broken
// for every client that so much as offers ML-KEM. Only the second is an outage
// waiting for a CDN to flip a default.
//
// It is exported for embedders that dial with their own TLS stack — a
// fingerprint probe, for instance — because two copies of this judgement is
// exactly one copy too many. A nil error is "ok", not abrupt.
func Classify(err error) (kind string, abrupt bool) {
	if err == nil {
		return string(probe.KindOK), false
	}
	k, _ := probe.Classify(err)
	return string(k), k.Abrupt()
}

// Describe is the one-line meaning of a class.
func Describe(class string) string { return verdict.Describe(verdict.Class(class)) }

func convert(r verdict.Report) Report {
	out := Report{
		Target:   r.Target,
		Class:    string(r.Class),
		Worst:    string(finding.Worst(r.Finding)),
		Findings: make([]Finding, 0, len(r.Finding)),
	}
	for _, f := range r.Finding {
		out.Findings = append(out.Findings, Finding{
			Check:   f.Check,
			Target:  f.Target,
			Status:  string(f.Status),
			Message: f.Message,
			Value:   f.Value,
			Unit:    f.Unit,
			Hint:    f.Hint,
		})
	}
	return out
}
