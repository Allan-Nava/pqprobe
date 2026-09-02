// Package finding is the result model: one Finding is one statement about one
// target, and the severity order plus the "worst first" sort are the two rules
// every renderer obeys.
//
// pqprobe findings are statements about a *handshake* — which client class the
// endpoint accepted, which one it refused and how it refused — so a finding
// carries the profile it came from in Target and, where there is a number
// (days to expiry, milliseconds), the number itself. A machine consumer must
// never parse Message.
package finding

import "sort"

// Status of a single finding. Severity order: OK < WARN < BAD < ERROR.
type Status string

const (
	OK   Status = "OK"
	WARN Status = "WARN"
	BAD  Status = "BAD"
	// ERROR means the probe could not run — the name did not resolve, the port
	// refused the connection, no profile completed a handshake. It sorts above
	// BAD because nothing below it can be concluded: an endpoint that was never
	// reached is not an endpoint that passed.
	ERROR Status = "ERROR"
)

var severity = map[Status]int{OK: 0, WARN: 1, BAD: 2, ERROR: 3}

// Severity is the numeric rank of s in the order OK < WARN < BAD < ERROR.
func Severity(s Status) int { return severity[s] }

// AtLeast reports whether s is at or above threshold. An empty threshold is
// satisfied by anything, since severity[""] is the zero value — a caller that
// means "no threshold at all" must test for "" itself.
func AtLeast(s, threshold Status) bool { return severity[s] >= severity[threshold] }

// Finding is one statement about one endpoint.
//
// Check is the analysis that produced it (handshake, chain, expiry, verdict),
// Target names what was looked at — "host:port" or "host:port/profile" — and
// Hint says what it means operationally, which for pqprobe is usually *which
// real clients* are affected.
type Finding struct {
	Check   string   `json:"check"`
	Target  string   `json:"target"`
	Status  Status   `json:"status"`
	Message string   `json:"message"`
	Value   *float64 `json:"value,omitempty"`
	Unit    string   `json:"unit,omitempty"`
	Hint    string   `json:"hint,omitempty"`
}

// Num returns a pointer to v, for setting Finding.Value inline.
func Num(v float64) *float64 { return &v }

// Summarize counts findings per status.
func Summarize(fs []Finding) map[Status]int {
	out := map[Status]int{OK: 0, WARN: 0, BAD: 0, ERROR: 0}
	for _, f := range fs {
		out[f.Status]++
	}
	return out
}

// Worst returns the highest severity present, or OK for no findings.
func Worst(fs []Finding) Status {
	worst := OK
	for _, f := range fs {
		if AtLeast(f.Status, worst) {
			worst = f.Status
		}
	}
	return worst
}

// SortWorstFirst orders findings by descending severity, then by target and
// check, so two runs over the same fleet render in the same order — the target
// first, because an operator reads this per endpoint.
func SortWorstFirst(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := severity[fs[i].Status], severity[fs[j].Status]; a != b {
			return a > b
		}
		if fs[i].Target != fs[j].Target {
			return fs[i].Target < fs[j].Target
		}
		return fs[i].Check < fs[j].Check
	})
}
