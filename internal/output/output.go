// Package output renders reports. Three renderers, one rule: worst first, and
// every line traceable to the handshake behind it.
//
// The text renderer is for a person reading a terminal, --json for a machine
// that wants everything including the negotiated group per profile, and
// --findings for the flat contract the rest of the toolchain already speaks
// (one array of findings, no nesting, no prose to parse).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// Text renders reports for a terminal. min filters findings by severity; the
// endpoint header is always printed, because "this endpoint was probed and had
// nothing above the threshold" is information too.
func Text(w io.Writer, reps []verdict.Report, min finding.Status) error {
	sort.SliceStable(reps, func(i, j int) bool {
		if a, b := finding.Severity(reps[i].Worst()), finding.Severity(reps[j].Worst()); a != b {
			return a > b
		}
		return reps[i].Target < reps[j].Target
	})
	for _, rep := range reps {
		if _, err := fmt.Fprintf(w, "%-5s %s  %s\n", rep.Worst(), rep.Target, rep.Class); err != nil {
			return err
		}
		for _, f := range rep.Finding {
			if min != "" && !finding.AtLeast(f.Status, min) {
				continue
			}
			line := fmt.Sprintf("  %-5s %-28s %s", f.Status, shortCheck(f, rep.Target), f.Message)
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
			if f.Hint != "" {
				if _, err := fmt.Fprintf(w, "        ↳ %s\n", f.Hint); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Summary is the one line at the end: how many endpoints, how many in each
// state. A run over a fleet is unreadable without it.
func Summary(w io.Writer, reps []verdict.Report) error {
	byClass := map[verdict.Class]int{}
	worst := map[finding.Status]int{}
	for _, r := range reps {
		byClass[r.Class]++
		worst[r.Worst()]++
	}
	classes := make([]string, 0, len(byClass))
	for c, n := range byClass {
		classes = append(classes, fmt.Sprintf("%d %s", n, c))
	}
	sort.Strings(classes)
	_, err := fmt.Fprintf(w, "\n%d endpoint(s): %s · worst: %d ERROR, %d BAD, %d WARN, %d OK\n",
		len(reps), strings.Join(classes, ", "),
		worst[finding.ERROR], worst[finding.BAD], worst[finding.WARN], worst[finding.OK])
	return err
}

// JSON renders everything, including every per-profile result.
func JSON(w io.Writer, reps []verdict.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Tool    string           `json:"tool"`
		Reports []verdict.Report `json:"reports"`
	}{Tool: "pqprobe", Reports: reps})
}

// Findings renders the flat findings array. An empty run emits `[]`, never
// `null`: a consumer that does `for f in findings` must not have to special-case
// a healthy fleet.
func Findings(w io.Writer, reps []verdict.Report, min finding.Status) error {
	out := []finding.Finding{}
	for _, r := range reps {
		for _, f := range r.Finding {
			if min != "" && !finding.AtLeast(f.Status, min) {
				continue
			}
			out = append(out, f)
		}
	}
	finding.SortWorstFirst(out)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// shortCheck drops the repeated target prefix from a per-profile finding, so a
// terminal shows "handshake/pq-preferred" rather than the endpoint twice.
func shortCheck(f finding.Finding, target string) string {
	if suffix, ok := strings.CutPrefix(f.Target, target+"/"); ok {
		return f.Check + "/" + suffix
	}
	return f.Check
}
