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
	"errors"
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
// Markdown renders a run the way a pull request comment or a job summary reads
// (PQ-27): a table first, because that is what somebody sees at a glance, and
// the detail after it for whoever is going to fix something.
//
// Same findings, same order, same --min-severity as every other renderer. No
// new checks and no colour: a comment that carried terminal escapes would be
// unreadable in the one place this format exists for.
func Markdown(w io.Writer, reps []verdict.Report, min finding.Status) error {
	if len(reps) == 0 {
		_, err := fmt.Fprintln(w, "**pqprobe** probed no endpoint.")
		return err
	}

	sorted := make([]verdict.Report, len(reps))
	copy(sorted, reps)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].Worst(), sorted[j].Worst()
		if a != b {
			return finding.AtLeast(a, b)
		}
		return sorted[i].Target < sorted[j].Target
	})

	counts := map[finding.Status]int{}
	for _, r := range sorted {
		counts[r.Worst()]++
	}
	fmt.Fprintf(w, "**pqprobe** — %d endpoint(s): %d ERROR, %d BAD, %d WARN, %d OK\n\n",
		len(sorted), counts[finding.ERROR], counts[finding.BAD], counts[finding.WARN], counts[finding.OK])

	fmt.Fprintln(w, "| Endpoint | Class | Worst |")
	fmt.Fprintln(w, "|---|---|---|")
	for _, r := range sorted {
		fmt.Fprintf(w, "| `%s` | `%s` | %s |\n", mdCell(r.Target), mdCell(string(r.Class)), r.Worst())
	}

	for _, r := range sorted {
		var keep []finding.Finding
		for _, f := range r.Finding {
			if finding.AtLeast(f.Status, min) {
				keep = append(keep, f)
			}
		}
		if len(keep) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n<details><summary><code>%s</code> — %s</summary>\n\n",
			r.Target, r.Class)
		for _, f := range keep {
			fmt.Fprintf(w, "- **%s** `%s` — %s\n", f.Status, shortCheck(f, r.Target), f.Message)
			if f.Hint != "" {
				fmt.Fprintf(w, "  - %s\n", f.Hint)
			}
		}
		fmt.Fprintln(w, "\n</details>")
	}
	return nil
}

// mdCell escapes what would otherwise end a table cell early. A pipe in a
// message shifts every column after it, silently — the same trap the roadmap
// generator has to handle.
func mdCell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}

// LoadReports reads a baseline: a document JSON wrote earlier (PQ-24).
//
// The `tool` field is checked rather than trusted. A file that is not a pqprobe
// run must be an error, because a baseline that silently parsed as nothing
// would compare against nothing and report "no changes" for ever — which is
// the most expensive kind of quiet.
func LoadReports(r io.Reader) ([]verdict.Report, error) {
	var doc struct {
		Tool    string           `json:"tool"`
		Reports []verdict.Report `json:"reports"`
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a pqprobe --json document: %w", err)
	}
	if doc.Tool != "pqprobe" {
		return nil, fmt.Errorf("not a pqprobe --json document (tool = %q)", doc.Tool)
	}
	if len(doc.Reports) == 0 {
		return nil, errors.New("the baseline holds no reports")
	}
	return doc.Reports, nil
}

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
