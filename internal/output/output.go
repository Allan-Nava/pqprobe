// Package output renders reports. Three renderers, one rule: worst first, and
// every line traceable to the handshake behind it.
//
// The text renderer is for a person reading a terminal, --json for a machine
// that wants everything including the negotiated group per profile, and
// --findings for the flat contract the rest of the toolchain already speaks
// (one array of findings, no nesting, no prose to parse).
package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// FindingsWrapped is the shape the fleet aggregator consumes (PQ-37):
//
//	{"check": "pqprobe", "status": "bad", "summary": "…",
//	 "findings": [{"id": "…", "severity": "bad", "title": "…", "detail": "…"}]}
//
// The flat array `Findings` writes is still what `--findings` produces; this is
// `--findings=wrapped`. The README promised "the flat findings array the sibling
// tools speak" while the aggregator that actually reads it wanted this, so every
// consumer translated — which is what a shared shape exists to avoid.
//
// The **id** is the reason the wrapper exists: it fingerprints the same problem
// on the same target across runs, so an aggregator can tell a finding it has
// already seen from a new one. It is therefore built from the check and the
// target and *not* from the message, which carries days and byte counts that
// change on their own — an id derived from the text would report a new problem
// every morning.
func FindingsWrapped(w io.Writer, reps []verdict.Report, min finding.Status) error {
	type item struct {
		ID       string   `json:"id"`
		Severity string   `json:"severity"`
		Title    string   `json:"title"`
		Detail   string   `json:"detail,omitempty"`
		Target   string   `json:"target"`
		Check    string   `json:"check"`
		Value    *float64 `json:"value,omitempty"`
		Unit     string   `json:"unit,omitempty"`
	}

	items := make([]item, 0, 8)
	seen := map[string]int{}
	worst := finding.OK
	for _, r := range reps {
		for _, f := range r.Finding {
			if !finding.AtLeast(f.Status, min) {
				continue
			}
			if finding.AtLeast(f.Status, worst) {
				worst = f.Status
			}
			id := findingID(f)
			// Two findings of one check on one target in a single run would
			// otherwise share an id, and the aggregator would drop one.
			seen[id]++
			if n := seen[id]; n > 1 {
				id = fmt.Sprintf("%s-%d", id, n)
			}
			items = append(items, item{
				ID:       id,
				Severity: strings.ToLower(string(f.Status)),
				Title:    f.Message,
				Detail:   f.Hint,
				Target:   f.Target,
				Check:    f.Check,
				Value:    f.Value,
				Unit:     f.Unit,
			})
		}
	}

	doc := struct {
		Check    string `json:"check"`
		Status   string `json:"status"`
		Summary  string `json:"summary"`
		Findings []item `json:"findings"`
	}{
		Check:    "pqprobe",
		Status:   strings.ToLower(string(worst)),
		Summary:  wrappedSummary(reps),
		Findings: items,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// findingID is a stable fingerprint of check plus target — the identity of the
// problem, not of the sentence describing it.
func findingID(f finding.Finding) string {
	sum := sha256.Sum256([]byte(f.Check + "|" + f.Target))
	return hex.EncodeToString(sum[:6])
}

// wrappedSummary is the one line a digest quotes when it has room for one.
func wrappedSummary(reps []verdict.Report) string {
	if len(reps) == 0 {
		return "no endpoint was probed"
	}
	classes := map[verdict.Class]int{}
	for _, r := range reps {
		classes[r.Class]++
	}
	names := make([]string, 0, len(classes))
	for c := range classes {
		names = append(names, string(c))
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%d %s", classes[verdict.Class(n)], n))
	}
	return fmt.Sprintf("%d endpoint(s): %s", len(reps), strings.Join(parts, ", "))
}

// Textfile writes the run for a node exporter's textfile collector (PQ-15).
//
// Written to a temporary file in the same directory and renamed over the
// target, because the collector reads whatever is in the file when it scrapes —
// including half of it. Replaced whole rather than appended, or a target would
// briefly hold two classes at once.
//
// The series are the ones an alert is actually built from: a numeric severity
// to threshold on, the class as a label to put in the message, the certificate
// days, the measured hello sizes, and the run timestamp — without which a probe
// that silently stopped running looks exactly like a fleet that is fine.
func Textfile(path string, reps []verdict.Report, now time.Time) error {
	var b strings.Builder

	fmt.Fprintf(&b, "# HELP pqprobe_last_run_timestamp_seconds When pqprobe last completed a run.\n")
	fmt.Fprintf(&b, "# TYPE pqprobe_last_run_timestamp_seconds gauge\n")
	fmt.Fprintf(&b, "pqprobe_last_run_timestamp_seconds %d\n", now.Unix())
	fmt.Fprintf(&b, "# HELP pqprobe_endpoints How many endpoints the run probed.\n")
	fmt.Fprintf(&b, "# TYPE pqprobe_endpoints gauge\n")
	fmt.Fprintf(&b, "pqprobe_endpoints %d\n", len(reps))

	if len(reps) == 0 {
		return writeAtomic(path, b.String())
	}

	// One family at a time: HELP and TYPE may appear once each, and a collector
	// rejects the whole file otherwise — so all the series of a family are
	// written together rather than per endpoint.
	fmt.Fprintf(&b, "# HELP pqprobe_class The endpoint's class, as a label. Always 1.\n")
	fmt.Fprintf(&b, "# TYPE pqprobe_class gauge\n")
	for _, r := range reps {
		fmt.Fprintf(&b, "pqprobe_class{target=%q,class=%q} 1\n", r.Target, string(r.Class))
	}

	fmt.Fprintf(&b, "# HELP pqprobe_status Worst finding severity: 0 OK, 1 WARN, 2 BAD, 3 ERROR.\n")
	fmt.Fprintf(&b, "# TYPE pqprobe_status gauge\n")
	for _, r := range reps {
		fmt.Fprintf(&b, "pqprobe_status{target=%q} %d\n", r.Target, promStatus(r.Worst()))
	}

	fmt.Fprintf(&b, "# HELP pqprobe_findings Findings per status.\n")
	fmt.Fprintf(&b, "# TYPE pqprobe_findings gauge\n")
	for _, r := range reps {
		counts := finding.Summarize(r.Finding)
		for _, st := range []finding.Status{finding.OK, finding.WARN, finding.BAD, finding.ERROR} {
			if counts[st] == 0 {
				continue
			}
			fmt.Fprintf(&b, "pqprobe_findings{target=%q,status=%q} %d\n",
				r.Target, st, counts[st])
		}
	}

	// Certificate days come from the finding rather than being recomputed: the
	// thresholds are the run's, and two answers would drift.
	var expiry []string
	for _, r := range reps {
		for _, f := range r.Finding {
			if f.Check == "expiry" && f.Value != nil {
				expiry = append(expiry, fmt.Sprintf("pqprobe_cert_expiry_days{target=%q} %g\n",
					r.Target, *f.Value))
			}
		}
	}
	if len(expiry) > 0 {
		fmt.Fprintf(&b, "# HELP pqprobe_cert_expiry_days Days until the leaf certificate expires.\n")
		fmt.Fprintf(&b, "# TYPE pqprobe_cert_expiry_days gauge\n")
		for _, line := range expiry {
			b.WriteString(line)
		}
	}

	fmt.Fprintf(&b, "# HELP pqprobe_handshake_ok Whether that client shape completed a handshake.\n")
	fmt.Fprintf(&b, "# TYPE pqprobe_handshake_ok gauge\n")
	for _, r := range reps {
		for _, res := range r.Results {
			ok := 0
			if res.OK {
				ok = 1
			}
			fmt.Fprintf(&b, "pqprobe_handshake_ok{target=%q,profile=%q} %d\n",
				r.Target, res.Profile, ok)
		}
	}

	var hello []string
	for _, r := range reps {
		for _, res := range r.Results {
			if res.HelloBytes > 0 {
				hello = append(hello, fmt.Sprintf("pqprobe_hello_bytes{target=%q,profile=%q} %d\n",
					r.Target, res.Profile, res.HelloBytes))
			}
		}
	}
	if len(hello) > 0 {
		fmt.Fprintf(&b, "# HELP pqprobe_hello_bytes Size on the wire of the ClientHello that shape sent.\n")
		fmt.Fprintf(&b, "# TYPE pqprobe_hello_bytes gauge\n")
		for _, line := range hello {
			b.WriteString(line)
		}
	}

	return writeAtomic(path, b.String())
}

// writeAtomic replaces path in one step. Same directory, because a rename
// across filesystems is a copy and a copy is not atomic.
func writeAtomic(path, body string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pqprobe-*")
	if err != nil {
		return fmt.Errorf("textfile: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once the rename succeeded

	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return fmt.Errorf("textfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("textfile: %w", err)
	}
	// The collector reads this file without asking anybody, so it is
	// world-readable rather than 0600 as CreateTemp leaves it.
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("textfile: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("textfile: %w", err)
	}
	return nil
}

// Label values go through %q rather than a hand-rolled escaper: a target is a
// string somebody else chose — an inventory alias, an SNI — and Go's quoting is
// exactly what Prometheus wants for the three characters that matter, a quote,
// a backslash and a newline. The first version of this escaped them itself and
// then handed the result to %q, which escaped them twice.

// promStatus is the severity as a number to threshold on: `> 1` is every state
// somebody should be woken for.
func promStatus(s finding.Status) int {
	switch s {
	case finding.WARN:
		return 1
	case finding.BAD:
		return 2
	case finding.ERROR:
		return 3
	}
	return 0
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
