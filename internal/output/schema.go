package output

import "github.com/Allan-Nava/pqprobe/internal/verdict"

// Schema is the contract number every machine-facing document carries (PQ-70).
//
// It exists because "pqprobe" was the only thing in a document a consumer could
// branch on: checkfleet, an aggregator deduplicating on the finding id, a CI job
// reading --findings. A parser could not tell a document it understands from one
// written by a build that moved a field — it could only fail at the field, in
// production, at the point where the answer was needed.
//
// The number moves when the **shape** moves: a field renamed or removed, an
// object nested differently, an array that becomes an object. It does **not**
// move for a new field, a new class, a new check or a new finding — a consumer
// that breaks on those was already broken, and a number that moved every release
// is a number nobody pins.
//
// docs/schema.md says what each field means, and is generated from these types.
const Schema = 1

// Document is the `--json` run: everything pqprobe concluded, including every
// per-profile result. It is a named type because it is the contract — the page
// that describes it is walked from here, and an embedder can decode into it.
type Document struct {
	Schema  int              `json:"schema"`
	Tool    string           `json:"tool"`
	Reports []verdict.Report `json:"reports"`
}

// WrappedDocument is `--findings=wrapped`: the shape the fleet aggregator
// consumes, one object with one array inside it.
type WrappedDocument struct {
	Schema   int              `json:"schema"`
	Check    string           `json:"check"`
	Status   string           `json:"status"`
	Summary  string           `json:"summary"`
	Findings []WrappedFinding `json:"findings"`
}

// WrappedFinding is one finding as the aggregator wants it. The id is the
// reason the wrapper exists: it fingerprints the same problem on the same
// target across runs, so a finding already seen can be told from a new one.
type WrappedFinding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Target   string   `json:"target"`
	Check    string   `json:"check"`
	Value    *float64 `json:"value,omitempty"`
	Unit     string   `json:"unit,omitempty"`
}
