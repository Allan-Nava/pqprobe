package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// PQ-70. PQ-69 froze the *bytes* of every machine-facing document; this freezes
// what a consumer is allowed to conclude from them. Until now the only thing in
// a pqprobe document a parser could branch on was the string "pqprobe", so a
// consumer had no way to tell a document it understands from one written by a
// version that moved a field — it could only fail at the field.
//
// So every document says which schema it speaks, and docs/schema.md says what
// that schema is. The page is generated from the types, because a page
// maintained beside them is a page that is wrong by the second release.

// The contract number a document claims. It moves when the shape moves, and
// never for a new value of an existing field — which is why the test that
// guards it lives next to the one that regenerates the page.
func TestEveryMachineFacingDocumentSaysWhichSchemaItSpeaks(t *testing.T) {
	reps := goldenRun(t)

	var b bytes.Buffer
	if err := JSON(&b, reps); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema int    `json:"schema"`
		Tool   string `json:"tool"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("--json is not JSON: %v", err)
	}
	if doc.Schema != Schema {
		t.Errorf("--json says schema %d, want %d", doc.Schema, Schema)
	}

	b.Reset()
	if err := FindingsWrapped(&b, reps, ""); err != nil {
		t.Fatal(err)
	}
	var wrapped struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(b.Bytes(), &wrapped); err != nil {
		t.Fatalf("--findings=wrapped is not JSON: %v", err)
	}
	if wrapped.Schema != Schema {
		t.Errorf("--findings=wrapped says schema %d, want %d", wrapped.Schema, Schema)
	}

	// The textfile has no envelope to carry a field, so the number is a series:
	// a scrape that finds pqprobe_schema_version at an unexpected value is the
	// same signal, in the one shape a collector can read.
	dir := t.TempDir()
	path := filepath.Join(dir, "pqprobe.prom")
	if err := Textfile(path, reps, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("pqprobe_schema_version %d\n", Schema)
	if !strings.Contains(string(body), want) {
		t.Errorf("the textfile does not carry %q:\n%s", want, body)
	}

	// An empty run is the case that matters most here: it is what a consumer
	// gets from a fleet that resolved to nothing, and it still has to say which
	// contract the emptiness is written in.
	empty := filepath.Join(dir, "empty.prom")
	if err := Textfile(empty, nil, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(empty)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), want) {
		t.Errorf("an empty run's textfile does not carry %q:\n%s", want, body)
	}
}

// A baseline written by a newer pqprobe is not a baseline this build can
// compare against: the fields it would read may mean something else. Refusing
// it is the whole point of putting a number in the document.
func TestLoadReportsRefusesADocumentFromANewerSchema(t *testing.T) {
	doc := fmt.Sprintf(`{"schema": %d, "tool": "pqprobe", "reports": [{"target": "h:443"}]}`, Schema+1)
	_, err := LoadReports(strings.NewReader(doc))
	if err == nil {
		t.Fatal("a document from a newer schema was accepted")
	}
	if !strings.Contains(err.Error(), "newer") {
		t.Errorf("the error does not say the document is newer: %v", err)
	}
}

// And one written before there was a number still reads: every stored baseline
// on disk today has no `schema` field, and a gate that made those unreadable
// would turn an upgrade into a lost history.
func TestLoadReportsStillReadsADocumentFromBeforeTheSchemaField(t *testing.T) {
	doc := `{"tool": "pqprobe", "reports": [{"target": "h:443", "class": "pq-ready"}]}`
	reps, err := LoadReports(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("a pre-schema baseline was refused: %v", err)
	}
	if len(reps) != 1 || reps[0].Target != "h:443" {
		t.Fatalf("the reports did not survive the read: %+v", reps)
	}
}

// The page is generated from the types. A field added, renamed or removed
// changes this file, and the diff is the review — the same rule the golden
// documents follow, for the same reason.
func TestTheSchemaPageMatchesTheTypes(t *testing.T) {
	page, err := schemaPage(goldenRun(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "schema.md")
	if *update {
		if err := os.WriteFile(path, []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v — run `go test ./internal/output/ -update`", err)
	}
	if page != string(want) {
		t.Errorf("docs/schema.md no longer describes the types.\n"+
			"If the shape changed on purpose, re-run with -update, bump Schema if a\n"+
			"consumer has to notice, and read the diff as what it is: a change to\n"+
			"somebody else's parser.\n\ngot:\n%s", page)
	}
}

// A field with no meaning written down is a field a consumer has to guess at,
// so the generator refuses to describe one — which makes adding a field to a
// document a red test until somebody says what it is for.
func TestEveryDocumentedFieldHasAMeaning(t *testing.T) {
	missing := undescribedFields()
	if len(missing) > 0 {
		t.Errorf("these fields reach a machine-facing document and nothing says what they mean:\n  %s\n"+
			"add them to fieldMeaning in schema_doc_test.go", strings.Join(missing, "\n  "))
	}
}

// The number in the page and the number in the code are the same number.
func TestTheSchemaPageStatesTheCurrentNumber(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), fmt.Sprintf("`schema` is **%d**", Schema)) {
		t.Errorf("docs/schema.md does not state that the current schema is %d", Schema)
	}
}

// Guard against the reflection walk quietly describing nothing: if the walk
// stopped at the top-level struct, every table below would vanish and the
// golden would happily record the emptiness.
func TestTheWalkReachesTheNestedDocumentTypes(t *testing.T) {
	types := documentTypes(reflect.TypeOf(Document{}))
	want := []string{"Document", "Report", "Result", "Cert", "Finding"}
	got := map[string]bool{}
	for _, ty := range types {
		got[ty.Name()] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("the walk over the --json document never reached %s", name)
		}
	}
}
