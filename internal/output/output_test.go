package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

func reports() []verdict.Report {
	return []verdict.Report{
		{Target: "quiet:443", Class: verdict.PQReady, Finding: []finding.Finding{
			{Check: "handshake", Target: "quiet:443/pq-only", Status: finding.OK, Message: "TLS 1.3"},
		}},
		{Target: "broken:443", Class: verdict.PQIntolerant, Finding: []finding.Finding{
			{Check: "verdict", Target: "broken:443", Status: finding.BAD, Message: "pq-intolerant", Hint: "clients that offer ML-KEM fail"},
			{Check: "handshake", Target: "broken:443/classic", Status: finding.OK, Message: "TLS 1.3"},
		}},
	}
}

func TestTextPutsTheWorstEndpointFirst(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, reports(), ""); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, "BAD") {
		t.Fatalf("worst endpoint must lead:\n%s", out)
	}
	if !strings.Contains(out, "handshake/classic") {
		t.Fatalf("a per-profile finding must show its profile, not the target twice:\n%s", out)
	}
	if !strings.Contains(out, "↳ clients that offer ML-KEM fail") {
		t.Fatalf("the hint is the actionable half; it must be rendered:\n%s", out)
	}
}

func TestTextMinSeverityKeepsTheEndpointHeader(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, reports(), finding.BAD); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "quiet:443") {
		t.Fatalf("an endpoint with nothing above the threshold was probed too, and must still appear:\n%s", out)
	}
	if strings.Contains(out, "TLS 1.3") {
		t.Fatalf("findings below the threshold must be hidden:\n%s", out)
	}
}

// A healthy fleet must not emit `null`: a consumer iterating the array should
// not have to special-case success.
func TestFindingsEmitsAnEmptyArrayNotNull(t *testing.T) {
	var b bytes.Buffer
	if err := Findings(&b, nil, ""); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(b.String()) != "[]" {
		t.Fatalf("got %q", b.String())
	}
	var parsed []finding.Finding
	if err := json.Unmarshal(b.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
}

func TestJSONCarriesEveryProfileResult(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, reports()); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Tool    string `json:"tool"`
		Reports []struct {
			Target   string `json:"target"`
			Class    string `json:"class"`
			Findings []struct {
				Check string `json:"check"`
			} `json:"findings"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(b.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Tool != "pqprobe" || len(parsed.Reports) != 2 {
		t.Fatalf("parsed = %+v", parsed)
	}
	if len(parsed.Reports[0].Findings) == 0 {
		t.Fatal("findings must survive the JSON round trip")
	}
}

func TestSummaryCountsClasses(t *testing.T) {
	var b bytes.Buffer
	if err := Summary(&b, reports()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "2 endpoint(s)") || !strings.Contains(out, "1 pq-intolerant") {
		t.Fatalf("summary = %q", out)
	}
}

// PQ-24. A baseline is a previous --json run, read back. The shape has to be
// the one this tool writes, or the flag is a promise it cannot keep.
func TestLoadReportsReadsWhatJSONWrote(t *testing.T) {
	want := []verdict.Report{
		{Target: "a.example:443", Class: verdict.PQReady},
		{Target: "b.example:443", Class: verdict.PQIntolerant},
	}
	var buf bytes.Buffer
	if err := JSON(&buf, want); err != nil {
		t.Fatal(err)
	}

	got, err := LoadReports(&buf)
	if err != nil {
		t.Fatalf("LoadReports: %v", err)
	}
	if len(got) != 2 || got[0].Target != "a.example:443" || got[1].Class != verdict.PQIntolerant {
		t.Fatalf("round trip lost something: %+v", got)
	}
}

// A file that is not a pqprobe run must say so, not silently compare against
// nothing — a baseline that quietly matched everything would report "no
// changes" for ever.
func TestLoadReportsRejectsSomethingElse(t *testing.T) {
	for _, in := range []string{`{"tool":"segcheck","reports":[]}`, `[]`, `not json at all`, `{}`} {
		if _, err := LoadReports(strings.NewReader(in)); err == nil {
			t.Errorf("%q was accepted as a baseline", in)
		}
	}
}

// PQ-27. The same findings in the shape a review can read: a table first,
// because a PR comment is read at a glance, and the detail after it for whoever
// is actually going to fix something.
func TestMarkdownLeadsWithATableWorstFirst(t *testing.T) {
	reps := []verdict.Report{
		{Target: "good.example:443", Class: verdict.PQReady, Finding: []finding.Finding{
			{Check: "verdict", Target: "good.example:443", Status: finding.OK, Message: "pq-ready — fine"},
		}},
		{Target: "bad.example:443", Class: verdict.PQIntolerant, Finding: []finding.Finding{
			{Check: "verdict", Target: "bad.example:443", Status: finding.BAD,
				Message: "pq-intolerant — capable clients cannot connect", Hint: "look at the path"},
			{Check: "handshake", Target: "bad.example:443/pq-preferred", Status: finding.WARN, Message: "no handshake (reset)"},
		}},
	}

	var b bytes.Buffer
	if err := Markdown(&b, reps, finding.OK); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	if !strings.Contains(out, "| Endpoint | Class |") {
		t.Errorf("no table header:\n%s", out)
	}
	bad := strings.Index(out, "bad.example")
	good := strings.Index(out, "good.example")
	if bad == -1 || good == -1 || bad > good {
		t.Errorf("the worst endpoint has to come first (bad at %d, good at %d)", bad, good)
	}
	if !strings.Contains(out, "pq-intolerant") || !strings.Contains(out, "look at the path") {
		t.Errorf("the finding and its hint have to survive into the detail:\n%s", out)
	}
	// A PR comment that says "2 endpoints" saves the reader counting rows.
	if !strings.Contains(out, "2 endpoint") {
		t.Errorf("no summary line:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("markdown must carry no terminal escapes")
	}
}

// --min-severity has to mean the same thing here as everywhere else, or a
// comment posted with it says more than the run was asked to say.
func TestMarkdownRespectsMinSeverity(t *testing.T) {
	reps := []verdict.Report{{Target: "h:443", Class: verdict.PQBlind, Finding: []finding.Finding{
		{Check: "verdict", Target: "h:443", Status: finding.WARN, Message: "pq-blind — plan it"},
		{Check: "handshake", Target: "h:443/classic", Status: finding.OK, Message: "TLS 1.3, X25519"},
	}}}

	var b bytes.Buffer
	if err := Markdown(&b, reps, finding.WARN); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "TLS 1.3, X25519") {
		t.Errorf("an OK finding survived --min-severity WARN:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "pq-blind") {
		t.Error("the WARN finding must still be there")
	}
}

// A run with nothing in it must say so. An empty table in a pull request reads
// as a broken tool, which is worse than a sentence.
func TestMarkdownSaysWhenThereIsNothing(t *testing.T) {
	var b bytes.Buffer
	if err := Markdown(&b, nil, finding.OK); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "no endpoint") {
		t.Errorf("output = %q", b.String())
	}
	if strings.Contains(b.String(), "| Endpoint |") {
		t.Error("an empty table is worse than a sentence")
	}
}

// A pipe in a *table cell* splits it and silently shifts every column after
// it — the same trap the roadmap generator already has to handle. In the detail
// list a pipe is literal text and escaping it would only add backslashes, so
// this asserts the table and leaves the prose alone.
func TestMarkdownEscapesPipesInTableCellsOnly(t *testing.T) {
	reps := []verdict.Report{{Target: "h:443|weird", Class: verdict.PQBlind, Finding: []finding.Finding{
		{Check: "verdict", Target: "h:443|weird", Status: finding.WARN, Message: "a|b|c"},
	}}}
	var b bytes.Buffer
	if err := Markdown(&b, reps, finding.OK); err != nil {
		t.Fatal(err)
	}

	var row string
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "| `h:443") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("no table row for the endpoint:\n%s", b.String())
	}
	if strings.Count(row, "|") != strings.Count(row, "\\|")+4 {
		t.Errorf("the row has an unescaped pipe and its columns will shift: %q", row)
	}
	if !strings.Contains(b.String(), "a|b|c") {
		t.Error("a pipe in prose is literal text: escaping it would only add backslashes")
	}
}
