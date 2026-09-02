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
