package verdict

import (
	"testing"

	"github.com/Allan-Nava/pqprobe/internal/clientprofile"
	"github.com/Allan-Nava/pqprobe/internal/finding"
	"github.com/Allan-Nava/pqprobe/internal/probe"
)

// PQ-67. Every sentence asserted below is written in prose somewhere in this
// repository — in INTENT.md, in a doc comment, in a hint. Three of them were
// false last week (PQ-65) and no gate said so, because every test that could
// have caught them was written by whoever wrote the code and used the results a
// real run produces.
//
// These results are generated instead. The point is not to model a plausible
// endpoint; it is to reach the combinations nobody thought to write down.

// profiles is the vocabulary a run can produce: the client shapes, plus the
// probes that are held out of the classification.
var fuzzProfiles = []string{
	"classic", "pq-preferred", "pq-only", "tls13-only", "tls12",
	clientprofile.GroupPrefix + "X25519MLKEM768",
	clientprofile.GroupPrefix + "SecP256r1MLKEM768",
	clientprofile.GroupPrefix + "X25519",
	clientprofile.SizePrefix + "2048",
	clientprofile.SizePrefix + "4096",
	clientprofile.ALPNProbeName,
	clientprofile.ECHPrefix + "off",
	clientprofile.ECHPrefix + "on",
	clientprofile.CustomPrefix + "X25519",
}

var fuzzKinds = []probe.Kind{
	probe.KindOK, probe.KindDNS, probe.KindRefused, probe.KindStartTLS,
	probe.KindProxy, probe.KindUnroutable, probe.KindTimeout, probe.KindReset,
	probe.KindEOF, probe.KindAlert, probe.KindRecord, probe.KindECHReject,
	probe.KindOther,
}

// resultsFrom turns fuzz bytes into a set of results: six bytes per result, so
// the generator is stable and the corpus stays meaningful across runs.
func resultsFrom(b []byte) []probe.Result {
	var out []probe.Result
	for i := 0; i+5 < len(b) && len(out) < 12; i += 6 {
		k := fuzzKinds[int(b[i+1])%len(fuzzKinds)]
		r := probe.Result{
			Profile:     fuzzProfiles[int(b[i])%len(fuzzProfiles)],
			Kind:        k,
			OK:          k == probe.KindOK,
			HelloBytes:  int(b[i+2])<<4 | int(b[i+3]>>4),
			PQ:          b[i+4]&1 == 1,
			ECHAccepted: b[i+4]&2 == 2,

			ClientCertRequested: b[i+4]&4 == 4,
			Version:             "TLS 1.3",
			Group:               "X25519MLKEM768",
		}
		if b[i+5]&1 == 1 {
			r.Version = "TLS 1.2"
		}
		if !r.OK {
			r.Err = string(k)
		}
		out = append(out, r)
	}
	return out
}

func FuzzVerdictInvariants(f *testing.F) {
	f.Add([]byte{0, 0, 5, 0, 0, 0, 1, 0, 6, 0, 1, 0, 2, 9, 0, 0, 1, 0})
	f.Add([]byte{0, 9, 0, 0, 0, 0, 1, 9, 0, 0, 0, 0, 2, 9, 0, 0, 0, 0})
	f.Add([]byte{5, 0, 6, 0, 1, 0, 6, 9, 0, 0, 0, 0, 11, 0, 6, 0, 1, 0, 12, 0, 7, 0, 3, 0})
	f.Add([]byte{})

	classes := map[Class]bool{}
	for _, c := range Classes() {
		classes[c] = true
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		results := resultsFrom(b)
		if len(results) == 0 {
			return
		}
		rep := Evaluate("h:443", results, opts())

		// 1. The class is one of the ones `explain` and the docs know about.
		if !classes[rep.Class] {
			t.Fatalf("class %q is not in Classes()", rep.Class)
		}
		if _, ok := Explain(rep.Class); !ok {
			t.Fatalf("class %q has no explanation", rep.Class)
		}

		// 2. No post-quantum grade without a working baseline. "Grading an
		//    endpoint nobody reached is how a monitoring system starts lying."
		graded := map[Class]bool{PQReady: true, PQCapable: true, PQBlind: true,
			PQIntolerant: true, PQRefusing: true, NoTLS13: true}
		if graded[rep.Class] {
			any := false
			for _, r := range results {
				if r.OK && !clientprofile.IsGroupProbe(r.Profile) &&
					!clientprofile.IsSizeProbe(r.Profile) && !clientprofile.IsECHProbe(r.Profile) {
					any = true
				}
			}
			if !any {
				t.Fatalf("class %q with no client profile connected: %+v", rep.Class, results)
			}
		}

		worst := finding.Status("")
		for i, fnd := range rep.Finding {
			// 3. A number needs a unit, or a machine consumer cannot read it.
			if fnd.Value != nil && fnd.Unit == "" {
				t.Fatalf("finding %q carries %v with no unit", fnd.Check, *fnd.Value)
			}
			// 4. Bytes are never negative: that was PQ-65's `-1519 bytes of ALPN`.
			if fnd.Unit == "bytes" && fnd.Value != nil && *fnd.Value < 0 {
				t.Fatalf("finding %q reports %v bytes", fnd.Check, *fnd.Value)
			}
			// 5. Worst first, in every renderer, because the output is read
			//    under pressure in a terminal that has already scrolled.
			if i > 0 && finding.Severity(fnd.Status) > finding.Severity(worst) {
				t.Fatalf("finding %d (%s) sorts above the one before it (%s)", i, fnd.Status, worst)
			}
			worst = fnd.Status
			if fnd.Check == "" || fnd.Message == "" {
				t.Fatalf("finding %d has no check or no message: %+v", i, fnd)
			}
		}

		// 6. Nothing may claim a size when no hello reached the wire — the
		//    audit's own bug, stated as a property.
		sent := false
		for _, r := range results {
			if r.HelloBytes > 0 {
				sent = true
			}
		}
		if !sent {
			for _, fnd := range rep.Finding {
				if fnd.Unit == "bytes" && fnd.Value != nil && *fnd.Value != 0 {
					t.Fatalf("finding %q reports %v bytes and no hello was ever sent", fnd.Check, *fnd.Value)
				}
			}
		}
	})
}
