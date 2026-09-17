package output

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// The generator behind docs/schema.md (PQ-70).
//
// It lives in a test file on purpose: the page is a gate, not a feature, and
// nothing in the shipped binary should carry a reflection walk over its own
// output types. `go test ./internal/output/ -update` rewrites the page;
// TestTheSchemaPageMatchesTheTypes fails the build when it drifts.
//
// The field names and their types come from the structs, so they cannot be
// wrong. What each field *means* cannot be reflected over, so it lives in
// fieldMeaning below — and a field with no entry is a failing test rather than
// an empty cell, because an undocumented field is a field a consumer guesses
// at.

// fieldMeaning is keyed "Type.json_name".
var fieldMeaning = map[string]string{
	// The --json envelope.
	"Document.schema":  "which document contract this is; see the number at the top of this page",
	"Document.tool":    "always `pqprobe` — a document that says anything else is not one of ours",
	"Document.reports": "one entry per endpoint probed, in the order the run produced them",

	// verdict.Report.
	"Report.target":   "the endpoint as it was probed, `host:port` (with ` (sni …)` appended when the server name differs from the host)",
	"Report.class":    "what this endpoint is, in one word — see [Findings](findings.md) for the list",
	"Report.results":  "one entry per client profile, in the order they were dialled",
	"Report.findings": "every statement about this endpoint, worst first",

	// probe.Result.
	"Result.profile":               "the client shape that was dialled: a capability class, never a fingerprint of a real client",
	"Result.ok":                    "whether that shape completed a handshake",
	"Result.kind":                  "how the attempt ended: `ok`, `alert`, `reset`, `timeout`, `eof`, `refused`, `not-tls`, `dns`, `proto` or `other`",
	"Result.error":                 "the error as the TLS stack reported it, when the attempt did not complete",
	"Result.tls_version":           "the negotiated version, e.g. `TLS 1.3`",
	"Result.group":                 "the negotiated key exchange group, e.g. `X25519MLKEM768`",
	"Result.cipher":                "the negotiated cipher suite",
	"Result.alpn":                  "the protocol agreed by ALPN, when one was",
	"Result.elapsed_ns":            "how long the attempt took, in nanoseconds",
	"Result.pq":                    "true when the negotiated key exchange was a post-quantum hybrid",
	"Result.chain":                 "the certificate chain as the peer sent it, leaf first",
	"Result.chain_verified":        "whether that chain verifies against the system roots — verified after the handshake, never by the dialler",
	"Result.chain_error":           "why the chain did not verify",
	"Result.attempts":              "how many handshakes this result is based on: two when an abrupt failure was re-dialled to confirm it",
	"Result.first_kind":            "how the first attempt ended, when there was more than one",
	"Result.reproduced":            "both attempts ended abruptly: the refusal is a wall rather than a flap",
	"Result.flapped":               "the first attempt ended abruptly and the second connected: the endpoint works and is unstable",
	"Result.ech_accepted":          "the peer accepted Encrypted Client Hello — read from the connection, never inferred from a handshake that merely succeeded",
	"Result.hello_bytes":           "the size on the wire of the first ClientHello record, measured rather than estimated",
	"Result.hello_count":           "how many ClientHellos went out; two means the peer sent a HelloRetryRequest",
	"Result.hrr":                   "the peer answered with a HelloRetryRequest: it asked for a different group, which costs a round trip",
	"Result.client_cert_requested": "the peer asked for a client certificate: this endpoint is mutual TLS",
	"Result.chain_bytes":           "what the whole chain cost on the wire, in bytes of DER — the headroom number for post-quantum certificates",
	"Result.peer_chain_len":        "how many certificates the peer sent; one means it sent the leaf alone",

	// probe.Cert.
	"Cert.bytes":      "the DER length the peer sent for this certificate",
	"Cert.subject":    "the certificate's subject common name",
	"Cert.issuer":     "the issuer's common name",
	"Cert.not_after":  "when the certificate expires, RFC 3339",
	"Cert.not_before": "when the certificate becomes valid, RFC 3339",
	"Cert.dns_names":  "the names the certificate is valid for",
	"Cert.is_ca":      "whether this certificate is a CA",
	"Cert.key_bytes":  "what this certificate's subjectPublicKeyInfo weighs in the DER the peer sent — one of the two inputs to the post-quantum projection",
	"Cert.sig_bytes":  "what this certificate's signature weighs in that same DER — the other input: an ML-DSA certificate is this certificate with those two fields replaced",

	// finding.Finding.
	"Finding.check":   "which statement this is — see [Findings](findings.md) for the list",
	"Finding.target":  "what the statement is about: the endpoint, or `host:port/profile` for a per-profile one",
	"Finding.status":  "`OK`, `WARN`, `BAD` or `ERROR`",
	"Finding.message": "the statement, in one line of prose; **never parse this**",
	"Finding.value":   "the number the statement is about, when there is one — read this rather than the message",
	"Finding.unit":    "what that number counts, e.g. `days`, `bytes`",
	"Finding.hint":    "what to do about it, naming the affected clients",

	// The wrapped findings document.
	"WrappedDocument.schema":   "which document contract this is",
	"WrappedDocument.check":    "always `pqprobe`",
	"WrappedDocument.status":   "the worst severity in the run, lower-cased",
	"WrappedDocument.summary":  "the one line a digest quotes when it has room for one",
	"WrappedDocument.findings": "the findings, worst first",

	"WrappedFinding.id":       "a stable fingerprint of this problem on this target — see below",
	"WrappedFinding.severity": "`ok`, `warn`, `bad` or `error`, lower-cased",
	"WrappedFinding.title":    "the finding's message",
	"WrappedFinding.detail":   "the finding's hint, when it has one",
	"WrappedFinding.target":   "what the finding is about",
	"WrappedFinding.check":    "which statement this is",
	"WrappedFinding.value":    "the number the statement is about, when there is one",
	"WrappedFinding.unit":     "what that number counts",
}

// documentTypes returns every struct type reachable from root, in the order a
// reader meets them, so the page reads top-down rather than alphabetically.
func documentTypes(root reflect.Type) []reflect.Type {
	var out []reflect.Type
	seen := map[reflect.Type]bool{}

	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		t = deref(t)
		if t.Kind() != reflect.Struct || t == reflect.TypeOf(time.Time{}) || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" || jsonName(f) == "" {
				continue
			}
			walk(f.Type)
		}
	}
	walk(root)
	return out
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	return t
}

// jsonName is the field's name in the document, or "" when it never appears.
func jsonName(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}

func omitEmpty(f reflect.StructField) bool {
	return strings.Contains(f.Tag.Get("json"), ",omitempty")
}

// jsonType is the field's type as a consumer sees it, not as Go spells it.
func jsonType(t reflect.Type) string {
	switch {
	case t == reflect.TypeOf(time.Time{}):
		return "string (RFC 3339)"
	case t == reflect.TypeOf(time.Duration(0)):
		return "number (nanoseconds)"
	}
	switch t.Kind() {
	case reflect.Ptr:
		return jsonType(t.Elem())
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Struct {
			return fmt.Sprintf("array of [`%s`](#%s)", t.Elem().Name(), anchor(t.Elem().Name()))
		}
		return "array of " + jsonType(t.Elem())
	case reflect.Struct:
		return fmt.Sprintf("[`%s`](#%s)", t.Name(), anchor(t.Name()))
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	}
	return t.Kind().String()
}

func anchor(name string) string { return strings.ToLower(name) }

// undescribedFields is every field that reaches a document with nothing in
// fieldMeaning to say what it is.
func undescribedFields() []string {
	var missing []string
	for _, t := range append(documentTypes(reflect.TypeOf(Document{})),
		documentTypes(reflect.TypeOf(WrappedDocument{}))...) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := jsonName(f)
			if f.PkgPath != "" || name == "" {
				continue
			}
			key := t.Name() + "." + name
			if fieldMeaning[key] == "" {
				missing = append(missing, key)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// table renders one struct as a Markdown table.
func table(b *strings.Builder, t reflect.Type) error {
	fmt.Fprintf(b, "### `%s`\n\n", t.Name())
	fmt.Fprintln(b, "| Field | Type | Present | Meaning |")
	fmt.Fprintln(b, "|---|---|---|---|")
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := jsonName(f)
		if f.PkgPath != "" || name == "" {
			continue
		}
		meaning := fieldMeaning[t.Name()+"."+name]
		if meaning == "" {
			return fmt.Errorf("no meaning for %s.%s", t.Name(), name)
		}
		present := "always"
		if omitEmpty(f) {
			present = "when set"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", name, jsonType(f.Type), present, meaning)
	}
	fmt.Fprintln(b)
	return nil
}

// promFamilies is the metric list, read back out of a rendered textfile rather
// than written down beside it: the HELP line a scrape sees is the description.
func promFamilies(reps []verdict.Report) ([][2]string, error) {
	dir, err := os.MkdirTemp("", "pqprobe-schema")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "pqprobe.prom")
	if err := Textfile(path, reps, time.Unix(0, 0)); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	for _, line := range strings.Split(string(body), "\n") {
		rest, ok := strings.CutPrefix(line, "# HELP ")
		if !ok {
			continue
		}
		name, help, _ := strings.Cut(rest, " ")
		out = append(out, [2]string{name, help})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the textfile carried no HELP lines")
	}
	return out, nil
}

// schemaPage renders docs/schema.md. The prose lives here rather than in the
// file, because a page half generated and half edited is a page where the
// edited half is stale.
func schemaPage(reps []verdict.Report) (string, error) {
	var b strings.Builder

	fmt.Fprintf(&b, `<!-- GENERATED by go test ./internal/output/ -update — do not edit by hand. -->

# Document schema

The shapes pqprobe writes for machines, and what a consumer may conclude from
them. The tables below are generated from the types that render the documents,
so a field here is a field the tool emits.

Today's `+"`schema`"+` is **%d**.

## What the number promises

`+"`schema`"+` moves when the **shape** moves: a field renamed or removed, an object
nested differently, an array that becomes an object. It does **not** move for:

- a new field — a parser that breaks on an unknown key was already broken;
- a new class, check, finding or profile — those are *values*, and new ones
  appear whenever the tool learns to say something new;
- a new metric family in the Prometheus textfile;
- any change to the wording of a `+"`message`"+`, `+"`title`"+`, `+"`hint`"+` or `+"`summary`"+`.
  Prose is for people: read `+"`value`"+`, `+"`unit`"+`, `+"`status`"+`, `+"`check`"+` and `+"`class`"+` instead.

A document that carries no `+"`schema`"+` at all was written before %s had the
field, and is read as this schema. A document carrying a **higher** number is
refused by `+"`--baseline`"+`: the fields it would be read for may mean something
else.

## The %s document

`+"```console"+`
$ pqprobe probe origin.example.com --json
`+"```"+`

`, Schema, "pqprobe", "`--json`")

	for _, t := range documentTypes(reflect.TypeOf(Document{})) {
		if err := table(&b, t); err != nil {
			return "", err
		}
	}

	fmt.Fprint(&b, "## The `--findings` array\n\n"+
		"`--findings` is the flat array — the [`Finding`](#finding) objects above and\n"+
		"nothing around them, worst first. An empty run emits `[]`, never `null`, so a\n"+
		"consumer that iterates does not have to special-case a healthy fleet.\n\n"+
		"It carries no `schema` field, because it has nowhere to carry one: the document\n"+
		"is an array. Its contract is the `Finding` table above, and it moves with the\n"+
		"same number.\n\n"+
		"## The `--findings=wrapped` document\n\n")

	for _, t := range documentTypes(reflect.TypeOf(WrappedDocument{})) {
		if err := table(&b, t); err != nil {
			return "", err
		}
	}

	fmt.Fprint(&b, "### What `id` is a fingerprint of\n\n"+
		"`id` exists so an aggregator can tell a finding it has already seen from a new\n"+
		"one. It is the first 6 bytes of `sha256(check + \"|\" + target)`, hex-encoded —\n"+
		"the identity of the **problem**, deliberately not of the sentence describing\n"+
		"it. A message carries days and byte counts that change on their own, and an id\n"+
		"derived from the text would report a new problem every morning.\n\n"+
		"Two findings of one check on one target in a single run would otherwise share\n"+
		"an id, so the second and later ones are suffixed `-2`, `-3`. The suffix is\n"+
		"part of the id and is stable for as long as the run keeps producing them in\n"+
		"the same order.\n\n"+
		"An id changes when the target changes — probing `origin.example:443` by name\n"+
		"and by address are two identities, because they are two things that can fail\n"+
		"separately.\n\n"+
		"## The Prometheus textfile\n\n"+
		"`--textfile` writes these families. The file is replaced whole, so a target\n"+
		"that stops being probed stops having series rather than keeping stale ones.\n\n"+
		"| Metric | Meaning |\n|---|---|\n")

	fams, err := promFamilies(reps)
	if err != nil {
		return "", err
	}
	for _, f := range fams {
		fmt.Fprintf(&b, "| `%s` | %s |\n", f[0], f[1])
	}

	fmt.Fprint(&b, "\nLabels are `target`, `class`, `profile` and `status`. A new label on an\n"+
		"existing family moves the schema; a new *value* of one does not.\n\n"+
		"## What is allowed to grow\n\n"+
		"- **Fields.** New ones appear in any of the objects above. Ignore what you do\n"+
		"  not know.\n"+
		"- **Values.** New classes, checks, kinds, profiles and groups appear as the\n"+
		"  tool learns to say more. Treat an unknown one as unknown rather than as an\n"+
		"  error, and never as `ok`.\n"+
		"- **Findings.** A run emits more of them over time. The number of findings is\n"+
		"  not a signal; their `status` is.\n\n"+
		"What will not change without the number moving: the name and nesting of every\n"+
		"field in the tables above, the meaning of `status` and `severity`, and what\n"+
		"`id` is computed from.\n")

	return b.String(), nil
}
