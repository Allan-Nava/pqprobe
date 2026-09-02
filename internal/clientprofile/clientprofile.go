// Package clientprofile defines the client shapes pqprobe dials with.
//
// A profile is a *capability class*, never a fingerprint. pqprobe builds its
// ClientHello with Go's crypto/tls, so it cannot reproduce Chrome's extension
// order or CloudFront's exact cipher list, and it never claims to: what a
// profile pins down is which key exchange groups are offered and which TLS
// versions are acceptable. That is the property that decides whether a
// post-quantum-capable client can complete a handshake, and it is the property
// that broke origins in 2025 and 2026 when CDNs and browsers turned hybrid
// ML-KEM on by default.
//
// Clients names the real software that lands in the same class, and it exists
// so a report can say who is affected. It is a statement about capability, not
// a guarantee that the named client sends this exact ClientHello.
package clientprofile

import "crypto/tls"

// Profile is one client shape to dial with.
type Profile struct {
	Name    string
	Summary string
	// Clients names real software whose key exchange capability matches this
	// profile. Reports quote it; nothing branches on it.
	Clients string
	// Groups are the key exchange groups offered, in order. Empty means Go's
	// default set, which is deliberately not used by any profile: a default
	// that changes with the toolchain would silently change what a run proves.
	Groups     []tls.CurveID
	MinVersion uint16
	MaxVersion uint16
	// OffersPQ is true when the ClientHello carries a hybrid ML-KEM key share.
	OffersPQ bool
	// RequiresPQ is true when *only* post-quantum groups are offered, so a peer
	// without ML-KEM has no fallback and must refuse.
	RequiresPQ bool
}

// TLSConfig builds the client configuration for the profile.
//
// InsecureSkipVerify is always set, and that is not a shortcut: pqprobe asks
// "did the handshake complete?", and an expired certificate answering "no"
// would make a capability report say something about capability that is not
// true. The chain is verified separately, from the certificates the peer
// actually sent, so an expiry problem is reported as an expiry problem.
func (p Profile) TLSConfig(serverName string, alpn []string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // verified separately; see doc comment
		MinVersion:         p.MinVersion,
		MaxVersion:         p.MaxVersion,
		CurvePreferences:   p.Groups,
		NextProtos:         alpn,
	}
}

// All is the profile set, in the order a report reads best: the baseline first,
// then the two questions about post-quantum, then the version edges.
var All = []Profile{
	{
		Name:    "classic",
		Summary: "TLS 1.3 offering only classical groups (X25519, P-256)",
		Clients: "curl, openssl s_client, any pre-2024 client, and every health check you already run",
		Groups:  []tls.CurveID{tls.X25519, tls.CurveP256},
		// A baseline that allowed 1.2 would hide a 1.3 problem behind a
		// successful 1.2 handshake, and the baseline's job is to prove the
		// endpoint is reachable and serving TLS at all.
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	},
	{
		Name:    "pq-preferred",
		Summary: "TLS 1.3 offering hybrid ML-KEM first, with X25519 and P-256 behind it",
		Clients: "Chrome and Edge 131+, Firefox 132+, CloudFront and other CDNs with post-quantum enabled, Go 1.24+, OpenSSL 3.5+",
		Groups:  []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		// This is the profile that matters. A peer that cannot do ML-KEM is
		// still expected to complete it — by picking X25519, with or without a
		// HelloRetryRequest. A failure here is not "no post-quantum support",
		// it is "cannot talk to a client that merely offered it", and the
		// ~1.2 KB ClientHello that carries the ML-KEM key share is usually why.
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		OffersPQ:   true,
	},
	{
		Name:       "pq-only",
		Summary:    "TLS 1.3 offering only hybrid ML-KEM — no classical fallback",
		Clients:    "a client with post-quantum required, and the default of the next few years",
		Groups:     []tls.CurveID{tls.X25519MLKEM768},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		OffersPQ:   true,
		RequiresPQ: true,
	},
	{
		Name:       "tls13-only",
		Summary:    "TLS 1.3 required, classical groups",
		Clients:    "a modern client with TLS 1.2 disabled",
		Groups:     []tls.CurveID{tls.X25519, tls.CurveP256},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	},
	{
		Name:       "tls12",
		Summary:    "TLS 1.2 only, classical groups",
		Clients:    "old Java and .NET stacks, embedded set-top boxes, legacy CDN pull agents",
		Groups:     []tls.CurveID{tls.X25519, tls.CurveP256},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	},
}

// Default is the set dialled when no --profile is given: everything except the
// version edges, which answer a different question and double the connections.
var Default = []string{"classic", "pq-preferred", "pq-only"}

// ByName returns the named profile.
func ByName(name string) (Profile, bool) {
	for _, p := range All {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Names is every profile name, in All order.
func Names() []string {
	out := make([]string, 0, len(All))
	for _, p := range All {
		out = append(out, p.Name)
	}
	return out
}

// Select resolves a list of names to profiles, preserving All's order so a
// report always reads baseline-first regardless of how the flag was written.
// An unknown name is returned as-is for the caller to report.
func Select(names []string) ([]Profile, []string) {
	want := make(map[string]bool, len(names))
	var unknown []string
	for _, n := range names {
		if _, ok := ByName(n); !ok {
			unknown = append(unknown, n)
			continue
		}
		want[n] = true
	}
	var out []Profile
	for _, p := range All {
		if want[p.Name] {
			out = append(out, p)
		}
	}
	return out, unknown
}

// GroupName is the human name of a negotiated key exchange group. Go's own
// CurveID.String() is stable for the ones it knows, but an unknown group must
// still print as something an operator can look up, not as an empty string.
func GroupName(id tls.CurveID) string {
	switch id {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case 0:
		return ""
	default:
		return id.String()
	}
}

// IsPQ reports whether a negotiated group is a post-quantum hybrid.
func IsPQ(id tls.CurveID) bool { return id == tls.X25519MLKEM768 }
