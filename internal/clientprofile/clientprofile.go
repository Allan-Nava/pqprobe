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

import (
	"crypto/tls"
	"fmt"
	"strings"
)

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
	// Pad is roughly how many bytes of filler to add to the ClientHello, for
	// the size sweep. See TLSConfig: the filler is ALPN, because Go exposes no
	// padding extension and in TLS 1.3 the cipher list is fixed.
	Pad int
}

// TLSConfig builds the client configuration for the profile.
//
// InsecureSkipVerify is always set, and that is not a shortcut: pqprobe asks
// "did the handshake complete?", and an expired certificate answering "no"
// would make a capability report say something about capability that is not
// true. The chain is verified separately, from the certificates the peer
// actually sent, so an expiry problem is reported as an expiry problem.
func (p Profile) TLSConfig(serverName string, alpn []string) *tls.Config {
	if p.Pad > 0 {
		alpn = append(append([]string{}, alpn...), padProtos(p.Pad)...)
	}
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

// GroupPrefix marks a synthetic profile that offers a single key exchange
// group. It is a prefix rather than a flag because the name travels through
// every result, finding and JSON document, and one place has to be able to say
// "this was a group probe, not a client".
const GroupPrefix = "group:"

// Probed is the group set the per-group pass walks: every group Go can offer,
// hybrid first. Written out rather than derived, for the same reason a profile
// pins its groups — a toolchain upgrade must not change what a run proves.
var Probed = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// GroupProbeName is the profile name for a single-group probe.
func GroupProbeName(id tls.CurveID) string { return GroupPrefix + GroupName(id) }

// IsGroupProbe reports whether a profile name came from GroupProbes. The
// verdict uses it to keep these results out of the classification: a
// single-group ClientHello answers "does the peer accept this group", which is
// a different question from "can a realistic client connect".
func IsGroupProbe(name string) bool {
	return len(name) > len(GroupPrefix) && name[:len(GroupPrefix)] == GroupPrefix
}

// GroupProbes is one profile per group in Probed, each offering that group
// alone.
//
// TLS 1.3 is pinned at both ends deliberately: post-quantum key exchange lives
// in the 1.3 key_share extension, and a probe that fell back to 1.2 would
// report a group as refused when the peer never had the chance to pick it.
func GroupProbes() []Profile {
	out := make([]Profile, 0, len(Probed))
	for _, id := range Probed {
		name := GroupName(id)
		out = append(out, Profile{
			Name:       GroupProbeName(id),
			Summary:    "TLS 1.3 offering " + name + " and nothing else",
			Clients:    "no real client dials like this — it is a question about " + name + ", not a client class",
			Groups:     []tls.CurveID{id},
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			OffersPQ:   IsPQ(id),
			RequiresPQ: IsPQ(id),
		})
	}
	return out
}

// SizePrefix marks a profile that exists to make the ClientHello a given size.
const SizePrefix = "size:"

// SizeTargets is the sweep, in bytes of ClientHello. The first is above what a
// hybrid hello already costs (~1.5 KB), and the rest climb past the sizes that
// break things in practice: one TCP segment, two, four, and the largest record
// a TLS implementation has to accept.
var SizeTargets = []int{2048, 3072, 4096, 6144, 8192, 12288}

// IsSizeProbe reports whether a profile name came from SizeProbes. The verdict
// keeps these out of the classification: a padded hello answers "how big is too
// big", not "can a realistic client connect".
func IsSizeProbe(name string) bool {
	return len(name) > len(SizePrefix) && name[:len(SizePrefix)] == SizePrefix
}

// SizeProbes is the sweep: the realistic hybrid client, grown in steps.
//
// It is the hybrid hello that middleboxes choke on, so that is the shape being
// padded — with ALPN entries, because Go exposes no padding extension and the
// TLS 1.3 cipher list is not the caller's to grow. That has a consequence the
// report has to carry: a peer that inspects ALPN may treat these differently
// from a hello made large by a key share. The number is still the number at
// which *this* peer stopped answering.
func SizeProbes() []Profile {
	hybrid := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	out := make([]Profile, 0, len(SizeTargets))
	for _, n := range SizeTargets {
		out = append(out, Profile{
			Name:       fmt.Sprintf("%s%d", SizePrefix, n),
			Summary:    fmt.Sprintf("the hybrid client, padded to about %d bytes of ClientHello", n),
			Clients:    "no client dials like this — it is a question about size, not about a client",
			Groups:     hybrid,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			OffersPQ:   true,
			// The hybrid hello is already around 1.5 KB, so the filler is the
			// difference. Negative means nothing to add.
			Pad: n - 1500,
		})
	}
	return out
}

// padProtos builds ALPN entries adding about n bytes. Each entry costs one
// length byte plus its text, and the wire format caps an entry at 255 bytes.
func padProtos(n int) []string {
	const max = 255
	var out []string
	for n > 0 {
		size := max
		if n < max+1 {
			size = n - 1
		}
		if size < 1 {
			break
		}
		// Recognisable in a packet capture, and not a real protocol name.
		s := fmt.Sprintf("pqprobe-pad-%d", len(out))
		if len(s) > size {
			s = s[:size]
		}
		out = append(out, s+strings.Repeat("x", size-len(s)))
		n -= size + 1
	}
	return out
}

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
