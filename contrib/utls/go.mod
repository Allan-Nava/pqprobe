// A module of its own, deliberately (PQ-10).
//
// uTLS is a dependency, and the root module has none — that is a product
// property enforced in CI, not an aesthetic: it is what makes the binary
// reasonable to run inside somebody else's production network. Keeping this
// here means the default pqprobe stays dependency-free and this is built only
// by whoever wants a real fingerprint.
module github.com/Allan-Nava/pqprobe/contrib/utls

go 1.25.0

require (
	github.com/Allan-Nava/pqprobe v0.24.0
	github.com/refraction-networking/utls v1.8.2
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

replace github.com/Allan-Nava/pqprobe => ../..
