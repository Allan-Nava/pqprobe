// A module of its own, like contrib/utls (PQ-19).
//
// A QUIC stack is a dependency, and the root module has none — enforced in CI
// and stated in INTENT.md. Keeping it here means the default pqprobe stays
// dependency-free and this is built only by whoever asks the HTTP/3 question.
module github.com/Allan-Nava/pqprobe/contrib/quic

go 1.26.0

replace github.com/Allan-Nava/pqprobe => ../..

require (
	github.com/Allan-Nava/pqprobe v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.62.0
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
