#!/bin/sh
# interop.sh — assert pqprobe's classes against TLS stacks that are not Go.
#
#   sh scripts/interop.sh            run the lab
#   sh scripts/interop.sh --list     print the cases and exit
#
# Every other test in this repository stands up a listener from Go's own
# crypto/tls, which means the distinction the whole tool rests on — a peer that
# declined against a peer that vanished — has only ever been checked against an
# implementation that shares our bugs. This lab points pqprobe at OpenSSL 3.5
# and nginx and asserts the class each configuration deserves.
#
# It paid for itself before it was written: the first container stood up by hand
# was an OpenSSL server speaking only SecP256r1MLKEM768, and pqprobe called a
# fully post-quantum endpoint `tls-broken` (PQ-59, PQ-60).
#
# The containers live here and in CI, never in `go.mod` and never in the binary:
# the zero-dependency property is about what ships, and this is what proves what
# ships is right. Without Docker the lab skips rather than failing — a
# maintainer's laptop is not a reason to block a release, and CI has it.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

img=${INTEROP_IMAGE:-alpine:edge}
nginx_img=${INTEROP_NGINX_IMAGE:-nginx:alpine}
port=${INTEROP_PORT:-14433}

pass=0
fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# The cases: name | server | expected class | extra pqprobe flags | a substring
# the JSON report must contain.
#
# `server` is the argument to the runner below, not a shell command, so a case
# cannot smuggle in a step the report does not describe. The last field is how a
# case asserts more than a class — the sweep against the wall has to *find* the
# wall, not merely be graded next to it.
cases='
openssl-hybrid-and-classical|openssl X25519MLKEM768:X25519:P-256|pq-ready||
openssl-classical-only|openssl X25519:P-256|pq-blind||
openssl-p256-hybrid-only|openssl SecP256r1MLKEM768|pq-other-hybrid|--per-group|
openssl-tls12-ceiling|openssl-tls12 X25519:P-256|no-tls13||
openssl-behind-a-wall|wall X25519MLKEM768:X25519:P-256|pq-intolerant||
openssl-wall-size-sweep|wall X25519MLKEM768:X25519:P-256|pq-intolerant|--size-sweep|"check": "size-limit"
nginx-classical|nginx|pq-blind||
'

if [ "${1:-}" = "--list" ]; then
	echo "$cases" | while IFS='|' read -r name server class flags expect; do
		[ -n "$name" ] || continue
		printf '  %-28s %-40s expects %s %s %s\n' "$name" "$server" "$class" "$flags" "$expect"
	done
	exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "interop: docker is not installed — skipping the lab (CI runs it)"
	exit 0
fi
if ! docker info >/dev/null 2>&1; then
	echo "interop: docker is installed but not running — skipping the lab (CI runs it)"
	exit 0
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-interop.XXXXXX")
name=pqprobe-interop
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || :; rm -rf "$tmp"; }
trap cleanup EXIT INT HUP TERM

echo "building the binary under test"
go build -o "$tmp/pqprobe" ./cmd/pqprobe

# A self-signed certificate is all these servers need: pqprobe never verifies
# during the handshake, and the chain is graded separately.
cert_cmd='openssl req -x509 -newkey rsa:2048 -keyout /k.pem -out /c.pem -days 3 -nodes -subj /CN=interop >/dev/null 2>&1'

# In a loop, deliberately: `openssl s_server` serves one connection at a time and
# exits on some of them — a client that completes a handshake and closes without
# reading the -www response is one — so a single invocation makes every case
# after the first look like a dead port. Diagnosed the hard way: five cases went
# `tls-broken` at once, which is never what five different servers do.
serve() {
	printf 'while :; do openssl s_server -accept 4433 -cert /c.pem -key /k.pem -www -quiet %s >/dev/null 2>&1 || true; done' "$1"
}

# inner_port is where the server listens *inside* the container, which is the
# only place readiness can honestly be asked about — see ready().
inner_port=4433

start() { # start <kind> <groups>
	docker rm -f "$name" >/dev/null 2>&1 || :
	inner_port=4433
	[ "$1" = nginx ] && inner_port=443
	case "$1" in
	openssl)
		docker run -d --rm --name "$name" -p "$port:4433" "$img" sh -c \
			"apk add --no-cache openssl >/dev/null 2>&1; $cert_cmd; $(serve "-groups $2")" >/dev/null
		;;
	openssl-tls12)
		docker run -d --rm --name "$name" -p "$port:4433" "$img" sh -c \
			"apk add --no-cache openssl >/dev/null 2>&1; $cert_cmd; $(serve -no_tls1_3)" >/dev/null
		;;
	wall)
		# The failure this tool exists for, reproduced rather than described: a
		# packet filter that drops anything over 1000 bytes is what a middlebox
		# unable to carry the second segment of a large ClientHello does to the
		# connection. The classical hello (~285 B) crosses; the hybrid one
		# (~1.5 KB) never arrives, and the peer never gets to refuse it.
		docker run -d --rm --name "$name" --cap-add=NET_ADMIN -p "$port:4433" "$img" sh -c \
			"apk add --no-cache openssl iptables >/dev/null 2>&1; iptables -A INPUT -p tcp --dport 4433 -m length --length 1000:65535 -j DROP; $cert_cmd; $(serve "-groups $2")" >/dev/null
		;;
	nginx)
		docker run -d --rm --name "$name" -p "$port:443" "$nginx_img" sh -c \
			"apk add --no-cache openssl >/dev/null 2>&1; $cert_cmd; printf 'events{}\nhttp{server{listen 443 ssl;ssl_certificate /c.pem;ssl_certificate_key /k.pem;ssl_protocols TLSv1.2 TLSv1.3;ssl_ecdh_curve X25519:prime256v1;return 200 \"ok\";}}\n' > /etc/nginx/nginx.conf; nginx -g 'daemon off;'" >/dev/null
		;;
	*)
		echo "interop: unknown server kind $1" >&2
		return 1
		;;
	esac
}

# ready waits for the port to answer TLS at all, using the binary under test:
# anything else here would be a second opinion about reachability.
#
# The local variable is `seen`, deliberately: in POSIX sh there are no locals,
# and the first version of this called it `class` — which silently overwrote the
# expected class of the case being run, so every assertion compared a result
# against itself. Four cases "failed" while the tool was right about all four.
# ready waits for the server *inside* the container to be listening.
#
# Not from the outside: `docker run -p` publishes the port immediately, so a
# connection from here succeeds — and the handshake fails — while the image is
# still installing OpenSSL. Waiting on that answered "ready" within a second and
# every case after the first came back `tls-broken`, which is never what five
# different servers do at once.
ready() {
	i=0
	while [ "$i" -lt 60 ]; do
		if docker exec "$name" sh -c "nc -z 127.0.0.1 $inner_port" >/dev/null 2>&1; then
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	return 1
}

printf '\npqprobe against stacks that are not Go:\n'
echo "$cases" | while IFS='|' read -r case_name server class flags expect; do
	[ -n "$case_name" ] || continue
	# shellcheck disable=SC2086
	if ! start $server; then
		notok "$case_name: the server would not start"
		continue
	fi
	if ! ready; then
		notok "$case_name: the server never answered on $port"
		docker logs "$name" 2>&1 | tail -3
		continue
	fi
	# shellcheck disable=SC2086
	"$tmp/pqprobe" probe "127.0.0.1:$port" --timeout 5s --json $flags > "$tmp/report.json" 2>/dev/null || :
	got=$(sed -n 's/.*"class": *"\([a-z0-9-]*\)".*/\1/p' "$tmp/report.json" | head -1)
	if [ "$got" != "$class" ]; then
		notok "$case_name is $got, want $class"
	elif [ -n "$expect" ] && ! grep -q "$expect" "$tmp/report.json"; then
		notok "$case_name is $class but the report has no $expect"
	else
		ok "$case_name is $class${expect:+ (with $expect)}"
	fi
	docker rm -f "$name" >/dev/null 2>&1 || :
done > "$tmp/results"

cat "$tmp/results"
fail=$(grep -c '  FAIL' "$tmp/results" || :)
pass=$(grep -c '  ok  ' "$tmp/results" || :)
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
