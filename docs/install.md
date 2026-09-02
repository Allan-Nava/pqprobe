# Install

## Go

```sh
go install github.com/Allan-Nava/pqprobe/cmd/pqprobe@latest
```

Go 1.25 or newer. The hybrid group `X25519MLKEM768` comes from the standard
library, which is why the tool has no dependencies at all.

## From source

```sh
git clone https://github.com/Allan-Nava/pqprobe
cd pqprobe
go build -o pqprobe ./cmd/pqprobe
./pqprobe probe example.com
```

## Docker

The image is `scratch` plus the binary and the CA bundle — no shell, nothing
else to reason about when it is pointed at production endpoints.

```sh
docker build -t pqprobe .
docker run --rm pqprobe probe example.com
```

## What it needs

Outbound TCP to the endpoints being probed, and nothing else. No agent on the
targets, no credentials, no configuration file.
