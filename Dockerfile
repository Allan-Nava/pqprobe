# A static binary on scratch. pqprobe opens TLS connections and reads the
# certificates the peer sends; it verifies the chain against the system roots
# when they are there, so the image carries CA certificates and nothing else.
# There is no shell in it — a container that can only run one program is one
# less thing to reason about when it is pointed at production endpoints.
FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /pqprobe ./cmd/pqprobe

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /pqprobe /pqprobe
USER 65534:65534
ENTRYPOINT ["/pqprobe"]
CMD ["help"]
