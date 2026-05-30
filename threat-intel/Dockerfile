FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build
COPY go.mod go.sum ./
COPY . .
# NOTE: go-redis v9's *test* deps reference a dead repo (bsm/gredis, 404), which
# breaks `go mod download` (it walks test deps). `-mod=mod` on `go build` fetches
# only the build deps we actually need and updates go.sum in-layer.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w" \
    -o tsm-threat-intel ./cmd/threat-intel

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/tsm-threat-intel /usr/local/bin/tsm-threat-intel

EXPOSE 9100
ENTRYPOINT ["/usr/local/bin/tsm-threat-intel"]
