# TSM Control Plane — Go binary, distroless runtime
FROM golang:1.22-bookworm AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum* ./
RUN go mod download

# Build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /tsm-control-plane .

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /tsm-control-plane /tsm-control-plane

ENV TSM_CP_PORT=9090 \
    TSM_CP_LOG_LEVEL=info \
    TSM_CP_HEALTH_INTERVAL=10s

EXPOSE 9090

ENTRYPOINT ["/tsm-control-plane"]
