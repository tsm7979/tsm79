# TSM overlay-node — libp2p Kademlia DHT name peer (Phase 2a).
# Multi-stage: compile a static Go binary, ship on distroless nonroot.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
# `go mod tidy` resolves the full go-libp2p dependency graph + writes go.sum.
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /overlay-node .

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
LABEL org.opencontainers.image.title="TSM overlay-node"
LABEL org.opencontainers.image.description="libp2p Kademlia DHT peer for the ICANN-free .tsm namespace"
COPY --from=build /overlay-node /usr/local/bin/overlay-node
ENV TSM_OVERLAY_LISTEN="/ip4/0.0.0.0/tcp/4001" \
    TSM_OVERLAY_API=":7700"
EXPOSE 4001 7700
ENTRYPOINT ["/usr/local/bin/overlay-node"]
