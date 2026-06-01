# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:8.0-jammy AS build

WORKDIR /build

# Restore first (layer-cache NuGet) — csproj only depends on the BCL, so this
# is fast and offline-friendly.
COPY PolicyLsp.csproj ./
RUN dotnet restore PolicyLsp.csproj

# Build a self-contained, trimmed single-file binary for linux-x64.
COPY . .
RUN dotnet publish PolicyLsp.csproj -c Release -r linux-x64 \
        --self-contained true \
        -p:PublishSingleFile=true \
        -o /out

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Self-contained build needs only the OS + ICU-less globalization (the project
# sets InvariantGlobalization), so the runtime-deps image is sufficient.
FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy AS runtime

WORKDIR /app
COPY --from=build /out/tsm-policy-lsp /app/tsm-policy-lsp

# The LSP speaks over stdio by default; expose nothing. Operators invoke it as
# the policy language server from an editor or the admin tooling.
ENTRYPOINT ["/app/tsm-policy-lsp"]
