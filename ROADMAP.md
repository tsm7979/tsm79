# Roadmap

The public roadmap. Dates are intent, not commitment.

## Now — Q2 2026 (shipping)

- **Polyglot stack v3.0** — Rust dataplane, Python ML detector, Go control-plane / threat-intel / overlay-node, Java admin-api, .NET policy-lsp, C++ wasmtime edge, eBPF/XDP packet authority, TypeScript dashboard, MV3 extension. **Done — landed on `main`.**
- **Sovereign overlay (`.tsm`) — slice 1 + 2** — self-certifying names, signed `NameRecord`, base32 derive_address, local resolver with anti-hijack + anti-replay, `/_tsm/<name>` gateway, Go libp2p DHT node, MV3 browser extension front-door. **Done.**
- **Cinematic landing v5 (LIVE)** — WebGL backdrop, 3-mesh scroll-tied crossfade, OFL-only typography, mailto CTAs. <https://www.thesovereignmechanica.ai/>. **Done.**

## Next — Q3 2026

- **#28 — Wire dataplane → gRPC + edge on request path.** Wasm edge call from the dataplane, completing the C++/V8 + WebAssembly edge-compute slice.
- **#31 — rustc 1.95.0 ICE workaround on dataplane test/dev builds.** Pin a known-good toolchain or upstream a minimal repro to rust-lang.
- **#35 — Multi-node DHT mesh test.** docker network + 2 `tsm-overlay-node` peers, cross-implementation propagation verified end-to-end through libp2p Kademlia.
- **Quarantine UI in the dashboard.** Review queue, decision audit, human-in-the-loop reinforcement signal back into the detector.
- **Per-tenant rule import/export.** Operators move policy across workspaces with one CLI command, signed bundles.
- **SDK polish.** Stabilise the Python SDK; add Node and Go SDKs to parity.

## Later — Q4 2026

- **Token-budget enforcement.** Per-workspace and per-key spend ceilings tracked through the existing `tokens_prompt_total` / `tokens_completion_total` counters.
- **Detector model card v1.** Reproducible training set, fairness audit, drift monitoring, confidence calibration curves.
- **`.tsm` overlay — slice 3.** Mirror replication, signed mirror lists, geographic failover. Begin federation experiments with a second independent DHT.
- **Public threat-intel feed.** Curated, signed, expiring — operators subscribe over the gRPC channel.
- **Hosted control plane.** Optional, opt-in — same dataplane image, hosted policy and audit, BYO data plane.

## 2027 candidate

- **BGP anycast PoPs.** Layer-0 routing of provider prefixes through TSM-operated PoPs. ExaBGP announces, XDP enforces. Latency floor in low-double-digit microseconds.
- **Sovereign overlay v2.** Quorum-signed names, time-locked rotation, deniable record types. Spec published as a draft RFC.
- **`tsm-pq` — post-quantum overlay signatures.** Hybrid Ed25519 + ML-DSA-65, default-on.
- **Detector v2.** Smaller models, longer context, on-device CPU-only inference target. Goal: dataplane → detector hop fits in p99 ≤ 2ms on commodity x86_64.
- **Multi-region active-active.** ClickHouse sharded, Postgres logical replication, audit-chain merge protocol.

## Won't Do

- A SaaS-only product. The data plane runs in your perimeter, on your iron.
- A telemetry-back-to-vendor mode. Operators control their data.
- A "smart" mode that overrides operator policy. The firewall does what the policy says, every time, even when it's "wrong".
- An autoscan-and-classify-other-people's-content product. We govern your inflight prompts, nothing else.

## How to Influence the Roadmap

- Open a [discussion](https://github.com/tsm7979/tsm79/discussions) titled `[RFC] <thing>` with a problem statement, three options, and a recommendation
- Open an issue with the `proposal` label
- Send a PR — a working prototype is the most persuasive RFC

Maintainer email for strategic conversations: <founder@thesovereignmechanica.ai>.
