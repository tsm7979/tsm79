# TSM79 — Sovereign AI Control Plane

> **SOVEREIGN. CONTROL. GOVERN.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Live: thesovereignmechanica.ai](https://img.shields.io/badge/live-thesovereignmechanica.ai-c7f23e)](https://www.thesovereignmechanica.ai/)
[![Dataplane: 237 tests](https://img.shields.io/badge/dataplane-237%20tests-c7f23e)](dataplane/)

TSM79 is an inline AI control plane — a low-latency proxy that sits between your application and every model you use (public, private, sovereign). Every prompt is evaluated before it leaves the perimeter: PII is detected and redacted, secrets are blocked, the request is routed by policy, and the whole event is committed to a tamper-evident audit ledger. Prevention-first. By design.

Built by **The Sovereign Mechanica** (TSM Pvt Ltd) — the live marketing surface is at <https://www.thesovereignmechanica.ai/>.

---

## What you get

| Verdict | Behaviour | HTTP |
|---|---|---|
| `allow` | forwarded unchanged | upstream's |
| `redact` | PII / secret spans stripped, forwarded sanitised | upstream's |
| `route_local` | held inside your perimeter (Ollama / VPC / on-prem) | upstream's |
| `quarantine` | held for human review — not forwarded, not denied | **202** |
| `block` | refused at the gate, never sent upstream | **400** |

Detection coverage on the local fast path:

| Type | Method | Severity |
|---|---|---|
| OpenAI / Anthropic / GitHub / AWS / Stripe / HuggingFace / GitLab / SendGrid keys | Known prefix + min-length | critical |
| Private keys, JWTs | Structural parse | critical |
| SSN, credit cards | Regex + Luhn | high |
| Email, phone, IPv4 | Regex + context negation | medium |
| High-entropy payloads | Shannon (≥ 4.5 bits/char) | high |
| Jailbreak / prompt-injection | Pattern + BPE token-splitting | critical — blocked |
| Ambiguous PII (NER signal) | ONNX heuristic → gRPC escalation → quarantine | varies |

When the fast path is uncertain, escalation goes to the Python detector over gRPC; the Rust core never leaves microsecond response times for the clean case.

---

## Run the enterprise stack

The full stack (dataplane, detector, control-plane, threat-intel, admin-api, dashboard, observability) is one compose file:

```bash
git clone https://github.com/tsm7979/tsm79.git
cd tsm79
cp .env.example .env       # fill in CLICKHOUSE_PASSWORD + provider keys
docker compose -f docker-compose.enterprise.yml up -d
```

You'll have:

| Endpoint | Port | What it is |
|---|---|---|
| Dataplane HTTP | `:8080` | OpenAI-compatible proxy — point your SDK base_url here |
| Dataplane `/metrics` | `:8080/metrics` | Prometheus exposition (latency, verdicts, tokens-per-provider) |
| Dataplane `/_tsm/resolve/<name>` | `:8080` | Sovereign-overlay name resolution |
| Detector gRPC | `:50051` | Python ML detector (NER + classifier escalation) |
| Admin API | `:8088` | Spring Boot control plane (workspace/policy/key mgmt) |
| Dashboard | `:3000` | Next.js operator UI |
| Postgres | `:5432` | Audit ledger + Merkle chain |
| ClickHouse | `:8123` | Analytics ingest (`tsm.ai_requests` rows) |
| Redis | `:6379` | Rate limit + session pinning |

Point your existing OpenAI SDK at the dataplane and stop touching application code:

```bash
export OPENAI_BASE_URL=http://localhost:8080
python your_existing_app.py
```

---

## Architecture — best language per layer

Each layer in the language that earns its place. Nothing is monolithic, nothing is Python by default.

```
┌──────────────────────────────────────────────────────────────────────┐
│  Client SDK / curl / dashboard                                       │
└─────────────────────┬────────────────────────────────────────────────┘
                      │ OpenAI-compatible HTTP/1.1 (+ SSE)
                      ▼
┌──────────────────────────────────────────────────────────────────────┐
│  dataplane/ — Rust (the inline AI firewall)                          │
│    • h1 / h2 / hpack parsers, TLS + mTLS, conn pool, rate limit      │
│    • detect: regex set + Aho-Corasick prefilter + BPE structural     │
│              + entropy + ONNX heuristic + NER trigger                │
│    • policy: rule engine + builtin rules (incl. quarantine)          │
│    • overlay: self-certifying .tsm names + gateway                   │
│    • audit: Merkle chain → Postgres                                  │
│    • observability: ClickHouse JSONEachRow + Prometheus              │
└────┬──────────────────┬───────────────────┬───────────────┬──────────┘
     │ gRPC             │ HTTP              │ Postgres      │ ClickHouse
     ▼                  ▼                   ▼               ▼
┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ detector │   │ control-plane│   │   audit      │   │ analytics    │
│ Python   │   │ Go           │   │  ledger      │   │  events      │
│ (ML +    │   │ (config /    │   │              │   │              │
│  NER)    │   │  threat-intel│   │              │   │              │
└──────────┘   └──────────────┘   └──────────────┘   └──────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  Companions, each in its right language                              │
├──────────────────────────────────────────────────────────────────────┤
│  admin-api/      Java (Spring Boot) — workspace / policy / key REST  │
│  policy-lsp/     C# (.NET LSP)      — policy YAML diagnostics in IDE │
│  edge/           C++ (wasmtime)     — sandboxed Wasm edge workers    │
│  overlay-node/   Go (libp2p)        — sovereign-overlay Kademlia DHT │
│  ebpf-loader/    Rust + C variants  — XDP/TC kernel packet authority │
│  dashboard/      TypeScript (Next)  — operator UI                    │
│  landing-v5/     static (WebGPU)    — public marketing — LIVE        │
│  extension/      MV3 (TypeScript)   — browser front-door for .tsm    │
└──────────────────────────────────────────────────────────────────────┘
```

The dataplane is the only component on the request hot path. Everything else is async, optional, or operator-facing.

---

## The sovereign overlay (`.tsm`)

An ICANN-free namespace that rides on top of the existing internet — Tor/IPFS-class, opt-in, governed by the same TSM dataplane firewall.

- **Names are Ed25519 keypairs.** A `.tsm` name is bound to a public key by a signed `NameRecord`; the holder of the private key owns the binding. Anyone can verify offline. Forged signatures, hijack attempts (rebinding to a different key), and stale-sequence replays are rejected at the resolver.
- **Resolved through `/_tsm/resolve/<name>`** on the dataplane. Self-certifying addresses derived as `<base32(pubkey)>.tsm` — the Tor v3 `.onion` model.
- **Loaded through `/_tsm/<name>`** — the gateway fetches the resolved endpoint AND runs the content through `Detector::scan` before serving it. Malicious overlay content is blocked at the door, the same way it is on the AI request path. The firewall governs the new network space for free.
- **DHT propagation** via the Go `overlay-node/` (libp2p Kademlia under a dedicated `/tsm` protocol prefix — isolated from the public IPFS DHT). The Rust and Go sides share byte-compatible signing bytes, so cross-implementation propagation is verifiable.
- **Front-door**: the MV3 browser extension in `extension/` lets the user type `tsm hub` in the address bar and reach the gateway with no DNS leak.

See `dataplane/src/overlay/`, `overlay-node/`, `extension/`.

---

## Repository layout

```
.
├── dataplane/         Rust — the inline AI firewall (237 tests)
├── detector/          Python — ML detector (gRPC + HTTP), NER escalation
├── control-plane/     Go — config + workspace + key store
├── threat-intel/      Go — IP reputation feeds
├── admin-api/         Java (Spring Boot) — operator REST
├── policy-lsp/        C# (.NET) — policy DSL language server
├── edge/              C++ (wasmtime) — Wasm worker host
├── overlay-node/      Go (libp2p) — sovereign overlay DHT node
├── ebpf-loader/       Rust — XDP/TC loader (Aya variant)
├── ebpf-loader-c/     C — XDP/TC loader (libbpf variant, default in CI)
├── ebpf/              eBPF/XDP C — packet-authority programs
├── dashboard/         TypeScript (Next.js) — operator UI
├── landing/           TypeScript (Vite) — older landing iteration
├── landing-v4/        static — brand-correct sovereign landing kit
├── landing-v5/        static — cinematic upgrade (LIVE)
├── extension/         MV3 — browser front-door for the .tsm overlay
├── proto/             Protobufs (dataplane↔detector gRPC)
├── observability/     ClickHouse schema + Rust ingestor
├── deploy/            Postgres migrations, nginx confs
├── tests/             Cross-component end-to-end tests
└── docker-compose.enterprise.yml
```

---

## Detection — anything past the regex set

The fast path stays microsecond. When it's uncertain, two escalation hops:

1. **In-Rust ONNX heuristic** (`dataplane/src/detect/onnx_engine.rs`) — secret/jailbreak/PII-leak labels with confidence. If confident enough to act (≥ 0.85) or low enough to dismiss (< 0.70 and `Clean`), decided locally.
2. **Python detector over gRPC** (`detector/grpc_server.py`) — NER + classifier for content the Rust ONNX path is genuinely unsure about. The 0.70–0.85 dead zone is preserved as `Ambiguous` rather than silently waved through — fail-secure.
3. **Quarantine** for content the ML triage couldn't resolve and that carries a NER signal (`NER_REVIEW`). Held at HTTP 202 for human review, audited as `quarantine`, never forwarded.

The dead-zone preservation is what makes quarantine reachable end-to-end — and what closes a fail-OPEN gap that existed before.

---

## Brand and voice

Operator-facing copy (CLI, dashboard, marketing) speaks in the **TSM voice** — terse, mechanical, em-dash-heavy, sovereign-agency register. Visual grammar is square corners, hairline borders, a single `#C7F23E` (`--signal`) accent per fold, mask-wipe reveals, no drop shadows, no gradients.

The full brand spec, design tokens, and component kit live in a separate **TSM — Sovereign Design System** distribution. The public landing (`landing-v5/`) is the canonical rendering of it.

What we never write: *empower / unlock / seamless / leverage / revolutionary / AI-powered*.

---

## License

MIT — see [LICENSE](LICENSE).

Trade name: **The Sovereign Mechanica.** Legal entity: TSM Pvt Ltd. Contact: <founder@thesovereignmechanica.ai>.
