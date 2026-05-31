<div align="center">

# TSM79 — Sovereign AI Control Plane

**SOVEREIGN. CONTROL. GOVERN.**

*The inline AI firewall. Every prompt evaluated before it leaves the perimeter.
PII detected. Secrets blocked. Policy enforced. Audit tamper-evident. By design.*

<br/>

[![CI](https://img.shields.io/github/actions/workflow/status/tsm7979/tsm79/ci.yml?branch=main&label=CI&style=for-the-badge&labelColor=000&color=c7f23e)](https://github.com/tsm7979/tsm79/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-c7f23e?style=for-the-badge&labelColor=000)](LICENSE)
[![Release](https://img.shields.io/github/v/tag/tsm7979/tsm79?label=release&style=for-the-badge&labelColor=000&color=c7f23e)](https://github.com/tsm7979/tsm79/releases)
[![Live](https://img.shields.io/badge/live-thesovereignmechanica.ai-c7f23e?style=for-the-badge&labelColor=000)](https://www.thesovereignmechanica.ai/)

[![Stars](https://img.shields.io/github/stars/tsm7979/tsm79?style=flat-square&labelColor=000&color=c7f23e)](https://github.com/tsm7979/tsm79/stargazers)
[![Discussions](https://img.shields.io/github/discussions/tsm7979/tsm79?style=flat-square&labelColor=000&color=c7f23e)](https://github.com/tsm7979/tsm79/discussions)
[![Last commit](https://img.shields.io/github/last-commit/tsm7979/tsm79/main?style=flat-square&labelColor=000&color=c7f23e)](https://github.com/tsm7979/tsm79/commits/main)
[![Dataplane: 237 tests](https://img.shields.io/badge/dataplane-237%20tests%20%E2%9C%93-c7f23e?style=flat-square&labelColor=000)](dataplane/)
[![Sovereign overlay](https://img.shields.io/badge/sovereign%20overlay-.tsm%20namespace-c7f23e?style=flat-square&labelColor=000)](docs/OVERLAY.md)
[![Code of Conduct](https://img.shields.io/badge/contributor%20covenant-2.1-c7f23e?style=flat-square&labelColor=000)](CODE_OF_CONDUCT.md)

<br/>

[**Live demo**](https://www.thesovereignmechanica.ai/) · [**Architecture**](ARCHITECTURE.md) · [**Sovereign overlay**](docs/OVERLAY.md) · [**Deploy**](docs/DEPLOY.md) · [**SDK**](docs/SDK.md) · [**Policy DSL**](docs/POLICY.md) · [**Threat model**](docs/THREAT_MODEL.md)

</div>

---

## Why TSM

Every prompt your application sends to a model is a leak surface — for PII, for credentials, for jailbreaks, for prompt injection, for shadow tokens. Existing answers either bolt on after the fact (DLP scans logs you've already shipped) or sit beside the request (a sidecar your app might bypass). TSM is inline. The dataplane is **on the wire**, not next to it. Bypass requires routing around your own infrastructure.

| | Bolt-on DLP | LLM gateway (sidecar) | **TSM79** |
|---|---|---|---|
| **Position** | Post-hoc, on logs | Beside the request | **On the wire** |
| **Bypassable** | Yes — logs are downstream | Yes — apps can skip the sidecar | **No — the dataplane is the upstream** |
| **Hot path** | n/a — async | ~30–80 ms (Python/Node sidecar) | **~10–30 µs measured (Python ref); sub-10 µs Rust target** |
| **Detection escalation** | None — single pass | None — single pass | **5-stage: regex → entropy → structural → ONNX → NER → quarantine** |
| **Quarantine verdict** | Logs only | Block or allow | **`202` for human review — fail-secure** |
| **Audit** | Application logs | Sidecar's own log | **Tamper-evident Merkle chain in Postgres** |
| **Sovereign overlay** | No | No | **`.tsm` namespace governed by the same firewall** |
| **Open source** | Mostly proprietary | Mixed | **MIT, all 11 services, all code** |

---

## The Five-Verdict Taxonomy

The dataplane returns one of five verdicts on every request:

| Verdict | Behaviour | HTTP |
|---|---|---|
| `allow` | forwarded unchanged | upstream's |
| `redact` | PII / secret spans replaced with `[REDACTED:<type>]` before forwarding | upstream's |
| `route_local` | held inside your perimeter — sent to a local model (Ollama / VPC / on-prem) | upstream's |
| `quarantine` | held for human review — not forwarded, not denied | **`202`** |
| `block` | refused at the gate, never sent upstream | **`400`** |

`quarantine` was added in v3.0.0. It closes a fail-OPEN gap that existed when the ML triage was unsure about ambiguous content — those requests now stop and wait for a human, instead of silently passing.

---

## Detection Coverage

What gets caught on the local fast path:

| Type | Method | Severity |
|---|---|---|
| OpenAI / Anthropic / GitHub / AWS / Stripe / HuggingFace / GitLab / SendGrid keys | Known prefix + min-length | `critical` |
| Private keys (RSA / EC / OpenSSH / DSA), JWTs | Structural parse | `critical` |
| Jailbreak / prompt-injection (incl. leet / unicode / BPE-split variants) | Pattern + BPE token-splitting | `critical — blocked` |
| SSN, credit cards (Luhn-validated) | Regex + Luhn | `high` |
| High-entropy payloads | Shannon ≥ 4.5 bits/char | `high` |
| Email, phone, IPv4 | Regex + context negation | `medium` |
| Names, organisations, locations | spaCy NER (via gRPC escalation) | `medium` |
| Ambiguous PII (NER signal, no fast-path hit) | ONNX heuristic → gRPC escalation → **quarantine** | varies |

When the fast path is uncertain, escalation goes to the Python detector over gRPC. The Python reference path adds ~10-30 µs per request (measured, see [Performance](#performance)); the Rust core targets sub-10 µs.

---

## Performance

TSM's job is to guard a model call *without* adding meaningful latency. The number that matters is **added overhead** -- how long the inline detection (`PIIDetector.scan`) takes per request. Upstream model latency (hundreds of ms) is unaffected.

### Measured today -- Python reference implementation

Reproduce in one command, no setup:

```bash
python benchmark/bench.py
```

Real numbers (Windows 11, CPython 3.12, single thread, AMD 16-core; 10,000 iters/category):

| Category | p50 (µs) | p99 (µs) | mean (µs) | req/s (1 core) | severity |
|---|---:|---:|---:|---:|---|
| clean prompt | 9.7 | 30.5 | 11.2 | 89,184 | none |
| secret | 12.4 | 35.6 | 14.2 | 70,303 | critical (blocked) |
| PII | 21.6 | 50.2 | 24.0 | 41,601 | critical / medium |
| mixed (PII + secret) | 27.3 | 56.7 | 30.2 | 33,073 | critical |

Aggregate **19.9 µs mean added latency, ~50,000 req/s on a single core**. Every run writes a machine fingerprint, p50/p90/p99 percentiles, and the severity distribution to [`benchmark/RESULTS.md`](benchmark/RESULTS.md) -- so any number is traceable to the box that produced it. Methodology: [`benchmark/`](benchmark/).

### Design targets -- Rust dataplane

The Rust dataplane (`dataplane/`) targets a higher tier: sub-10 µs fast-path detection and 100k+ req/s per core via an Aho-Corasick prefilter and a `RegexSet` SIMD DFA. **These are design targets, not measured results.** The dataplane build is being unblocked ([#36](https://github.com/tsm7979/tsm79/issues/36)); once green it is benchmarked by the same harness and these numbers are replaced with measurements.

## 90-Second Quickstart

```bash
git clone https://github.com/tsm7979/tsm79.git
cd tsm79
cp .env.example .env       # set CLICKHOUSE_PASSWORD + provider keys
docker compose -f docker-compose.enterprise.yml up -d
```

Eleven services come up. `docker compose ps` reaches `Up (healthy)` within ~60 s.

Point your existing OpenAI SDK at the dataplane and stop touching application code:

```bash
export OPENAI_BASE_URL=http://localhost:8080
python your_existing_app.py
```

Detection, redaction, routing, and audit happen inline. Zero code changes.

See [docs/DEPLOY.md](docs/DEPLOY.md) for production deployment (mTLS, secret rotation, backups, sizing).

---

## The Stack

Eleven services, eight languages. Each layer in the language that earns its place.

| Component | Language | Purpose |
|---|---|---|
| **`dataplane/`** | **Rust** | The inline AI firewall — h1/h2/hpack, TLS+mTLS, connection pool, rate limit, detection, policy, overlay, audit |
| `detector/` | Python | ML detector — NER + classifier escalation over gRPC |
| `control-plane/` | Go | Config + workspace + key store |
| `threat-intel/` | Go | IP reputation feeds |
| `overlay-node/` | Go + libp2p | Sovereign-overlay Kademlia DHT under `/tsm` |
| `admin-api/` | Java (Spring Boot) | Operator REST — workspace, policy, key management |
| `policy-lsp/` | C# (.NET) | Language server for the policy DSL — IDE diagnostics & completions |
| `edge/` | C++ (wasmtime) | Sandboxed Wasm worker host — memory ceiling, epoch, fuel |
| `ebpf-loader/` | Rust (Aya) | XDP/TC loader — kernel-level packet authority |
| `ebpf-loader-c/` | C (libbpf) | XDP/TC loader (default in CI) |
| `tsm/` | Python | SDK + CLI |
| `tsm-ctl/` | Rust | Operator CLI |

The operator dashboard, browser extension, and public landing site live in separate companion repositories so this repo stays focused on the data-plane and detection core. The live landing is at <https://www.thesovereignmechanica.ai/>.

[Full architecture →](ARCHITECTURE.md)

---

## The Sovereign Overlay (`.tsm`)

An ICANN-free namespace that rides on top of the existing internet — Tor / IPFS-class, opt-in, governed by the same TSM dataplane firewall.

- **Names are Ed25519 keypairs.** `<base32(pubkey)>.tsm` — the Tor v3 `.onion` model. Self-certifying.
- **`NameRecord` is signed.** Forged signatures, hijack attempts (rebinding to a different key), and stale-sequence replays are rejected at the resolver.
- **`/_tsm/<name>` gateway.** The dataplane fetches the resolved endpoint AND runs the content through `Detector::scan` before serving it. The firewall governs the new network space for free.
- **DHT propagation.** Go `overlay-node/` (libp2p Kademlia under `/tsm` — isolated from public IPFS). Rust and Go sides produce byte-compatible signing bytes.
- **Browser front-door.** MV3 extension; type `tsm hub` in the address bar and reach the gateway with no DNS leak.

[Full protocol spec →](docs/OVERLAY.md)

---

## Repository Layout

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
├── tsm/               Python — SDK + CLI
├── tsm-ctl/           Rust — operator CLI
├── proto/             Protobufs (dataplane↔detector gRPC + dataplane↔edge gRPC)
├── observability/     ClickHouse schema + Rust ingestor
├── deploy/            Postgres migrations + nginx config
├── docs/              Technical deep-dives (OVERLAY, DEPLOY, POLICY, OBSERVABILITY, THREAT_MODEL, SDK)
├── tests/             Cross-component end-to-end tests
└── docker-compose.enterprise.yml
```

---

## Documentation

| Doc | What's in it |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Layer model — BGP / XDP / TLS / policy / overlay / audit |
| [docs/OVERLAY.md](docs/OVERLAY.md) | Sovereign overlay protocol spec (`.tsm`) — names, records, resolver, gateway, DHT |
| [docs/DEPLOY.md](docs/DEPLOY.md) | Production deployment — sizing, mTLS, secret rotation, backups, DR |
| [docs/POLICY.md](docs/POLICY.md) | Policy DSL reference — rules, matchers, priority, workspace isolation |
| [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) | Metrics, logs, ClickHouse analytics, audit ledger |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE per asset, trust boundaries, mitigations |
| [docs/SDK.md](docs/SDK.md) | Drop-in HTTP, Python SDK, gRPC, CLI |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [ROADMAP.md](ROADMAP.md) | What we're building next |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |

---

## Brand & Voice

Operator-facing copy (CLI, dashboard, marketing, docs) speaks in the **TSM voice** — terse, mechanical, em-dash-heavy, sovereign-agency register. Visual grammar is square corners, hairline borders, a single `#C7F23E` (`--signal`) accent per fold, mask-wipe reveals, no drop shadows, no gradients.

The full brand spec, design tokens, and component kit live in the **TSM — Sovereign Design System** distribution. The public landing (`landing-v5/`) is the canonical rendering of it.

Words we never write: *empower / unlock / seamless / leverage / revolutionary / AI-powered*.

---

## Used By

_Are you using TSM79 in production? Open a PR to add yourself here. We'll never add you without your consent._

<sub>This space deliberately left empty. We don't fabricate logos.</sub>

---

## Community

- **GitHub Discussions** — design conversations, RFCs, questions → [discussions](https://github.com/tsm7979/tsm79/discussions)
- **GitHub Issues** — bugs, concrete feature proposals → [issues](https://github.com/tsm7979/tsm79/issues)
- **Security** — vulnerability disclosures → see [SECURITY.md](SECURITY.md)
- **Founder direct** — partnerships, sovereign deployments → <founder@thesovereignmechanica.ai>

---

## Citation

If you reference TSM79 in academic or industry publications, please cite via [CITATION.cff](CITATION.cff).

---

## License

MIT — see [LICENSE](LICENSE).

Trade name: **The Sovereign Mechanica.** Legal entity: TSM Pvt Ltd. Contact: <founder@thesovereignmechanica.ai>.

<br/>

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=tsm7979/tsm79&type=Date)](https://star-history.com/#tsm7979/tsm79&Date)

</div>
