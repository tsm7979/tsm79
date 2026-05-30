# Threat Model

STRIDE-style threat model for the TSM79 polyglot stack and sovereign overlay.

This document is a living artefact. Open a PR with `[threat-model]` in the title to propose updates.

---

## Trust boundaries

```
┌──────────────────────────────────────────────────────────────────────────┐
│  EXTERNAL — UNTRUSTED                                                    │
│  • clients (apps, SDKs, curl)                                            │
│  • upstream LLM providers (openai.com, anthropic.com, etc.)              │
│  • public internet                                                       │
│  • sovereign-overlay DHT peers (cryptographically authenticated, but     │
│    not pre-trusted)                                                      │
└──────────────────────────────────────────────────────────────────────────┘
                                ▲
                                │  TLS (clients) | TLS (upstreams) | libp2p (DHT)
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  PERIMETER — TRUSTED (operator-controlled)                               │
│                                                                          │
│  ┌─── INTERNAL NETWORK (compose / k8s overlay) ─────────────────────┐    │
│  │                                                                   │    │
│  │   dataplane   ──gRPC───>   detector                              │    │
│  │       │                                                          │    │
│  │       ├──HTTP───>  admin-api  ──SQL──>  postgres                 │    │
│  │       │                                                          │    │
│  │       ├──HTTP───>  control-plane                                 │    │
│  │       │                                                          │    │
│  │       ├──HTTP───>  threat-intel                                  │    │
│  │       │                                                          │    │
│  │       ├──HTTP───>  clickhouse  (analytics)                       │    │
│  │       │                                                          │    │
│  │       ├──HTTP───>  redis     (rate limit + session pinning)      │    │
│  │       │                                                          │    │
│  │       └──Unix sock>  overlay-node  ──libp2p──>  (external DHT)   │    │
│  │                                                                  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  Operator surface (also trusted, separate auth domain):                  │
│  • admin-api (mTLS)                                                      │
│  • dashboard (admin-api authn)                                           │
│  • CLI (~/.tsm/keys/)                                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

The dataplane is the only component on the request hot path. The detector is escalated to only when the fastpath is uncertain.

---

## STRIDE — per asset

### Asset: client → dataplane request

| Threat | Mitigations |
|---|---|
| **S** — Spoof: client forges identity | Workspace API key required; rate-limited per-IP; admin-api mTLS for control |
| **T** — Tamper: client sends crafted bypass payload (prompt injection, leetspeak PII) | 5-stage detection: regex+context → entropy → structural → ONNX → NER → quarantine; jailbreak corpus baked into the regex set; ML escalation for ambiguity |
| **R** — Repudiate: client denies sending a leaking prompt | HMAC-SHA256 Merkle-chained audit log; verify with `tsm audit verify`; tamper alerts via Prometheus |
| **I** — Info disclose: client reads another tenant's data | Strict workspace isolation enforced at admin-api + dataplane; per-workspace API keys; per-workspace policies; per-workspace audit rows |
| **D** — DoS: client floods | Token-bucket rate limit; per-upstream circuit breaker; XDP layer (when deployed) drops at 100Gbps line rate |
| **E** — EoP: client escalates to operator | No operator-level operation reachable via the dataplane HTTP surface; admin-api is on a different port and gated by mTLS |

### Asset: dataplane → upstream provider request

| Threat | Mitigations |
|---|---|
| **S** — Provider spoof (BGP hijack, DNS poisoning) | TLS hostname verification; pinned CA in `dataplane/src/upstream/tls.rs`; layer-0 BGP-anycast roadmap eliminates externally-routed hijack |
| **T** — Provider returns tampered response | Response also passes through detection — overlay gateway treats responses like requests for the `_tsm/<name>` path |
| **R** — Provider denies receiving the request | Postgres audit row commits BEFORE the request goes upstream (fail-secure ordering) |
| **I** — Provider sees more than they should | Detection-based redaction strips PII / secrets before forwarding; route_local routes to operator-controlled local model |
| **D** — Provider rate-limits us | Per-upstream circuit breaker absorbs OPEN state; back-pressure surfaces as 429 to client |
| **E** — Provider compromises the dataplane | Network-level egress restrictions recommended; dataplane runs as non-root in a distroless container |

### Asset: detector

| Threat | Mitigations |
|---|---|
| **S** — Fake detector responding to dataplane | gRPC TLS with pinned CA; service-mesh mTLS recommended |
| **T** — Adversarial prompt that fools the classifier | Fail-secure: ambiguous output (0.70–0.85 confidence) preserved as `Ambiguous` rather than waved through; quarantine verdict reachable for NER_REVIEW signal |
| **R** — Detector returns inconsistent decisions | Deterministic model weights checkpoint-pinned; model card v1 with reproducible training set (roadmap) |
| **I** — Detector logs prompt content | Detector logs only PII types + risk score, never the prompt itself (the prompt is logged in the audit row inside the dataplane perimeter) |
| **D** — Detector slow or crashed | Dataplane fail-secure: requests requiring escalation are dropped at `quarantine` until detector returns |
| **E** — Detector compromise → arbitrary policy decision | Workspace policy enforced by the dataplane, not the detector; the detector is a signal source, not a decision maker |

### Asset: sovereign overlay (`.tsm`)

| Threat | Mitigations |
|---|---|
| **S** — Spoof: someone publishes a `NameRecord` for someone else's name | Records reject if `signature` doesn't verify under `pubkey`; reject if `name != derive_address(pubkey)` (hijack); resolver pins first-seen `pubkey` per name |
| **T** — Tamper: DHT peer corrupts records in flight | Each record is self-authenticating via Ed25519 signature; DHT peers MUST verify before storing or relaying |
| **R** — Author denies publishing a record | Records are signed by the author's private key — non-repudiable |
| **I** — DHT leaks who is publishing what | Records are public by design (this is a name layer, not a privacy layer). For privacy use Tor or I2P |
| **D** — DHT flooding | Per-peer rate limits in `overlay-node`; libp2p built-in connection manager limits; `republish_interval` keeps publication cost bounded |
| **E** — DHT compromise → name hijack | Cannot — name-to-key binding is cryptographic, not consensus-based. A malicious peer can't change a name's `pubkey` without the private key |

### Asset: audit ledger

| Threat | Mitigations |
|---|---|
| **S** — Forged audit entry | `entry_hash = HMAC_SHA256(prev_hash || row_bytes)` chain — forgery requires the HMAC key which lives only in `admin-api`'s secret store |
| **T** — Tamper with historical entry | Chain breaks on tamper; `tsm audit verify` detects within seconds; Prometheus alert fires immediately |
| **R** — Operator denies a policy decision | Audit row links request_id ↔ verdict ↔ rule_id ↔ workspace_id ↔ timestamp, signed via Merkle chain |
| **I** — Audit row leaks customer data | Audit row stores PII types + severity + rule, never the prompt content itself; configurable retention with cryptographic erasure |
| **D** — Audit log fills disk | `purge_old_events()` cron + retention policy in `deploy/postgres/migrations/V006__views_functions_cron.sql` |
| **E** — Audit-only role escalates | Postgres RLS recommended; admin-api enforces RBAC by claims on operator JWTs |

### Asset: Wasm edge worker (`edge/`)

| Threat | Mitigations |
|---|---|
| **S** — Spoofed Wasm module | Modules signed; signature verified before instantiation |
| **T** — Sandbox escape | wasmtime with memory ceiling + epoch interruption + fuel limit; no host imports beyond the explicit allow-list |
| **R** — Module denies producing an output | Audit row records every edge call with input hash + output hash |
| **I** — Module reads host memory | wasmtime memory isolation; no shared memory with host process |
| **D** — Module loops forever | Epoch interruption forces yield; fuel limit kills runaway execution |
| **E** — Module → host RCE | wasmtime sandbox is the trust boundary; modules cannot exec, fork, or access syscalls |

### Asset: MV3 browser extension (`extension/`)

| Threat | Mitigations |
|---|---|
| **S** — Malicious site impersonates the gateway | Gateway URL is configured in `chrome.storage.local` and shown in the popup; the extension does not auto-trust remote configuration |
| **T** — Extension tampered by another extension | Chrome extension sandbox; MV3 service worker isolation |
| **R** — User claims they didn't navigate | Browser history is authoritative |
| **I** — Extension reads page content | The extension does NOT request `<all_urls>` host permissions; it intercepts only `.tsm` navigations via declarativeNetRequest |
| **D** — Extension blocks legitimate navigations | Operator can pin gateway URL to a known-good local instance |
| **E** — Extension escalates browser privileges | MV3 sandboxes prevent this; no remote code is loaded |

---

## Cross-cutting threats

### Supply-chain

- Cargo dependencies: `cargo audit` weekly via Dependabot; `cargo deny` for license + advisory enforcement
- Python dependencies: `pip-audit` weekly; pinned via `pyproject.toml`
- Go dependencies: `govulncheck` weekly; pinned via `go.mod`
- npm dependencies: `npm audit` weekly; `pnpm audit --audit-level=high` in CI
- Docker bases: digest-pinned, weekly Dependabot upgrades, Trivy scan in CI
- Maven / NuGet: weekly Dependabot upgrades, signature verification on pull

### Build provenance

- Reproducible builds: planned for v3.1 (SLSA Level 2 target)
- Signed releases: planned (cosign + Sigstore)
- SBOM emitted for every release (CycloneDX format)

### Operator credentials

- Provider API keys: stored in `.env` (operator-managed); supports HashiCorp Vault / AWS Secrets Manager / Azure Key Vault via the `SECRET_BACKEND` envar
- Workspace API keys: stored hashed (Argon2id) in Postgres; comparison via constant-time HMAC
- mTLS client certs: short-lived (90 days default), revocable via CRL distributed by the admin-api
- Sovereign-overlay private keys: operator-managed at rest; recommend Shamir-shared backup

---

## Out of scope

These are explicitly NOT in the threat model — operators are responsible:

- Physical security of the host machine
- Hypervisor compromise (we assume an honest host)
- Side-channel attacks (Spectre / Meltdown / RowHammer)
- Operator's own laptop / SSO / MFA — if `kubectl` is compromised, everything downstream is compromised
- The marketing landing at <https://www.thesovereignmechanica.ai/> — runs in a totally separate trust domain from the data plane

---

## Reporting threats

See [SECURITY.md](../SECURITY.md).
