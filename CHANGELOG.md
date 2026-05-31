# Changelog

All notable changes to TSM79 — Sovereign AI Control Plane.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [3.1.0] — 2026-05-30

### Repository — focus on the data plane

This repository now contains only the **core infrastructure**: the Rust dataplane, the Python ML detector, the Go control-plane / threat-intel / overlay-node, the Java admin-api, the .NET policy-lsp, the C++ wasmtime edge worker host, the eBPF/XDP loader pair, the SDK (`tsm/`), the operator CLI (`tsm-ctl/`), the protobuf contracts, and the production deployment + observability + tests.

The following surfaces moved out so the data plane is what visitors see first:

- `dashboard/` — the Next.js operator UI
- `extension/` — the MV3 browser front-door for the `.tsm` overlay
- `landing/`, `landing-v4/`, `landing-v5/` — public marketing surfaces (the live landing remains at <https://www.thesovereignmechanica.ai/>)
- `proxy/`, `proxy-go/` — legacy proxy implementations superseded by `dataplane/`
- `sdk/` — duplicate of `tsm/`; consolidated into `tsm/`
- `tsm_firewall.egg-info/`, `tsm_audit.jsonl` — Python build / runtime artefacts
- `Dockerfile.dashboard`, `Dockerfile.proxy`, `start-all.sh` — references for removed components

These removals strip ~111 tracked files from the repo. The history of every removed surface is preserved on the `wip/crash-recovery-2026-05-21` branch on origin. Companion repositories for the dashboard, extension, and landing will be published separately as they reach v1.

### Docker compose

- `docker-compose.enterprise.yml` — dashboard service removed; nginx no longer depends on dashboard. Operators deploying the companion dashboard should add it back per its own README.

### Documentation

- README repo layout, CONTRIBUTING repo layout, SECURITY in-scope list, ROADMAP, dependabot ecosystems, CODEOWNERS, PR template scope checklist, bug_report / feature_request component pickers, docs/DEPLOY service table, docs/OBSERVABILITY health-check list — all updated to reflect the data-plane-focused layout.

---

## [3.0.0] — 2026-05-30

### Polyglot stack expansion
- **admin-api/** (Java, Spring Boot): operator REST control plane — workspace, policy, and API-key management
- **policy-lsp/** (.NET, C#): language server for the policy YAML DSL — diagnostics + completions in any LSP-aware editor
- **edge/** (C++, wasmtime): sandboxed Wasm worker host with memory ceilings, epoch interruption, and fuel limits
- **overlay-node/** (Go, libp2p): Kademlia DHT peer for the sovereign-overlay name layer
- **ebpf-loader-c/** (C, libpbf): default loader for the XDP/TC kernel packet-authority programs (no Aya toolchain dependency)
- **extension/** (MV3 browser extension): URL-bar front-door for the `.tsm` overlay (omnibox keyword + declarativeNetRequest redirect)

### Sovereign overlay layer (`.tsm` namespace, #35)
- **Self-certifying names**: `dataplane/src/overlay/{name,resolver,gateway}.rs` — Ed25519-signed `NameRecord`, base32 `derive_address` (Tor v3 `.onion` model), local resolver with anti-hijack + anti-replay
- **Gateway endpoint**: `GET /_tsm/<name>` — resolves, fetches, runs the fetched content through `Detector::scan`, then serves. The firewall governs overlay content the same way it governs AI requests.
- **DHT layer**: Go `overlay-node/` (libp2p) under a dedicated `/tsm` protocol prefix — isolated from the public IPFS DHT. Cross-implementation signing-byte parity with Rust verified.
- **MV3 extension** for the browser front-door: omnibox keyword `tsm` + declarativeNetRequest redirect for `*.tsm` navigations.

### Dataplane (#29, #30, #33, #34)
- **Action::Quarantine** — 5th verdict (taxonomy now `allow / redact / route_local / quarantine / block`). HTTP 202, audited as `quarantine`, never forwarded. Builtin rule priority 45 triggered by NER_REVIEW.
- **ONNX dead-zone fix** — confidence 0.70–0.85 was silently clearing `Ambiguous` → `Clean`. Now preserves the fast-path verdict (fail-secure). Makes quarantine reachable.
- **h1 last-header fix** — HTTP/1.1 parser was dropping the last header of every request/response because the loop read from a slice that excluded the terminating `\r\n\r\n`. Restored full header capture.
- **Exact token capture** — `parse_usage()` extracts `prompt_tokens` / `completion_tokens` from upstream OpenAI + Anthropic responses; provider-keyed `tokens_prompt_total` / `tokens_completion_total` Prometheus counters added.
- **237 dataplane unit tests passing** (was 220 pre-quarantine).

### Observability (#32)
- **ClickHouse ingest fixed end-to-end** — two stacked bugs in `observability/clickhouse/ingestor.rs`:
  - `http_post` left `user:password@` userinfo inline in the authority; now `rsplit_once('@')` separates it and sends `X-ClickHouse-User`/`Key` headers.
  - Empty `client_ip` / `original_dst_ip` strings into `IPv4` columns produced "400 Cannot parse IPv4"; now `ipv4_or_zero()` coerces empty → `0.0.0.0`.
- Verified: count went 0 → rows landing with correct `action`/`pii_types`/`risk` and `original_dst_ip = 0.0.0.0`.

### Landing (#36, #37)
- **landing-v4/** — brand-correct sovereign landing standup: 9 sections, masthead with live timecode, infinite-loop ticker band, WebGPU/TSL pipeline with bloom + chromatic aberration + grain + cursor flowmap + 90-frame idle guard + canvas-2D fallback.
- **landing-v5/** — cinematic upgrade on top of v4, **deployed at <https://www.thesovereignmechanica.ai/>**:
  - Engine: WebGL backdrop full-viewport (not hero-scoped); persistent procedural core; **scroll-tied 3-mesh crossfade** (Torus → Icosahedron → Octahedron with triangle-window weights); bloom 1.8 (was 0.9); grain 0.09; vignette + scanlines; ~2× cursor-coupled chromatic aberration.
  - Typography: **OFL Playfair Display + Mona Sans + Host Grotesk** swapped in as primaries (replacing Newsreader / Inter Tight). Anton + Big Shoulders Display + IBM Plex Mono loaded via Google Fonts.
  - Type scale bumped to brand-spec ranges (hero `64–152px`, t-display `56–128px`, philosophy `56–156px`).
  - Anton wired into the giant "0" in the Incidents pane (`clamp 128–240px`) and the footer wordmark; IBM Plex Mono wired into the YAML policy editor; Host Grotesk wired into ticker + section-mark kickers.
  - All CTAs re-pointed to `mailto:founder@thesovereignmechanica.ai` with em-dash subject lines (5 buttons + footer link).
  - Commercial fonts (PPFormula / Fraktion / Brier / BiggerDisplay / Summertime) deliberately NOT bundled — OFL-licensed faces only.

### Infrastructure
- `docker-compose.enterprise.yml`: detector-grpc + observability services, TSM_CLICKHOUSE_URL wiring, healthchecks
- `deploy/postgres/migrations/V004__audit_log.sql` + `V006__views_functions_cron.sql`
- `deploy/nginx/conf.d/mtls.conf` for admin endpoints
- `.gitignore` expanded for the polyglot build artifacts (Java `target/` + `*.class` + `*.jar`, .NET `bin/` + `obj/`, Go binaries) and Vite captures

### Documentation
- README rewritten to reflect the actual polyglot architecture (was framed for a hypothetical `pip install tsm-firewall` package)
- Brand voice + design system reference added

---

## [2.0.0] — 2026-04-11

### Architecture
- **Multi-language microservice stack**: TypeScript proxy (Node.js) for high-throughput HTTP + SSE, Python FastAPI detector for ML pipeline, Next.js dashboard for live observability
- **Go proxy** (`proxy-go/`): goroutine-per-request model, targeting <5ms end-to-end PII detection latency; compiled fast-path regex eliminates detector round-trip for obvious critical hits
- **HMAC-SHA256 chained audit log**: tamper-proof, append-only, every entry linked to previous hash — verify integrity with `audit.Verify()`

### Detection
- **5-stage pipeline**: regex + context negation → entropy scan → structural (JWT, API key prefixes) → spaCy NER (prose PII: names, orgs, locations) → LLM-assisted classification for ambiguous cases
- **PII coverage**: SSN, credit cards, email, phone, API keys (OpenAI/Anthropic/GitHub/AWS), JWTs, private keys, IBAN, passport patterns
- **False-positive reduction**: Luhn validation on credit cards, context negation on synthetic data phrases, entropy thresholds on random strings

### Policy Engine
- **Declarative DSL**: `any_of`, `all_of`, `contains_pii`, `risk_score_gte`, `severity`, `user_role`, `model_prefix`
- **6 built-in rules**: block_secrets, block_high_risk, redact_medium_risk, allow_trusted_roles, route_local_pii, allow_clean
- **Multi-tenancy**: per-workspace isolated `PolicyEngine` persisted to `~/.tsm/workspaces/`
- **Custom rules** via REST API: `POST /workspaces/{id}/rules`

### Infrastructure
- **Docker Compose**: 4-service stack (db/detector/proxy/dashboard) with healthchecks on all services
- **Helm chart**: full Kubernetes deployment — `deployment.yaml`, `service.yaml`, `ingress.yaml`, `hpa.yaml` (autoscaling/v2), `configmap.yaml`, `secret.yaml`
- **PostgreSQL schema**: `audit_events` (GIN index on `pii_types[]`), `workspaces`, `metrics_hourly`, `purge_old_events()` retention function
- **Prometheus metrics** on `/metrics`: request latency histograms, PII type counters, circuit breaker state, rate limit counters

### Reliability
- **Token-bucket rate limiting** per client IP (`TSM_RATE_LIMIT`, default 100 req/min)
- **Per-upstream circuit breaker** CLOSED → OPEN → HALF state machine (`TSM_CB_THRESHOLD`, `TSM_CB_TIMEOUT_MS`)
- **Webhook alerting**: Slack/Teams/generic, auto-detected by URL, fires on risk_score ≥ 80 or block/route_local

### SDK
- **`@tsm.protect` decorator**: scans first string argument, redacts or raises `TSMBlockedError`
- **`scan()` context manager** and `scan_text()` synchronous helper
- **`TSMClient`**: `detect()`, `detect_text()`, `add_rule()`, `get_rules()`; fails open on network errors
- **LangChain integration**: `TSMCallbackHandler` intercepts `on_chat_model_start` / `on_llm_start`

### Bug Fixes
- Credit card regex now matches spaced format (`4111 1111 1111 1111`) via `[\s\-]?` between groups
- Phone regex uses `(?<!\d)` lookbehind instead of `\b` to handle parenthesized area codes
- Policy engine test isolation: replaced `tmp_path` fixture with `tempfile.NamedTemporaryFile` for Windows compatibility
- `tsm analyze` now correctly handles Unicode in prompt text on Windows

---

## [1.0.0] — 2026-03-15

### Added
- Initial Python proxy with PII detection (regex-based)
- `tsm analyze` command: risk score + leak breakdown
- `tsm enable` / `tsm disable` hook management
- Basic audit ledger (JSONL append-only)
- Support for OpenAI, Anthropic, Ollama adapters

---
