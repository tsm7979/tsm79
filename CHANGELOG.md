# Changelog

All notable changes to TSM — The AI Firewall.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

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
