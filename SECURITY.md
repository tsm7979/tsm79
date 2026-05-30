# Security Policy

TSM79 is security-critical infrastructure. We take vulnerability reports seriously and respond on a defined SLA.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email <founder@thesovereignmechanica.ai> with:

- Affected component (dataplane, detector, control-plane, admin-api, overlay-node, edge, dashboard, landing, extension, eBPF loader, …)
- Affected version or commit SHA
- A description of the vulnerability, including the impact you observed
- Reproduction steps — minimal, deterministic
- Optional: a proposed remediation, a patch, or a PoC exploit

PGP-encrypted reports are accepted — the maintainer key fingerprint will be published at <https://www.thesovereignmechanica.ai/.well-known/security.txt> when key rotation completes.

## What to Expect

| Stage | SLA |
|---|---|
| Acknowledgement of report | within **48 hours** |
| Triage + severity assessment | within **5 business days** |
| Fix or mitigation plan communicated | within **10 business days** for `critical` / `high` |
| Public advisory + CVE request | coordinated with reporter, default 90-day embargo |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). Reporters who follow this policy and act in good faith are not pursued legally and are credited in the public advisory (unless they prefer anonymity).

## Severity Classification

| Severity | Examples |
|---|---|
| **Critical** | Authentication bypass on dataplane / admin-api · audit-ledger tamper without detection · sovereign-overlay name hijack · arbitrary code execution in Wasm edge sandbox escape · plaintext API-key leak |
| **High** | Detection evasion (PII / secret bypass in a default rule) · DoS at < 10 req/s · TLS verification skipped · ClickHouse ingest auth bypass |
| **Medium** | Detection false-negative on a non-default rule · log injection · CSRF on a non-state-changing endpoint |
| **Low** | Information disclosure of non-sensitive metadata · timing oracles on non-authentication code paths |

## In-Scope

- All code in this repository (`dataplane/`, `detector/`, `control-plane/`, `threat-intel/`, `admin-api/`, `policy-lsp/`, `edge/`, `overlay-node/`, `ebpf-loader/`, `ebpf-loader-c/`, `dashboard/`, `extension/`, `landing-v4/`, `landing-v5/`)
- The published Docker images
- The default `docker-compose.enterprise.yml` topology
- The sovereign-overlay protocol (`.tsm` namespace, signing-byte format, DHT propagation)
- The marketing landing at <https://www.thesovereignmechanica.ai/>

## Out-of-Scope

- Self-inflicted misconfiguration (running with `TSM_DEV_MODE=1`, disabling TLS, exposing admin-api unauthenticated to the internet, …)
- Third-party dependencies — please report those upstream and CC us
- Findings that require physical access to the host
- Theoretical timing attacks without a working PoC
- Vulnerabilities only reachable by a privileged on-host attacker
- Test fixtures, demo data, and the in-browser "Inspect a prompt" widget on the landing — these contain intentionally synthetic secrets (e.g., `ghp_DEMO_FIXTURE_…`, `AKIA_DEMO_FIXTURE_AB`) so visitors can observe detection in action

## Security Hardening Defaults

Out-of-the-box, the enterprise compose stack is hardened:

- mTLS on admin-api endpoints (`deploy/nginx/conf.d/mtls.conf`)
- Workspace-scoped API keys with HMAC-SHA256 chained audit ledger
- Rate limiting (token bucket per IP) on dataplane HTTP
- Per-upstream circuit breaker (`CLOSED → OPEN → HALF`)
- Wasm edge sandbox with memory ceiling + epoch interruption + fuel limits
- ClickHouse + Postgres with auth required at startup (no anonymous mode)
- Detector escalation over gRPC on a private network
- All container images run as non-root, with no shell, on distroless bases

We do **not** ship with telemetry-back-to-vendor enabled. Operators control their own data.

## Supported Versions

| Version | Status | Security patches |
|---|---|---|
| `3.0.x` | **Current** | Yes |
| `2.x` | Maintenance | Critical only |
| `< 2.0` | End of life | No |

Upgrade to `3.0.x` for the polyglot stack + sovereign overlay + production-hardened dataplane.

## Hall of Fame

Reporters who have responsibly disclosed vulnerabilities are credited here after the embargo lifts.

_(none yet — be the first)_

---

**Legal entity:** TSM Pvt Ltd.
**Contact:** <founder@thesovereignmechanica.ai>
