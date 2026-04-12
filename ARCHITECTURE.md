# TSM Architecture

## Stack Layers — Silicon to Browser

| Layer | Language | Component | Role |
|---|---|---|---|
| Silicon / Kernel | C + eBPF | `ebpf/` XDP program | Packet-level IP filtering, rate enforcement before userspace |
| OS / Network | Rust | `dataplane/` | TCP accept, TLS 1.3, HTTP/1.1+2, detection, policy, upstream forwarding |
| Control Plane | Go | `control-plane/` | Policy versioning, cluster health federation, node registry |
| Detection | Python | `detector/` | 5-layer ML pipeline: regex→entropy→structural→NER→LLM |
| Dashboard | TypeScript/Next.js | `dashboard/` | Real-time audit viewer, risk heatmaps, policy editor |
| Infrastructure | HCL (Terraform) | `deploy/` | Kubernetes manifests, Kustomize overlays |

## Request Data Flow (v2)

```
Client (SDK / curl / browser)
        │  OPENAI_BASE_URL=http://tsm:8080
        │  ANTHROPIC_BASE_URL=http://tsm:8080
        ▼
┌─────────────────────────────────────────────────────────────┐
│  eBPF XDP (kernel)  — egress.c / ingress.c                  │
│  • IP allowlist enforcement at NIC driver level              │
│  • Token-bucket rate limit (BPF map, no context switch)     │
│  • Packet count telemetry → perf ring buffer                │
└──────────────────────────┬──────────────────────────────────┘
                           │  TCP segments (allowed traffic only)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Rust Dataplane  dataplane/src/                             │
│                                                             │
│  1. TCP accept  (thread-per-connection, no tokio)           │
│  2. Per-IP token-bucket rate limit  → 429 on excess         │
│  3. HTTP/1.1 + 2 parse  (zero-copy header extraction)       │
│  4. Body read loop  (4 MB limit, 413 on oversize)           │
│  5. Fast-path regex+entropy scan  (<0.5 ms)                 │
│     Clean / Block / Redact / RouteLocal → resolved here     │
│     Ambiguous → Python detector (500 ms timeout, fail-open) │
│  6. PolicyEngine::evaluate()  (RwLock<Vec<Rule>>, hot-reload)│
│  7. Structured 400 block response with spans + remediation  │
│     OR forward to upstream with real TLS 1.3                │
│  8. SSE streaming loop for streamed responses               │
│  9. Structured JSON access log + HMAC audit chain           │
└──────────────────────────┬──────────────────────────────────┘
                           │  Ambiguous only (~10–20% of traffic)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Python Detector  detector/                                 │
│                                                             │
│  Layer 1: Regex + Luhn + URL-decode normalization           │
│  Layer 2: Shannon entropy (secrets, JWTs)                   │
│  Layer 3: Structural (API key prefixes, base64 variants)    │
│  Layer 4: spaCy NER (names, addresses, orgs)                │
│  Layer 5: LLM-assisted (only for truly ambiguous ~5%)       │
│  + Behavioral: velocity / exfiltration / category-scan      │
│  → Returns risk_score, action, pii_types, redacted_body     │
└──────────────────────────┬──────────────────────────────────┘
                           │  parallel (background)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Go Control Plane  control-plane/                           │
│                                                             │
│  • POST /nodes/register  — dataplane self-registration      │
│  • GET  /config/policy  (ETag/If-None-Match, 304 on no-op)  │
│  • PUT  /config/policy  — admin hot-reload (no restart)     │
│  • PATCH /config/policy/rules  — add/update single rule     │
│  • GET  /nodes  — live cluster health map                   │
│  • 10s health poller marks nodes healthy/unhealthy           │
└──────────────────────────┬──────────────────────────────────┘
                           │  encrypted (real TLS 1.3)
                           ▼
               OpenAI / Anthropic / Ollama upstream
```

## Detection Actions

| Action | Trigger | Behaviour |
|---|---|---|
| **allow** | risk < 40, no PII | Forward unchanged |
| **redact** | EMAIL / PHONE / IP (risk 40–79) | Strip PII tokens, forward redacted body |
| **block** | SSN / CC / API_KEY / JAILBREAK (risk ≥ 80) | 400 with structured JSON: spans + rule + remediation |
| **route_local** | risk ≥ 80, Ollama available | Forward to on-prem model, cloud never sees it |

## Entry Point

**One command, everything starts:**

```bash
tsm enable
```

This:
1. Starts the proxy at `localhost:8080` (background subprocess, survives terminal close)
2. Injects `OPENAI_BASE_URL` into your shell session
3. Fires 4 live test requests so you see detection working immediately
4. Enters monitoring mode — streams every interception to your terminal

All other commands are surfaced via the same CLI:

```
tsm scan "text"     — check text for PII (no proxy needed)
tsm hook claude     — wrap claude with TSM
tsm hook codex      — wrap codex with TSM
tsm run cmd         — run any command through the firewall
tsm status          — what's been intercepted
tsm test            — self-test (8/8 pattern types)
tsm skills          — list available skill packs
tsm stop            — stop the proxy
```

## Package Layout

```
tsm/                        ← installable Python package
├── cli/
│   └── main.py             ← THE entry point (tsm command)
├── proxy/
│   ├── server.py           ← HTTP proxy (OpenAI-compatible)
│   └── logger.py           ← colored terminal output
├── detectors/
│   └── pii.py              ← 14-pattern PII scanner
└── hooks/
    └── env.py              ← ENV injection for shell hooks

skills/                     ← behavior packs (markdown)
├── claude.md
├── codex.md
├── secure-coding.md
└── general.md

examples/                   ← runnable demos
├── curl_demo.sh
└── python_openai.py

docs/                       ← extended documentation
tests/                      ← test suite
internal/                   ← extended modules (not required for core)
```

## Severity Tiers

| Tier     | Examples                         | Action                  | Cost   |
|----------|----------------------------------|-------------------------|--------|
| CRITICAL | SSN, Credit Card, Private Key    | Block → local model     | $0.00  |
| HIGH     | API Key, AWS Key, JWT, Password  | Redact → cloud          | normal |
| MEDIUM   | Email, Phone, Passport           | Redact → cloud          | normal |
| LOW      | IP Address                       | Log → cloud unchanged   | normal |
| CLEAN    | No PII                           | Pass through unchanged  | normal |

## Zero Dependencies

The entire core (`tsm/`) runs on Python 3.8+ stdlib only:

- `http.server` — proxy HTTP server
- `re` — PII pattern matching
- `threading` — background server
- `subprocess` — daemon process
- `urllib.request` — HTTP client for live demo
- `json`, `time`, `os`, `pathlib` — utilities

No `pip install` required beyond `tsm-firewall` itself.
