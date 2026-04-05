# TSM Architecture

## Data Flow

Every AI call you make goes through this chain. One entry point, one exit.

```
User / Tool (claude, codex, your app)
        │
        │  OPENAI_BASE_URL=http://localhost:8080
        ▼
┌─────────────────────────────────────────────────────────┐
│  tsm/proxy/server.py  (OpenAI-compatible HTTP proxy)    │
│  POST /v1/chat/completions                              │
│  POST /v1/completions                                   │
└───────────────────┬─────────────────────────────────────┘
                    │  raw prompt text
                    ▼
┌─────────────────────────────────────────────────────────┐
│  tsm/detectors/pii.py  (14-pattern PII scanner)         │
│                                                         │
│  CRITICAL  SSN, Credit Card, Private Key                │
│  HIGH      API Key, AWS Key, Password, JWT              │
│  MEDIUM    Email, Phone, Passport                       │
│  LOW       IP Address                                   │
└───────────────────┬─────────────────────────────────────┘
                    │  ScanResult (types, severity, clean?)
                    ▼
┌─────────────────────────────────────────────────────────┐
│  Router  (inside proxy/server.py)                       │
│                                                         │
│  CRITICAL → local model   (cloud never sees it)         │
│  HIGH     → redact + cloud                              │
│  MEDIUM   → redact + cloud                              │
│  CLEAN    → cloud unchanged                             │
└───────────────────┬─────────────────────────────────────┘
                    │  routing decision + redacted body
                    ▼
┌─────────────────────────────────────────────────────────┐
│  Response builder                                       │
│  OpenAI-format response + tsm metadata field            │
│  Audit entry → tsm_audit.jsonl                          │
└───────────────────┬─────────────────────────────────────┘
                    │  JSON response
                    ▼
        User / Tool gets the answer
        (sensitive data never left the machine)
```

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
