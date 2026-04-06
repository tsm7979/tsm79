# TSM — The AI Firewall

[![CI](https://github.com/tsm7979/tsm79/actions/workflows/ci.yml/badge.svg)](https://github.com/tsm7979/tsm79/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tsm-firewall)](https://pypi.org/project/tsm-firewall/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Every prompt your app sends to an AI goes through TSM first. It scans for PII and secrets, redacts them, routes sensitive requests to a local model, and logs everything to a tamper-evident audit trail — without you changing a single line of application code.

---

## Install and run

```bash
pip install tsm-firewall
tsm enable
```

You'll see this immediately:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  My SSN is 123-45-6789. Help me file taxes.
[TSM] 🚨 Detected: SSN
[TSM] 🛡  Redacted: SSN → [REDACTED]
[TSM] 🔒 Routing → local model  (cloud never saw this)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-4  Token: ghp_abc123realrealrealrealtoken
[TSM] 🚨 Detected: GITHUB_TOKEN  severity=critical
[TSM] BLOCKED — secret never left your machine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  What is the capital of France?
[TSM] ✓ Clean — forwarded unchanged
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Zero code changes

Point your existing OpenAI SDK at TSM. Nothing else changes.

```python
# Before
client = OpenAI()

# After TSM (run `tsm enable` first)
client = OpenAI(base_url="http://localhost:8080")
```

Or set an environment variable and don't touch the code at all:

```bash
export OPENAI_BASE_URL=http://localhost:8080
python your_existing_app.py   # unchanged
```

---

## What it detects

| Type | Method | Severity |
|---|---|---|
| GitHub / OpenAI / Anthropic / AWS / Stripe keys | Known prefix + min-length | Critical |
| Private keys, JWTs | Structural parsing | Critical |
| SSN, Credit cards | Regex + Luhn algorithm | High |
| High-entropy secrets | Shannon entropy (>=4.5 bits/char) | High |
| Email, phone, IP | Regex + context negation | Medium |
| Jailbreak attempts | Pattern matching, 8 variants | Critical — blocked |
| Ambiguous PII | LLM-assisted classification | Varies |

Context negation suppresses false positives: `"fake SSN 123-45-6789"` is not flagged.

---

## Architecture

Three services. Each in the right language for the job.

```
Your App
   |
   v
proxy/          TypeScript (Node.js)   — production HTTP proxy, SSE, concurrent streams
   |
   v
detector/       Python (FastAPI)        — detection pipeline, policy engine, LLM-assist
   |
   v
Upstream AI     OpenAI / Anthropic / Ollama (local)
```

```
dashboard/      Next.js                — live observability UI at localhost:3001
```

### Detection pipeline (4 stages, in order)

```
1. Regex + context negation    ~0ms     SSN, CC, keys, PII — false positives suppressed
2. Shannon entropy analysis    ~0ms     obfuscated secrets, high-entropy tokens
3. Structural parsing          ~0ms     JWTs, base64 blobs, API key formats
4. LLM-assisted classification ~300ms   ambiguous cases only (names+DOB, medical context)
```

### Policy engine

Replaces hardcoded if/else with a declarable rule DSL. Rules live in `~/.tsm/policy.json` and are editable at runtime via the API.

```json
{ "rules": [
  { "name": "block_secrets",   "condition": { "any_of": ["GITHUB_TOKEN", "OPENAI_KEY"] }, "action": "block",       "priority": 2  },
  { "name": "dev_redact_pii",  "condition": { "contains_pii": true, "user_role": "dev"  }, "action": "redact",      "priority": 10 },
  { "name": "high_risk_local", "condition": { "risk_score_gte": 70                       }, "action": "route_local", "priority": 20 }
]}
```

Add a rule without restarting:

```bash
curl -X POST http://localhost:8001/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"my_rule","condition":{"any_of":["EMAIL"]},"action":"redact","priority":15}'
```

---

## Full stack

```bash
# Option A — full stack (proxy + detector + dashboard)
bash start-all.sh

# Option B — CLI only (Python proxy, zero Node.js required)
tsm enable
```

| Service | Port | What it does |
|---|---|---|
| Proxy | 8080 | AI traffic intercept (TypeScript) |
| Detector | 8001 | Detection + policy API (Python) |
| Dashboard | 3001 | Live observability UI (Next.js) |

---

## Observability

```bash
tsm analyze              # risk score + PII breakdown
tsm audit search SSN     # query tamper-evident audit ledger
tsm audit verify         # check chain integrity
tsm report --framework gdpr   # compliance report

curl http://localhost:8080/metrics   # live JSON metrics
```

The dashboard at `http://localhost:3001` shows blocked / redacted / clean counts, average risk score, top PII types, and a live per-request table.

---

## Supported upstreams

| Model prefix | Routes to | Requires |
|---|---|---|
| `gpt-*`, `o1`, `o3` | OpenAI | `OPENAI_API_KEY` |
| `claude-*` | Anthropic | `ANTHROPIC_API_KEY` |
| `llama*`, `mistral*`, `phi*`, `gemma*` | Ollama (local) | Ollama running |
| Any + critical PII | Ollama (forced local) | — |

---

## Tests

```bash
pip install -e ".[dev,detector]"
pytest tests/ -v
```

```
tests/test_classifier.py          33 tests   entropy, Luhn, regex, negation, jailbreak
tests/test_policy_engine.py       24 tests   rule DSL, priority, persistence, CRUD
tests/test_proxy_integration.py   13 tests   HTTP proxy end-to-end, SSE streaming
```

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TSM_PORT` | `8080` | Proxy listen port |
| `TSM_DETECTOR_URL` | `http://localhost:8001` | Detector service URL |
| `OPENAI_API_KEY` | — | Forward to OpenAI |
| `ANTHROPIC_API_KEY` | — | Forward to Anthropic |
| `OLLAMA_HOST` | `http://localhost:11434` | Local model host |
| `TSM_POLICY_PATH` | `~/.tsm/policy.json` | Policy rules file |

---

## Why not just use X?

**vs. Presidio / spaCy**: Those are offline NLP libraries. TSM is a live proxy — your app doesn't change, every request is intercepted in real time, routing decisions happen per-request based on configurable policy.

**vs. OpenAI's content filter**: Catches output only, not input. Doesn't redact. Doesn't route locally. No audit trail.

**vs. writing your own scanner**: You'd need regex, entropy analysis, Luhn validation, context negation, jailbreak detection, SSE streaming, OpenAI API compatibility, and a policy engine. TSM ships all of it.

---

## License

MIT — [tsm7979/tsm79](https://github.com/tsm7979/tsm79)
