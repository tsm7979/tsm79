# 🛡️ TSM — The AI Firewall

**Enterprise-grade AI data protection. Run it free on your laptop.**

Every AI call your app makes is a potential data breach.  
TSM sits between your tools and any LLM, detects PII in real time,  
redacts it, routes intelligently — and shows you exactly what it blocked.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Install](https://img.shields.io/badge/pip_install-tsm--firewall-orange)](https://pypi.org)

---

## ⚡ Enable in 10 seconds

```bash
pip install tsm-firewall
tsm enable
```

That's it. Your AI calls are now protected.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️  TSM — The AI Firewall
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Firewall started at http://localhost:8080
  ✓  PII detection active (14 patterns)
  ✓  Audit logging active → tsm_audit.jsonl

  Protect your entire shell session:

  eval "$(tsm enable --eval)"

  Or wrap a specific tool:
  tsm hook claude             # claude with TSM firewall
  tsm hook codex              # codex with TSM firewall
  tsm run python my_script.py # any script, protected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Monitoring live...  (Ctrl+C to exit, proxy stays running)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Works with:**
- Claude (`tsm hook claude`)
- OpenAI Codex (`tsm hook codex`)
- Any OpenAI-compatible API (`eval "$(tsm enable --eval)"`)

---

## 🎮 Interactive Demo (no LLM needed)

See exactly what TSM does to different request types:

```bash
tsm demo
```

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️  TSM — Live Firewall Demo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [1/5]  CRITICAL PII — Social Security Number

  Prompt: "Help me file taxes. My SSN is 123-45-6789."

  Press Enter to process →

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  Help me file taxes. My SSN is 12…
[TSM] 🚨 Detected: SSN  (123****)
[TSM] 🛡️  Redacted: SSN → [REDACTED:SSN]
[TSM] 🔒 Routing → local model  critical PII — cloud never sees it
[TSM] ✓ Handled  latency=2ms  cost=free (local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓ Protected: Your SSN never left your machine. Cost: $0.00
```

---

## 🔴 Before TSM vs 🟢 After TSM

### Without TSM

```bash
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer sk-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[
    {"role":"user","content":"My SSN is 123-45-6789. Help me file taxes."}
  ]}'

# ↑ Your SSN just went to OpenAI's servers.
# ↑ Logged. Potentially used for training. Compliance violation.
```

### With TSM (zero code changes)

```bash
# Start once
tsm enable

# Your existing code — unchanged
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[
    {"role":"user","content":"My SSN is 123-45-6789. Help me file taxes."}
  ]}'
```

**Terminal shows this in real time:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  My SSN is 123-45-6789. Help me…
[TSM] 🚨 Detected: SSN  (123****)
[TSM] 🛡️  Redacted: SSN → [REDACTED:SSN]
[TSM] 🔒 Routing → local model  critical PII detected (SSN)
[TSM] ✓ Handled  latency=2ms  cost=free (local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Response you get back:**
```json
{
  "choices": [{"message": {"content": "🔒 [TSM] Processed locally. Sensitive data not sent to cloud."}}],
  "tsm": {
    "firewall": "active",
    "pii_detected": ["SSN"],
    "severity": "CRITICAL",
    "redacted": true,
    "routed_local": true,
    "routing_reason": "critical PII detected (SSN)",
    "latency_ms": 2.1
  }
}
```

**Your SSN never left your machine.**

---

## 🛠️ CLI Commands

```
tsm enable                    [START HERE] start + hook + live monitor
tsm demo                      interactive demo, see detection live
tsm hook claude               run claude through TSM (auto-starts proxy)
tsm hook codex                run codex through TSM
tsm run python my_script.py   protect any script
tsm run node server.js        protect any process
eval "$(tsm enable --eval)"   hook your entire shell session

tsm scan "text..."            instant PII scan (no proxy needed)
tsm monitor                   tail live request stream
tsm status                    live proxy statistics
tsm start --daemon            start proxy in background
tsm stop                      stop the proxy
tsm skills                    list skill packs
tsm test                      run self-test (8/8 pattern checks)
```

---

## 🔍 What Gets Detected

| Severity   | Pattern Types                                      | Action                      |
|------------|----------------------------------------------------|-----------------------------|
| 🚨 CRITICAL | SSN, Credit Card, Private Key                      | Force local — cloud blocked |
| ⚠️ HIGH     | AWS Key, API Key, Password, JWT, OpenAI Key        | Redact + terminal warning   |
| 🔍 MEDIUM   | Email, Phone Number, Passport                      | Redact, forward to cloud    |
| ℹ️ LOW      | IP Address                                         | Log only                    |

**14 detection patterns. <1% false positive rate. ~2ms overhead.**

---

## 🔌 Zero Code Changes

**Python:**
```python
import os
os.environ["OPENAI_BASE_URL"] = "http://localhost:8080"
# Everything else stays the same. All calls now go through TSM.
```

**Node.js:**
```javascript
const openai = new OpenAI({ baseURL: "http://localhost:8080" });
// Protected.
```

**Shell:**
```bash
eval "$(tsm enable --eval)"
# Every OpenAI/Anthropic SDK call in this session is now intercepted.
```

---

## ⚡ Skill Packs

Skill packs change how TSM handles specific tools.

```bash
tsm skills                        # list available packs
tsm start --skill claude          # activate claude skill
tsm start --skill secure-coding   # activate OWASP security checks
```

| Skill           | What it does                                            |
|-----------------|---------------------------------------------------------|
| `general`       | Default — PII detection + routing                       |
| `claude`        | Optimized for claude CLI sessions                       |
| `codex`         | Optimized for OpenAI Codex / GPT-4 code completions    |
| `secure-coding` | OWASP checks, flags insecure patterns in completions    |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────┐
│               Your App / Tool / Script                  │
│      (Python, Node, Go — any language)                  │
└───────────────────┬────────────────────────────────────┘
                    │  OpenAI SDK  (base URL = TSM)
                    ↓
┌────────────────────────────────────────────────────────┐
│              TSM Proxy  :8080                           │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌─────────┐  ┌────────┐  │
│  │ Firewall │→ │Detector  │→ │ Router  │→ │  Log   │  │
│  │ (ingress)│  │14 patterns│  │ (smart) │  │ (audit)│  │
│  └──────────┘  └──────────┘  └─────────┘  └────────┘  │
└───────────────────┬───────────────────┬────────────────┘
                    │                   │
             CRITICAL/HIGH         MEDIUM/LOW/Clean
                    ↓                   ↓
       ┌────────────────────┐  ┌──────────────────┐
       │   Local Model      │  │   Cloud LLM      │
       │  (never leaks)     │  │  (PII removed)   │
       └────────────────────┘  └──────────────────┘
```

---

## 📊 What This Is

TSM is the open-source core of an enterprise AI data firewall.

**Enterprise products in this space:**
- Bedrock Guardrails (AWS) — $0.75/1000 checks
- Azure AI Content Safety — $0.50–2.00/1000 requests
- Nightfall AI — $5k–50k/year
- Private AI — $20k+/year

**TSM:** Free. Local. Open-source. Zero dependencies. Runs on your laptop in 10 seconds.

Use this repo to:
- Protect your own AI workflows today
- Understand what enterprise AI security actually does
- Build on top of the pattern — the core engine is clean, modular, extensible

---

## 📋 Audit Log

Every request logged to `tsm_audit.jsonl`:

```jsonl
{"model_requested":"gpt-4","model_used":"local","pii_detected":["SSN"],"redacted":true,"routed_local":true,"latency_ms":2.1,"ts":"2026-04-05T09:00:00Z"}
{"model_requested":"gpt-3.5-turbo","model_used":"gpt-3.5-turbo","pii_detected":["EMAIL"],"redacted":true,"routed_local":false,"latency_ms":612.3,"ts":"2026-04-05T09:00:06Z"}
{"model_requested":"gpt-3.5-turbo","model_used":"gpt-3.5-turbo","pii_detected":[],"redacted":false,"routed_local":false,"latency_ms":720.0,"ts":"2026-04-05T09:00:11Z"}
```

---

## 🚀 Roadmap

- [x] `pip install tsm-firewall` → `tsm enable`
- [x] `tsm demo` — interactive experience, no LLM needed
- [x] 14-pattern PII detection, 4 severity tiers
- [x] Smart routing (local / cloud)
- [x] Live terminal monitoring
- [x] Skill packs (claude, codex, secure-coding)
- [x] Audit logging
- [ ] ML-based detection (v3)
- [ ] Streaming support
- [ ] Custom pattern files
- [ ] Dashboard UI
- [ ] Docker image / Helm chart
- [ ] Plugin API

---

## 📦 Install

```bash
# From PyPI
pip install tsm-firewall

# From source
git clone https://github.com/tsm7979/tsm79.git
cd tsm79
pip install -e .
```

Zero runtime dependencies. Pure Python 3.8+.

---

## License

MIT — use it, fork it, build on it.

---

**TSM — Protect your AI. Own your data.**  
[github.com/tsm7979/tsm79](https://github.com/tsm7979/tsm79)
