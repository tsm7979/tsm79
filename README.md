# 🛡️ TSM — The AI Firewall

**Enterprise-grade AI data protection. Free. Local. 10 seconds.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Website](https://img.shields.io/badge/website-thesovereignmechanica.ai-purple)](https://thesovereignmechanica.ai/)

---

## ⚡ Enable in 10 seconds

```bash
pip install tsm-firewall
tsm enable
```

**That's it.** You'll see this:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️  TSM — The AI Firewall
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Firewall started at http://localhost:8080
  ✓  PII detection active  (14 patterns, 4 severity tiers)
  ✓  Audit log active      tsm_audit.jsonl

  Your AI tools are now protected.  To hook your shell:

  eval "$(tsm enable --eval)"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Sending test traffic — watch the firewall work:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  Help me file taxes. My SSN is 12…
[TSM] 🚨 Detected: SSN  (123****)
[TSM] 🛡️  Redacted: SSN → [REDACTED:SSN]
[TSM] 🔒 Routing → local model  cloud never sees it
[TSM] ✓ Done  latency=2ms  cost=free (local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-4  Charge my Visa 4111 1111 1111 1111…
[TSM] 🚨 Detected: CREDIT_CARD  (411***************)
[TSM] 🛡️  Redacted: CREDIT_CARD → [REDACTED:CC]
[TSM] 🔒 Routing → local model  cloud never sees it
[TSM] ✓ Done  latency=2ms  cost=free (local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  Email alice@company.com the Q1…
[TSM] 🔍 Detected: EMAIL  (ali***)
[TSM] 🛡️  Redacted: EMAIL → [REDACTED:EMAIL]
[TSM] ☁️  Routing → cloud  PII redacted
[TSM] ✓ Done  latency=612ms  cost=~$0.00012
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  What is the capital of France?
[TSM] ✓ Done  latency=720ms  cost=~$0.00008  (clean)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓  Firewall active. Your AI is protected.

  tsm hook claude          wrap claude
  tsm hook codex           wrap codex
  tsm run python app.py    wrap any script
  tsm status               live stats

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Monitoring live...  (Ctrl+C to exit, proxy keeps running)
```

Every real request your tools make will appear here in real time.

---

## 🔌 Works with any AI tool. Zero code changes.

```bash
tsm hook claude             # run claude through TSM
tsm hook codex              # run codex through TSM
tsm run python my_script.py # run any script through TSM
eval "$(tsm enable --eval)" # hook entire shell session
```

**Or one env var:**
```bash
export OPENAI_BASE_URL=http://localhost:8080
# Everything using the OpenAI SDK is now intercepted.
```

---

## 🎮 Interactive demo (no LLM, no account needed)

```bash
tsm demo
```

Walk through 5 real request types — SSN, credit card, AWS key, email, clean — and see exactly what TSM does to each one.

---

## 🔴→🟢 Before vs After

### Without TSM
```bash
# Your prompt goes directly to OpenAI
"My SSN is 123-45-6789. Help me file taxes."
# → OpenAI receives it. Logged. Compliance violation.
```

### With TSM (no code changes)
```bash
# Same prompt, same code, same tool
"My SSN is 123-45-6789. Help me file taxes."
# → TSM intercepts
# → [TSM] 🚨 Detected: SSN
# → [TSM] 🔒 Routing → local model
# → OpenAI never sees it
```

**curl before/after:**

```bash
# BEFORE — data goes to cloud
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-3.5-turbo","messages":[
        {"role":"user","content":"My SSN is 123-45-6789"}]}'

# AFTER — same curl, TSM intercepts
curl -X POST http://localhost:8080/v1/chat/completions \
  -d '{"model":"gpt-3.5-turbo","messages":[
        {"role":"user","content":"My SSN is 123-45-6789"}]}'
```

**Response:**
```json
{
  "choices": [{"message": {"content": "🔒 [TSM] Processed locally — data not sent to cloud."}}],
  "tsm": {
    "firewall": "active",
    "pii_detected": ["SSN"],
    "severity": "CRITICAL",
    "redacted": true,
    "routed_local": true,
    "latency_ms": 2.1
  }
}
```

---

## 🔍 What Gets Detected

| Severity   | Pattern Types                                   | Action                      |
|------------|-------------------------------------------------|-----------------------------|
| 🚨 CRITICAL | SSN, Credit Card, Private Key                   | Block from cloud entirely   |
| ⚠️ HIGH     | AWS Key, API Key, Password, JWT, OpenAI Key     | Redact + terminal alert     |
| 🔍 MEDIUM   | Email, Phone Number, Passport                   | Redact, allow cloud         |
| ℹ️ LOW      | IP Address                                      | Log only                    |

14 patterns. <1% false positives. ~2ms overhead.

---

## 🛠️ All Commands

```
tsm enable                    [START HERE] start + demo + monitor
tsm demo                      step-by-step walkthrough
tsm hook claude               wrap claude (auto-starts proxy)
tsm hook codex                wrap codex (auto-starts proxy)
tsm run python app.py         wrap any script (auto-starts proxy)
eval "$(tsm enable --eval)"   hook entire shell session
tsm scan "text..."            instant PII scan, no proxy needed
tsm monitor                   live request stream
tsm status                    proxy stats
tsm start --daemon            start proxy in background
tsm stop                      stop proxy
tsm skills                    list skill packs
tsm test                      self-test (8/8 pattern checks)
```

---

## ⚡ Skill Packs

```bash
tsm skills                        # list packs
tsm start --skill secure-coding   # OWASP checks on completions
tsm start --skill claude          # optimized for claude sessions
```

---

## 📊 What This Is

The free, open-source core of an enterprise AI security product.

**Comparable enterprise tools:**
- AWS Bedrock Guardrails — $0.75/1000 checks
- Nightfall AI — $5k–$50k/year
- Private AI — $20k+/year

**TSM:** Free. Local. No account. Runs in 10 seconds.

Use this repo to protect your own workflow today, and to understand what enterprise AI security actually does under the hood.

---

## 📦 Install

```bash
# PyPI
pip install tsm-firewall

# Source
git clone https://github.com/tsm7979/tsm79.git && cd tsm79 && pip install -e .
```

Zero runtime dependencies. Pure Python 3.8+.

---

MIT License — **TSM. Protect your AI. Own your data.**

[thesovereignmechanica.ai](https://thesovereignmechanica.ai/) · [github.com/tsm7979/tsm79](https://github.com/tsm7979/tsm79)
