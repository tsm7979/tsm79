# 🛡️ TSM — The AI Firewall

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Website](https://img.shields.io/badge/website-thesovereignmechanica.ai-purple)](https://thesovereignmechanica.ai/)

I built this because I kept accidentally pasting API keys and emails into AI chat windows.

Once you see your own SSN show up in a Claude prompt, you realize the problem is real and nothing out there actually solves it cheaply. So this is that — a firewall that intercepts every AI call you make, strips the sensitive stuff, and lets you watch it happen in real time.

---

## Try it right now

```bash
pip install tsm-firewall
tsm enable
```

You'll see this fire immediately in your terminal — no second window, no curl, nothing extra:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️  TSM — The AI Firewall
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓  Firewall started at http://localhost:8080
  ✓  PII detection active  (14 patterns, 4 severity tiers)
  ✓  Audit log active

  Sending test traffic — watch the firewall work:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  Help me file taxes. My SSN is 12…
[TSM] 🚨 Detected: SSN
[TSM] 🛡️  Redacted: SSN → [REDACTED:SSN]
[TSM] 🔒 Routing → local model  cloud never sees it
[TSM] ✓ Done  latency=2ms  cost=free (local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-4  Charge my Visa 4111 1111 1111 1111…
[TSM] 🚨 Detected: CREDIT_CARD
[TSM] 🔒 Routing → local model  cloud never sees it
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  Email alice@company.com the report
[TSM] 🔍 Detected: EMAIL
[TSM] 🛡️  Redacted: EMAIL → [REDACTED:EMAIL]
[TSM] ☁️  Routing → cloud  (PII removed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-3.5-turbo  What is the capital of France?
[TSM] ✓ Done  clean — forwarded unchanged
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓  Firewall active. Monitoring live requests...
```

That's it. From install to visible protection in under 30 seconds.

---

## How it works

TSM runs a local HTTP proxy on `:8080` that speaks the OpenAI API format. You point your tools at it instead of OpenAI. It scans every prompt before it leaves your machine, redacts what it finds, and makes a routing decision:

- **CRITICAL PII** (SSN, credit card, private key) → routed to a local model. Cloud never touches it.
- **HIGH PII** (API keys, passwords, JWT, AWS keys) → redacted, then forwarded to cloud.
- **MEDIUM PII** (emails, phone numbers) → redacted, forwarded.
- **Clean** → passes through unchanged.

All of this happens in `~2ms` of overhead. You see every decision printed to your terminal in real time.

---

## Hooking into your existing tools

This is the part that matters most. You don't change your code.

```bash
# Wrap a specific tool
tsm hook claude           # runs claude with TSM intercepting everything
tsm hook codex            # same for codex

# Or protect your entire shell session
eval "$(tsm enable --eval)"
# Now every python script, node app, or CLI tool that calls an AI is protected
```

If you use the OpenAI Python SDK:

```python
import os
os.environ["OPENAI_BASE_URL"] = "http://localhost:8080"

# Your existing code — completely unchanged
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(...)  # TSM intercepts this
```

---

## What gets caught

Tested against 8/8 pattern types through a live proxy:

| What                        | Severity | What TSM does                     |
|-----------------------------|----------|-----------------------------------|
| Social Security Number       | CRITICAL | Blocks from cloud entirely         |
| Credit card number           | CRITICAL | Blocks from cloud entirely         |
| Private key / PEM file       | CRITICAL | Blocks from cloud entirely         |
| AWS access key               | HIGH     | Strips it, forwards the rest       |
| OpenAI / API key             | HIGH     | Strips it, forwards the rest       |
| Password in prompt           | HIGH     | Strips it, forwards the rest       |
| Email address                | MEDIUM   | Strips it, forwards the rest       |
| Phone number                 | MEDIUM   | Strips it, forwards the rest       |
| Clean prompt                 | —        | Passes through, no overhead        |

Every decision gets logged to `tsm_audit.jsonl` for compliance purposes.

---

## Commands

```
tsm enable                    the main one — start + demo + live monitor
tsm demo                      step through 5 request types interactively
tsm scan "some text"          check text for PII without running the proxy
tsm hook claude               wrap claude
tsm hook codex                wrap codex
tsm run python app.py         run any script through the firewall
eval "$(tsm enable --eval)"   set env vars to protect your shell session
tsm status                    see what's been intercepted so far
tsm skills                    list behavior packs (claude, codex, secure-coding)
tsm stop                      stop the proxy
tsm test                      run the built-in detection test (8/8 checks)
```

---

## Skill packs

These are small markdown files that change how TSM handles specific tools.

```bash
tsm start --skill secure-coding   # flags insecure patterns in AI completions
tsm start --skill claude          # tweaked for claude sessions
tsm start --skill codex           # tweaked for code completion workflows
```

---

## The honest pitch

Companies charge $5k–$50k/year for products that do roughly what this does. Bedrock Guardrails, Nightfall, Private AI — they're all real products with real enterprise features (SOC 2, SSO, dashboards, Kubernetes). This repo isn't that.

What this is: the core detection and routing engine, open source, running on your laptop, showing you exactly what those products are protecting against. If you're building AI into a product and you haven't thought about this yet, this is a good place to start.

The enterprise version of TSM is [thesovereignmechanica.ai](https://thesovereignmechanica.ai/). The repo is the free tier.

---

## Install

```bash
# from PyPI
pip install tsm-firewall

# or from source
git clone https://github.com/tsm7979/tsm79.git
cd tsm79
pip install -e .
```

No dependencies outside the Python standard library. Python 3.8+.

---

MIT · [thesovereignmechanica.ai](https://thesovereignmechanica.ai/) · [github.com/tsm7979/tsm79](https://github.com/tsm7979/tsm79)
