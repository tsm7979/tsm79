# The Sovereign Mechanica (TSM)

**Stop leaking data to AI APIs. Intercept, sanitize, and route every LLM call.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## What is this?

**An AI firewall that sits between your code and OpenAI/Anthropic/etc.**

Every AI request goes through:
1. 🔍 **PII Detection** - Find SSNs, emails, secrets
2. 🧼 **Sanitization** - Auto-redact sensitive data
3. 🧠 **Smart Routing** - Use local models for sensitive data
4. 📝 **Audit Logging** - Track everything

**Zero code changes required.**

---

## Try it now (30 seconds)

```bash
# Clone and run
git clone https://github.com/tsm7979/tsm
cd tsm
python cli_app.py run "What is AI?"
```

That's it. No API keys needed for the demo.

---

## The Demo "

Try this:

```bash
python cli_app.py run "My name is John Smith, SSN 123-45-6789, analyze this contract risk"
```

**Watch what happens:**

```
==================================================
              TSM LAYER
     AI Firewall + Routing Active
==================================================

[SCAN] INPUT ANALYSIS
--------------------------------------------------
[!] Sensitive data detected:
   - Ssn
   - Personal Identity

[CLEAN] SANITIZATION
--------------------------------------------------
Original:
"My name is John Smith, SSN 123-45-6789, analyze this contrac..."

Sanitized:
"My name is [REDACTED] Smith, SSN [REDACTED_SSN], analyze thi..."

[ROUTE] ROUTING DECISION
--------------------------------------------------
[i] Model: local-llm
[i] Reason: sensitive data detected - privacy enforced
[i] Mode: fully private

[EXEC] EXECUTION
--------------------------------------------------
Processing request...

[OUTPUT] RESULT
--------------------------------------------------
Analysis complete. [Processed locally for privacy]

[LOG] AUDIT
--------------------------------------------------
[i] Trace ID: tsm_a2f6f971
[+] Full trace recorded
[+] Replay available

>> Tip: Use `tsm audit tsm_a2f6f971` to replay this request
```

**That's the power.**

TSM:
- Detected the SSN automatically
- Sanitized it
- Routed to a LOCAL model (zero data leak)
- Logged everything for audit

**All automatic. No code changes.**

---

## Why This Exists

**The Problem:**

Every time you do this:
```python
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": user_input}]
)
```

You might be sending:
- Customer SSNs
- API keys
- Internal code
- Business secrets

**To a third-party API.**

**The Solution:**

TSM Layer intercepts BEFORE the API call:

```
Your Code → TSM Firewall → (sanitize) → Cloud API
                    ↓
              [if sensitive]
                    ↓
              Local Model (private)
```

---

## Features

### 🔒 Privacy-First
- Detects: SSNs, emails, phone numbers, credit cards, API keys
- Auto-sanitizes sensitive data
- Routes to local models when needed
- **Zero data leaks**

### 🧠 Smart Routing
- Complex reasoning → GPT-4
- Code analysis → GPT-4 Turbo
- Simple queries → GPT-3.5
- **Sensitive data → Local model**

All automatic based on content.

### 📊 Full Observability
- Every request logged
- Replay any request: `tsm audit <trace_id>`
- See routing decisions
- Track costs

### 💰 Cost Optimization
- Routes to cheapest model for the task
- Caches common queries
- Usage tracking per tenant

---

## Commands

```bash
# Run a request
tsm run "your prompt here"

# View audit log
tsm audit <trace_id>

# Check config
tsm config
```

That's it. Three commands.

---

## Real-World Use Cases

### 1. Protect Customer Support Data

```bash
tsm run "Analyze this ticket: Customer jane@acme.com reported login issues"
```
→ Email redacted, processed safely

### 2. Analyze Internal Code

```bash
tsm run "Review this API endpoint for security issues"
```
→ Stays local if it detects secrets

### 3. Contract Analysis

```bash
tsm run "Summarize key risks in this NDA"
```
→ Routed to best model based on complexity

---

## How It Works

```
┌─────────────────────────────────────────┐
│           Your Application              │
└─────────────────┬───────────────────────┘
                  │
                  ↓
┌─────────────────────────────────────────┐
│          TSM FIREWALL LAYER             │
│                                         │
│  1. Scan for PII (SSN, email, etc.)    │
│  2. Sanitize sensitive data             │
│  3. Classify task complexity            │
│  4. Route to appropriate model          │
│  5. Log everything                      │
└─────────┬───────────────┬───────────────┘
          │               │
          ↓               ↓
  ┌──────────────┐  ┌──────────────┐
  │ Cloud APIs   │  │ Local Model  │
  │ (sanitized)  │  │ (private)    │
  └──────────────┘  └──────────────┘
```

---

## Architecture

**Production-grade AI control plane:**

- 35,000+ lines of production code
- 31 integrated systems
- 50+ comprehensive tests
- Kubernetes-ready

**Core systems:**
- PII detection engine
- Multi-tenant architecture
- RBAC (38 permissions)
- Circuit breakers
- GraphQL + REST APIs
- Message queue
- Metrics export (Prometheus, StatsD, InfluxDB)
- Distributed tracing

[See full architecture →](100_PERCENT_STEP1_COMPLETE.md)

---

## Roadmap

**Now (v1.0):**
- [x] CLI tool
- [x] PII detection
- [x] Smart routing
- [x] Audit logging

**Next (v1.1):**
- [ ] Python SDK
- [ ] Web dashboard
- [ ] Custom routing rules
- [ ] Policy engine

**Future (v2.0):**
- [ ] Team collaboration
- [ ] SSO integration
- [ ] Compliance reports
- [ ] Multi-region deployment

---

## Installation (Full Setup)

### Quick Install

```bash
git clone https://github.com/tsm7979/tsm
cd tsm
pip install -r requirements.txt
```

### Set API Keys (Optional)

```bash
export TSM_OPENAI_API_KEY=your-key
export TSM_ANTHROPIC_API_KEY=your-key
```

### Run

```bash
python cli_app.py run "your prompt"
```

---

## Deployment

### Docker

```bash
docker-compose up
```

### Kubernetes

```bash
kubectl apply -f deployment/kubernetes.yaml
```

Full deployment configs included for:
- Docker Compose
- Kubernetes
- Cloud platforms (AWS/GCP/Azure)

---

## Contributing

We're open source! PRs welcome.

```bash
git clone https://github.com/tsm7979/tsm
cd tsm
pip install -e .

# Run tests
pytest tests/
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Security

Found a vulnerability? Email: security@tsm-platform.com

---

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/tsm7979/tsm/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/tsm7979/tsm/discussions)
- 🐦 **Twitter**: [@tsm_layer](https://twitter.com/tsm_layer)

---

## Why "The Sovereign Mechanica"?

**Sovereign** = You own your data
**Mechanica** = Automated intelligence

**Your AI. Your control. Your privacy.**

---

**Built for developers who care about privacy.**

**Try it:** `git clone https://github.com/tsm7979/tsm`

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tsm7979/tsm&type=Date)](https://star-history.com/#tsm7979/tsm&Date)
