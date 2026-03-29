# TSM Layer

**AI Firewall + Routing for every LLM call**

Stop sending sensitive data to third-party APIs. Control, sanitize, and route every AI request.

## Why TSM?

Every time you call an LLM API, you're potentially leaking:
- Personal data (names, SSNs, emails)
- Business secrets
- Customer information
- Internal code

**TSM Layer** sits between your code and AI providers, giving you:

✅ **PII Detection & Sanitization** - Automatic redaction of sensitive data
✅ **Intelligent Routing** - Privacy-first: route to local models when needed
✅ **Full Audit Trail** - Every request logged and replayable
✅ **Cost Optimization** - Smart routing to cheapest model for the task
✅ **Zero Code Changes** - Drop-in replacement for your AI calls

## Install

```bash
pip install tsm-layer
```

## Quick Start (30 seconds)

### 1. Set your API key

```bash
export TSM_OPENAI_API_KEY=your-key-here
```

### 2. Run your first command

```bash
tsm run "Analyze this contract"
```

### 3. See the magic ✨

```
╭──────────────────────────────────────────────╮
│                TSM LAYER                     │
│     AI Firewall + Routing Active            │
╰──────────────────────────────────────────────╯

🔍 INPUT ANALYSIS
──────────────────────────────────────────────
✔ No sensitive data detected

🧠 ROUTING DECISION
──────────────────────────────────────────────
ℹ Model: gpt-4
ℹ Reason: complex reasoning required
ℹ Mode: cloud (sanitized)

⚙️ EXECUTION
──────────────────────────────────────────────
Processing request...

📊 RESULT
──────────────────────────────────────────────
Analysis complete. [Processed via cloud with sanitization]

🧾 AUDIT
──────────────────────────────────────────────
ℹ Trace ID: tsm_9x21ab
✔ Full trace recorded
✔ Replay available

💡 Tip: Use `tsm audit tsm_9x21ab` to replay this request
```

## The "WTF Moment" Demo

Try this:

```bash
tsm run "My name is John Smith, SSN 123-45-6789, analyze this contract risk"
```

Watch TSM:
1. **Detect** the SSN and personal data
2. **Sanitize** it automatically
3. **Route** to a local model (privacy enforced)
4. **Log** everything for audit

Output:

```
🔍 INPUT ANALYSIS
──────────────────────────────────────────────
⚠️  Sensitive data detected:
   • ssn
   • personal_identity

🧼 SANITIZATION
──────────────────────────────────────────────
Original:
"My name is John Smith, SSN 123-45-6789, analyze this..."

Sanitized:
"My name is [REDACTED], [REDACTED_SSN], analyze this..."

🧠 ROUTING DECISION
──────────────────────────────────────────────
ℹ Model: local-llm
ℹ Reason: sensitive data detected - privacy enforced
ℹ Mode: fully private

⚙️ EXECUTION
──────────────────────────────────────────────
Processing request...

📊 RESULT
──────────────────────────────────────────────
Analysis complete. [Processed locally for privacy]

🧾 AUDIT
──────────────────────────────────────────────
ℹ Trace ID: tsm_a7f3c2
✔ Full trace recorded
✔ Replay available
```

**That's the power of TSM.**

No code changes. Full control. Complete privacy.

## Features

### 🔒 Privacy-First
- Automatic PII detection (SSN, email, phone, credit cards)
- Intelligent sanitization
- Force local execution for sensitive data

### 🧠 Smart Routing
- **Complex reasoning** → GPT-4
- **Code tasks** → GPT-4 Turbo
- **Simple queries** → GPT-3.5 Turbo
- **Sensitive data** → Local model

### 📊 Full Observability
- Every request logged
- Replay any request with `tsm audit <id>`
- See routing decisions
- Track costs

### 💰 Cost Optimization
- Automatic routing to cheapest model
- Local fallback for simple tasks
- Usage tracking

## Commands

### Run AI Request

```bash
tsm run "your prompt here"
```

### View Audit Log

```bash
tsm audit <trace_id>
```

### Show Configuration

```bash
tsm config
```

## Use Cases

### Protect Customer Data

```bash
tsm run "Analyze this support ticket: Customer Jane Doe (jane@example.com) reported..."
```

→ Email automatically redacted, processed locally

### Analyze Code Safely

```bash
tsm run "Review this internal API code for vulnerabilities"
```

→ Routed to appropriate model, never sent to third parties if sensitive

### Contract Analysis

```bash
tsm run "Summarize key risks in this NDA"
```

→ Smart routing based on complexity

## How It Works

```
Your Prompt
    ↓
┌─────────────────┐
│  TSM Firewall   │  ← Detect PII, sanitize
└─────────────────┘
    ↓
┌─────────────────┐
│  Smart Router   │  ← Choose model based on task + sensitivity
└─────────────────┘
    ↓
┌─────────────────┐
│  Execution      │  ← Local or cloud
└─────────────────┘
    ↓
┌─────────────────┐
│  Audit Log      │  ← Full trace saved
└─────────────────┘
    ↓
Result + Trace ID
```

## Roadmap

- [x] CLI tool
- [x] PII detection & sanitization
- [x] Intelligent routing
- [x] Audit logging
- [ ] Python SDK
- [ ] Web dashboard
- [ ] Custom routing rules
- [ ] Policy engine
- [ ] Team collaboration
- [ ] Enterprise SSO

## Architecture

TSM is built on a production-grade control plane:

- **31 integrated systems**
- **35,000+ lines of production code**
- **50+ comprehensive tests**
- **Kubernetes-ready deployment**

Core systems:
- Firewall layer with PII detection
- Multi-tenant architecture
- RBAC with 38 permissions
- Circuit breakers & resilience
- GraphQL + REST APIs
- Message queue for events
- Metrics export (Prometheus, StatsD)
- Distributed tracing

[See full architecture →](100_PERCENT_STEP1_COMPLETE.md)

## Contributing

We're open source! Contributions welcome.

```bash
git clone https://github.com/tsm7979/tsm
cd tsm
pip install -e .
```

## License

MIT License - see [LICENSE](LICENSE)

## Security

Found a security issue? Email security@tsm-platform.com

## Support

- **Issues**: [GitHub Issues](https://github.com/tsm7979/tsm/issues)
- **Twitter**: [@tsm_layer](https://twitter.com/tsm_layer)

---

**Built with ❤️ for developers who care about privacy**

Try it now: `pip install tsm-layer`
