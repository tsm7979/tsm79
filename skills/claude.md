# TSM Skill Pack — Claude

Optimized behavior for Claude (claude.ai / claude CLI) passing through
the TSM proxy.

---

## What Changes

When `tsm hook claude` is used, every message to Claude:

1. Is scanned for PII before leaving your machine.
2. Has sensitive fields redacted automatically.
3. Is routed to a local model if CRITICAL PII is found.
4. Is logged to `tsm_audit.jsonl` with full metadata.

---

## Shell Quickstart

```bash
# Start TSM proxy
tsm start

# Run claude through TSM (all traffic inspected)
tsm hook claude

# Or set env vars and run normally
eval "$(tsm enable --eval)"
claude
```

---

## What TSM Protects

When you paste code into Claude that contains:

| Data Type      | What TSM Does                                      |
|----------------|----------------------------------------------------|
| API keys       | Redacts before sending, warns in terminal          |
| Passwords      | Redacts before sending                             |
| SSN / CC       | Forces local model — never leaves your machine     |
| Email / Phone  | Redacts before sending to cloud                    |
| AWS keys       | Redacts + fires a `⚠️ HIGH` alert in terminal      |
| JWT tokens     | Redacts before sending                             |

---

## Audit Log

Every request through TSM is logged:

```jsonl
{"model_requested":"claude-3-opus","model_used":"local","pii_detected":["SSN"],"redacted":true,"routed_local":true,"latency_ms":2.1,"ts":"2026-04-05T09:00:00Z"}
```

Log location: `tsm_audit.jsonl` (current directory)

---

## Activation

```bash
tsm start --skill claude
tsm hook claude
```
