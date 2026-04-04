# TSM Skill Pack — General

The default skill pack. Applied whenever no other skill is specified.

---

## Default Behavior

- Scan all user messages for PII (14 pattern types)
- Redact before sending to any cloud LLM
- Route CRITICAL PII to local model
- Log all decisions to `tsm_audit.jsonl`

---

## PII Severity Tiers

| Tier     | Types                                  | Action             |
|----------|----------------------------------------|--------------------|
| CRITICAL | SSN, Credit Card, Private Key          | Force local model  |
| HIGH     | API Key, Password, AWS Key, JWT, OpenAI| Redact + warn      |
| MEDIUM   | Email, Phone, Passport                 | Redact + allow cloud |
| LOW      | IP Address                             | Log only           |

---

## Endpoints Protected

| Endpoint                | Method | Description               |
|-------------------------|--------|---------------------------|
| `/v1/chat/completions`  | POST   | OpenAI-compatible chat    |
| `/v1/completions`       | POST   | OpenAI-compatible legacy  |
| `/health`               | GET    | Health check              |
| `/stats`                | GET    | Live statistics           |
| `/v1/models`            | GET    | Model list                |

---

## Audit Log Format

```jsonl
{
  "model_requested": "gpt-4",
  "model_used": "local",
  "pii_detected": ["SSN", "CREDIT_CARD"],
  "redacted": true,
  "routed_local": true,
  "latency_ms": 1.4,
  "ts": "2026-04-05T09:00:00Z"
}
```

---

## Activation

```bash
tsm start            # uses general skill pack by default
```
