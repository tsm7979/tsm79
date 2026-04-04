# TSM Skill Pack — Codex / OpenAI Codex

Intercepts every OpenAI Codex or GPT-4 code completion and applies
TSM's security firewall before data leaves your machine.

---

## Activation

```bash
tsm start --skill codex
tsm hook codex
# or for any OpenAI-SDK app:
eval "$(tsm enable --eval)"
```

---

## Code Completion Security

When Codex completions are routed through TSM:

1. **Secret Detection** — Inline secrets in generated code are flagged.
2. **Injection Prevention** — Shell injection patterns are annotated.
3. **Path Traversal** — `../` sequences in file ops are flagged.
4. **Hardcoded Credentials** — Any `password =` or `api_key =` literal
   in a completion triggers a `[TSM:HARDCODED_SECRET]` warning.

---

## Routing Logic

```
User Prompt → TSM Scan → CRITICAL PII?
    YES → Local model (no cloud)
    NO  → Redact remaining PII → OpenAI Codex
         ↓
Completion ← TSM Post-scan ← Cloud Response
    Contains secrets? → Redact + warn
    Contains vuln pattern? → Annotate
    Return to user
```

---

## Supported Models

TSM passes through to any model you configure in `OPENAI_BASE_URL`.
Default routing:

- Critical PII → `local` (blocks cloud)
- Everything else → your configured model

---

## Example Terminal Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TSM] → gpt-4  write a db connection function…
[TSM] ⚠️  Detected: PASSWORD  (pas***)
[TSM] 🛡️  Redacted: PASSWORD → [REDACTED]
[TSM] ☁️  Routing → cloud  high-risk data redacted
[TSM] ✓ Sent  model=gpt-4  latency=840ms  cost=$0.00041
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
