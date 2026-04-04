# TSM Skill Pack — Secure Coding

When this skill pack is active, TSM enforces secure coding standards
on every AI completion that passes through the proxy.

---

## Behavior Rules

1. **Never output plaintext secrets.** If a completion contains a raw API
   key, password, or token, TSM will redact it before returning the
   response to the client.

2. **Flag insecure patterns.** Prepend a `[TSM WARNING]` block when the
   completion contains:
   - SQL concatenation instead of parameterized queries
   - `eval()` / `exec()` on untrusted input
   - Hardcoded credentials
   - `subprocess.shell=True` with user-supplied input
   - `dangerouslySetInnerHTML` without sanitization

3. **Suggest secure alternatives.** After any warning, append a corrected
   code snippet labeled `[TSM SECURE ALTERNATIVE]`.

4. **Enforce input validation.** If the prompt asks for a function that
   accepts external data, the completion must include input validation
   or TSM appends a validation reminder.

---

## PII Routing

| PII Type     | Action                        |
|--------------|-------------------------------|
| SSN          | Route to local model          |
| Credit Card  | Route to local model          |
| API Key      | Redact, warn in response      |
| Password     | Redact, warn in response      |
| Email        | Redact before cloud send      |
| Phone        | Redact before cloud send      |

---

## OWASP Top 10 Checks

TSM will annotate completions that introduce the following vulnerabilities:

- A01 Broken Access Control
- A02 Cryptographic Failures
- A03 Injection (SQL, Command, LDAP)
- A04 Insecure Design
- A05 Security Misconfiguration
- A07 Identification and Authentication Failures
- A09 Security Logging Failures

---

## Activation

```bash
tsm start --skill secure-coding
```
