# Policy DSL

The TSM79 policy DSL is a small declarative YAML that decides which verdict a request gets. Operators write rules; the dataplane evaluates them in priority order.

For the policy file format, the language server is in `policy-lsp/` — install it in your editor for diagnostics, completions, and inline doc-on-hover.

---

## Verdict taxonomy

The dataplane emits one of five verdicts per request:

| Verdict | Behaviour | HTTP |
|---|---|---|
| `allow` | forwarded unchanged | upstream's |
| `redact` | PII / secret spans replaced with `[REDACTED:<type>]` before forwarding | upstream's |
| `route_local` | held inside the perimeter — forwarded to a local model (Ollama / VPC / on-prem) | upstream's |
| `quarantine` | held for human review — not forwarded, not denied | **202** |
| `block` | refused at the gate, never sent upstream | **400** |

`quarantine` was added in v3.0.0. It closes a fail-OPEN gap that existed in earlier versions when the ML triage was unsure about ambiguous PII (NER signal but no fast-path hit).

---

## Rule schema

```yaml
version: 1
workspace: default

rules:
  - id: block_critical_secrets
    priority: 10
    match:
      any_of:
        - contains_pii: [GITHUB_TOKEN, AWS_KEY, OPENAI_KEY, ANTHROPIC_KEY, STRIPE_SECRET, PRIVATE_KEY]
        - severity: critical
    action: block
    reason: "secret in prompt — refused"

  - id: route_local_for_pii
    priority: 30
    match:
      all_of:
        - contains_pii: [SSN, CREDIT_CARD, EMAIL, PHONE]
        - not: { user_role: trusted }
    action: route_local
    target: "http://ollama:11434"

  - id: quarantine_ambiguous_pii
    priority: 45
    match:
      all_of:
        - detector_signal: NER_REVIEW
        - risk_score_gte: 50
    action: quarantine

  - id: redact_medium_risk
    priority: 60
    match:
      any_of:
        - severity: medium
        - severity: high
    action: redact

  - id: allow_clean
    priority: 100
    match:
      severity: clean
    action: allow
```

### Field reference

| Field | Type | Notes |
|---|---|---|
| `id` | string | unique within a workspace, used in audit logs |
| `priority` | int | lower wins. Suggest 10/30/45/60/100 spacing to leave room |
| `match` | object | see matchers below |
| `action` | enum | one of `allow`, `redact`, `route_local`, `quarantine`, `block` |
| `target` | string | required when `action: route_local`. HTTP base URL of the local model |
| `reason` | string | optional. Surfaced to the client in `X-TSM-Reason` on block |

### Matchers

| Matcher | Argument | Notes |
|---|---|---|
| `contains_pii` | array of PII types | any one match satisfies |
| `severity` | one of `critical`, `high`, `medium`, `low`, `clean` | from the detector output |
| `risk_score_gte` | int 0–100 | matches if the request's risk score is at least N |
| `user_role` | string | from `X-TSM-User-Role` header or the workspace key's claimed role |
| `model_prefix` | string | matches request's `model` field's prefix (e.g. `gpt-4o`) |
| `detector_signal` | string | NER_REVIEW, JAILBREAK, etc. |
| `endpoint` | string | matches request's path (e.g. `/v1/chat/completions`) |
| `header` | `{name: value}` | header equality |
| `any_of` | array of matchers | OR — any one matches |
| `all_of` | array of matchers | AND — all match |
| `not` | matcher | negation |

---

## Built-in rules

Every workspace starts with these unless overridden by a rule of lower (better) priority on the same workspace.

```yaml
rules:
  - id: builtin_block_secrets
    priority: 10
    match: { contains_pii: [GITHUB_TOKEN, AWS_KEY, OPENAI_KEY, ANTHROPIC_KEY, STRIPE_SECRET, PRIVATE_KEY] }
    action: block

  - id: builtin_block_high_risk
    priority: 20
    match: { risk_score_gte: 90 }
    action: block

  - id: builtin_quarantine_ner_review
    priority: 45
    match: { detector_signal: NER_REVIEW }
    action: quarantine

  - id: builtin_redact_medium_risk
    priority: 60
    match: { severity: medium }
    action: redact

  - id: builtin_route_local_pii
    priority: 70
    match: { contains_pii: [SSN, CREDIT_CARD, EMAIL, PHONE] }
    action: route_local
    target: "http://ollama:11434"

  - id: builtin_allow_clean
    priority: 100
    match: { severity: clean }
    action: allow
```

Operators add custom rules with priorities BETWEEN the builtins to refine behaviour.

---

## Workspace isolation

Each workspace has its own policy file at `~/.tsm/workspaces/<id>/policy.yaml`. Workspaces do not share rules. The admin-api enforces strict workspace boundaries on key-to-policy mapping.

Custom rules via REST:

```bash
curl -X POST https://admin.tsm.local/workspaces/eng/rules \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Bearer $TSM_ADMIN_TOKEN" \
  --data-binary @new_rules.yaml
```

The admin-api validates the policy through `policy-lsp` before persisting. Invalid policies are rejected with diagnostics.

---

## Ordering

Rules are evaluated by ascending priority. The FIRST matching rule wins.

A request with `severity: critical` and a `GITHUB_TOKEN`:

1. `builtin_block_secrets` (priority 10) → matches → action `block` → DONE.

A request with `severity: medium` and a `CREDIT_CARD`:

1. `builtin_block_secrets` (10) → no match
2. `builtin_block_high_risk` (20) → no match
3. `builtin_quarantine_ner_review` (45) → no match
4. `builtin_redact_medium_risk` (60) → matches → action `redact` → DONE.

The `CREDIT_CARD` is redacted before the `route_local` rule (priority 70) gets a chance — which is intentional. The `redact` rule on medium-severity catches CC content because CC is medium-severity by default.

If the operator wants CC to route_local instead of redact, they add a rule at priority 50:

```yaml
- id: route_local_credit_card
  priority: 50
  match: { contains_pii: [CREDIT_CARD] }
  action: route_local
  target: "http://ollama:11434"
```

---

## Editor integration

`policy-lsp/` is a Language Server Protocol implementation for the policy DSL. Install in your editor:

| Editor | How |
|---|---|
| VS Code | Install the **TSM Policy** extension from the marketplace (or sideload from `policy-lsp/vscode/`) |
| Neovim | Add to `lspconfig` with `cmd = { "policy-lsp" }`, `filetypes = { "yaml" }`, `root_dir = util.root_pattern(".tsm-workspace") }` |
| Helix | Add to `~/.config/helix/languages.toml` with `language-servers = ["policy-lsp"]` on the `yaml` block |

You get:

- Inline diagnostics for unknown matchers, unknown PII types, missing required fields
- Completion on PII type names, severity values, action values
- Hover documentation on every field
- Go-to-definition jumping rule references to their definitions
- Code actions to insert built-in templates

---

## Testing policies

```
tsm policy lint   policy.yaml
tsm policy test   policy.yaml --case "STRIPE_KEY=sk_live_…"  --expect block
tsm policy test   policy.yaml --case "summarise board deck"   --expect allow
tsm policy bench  policy.yaml --iters 10000
```

The CLI reuses the same engine the dataplane uses, so test results are accurate.

---

## Authoring style

- Use `id: snake_case_action`
- Prefer `priority` gaps of 10 between rules for room to insert
- Put `reason: …` on every `block` rule so operators see why in audit logs
- Use `not` sparingly — it makes rules harder to reason about
- Comment policy files with `# why:` — your future self will thank you
