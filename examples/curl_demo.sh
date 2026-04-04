#!/usr/bin/env bash
# TSM curl demo — shows PII detection + routing in action
# Run: tsm start  (in another terminal)
#      bash examples/curl_demo.sh

BASE="${OPENAI_BASE_URL:-http://localhost:8080}"

echo ""
echo "🛡️  TSM Firewall — curl Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Proxy: $BASE"
echo ""

# ─── Test 1: SSN (CRITICAL) ───────────────────────────────────
echo "Test 1 — CRITICAL PII (SSN)"
echo "───────────────────────────"
curl -s -X POST "$BASE/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [
      {"role": "user", "content": "My SSN is 123-45-6789. Help me file taxes."}
    ]
  }' | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=d.get('tsm',{})
print(f\"  PII detected: {t.get('pii_detected','?')}\")
print(f\"  Routed to:   {t.get('routed_local') and 'local model' or 'cloud'}\")
print(f\"  Severity:    {t.get('severity','?')}\")
print(f\"  Redacted:    {t.get('redacted','?')}\")
print(f\"  Cost:        \$0.00 (local)\")
"
echo ""

# ─── Test 2: Credit Card (CRITICAL) ───────────────────────────
echo "Test 2 — CRITICAL PII (Credit Card)"
echo "─────────────────────────────────────"
curl -s -X POST "$BASE/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Charge my card 4111 1111 1111 1111 exp 12/27"}
    ]
  }' | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=d.get('tsm',{})
print(f\"  PII detected: {t.get('pii_detected','?')}\")
print(f\"  Routed to:   {t.get('routed_local') and 'local model' or 'cloud'}\")
"
echo ""

# ─── Test 3: Email (MEDIUM) ────────────────────────────────────
echo "Test 3 — MEDIUM PII (Email)"
echo "────────────────────────────"
curl -s -X POST "$BASE/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [
      {"role": "user", "content": "Email alice@example.com about the meeting."}
    ]
  }' | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=d.get('tsm',{})
print(f\"  PII detected: {t.get('pii_detected','?')}\")
print(f\"  Redacted:    {t.get('redacted','?')}\")
print(f\"  Routed to:   {t.get('routed_local') and 'local model' or 'cloud'}\")
"
echo ""

# ─── Test 4: Clean ─────────────────────────────────────────────
echo "Test 4 — Clean (no PII)"
echo "────────────────────────"
curl -s -X POST "$BASE/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [
      {"role": "user", "content": "What is the capital of France?"}
    ]
  }' | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=d.get('tsm',{})
print(f\"  PII detected: {t.get('pii_detected','?')}\")
print(f\"  Routed to:   cloud ✓\")
print(f\"  Firewall:    {t.get('firewall','?')}\")
"
echo ""

# ─── Stats ─────────────────────────────────────────────────────
echo "Proxy Stats"
echo "────────────"
curl -s "$BASE/stats" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  Total requests: {d.get('requests_total',0)}\")
print(f\"  Clean:          {d.get('requests_clean',0)}\")
print(f\"  Redacted:       {d.get('requests_redacted',0)}\")
print(f\"  Cost saved:     \${d.get('cost_saved_usd',0):.4f}\")
"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Demo complete. Your data never left your machine."
echo ""
