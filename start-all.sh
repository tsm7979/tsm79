#!/usr/bin/env bash
# start-all.sh — launch TSM stack (detector + proxy + dashboard)
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
DETECTOR_PORT="${DETECTOR_PORT:-8001}"
PROXY_PORT="${TSM_PORT:-8080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3001}"

# Cross-platform Python path: Linux/Mac use bin/, Windows uses Scripts/
PYTHON="${PYTHON:-.venv/bin/python}"
if [[ -f ".venv/Scripts/python" ]]; then PYTHON=".venv/Scripts/python"; fi

GREEN='\033[92m'; CYAN='\033[96m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}  TSM Stack${RESET}"
echo -e "${DIM}  ─────────────────────────────────────────────${RESET}"
echo ""

# ── 1. Python detector (FastAPI) ─────────────────────────────────────────────
echo -e "  Starting ${GREEN}detector${RESET} on :${DETECTOR_PORT}..."
cd "$REPO"
DETECTOR_PORT="$DETECTOR_PORT" \
  "$PYTHON" -m uvicorn detector.main:app \
    --host 0.0.0.0 --port "$DETECTOR_PORT" \
    --log-level warning \
    --no-access-log &
DETECTOR_PID=$!
echo "  detector PID: $DETECTOR_PID"

# Wait for detector to be ready
for i in {1..15}; do
  if curl -sf "http://localhost:${DETECTOR_PORT}/health" > /dev/null 2>&1; then
    echo -e "  detector ${GREEN}ready${RESET}"
    break
  fi
  sleep 0.5
done

# ── 2. TypeScript proxy (Node.js) ─────────────────────────────────────────────
echo -e "  Starting ${GREEN}proxy${RESET} on :${PROXY_PORT}..."
cd "$REPO/proxy"
if [ ! -d node_modules ]; then
  echo "  Installing proxy dependencies..."
  npm install --silent
fi
TSM_PORT="$PROXY_PORT" \
TSM_DETECTOR_URL="http://localhost:${DETECTOR_PORT}" \
  npx tsx src/index.ts &
PROXY_PID=$!
echo "  proxy PID: $PROXY_PID"
cd "$REPO"

# ── 3. Next.js dashboard ──────────────────────────────────────────────────────
echo -e "  Starting ${GREEN}dashboard${RESET} on :${DASHBOARD_PORT}..."
cd "$REPO/dashboard"
if [ ! -d node_modules ]; then
  echo "  Installing dashboard dependencies..."
  npm install --silent
fi
NEXT_PUBLIC_PROXY_URL="http://localhost:${PROXY_PORT}" \
  npm run dev > /dev/null 2>&1 &
DASHBOARD_PID=$!
echo "  dashboard PID: $DASHBOARD_PID"
cd "$REPO"

# ── Ready ──────────────────────────────────────────────────────────────────────
sleep 2
echo ""
echo -e "${DIM}  ─────────────────────────────────────────────${RESET}"
echo -e "  ${GREEN}✓${RESET} Proxy      http://localhost:${PROXY_PORT}"
echo -e "  ${GREEN}✓${RESET} Detector   http://localhost:${DETECTOR_PORT}/docs"
echo -e "  ${GREEN}✓${RESET} Dashboard  http://localhost:${DASHBOARD_PORT}"
echo ""
echo -e "  To use TSM in your app:"
echo -e "  ${DIM}export OPENAI_BASE_URL=http://localhost:${PROXY_PORT}${RESET}"
echo ""
echo -e "  Ctrl+C to stop all services"
echo ""

# ── Cleanup on exit ────────────────────────────────────────────────────────────
trap "echo '  Stopping...'; kill $DETECTOR_PID $PROXY_PID $DASHBOARD_PID 2>/dev/null; exit 0" SIGINT SIGTERM

wait
