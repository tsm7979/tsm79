#!/usr/bin/env bash
# TSM — One-liner installer
# Usage: curl -sSL https://raw.githubusercontent.com/tsm7979/tsm79/main/install.sh | bash

set -e

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[92m"
CYAN="\033[96m"
YELLOW="\033[93m"
RED="\033[91m"
GRAY="\033[90m"

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; exit 1; }
sep()  { echo -e "${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

echo
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${CYAN}  🛡️  TSM — The AI Firewall${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

# Check Python
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    err "Python 3.8+ is required. Install from https://python.org"
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    PYTHON="python"
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ok "Python $PY_VERSION found"

# Check pip
if ! "$PYTHON" -m pip --version &>/dev/null; then
    err "pip not found. Install with: $PYTHON -m ensurepip"
fi

# Install
info "Installing tsm-firewall..."
"$PYTHON" -m pip install tsm-firewall --quiet

# Verify
if command -v tsm &>/dev/null; then
    ok "tsm installed at $(command -v tsm)"
else
    warn "tsm not in PATH — try: $PYTHON -m tsm.cli.main"
fi

echo
sep
echo
echo -e "  ${BOLD}Ready. Start the AI firewall:${RESET}"
echo
echo -e "  ${GREEN}tsm enable${RESET}              ${GRAY}# start + hook + monitor${RESET}"
echo -e "  ${GREEN}tsm demo${RESET}                ${GRAY}# see detection live (no LLM needed)${RESET}"
echo -e "  ${GREEN}tsm hook claude${RESET}         ${GRAY}# wrap claude with TSM${RESET}"
echo
sep
echo
