"""
TSM Real-Time Logger
====================
The "visible magic" — beautiful terminal output that makes users go:
"holy sh*t this actually works"
"""

from __future__ import annotations
import sys
import time
from typing import List, Optional
from tsm.detectors.pii import Detection, ScanResult, Severity


# ANSI color codes
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    BG_RED = "\033[41m"
    BG_YEL = "\033[43m"
    BG_GRN = "\033[42m"


SEVERITY_COLOR = {
    Severity.CRITICAL: C.RED,
    Severity.HIGH:     C.YELLOW,
    Severity.MEDIUM:   C.CYAN,
    Severity.LOW:      C.GRAY,
}

SEVERITY_ICON = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH:     "⚠️ ",
    Severity.MEDIUM:   "🔍",
    Severity.LOW:      "ℹ️ ",
}


def _line(char: str = "━", width: int = 58) -> str:
    return C.GRAY + char * width + C.RESET


def log_request_start(model: str, content_preview: str) -> None:
    """Print when a new request comes in."""
    preview = content_preview[:50].replace("\n", " ")
    if len(content_preview) > 50:
        preview += "…"
    print(f"\n{_line()}")
    print(f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} {C.GRAY}→ {model}{C.RESET}  {C.DIM}{preview}{C.RESET}")


def log_scan_clean() -> None:
    print(f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} {C.GREEN}✓ Clean{C.RESET}  no sensitive data detected")


def log_scan_result(result: ScanResult) -> None:
    """Print PII scan detections — the viral moment."""
    if result.is_clean:
        log_scan_clean()
        return

    for d in result.detections:
        color = SEVERITY_COLOR[d.severity]
        icon  = SEVERITY_ICON[d.severity]
        print(
            f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} "
            f"{icon} {color}{C.BOLD}Detected:{C.RESET} "
            f"{color}{d.type}{C.RESET}  "
            f"{C.DIM}({d.preview}){C.RESET}"
        )


def log_redaction(before_types: List[str]) -> None:
    types_str = ", ".join(before_types)
    print(
        f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} "
        f"{C.YELLOW}🛡️  Redacted:{C.RESET} "
        f"{C.BOLD}{types_str}{C.RESET} "
        f"{C.GRAY}→ [REDACTED]{C.RESET}"
    )


def log_route(target: str, is_local: bool, reason: str) -> None:
    if is_local:
        label = f"{C.GREEN}local model{C.RESET}"
        icon  = "🔒"
    else:
        label = f"{C.BLUE}cloud{C.RESET}"
        icon  = "☁️ "
    print(
        f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} "
        f"{icon} Routing → {label}  "
        f"{C.DIM}{reason}{C.RESET}"
    )


def log_blocked(reason: str) -> None:
    print(
        f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} "
        f"{C.BG_RED}{C.WHITE}  BLOCKED  {C.RESET} "
        f"{C.RED}{reason}{C.RESET}"
    )


def log_sent(model: str, latency_ms: float, cost: float) -> None:
    cost_str = f"${cost:.5f}" if cost > 0 else "free (local)"
    print(
        f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} "
        f"{C.GREEN}✓ Sent{C.RESET}  "
        f"{C.GRAY}model={model}  "
        f"latency={latency_ms:.0f}ms  "
        f"cost={cost_str}{C.RESET}"
    )
    print(_line())


def log_server_start(host: str, port: int) -> None:
    print()
    print(f"{C.BOLD}{C.CYAN}" + "━" * 58 + C.RESET)
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM  —  AI Security Layer{C.RESET}")
    print(f"{C.CYAN}" + "━" * 58 + C.RESET)
    print(f"  {C.GREEN}✓{C.RESET}  Proxy  →  {C.BOLD}http://{host}:{port}{C.RESET}")
    print(f"  {C.GREEN}✓{C.RESET}  PII Detection    {C.GRAY}SSN, CC, API keys, emails…{C.RESET}")
    print(f"  {C.GREEN}✓{C.RESET}  Smart Routing    {C.GRAY}sensitive → local  clean → cloud{C.RESET}")
    print(f"  {C.GREEN}✓{C.RESET}  Audit Log        {C.GRAY}tsm_audit.jsonl{C.RESET}")
    print(f"{C.CYAN}" + "━" * 58 + C.RESET)
    print()
    print(f"  {C.BOLD}Drop-in usage:{C.RESET}")
    print(f"  {C.YELLOW}export OPENAI_BASE_URL=http://{host}:{port}{C.RESET}")
    print(f"  {C.GRAY}# that's it — your tools are now protected{C.RESET}")
    print()
    print(f"  {C.DIM}CTRL+C to stop{C.RESET}")
    print(f"{C.CYAN}" + "━" * 58 + C.RESET)
    print()


def log_skill_active(skill_name: str) -> None:
    print(
        f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} "
        f"{C.MAGENTA}⚡ Skill active:{C.RESET} {C.BOLD}{skill_name}{C.RESET}"
    )
