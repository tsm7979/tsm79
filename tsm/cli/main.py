"""
TSM CLI — The AI Firewall
=========================
One command. Instant protection.

    tsm enable                   start proxy + hook shell + monitor live
    tsm demo                     interactive demo — see detection happen
    tsm hook claude              run claude through TSM firewall
    tsm hook codex               run codex through TSM firewall
    tsm run <cmd>                run any command through TSM
    tsm monitor                  tail live request stream
    tsm scan <text>              scan text for PII instantly
    tsm start / stop / status    proxy management
    tsm skills                   list skill packs
    tsm test                     self-test
"""

from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import urllib.request
from typing import List, Optional

# Force UTF-8 output on Windows so emoji render correctly
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ─── ANSI ──────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    GRAY    = "\033[90m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GRN  = "\033[42m"


def _p(msg: str = "") -> None: print(msg)
def _ok(msg: str)    -> None: print(f"  {C.GREEN}✓{C.RESET}  {msg}")
def _warn(msg: str)  -> None: print(f"  {C.YELLOW}⚠{C.RESET}  {msg}")
def _err(msg: str)   -> None: print(f"  {C.RED}✗{C.RESET}  {msg}")
def _info(msg: str)  -> None: print(f"  {C.CYAN}→{C.RESET}  {msg}")
def _sep()           -> None: print(f"{C.GRAY}{'━' * 58}{C.RESET}")
def _tag(msg: str)   -> None: print(f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} {msg}")


# ─── Proxy helpers ─────────────────────────────────────────────

_DEFAULT_HOST = "localhost"
_DEFAULT_PORT = 8080


def _proxy_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def _ping(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"{_proxy_url(host, port)}/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _stats(host: str, port: int) -> Optional[dict]:
    try:
        with urllib.request.urlopen(f"{_proxy_url(host, port)}/stats", timeout=3.0) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _start_proxy_bg(host: str, port: int, skill: Optional[str] = None) -> bool:
    """Start the proxy in a background daemon thread. Returns True if up within 2s."""
    try:
        from tsm.proxy.server import start
    except ImportError:
        return False

    t = threading.Thread(
        target=start,
        kwargs={"host": host, "port": port, "skill": skill, "blocking": True},
        daemon=True,
    )
    t.start()
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if _ping(host, port, timeout=0.5):
            return True
        time.sleep(0.1)
    return False


def _ensure_proxy(host: str, port: int, skill: Optional[str] = None) -> bool:
    """Ensure proxy is running. Returns True if already up or successfully started."""
    if _ping(host, port):
        return True
    return _start_proxy_bg(host, port, skill)


# ─── Live output helpers ────────────────────────────────────────

def _type_line(line: str, delay: float = 0.018) -> None:
    """Print a line character by character for live effect."""
    for ch in line:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()


def _beat(ms: float = 300) -> None:
    time.sleep(ms / 1000)


def _print_request_log(model: str, preview: str, pii_types: list, severity: str,
                        routed_local: bool, latency_ms: float) -> None:
    """Print a full TSM request log block."""
    _sep()
    _tag(f"{C.GRAY}→ {model}{C.RESET}  {C.DIM}{preview[:50]}{'…' if len(preview)>50 else ''}{C.RESET}")
    _beat(200)

    SEVERITY_ICON = {
        "CRITICAL": f"{C.RED}🚨 Detected:{C.RESET}",
        "HIGH":     f"{C.YELLOW}⚠️  Detected:{C.RESET}",
        "MEDIUM":   f"{C.CYAN}🔍 Detected:{C.RESET}",
        "LOW":      f"{C.GRAY}ℹ️  Detected:{C.RESET}",
    }

    for pii in pii_types:
        icon = SEVERITY_ICON.get(severity, SEVERITY_ICON["MEDIUM"])
        _tag(f"{icon} {C.BOLD}{pii}{C.RESET}")
        _beat(150)

    if pii_types:
        types_str = ", ".join(pii_types)
        _tag(f"{C.YELLOW}🛡️  Redacted:{C.RESET} {C.BOLD}{types_str}{C.RESET} {C.GRAY}→ [REDACTED]{C.RESET}")
        _beat(150)

    if routed_local:
        _tag(f"{C.GREEN}🔒 Routing → {C.BOLD}local model{C.RESET}  {C.DIM}critical PII — cloud never sees it{C.RESET}")
    else:
        _tag(f"{C.CYAN}☁️  Routing → {C.BOLD}cloud{C.RESET}  {C.DIM}{'PII redacted' if pii_types else 'clean'}{C.RESET}")

    _beat(200)
    cost = "free (local)" if routed_local else f"${(latency_ms/1000)*0.001:.5f}"
    _tag(f"{C.GREEN}✓ Handled{C.RESET}  {C.GRAY}latency={latency_ms:.0f}ms  cost={cost}{C.RESET}")
    _sep()


# ─── cmd_enable ────────────────────────────────────────────────

def cmd_enable(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port
    base = _proxy_url(host, port)

    # --eval mode: just print raw exports for eval$()
    if getattr(args, "eval", False):
        print(f'export OPENAI_BASE_URL="{base}"')
        print(f'export OPENAI_API_BASE="{base}"')
        print(f'export ANTHROPIC_BASE_URL="{base}"')
        print('export TSM_ACTIVE="1"')
        return 0

    _p()
    print(f"{C.BOLD}{C.CYAN}{'━'*58}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM — The AI Firewall{C.RESET}")
    print(f"{C.CYAN}{'━'*58}{C.RESET}")

    # Auto-start proxy
    already_running = _ping(host, port)
    if already_running:
        _ok(f"Firewall already active at {C.BOLD}{base}{C.RESET}")
    else:
        _info("Starting firewall proxy...")
        if _start_proxy_bg(host, port):
            _ok(f"Firewall started at {C.BOLD}{base}{C.RESET}")
        else:
            _err("Could not start proxy — run: tsm start")
            return 1

    _ok(f"PII detection active  {C.DIM}(14 patterns, 4 severity tiers){C.RESET}")
    _ok(f"Audit logging active  {C.DIM}→ tsm_audit.jsonl{C.RESET}")
    _p()
    _sep()
    _p()

    print(f"  {C.BOLD}Protect your entire shell session:{C.RESET}")
    _p()
    print(f'  {C.YELLOW}eval "$(tsm enable --eval)"{C.RESET}')
    _p()
    print(f"  {C.DIM}Then run claude, python, node — everything is intercepted{C.RESET}")
    _p()
    print(f"  {C.BOLD}Or wrap a specific tool:{C.RESET}")
    _p()
    print(f"  {C.CYAN}tsm hook claude{C.RESET}            {C.DIM}# claude with TSM firewall{C.RESET}")
    print(f"  {C.CYAN}tsm hook codex{C.RESET}             {C.DIM}# codex with TSM firewall{C.RESET}")
    print(f"  {C.CYAN}tsm run python my_script.py{C.RESET} {C.DIM}# any script, protected{C.RESET}")
    _p()
    _sep()
    _p()
    print(f"  {C.BOLD}{C.MAGENTA}Monitoring live requests...{C.RESET}  {C.DIM}Ctrl+C to exit (proxy stays running){C.RESET}")
    _p()
    _sep()
    _p()

    _monitor_loop(host, port)
    return 0


# ─── cmd_demo ──────────────────────────────────────────────────

_DEMO_CASES = [
    {
        "label": "CRITICAL PII — Social Security Number",
        "model": "gpt-3.5-turbo",
        "prompt": "Help me file taxes. My SSN is 123-45-6789.",
        "pii": ["SSN"],
        "severity": "CRITICAL",
        "local": True,
        "latency": 2.0,
        "message": "Your SSN never left your machine. Cost: $0.00",
    },
    {
        "label": "CRITICAL PII — Credit Card",
        "model": "gpt-4",
        "prompt": "Charge my Visa 4111 1111 1111 1111 exp 12/28 for $199.",
        "pii": ["CREDIT_CARD"],
        "severity": "CRITICAL",
        "local": True,
        "latency": 1.8,
        "message": "Payment data blocked from cloud. Routed locally.",
    },
    {
        "label": "HIGH PII — AWS Key",
        "model": "gpt-4",
        "prompt": "Why is AKIAIOSFODNN7EXAMPLE1234 showing access denied?",
        "pii": ["AWS_KEY"],
        "severity": "HIGH",
        "local": False,
        "latency": 842.0,
        "message": "Key redacted before sending. Cloud got [REDACTED:AWS_KEY].",
    },
    {
        "label": "MEDIUM PII — Email",
        "model": "gpt-3.5-turbo",
        "prompt": "Write an intro email from alice@acmecorp.com to our new client.",
        "pii": ["EMAIL"],
        "severity": "MEDIUM",
        "local": False,
        "latency": 610.0,
        "message": "Email redacted. Response returned to your app normally.",
    },
    {
        "label": "Clean — No PII",
        "model": "gpt-3.5-turbo",
        "prompt": "Explain how neural networks learn from data.",
        "pii": [],
        "severity": None,
        "local": False,
        "latency": 720.0,
        "message": "Clean request forwarded to cloud without modification.",
    },
]


def cmd_demo(args: argparse.Namespace) -> int:
    _p()
    print(f"{C.BOLD}{C.CYAN}{'━'*58}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM — Live Firewall Demo{C.RESET}")
    print(f"{C.CYAN}{'━'*58}{C.RESET}")
    _p()
    print(f"  Enterprise-grade AI data protection — experience it now.")
    _p()
    print(f"  {len(_DEMO_CASES)} requests. Watch what TSM does to each one.")
    _p()
    _sep()

    total = len(_DEMO_CASES)
    blocked = 0
    redacted = 0
    cost_saved = 0.0

    for i, case in enumerate(_DEMO_CASES, 1):
        _p()
        print(f"  {C.BOLD}[{i}/{total}]  {case['label']}{C.RESET}")
        _p()
        print(f"  {C.DIM}Prompt: \"{case['prompt']}\"{C.RESET}")
        _p()

        try:
            input(f"  {C.GRAY}Press Enter to process →{C.RESET} ")
        except (EOFError, KeyboardInterrupt):
            _p()
            break

        _p()
        _print_request_log(
            model=case["model"],
            preview=case["prompt"],
            pii_types=case["pii"],
            severity=case["severity"] or "LOW",
            routed_local=case["local"],
            latency_ms=case["latency"],
        )
        _p()

        # Result line
        if case["local"]:
            print(f"  {C.GREEN}{C.BOLD}✓ Protected:{C.RESET} {case['message']}")
            blocked += 1
            cost_saved += 0.002
        elif case["pii"]:
            print(f"  {C.YELLOW}{C.BOLD}✓ Redacted:{C.RESET} {case['message']}")
            redacted += 1
        else:
            print(f"  {C.CYAN}{C.BOLD}✓ Clean:{C.RESET} {case['message']}")

        _p()

    # Summary
    _sep()
    _p()
    print(f"  {C.BOLD}Session Summary{C.RESET}")
    _p()
    print(f"  {C.GRAY}Requests          {C.RESET}{total}")
    print(f"  {C.RED}Routed local      {C.RESET}{blocked}  {C.DIM}(PII never sent to cloud){C.RESET}")
    print(f"  {C.YELLOW}Redacted + sent   {C.RESET}{redacted}  {C.DIM}(PII stripped before cloud){C.RESET}")
    print(f"  {C.GREEN}Cost saved        {C.RESET}${cost_saved:.4f}")
    _p()
    _sep()
    _p()
    print(f"  {C.BOLD}This is the free, open-source version.{C.RESET}")
    print(f"  {C.DIM}Enterprise deployments add SSO, policy engine, dashboard,{C.RESET}")
    print(f"  {C.DIM}custom patterns, Kubernetes, and compliance reporting.{C.RESET}")
    _p()
    print(f"  {C.CYAN}github.com/tsm7979/tsm79{C.RESET}")
    _p()
    _sep()
    _p()

    _p()
    print(f"  {C.BOLD}Ready to protect your tools?{C.RESET}")
    _p()
    print(f"  {C.GREEN}tsm enable{C.RESET}              {C.DIM}start + hook entire shell{C.RESET}")
    print(f"  {C.GREEN}tsm hook claude{C.RESET}         {C.DIM}wrap claude specifically{C.RESET}")
    print(f"  {C.GREEN}tsm run python app.py{C.RESET}   {C.DIM}protect any script{C.RESET}")
    _p()

    return 0


# ─── cmd_monitor ───────────────────────────────────────────────

def cmd_monitor(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port

    if not _ping(host, port):
        _warn(f"Proxy not running at {_proxy_url(host, port)}")
        _info("Start with: tsm enable")
        return 1

    _p()
    print(f"{C.BOLD}{C.CYAN}  🔭 TSM Live Monitor{C.RESET}  {C.DIM}Ctrl+C to exit{C.RESET}")
    _sep()
    _p()

    _monitor_loop(host, port)
    return 0


def _monitor_loop(host: str, port: int) -> None:
    """Tail tsm_audit.jsonl and pretty-print each new entry."""
    audit_path = pathlib.Path("tsm_audit.jsonl")
    audit_pos  = audit_path.stat().st_size if audit_path.exists() else 0
    last_total = 0

    SICON = {
        "CRITICAL": C.RED + "🚨" + C.RESET,
        "HIGH":     C.YELLOW + "⚠️ " + C.RESET,
        "MEDIUM":   C.CYAN + "🔍" + C.RESET,
        "LOW":      C.GRAY + "ℹ️ " + C.RESET,
        "none":     C.GREEN + "✓" + C.RESET,
    }

    try:
        while True:
            # Check audit log for new entries
            if audit_path.exists():
                current_size = audit_path.stat().st_size
                if current_size > audit_pos:
                    with open(audit_path, "r", encoding="utf-8") as f:
                        f.seek(audit_pos)
                        for raw in f:
                            raw = raw.strip()
                            if not raw:
                                continue
                            try:
                                e = json.loads(raw)
                            except Exception:
                                continue
                            model  = e.get("model_used", "?")
                            pii    = e.get("pii_detected", [])
                            local  = e.get("routed_local", False)
                            ms     = e.get("latency_ms", 0)
                            sev    = "CRITICAL" if any(p in ("SSN","CREDIT_CARD","PRIVATE_KEY") for p in pii) \
                                     else "HIGH" if pii else "none"

                            icon  = SICON.get(sev, SICON["none"])
                            route = f"{C.GREEN}local{C.RESET}" if local else f"{C.CYAN}cloud{C.RESET}"
                            pii_s = f"{C.YELLOW}{', '.join(pii)}{C.RESET}" if pii else f"{C.GREEN}clean{C.RESET}"

                            _tag(f"{icon} {pii_s}  →  {route}  {C.DIM}{ms:.0f}ms{C.RESET}")
                    audit_pos = current_size

            # Also check proxy stats for drift
            s = _stats(host, port)
            if s:
                total = s.get("requests_total", 0)
                if total != last_total and total > 0 and not audit_path.exists():
                    # Fallback if no audit log: just show counter
                    diff = total - last_total
                    if diff > 0:
                        _tag(f"{C.DIM}+{diff} request{'s' if diff>1 else ''} processed{C.RESET}")
                last_total = total

            time.sleep(0.4)

    except KeyboardInterrupt:
        _p()
        _ok("Monitor stopped. Proxy is still running.")
        _p()
        _info(f"tsm status   — live stats")
        _info(f"tsm stop     — stop the proxy")
        _p()


# ─── cmd_start ─────────────────────────────────────────────────

def cmd_start(args: argparse.Namespace) -> int:
    host  = args.host
    port  = args.port
    skill = getattr(args, "skill", None)

    if _ping(host, port):
        _warn(f"Proxy already running at {_proxy_url(host, port)}")
        return 0

    try:
        from tsm.proxy.server import start
    except ImportError:
        _err("tsm.proxy.server not found")
        return 1

    if getattr(args, "daemon", False):
        _p()
        print(f"{C.BOLD}{C.CYAN}  🛡️  TSM — Starting Proxy{C.RESET}")
        _sep()
        if _start_proxy_bg(host, port, skill):
            _ok(f"Proxy running at {C.BOLD}{_proxy_url(host, port)}{C.RESET}")
            _p()
            print(f"  {C.DIM}To protect your shell:{C.RESET}")
            print(f'  {C.YELLOW}eval "$(tsm enable --eval)"{C.RESET}')
            _p()
        else:
            _err("Proxy failed to start")
            return 1
    else:
        start(host=host, port=port, skill=skill, blocking=True)

    return 0


# ─── cmd_stop ──────────────────────────────────────────────────

def cmd_stop(args: argparse.Namespace) -> int:
    if not _ping(args.host, args.port):
        _warn("Proxy is not running")
        return 0
    try:
        from tsm.proxy.server import stop
        stop()
        _ok("Proxy stopped")
    except Exception:
        _err("Could not stop proxy — kill the process manually")
        return 1
    return 0


# ─── cmd_status ────────────────────────────────────────────────

def cmd_status(args: argparse.Namespace) -> int:
    host, port = args.host, args.port

    if not _ping(host, port):
        _p()
        _warn(f"TSM proxy is {C.RED}not running{C.RESET}")
        _p()
        _info(f"Start with: {C.BOLD}tsm enable{C.RESET}")
        _p()
        return 1

    data = _stats(host, port) or {}
    _p()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM Status{C.RESET}")
    _sep()
    _ok(f"Proxy at {C.BOLD}{_proxy_url(host, port)}{C.RESET}  {C.GREEN}running{C.RESET}")
    _p()

    uptime = data.get("uptime_seconds", 0)
    h, rem = divmod(uptime, 3600)
    m, s   = divmod(rem, 60)
    rows = [
        ("Uptime",       f"{h:02d}:{m:02d}:{s:02d}"),
        ("Total",        str(data.get("requests_total", 0))),
        ("Clean",        f"{C.GREEN}{data.get('requests_clean', 0)}{C.RESET}"),
        ("Redacted",     f"{C.YELLOW}{data.get('requests_redacted', 0)}{C.RESET}"),
        ("Blocked",      f"{C.RED}{data.get('requests_blocked', 0)}{C.RESET}"),
        ("Cost saved",   f"{C.CYAN}${data.get('cost_saved_usd', 0):.4f}{C.RESET}"),
    ]
    for label, val in rows:
        print(f"  {C.GRAY}{label:<12}{C.RESET}  {val}")

    pii = data.get("pii_types_detected", {})
    if pii:
        print(f"  {C.GRAY}{'PII seen':<12}{C.RESET}  " +
              "  ".join(f"{C.YELLOW}{k}×{v}{C.RESET}" for k, v in pii.items()))
    _p()
    _sep()
    _p()
    return 0


# ─── cmd_hook ──────────────────────────────────────────────────

_KNOWN_HOOKS = {
    "claude": ["claude"],
    "codex":  ["codex"],
    "openai": None,
    "cursor": ["cursor"],
    "aider":  ["aider"],
    "python": ["python"],
    "node":   ["node"],
}


def cmd_hook(args: argparse.Namespace) -> int:
    tool  = args.tool.lower()
    host  = args.host
    port  = args.port
    extra = args.extra or []

    if tool not in _KNOWN_HOOKS:
        _err(f"Unknown tool '{tool}'. Known: {', '.join(_KNOWN_HOOKS)}")
        return 1

    from tsm.hooks.env import inject_env

    # Auto-start proxy if not running
    if not _ping(host, port):
        _info("Starting TSM proxy...")
        if not _start_proxy_bg(host, port):
            _err("Could not start proxy")
            return 1

    env  = inject_env(host=host, port=port)
    base = _proxy_url(host, port)

    _p()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM Hook → {tool}{C.RESET}")
    _sep()
    _ok(f"Proxy:     {C.BOLD}{base}{C.RESET}")

    cmd_list = _KNOWN_HOOKS[tool]
    if cmd_list is None:
        _ok(f"OPENAI_BASE_URL set to {base}")
        _p()
        _info("Restart your app — it's now protected")
        return 0

    cmd_list = cmd_list + extra
    _ok(f"Launching: {C.BOLD}{' '.join(cmd_list)}{C.RESET}")
    _p()
    _sep()
    _p()

    try:
        return subprocess.run(cmd_list, env=env).returncode
    except FileNotFoundError:
        _err(f"'{tool}' not found in PATH — is it installed?")
        return 1


# ─── cmd_run ───────────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        _err("Usage: tsm run <command> [args...]")
        return 1

    host, port = args.host, args.port
    from tsm.hooks.env import inject_env

    # Auto-start proxy if not running
    if not _ping(host, port):
        _info("Starting TSM proxy...")
        if not _start_proxy_bg(host, port) and not getattr(args, "force", False):
            _err("Could not start proxy. Use --force to run without TSM.")
            return 1

    env = inject_env(host=host, port=port)
    _p()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM Run{C.RESET}")
    _sep()
    _ok(f"Command: {C.BOLD}{' '.join(args.command)}{C.RESET}")
    _ok(f"Proxy:   {C.BOLD}{_proxy_url(host, port)}{C.RESET}")
    _sep()
    _p()

    try:
        return subprocess.run(args.command, env=env).returncode
    except FileNotFoundError:
        _err(f"'{args.command[0]}' not found in PATH")
        return 1


# ─── cmd_scan ──────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    text = " ".join(args.text)
    if not text:
        _err("Usage: tsm scan <text>")
        return 1

    try:
        from tsm.detectors.pii import PIIDetector, Severity
    except ImportError:
        _err("PII detector not available")
        return 1

    detector = PIIDetector()
    result   = detector.scan(text)

    _p()
    print(f"{C.BOLD}{C.CYAN}  🔍 TSM Scan{C.RESET}")
    _sep()
    print(f"  {C.DIM}{text[:80]}{'…' if len(text)>80 else ''}{C.RESET}")
    _p()

    ICONS = {
        Severity.CRITICAL: f"{C.RED}🚨 CRITICAL{C.RESET}",
        Severity.HIGH:     f"{C.YELLOW}⚠️  HIGH    {C.RESET}",
        Severity.MEDIUM:   f"{C.CYAN}🔍 MEDIUM  {C.RESET}",
        Severity.LOW:      f"{C.GRAY}ℹ️  LOW     {C.RESET}",
    }

    if result.is_clean:
        _ok(f"{C.GREEN}Clean — no PII detected{C.RESET}")
    else:
        for d in result.detections:
            print(f"  {ICONS[d.severity]}  {C.BOLD}{d.type}{C.RESET}  {C.DIM}({d.preview}){C.RESET}")
        _p()
        if result.has_critical:
            _tag(f"{C.GREEN}🔒 Routing → {C.BOLD}local model{C.RESET}  {C.DIM}cloud never sees this{C.RESET}")
        else:
            _tag(f"{C.YELLOW}🛡️  Redacting{C.RESET} then forwarding to cloud")
        _p()
        print(f"  {C.BOLD}After redaction:{C.RESET}")
        print(f"  {C.YELLOW}{result.redacted_text}{C.RESET}")

    _p()
    _sep()
    _p()
    return 0


# ─── cmd_skills ────────────────────────────────────────────────

def cmd_skills(args: argparse.Namespace) -> int:
    skills_dir = _find_skills_dir()
    sub = getattr(args, "sub", None) or "list"

    if sub == "list":   return _skills_list(skills_dir)
    if sub == "install": return _skills_install(skills_dir, args)
    if sub == "show":    return _skills_show(skills_dir, args)
    return 0


def _find_skills_dir() -> pathlib.Path:
    if "TSM_SKILLS_DIR" in os.environ:
        return pathlib.Path(os.environ["TSM_SKILLS_DIR"])
    bundled = pathlib.Path(__file__).parent.parent.parent / "skills"
    if bundled.exists():
        return bundled
    return pathlib.Path.home() / ".tsm" / "skills"


def _skills_list(skills_dir: pathlib.Path) -> int:
    _p()
    print(f"{C.BOLD}{C.CYAN}  ⚡ TSM Skill Packs{C.RESET}")
    _sep()

    if not skills_dir.exists() or not list(skills_dir.glob("*.md")):
        _warn("No skill packs found")
        _p()
        return 0

    for p in sorted(skills_dir.glob("*.md")):
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
            desc  = next((l.lstrip("# ") for l in lines if l.strip() and not l.startswith("---")), "")
        except Exception:
            desc = ""
        print(f"  {C.CYAN}⚡{C.RESET} {C.BOLD}{p.stem:<20}{C.RESET}  {C.DIM}{desc[:55]}{C.RESET}")

    _p()
    _info(f"Activate:  {C.BOLD}tsm start --skill <name>{C.RESET}")
    _p()
    return 0


def _skills_install(skills_dir: pathlib.Path, args: argparse.Namespace) -> int:
    src = pathlib.Path(getattr(args, "file", ""))
    if not src.exists():
        _err(f"File not found: {src}")
        return 1
    skills_dir.mkdir(parents=True, exist_ok=True)
    dest = skills_dir / src.name
    dest.write_bytes(src.read_bytes())
    _ok(f"Installed: {dest}")
    return 0


def _skills_show(skills_dir: pathlib.Path, args: argparse.Namespace) -> int:
    path = skills_dir / f"{getattr(args, 'name', '')}.md"
    if not path.exists():
        _err(f"Skill not found: {getattr(args, 'name', '')}")
        return 1
    print(path.read_text(encoding="utf-8"))
    return 0


# ─── cmd_test ──────────────────────────────────────────────────

def cmd_test(args: argparse.Namespace) -> int:
    _p()
    print(f"{C.BOLD}{C.CYAN}  🧪 TSM Self-Test{C.RESET}")
    _sep()

    try:
        from tsm.detectors.pii import PIIDetector, Severity
    except ImportError as e:
        _err(f"Import failed: {e}")
        return 1

    d = PIIDetector()
    cases = [
        ("SSN",         "My SSN is 123-45-6789",              Severity.CRITICAL),
        ("CREDIT_CARD", "Card: 4111 1111 1111 1111",          Severity.CRITICAL),
        ("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----",    Severity.CRITICAL),
        ("OPENAI_KEY",  "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZabcd", Severity.HIGH),
        ("AWS_KEY",     "key=AKIAIOSFODNN7EXAMPLE1234",        Severity.HIGH),
        ("EMAIL",       "email me at user@example.com",        Severity.MEDIUM),
        ("PHONE",       "call (555) 123-4567",                 Severity.MEDIUM),
        ("CLEAN",       "What is 2 + 2?",                      None),
    ]

    passed = 0
    for name, text, expected in cases:
        result = d.scan(text)
        ok = result.is_clean if expected is None else result.worst_severity == expected
        if ok:
            _ok(f"{name:<20} {C.GREEN}pass{C.RESET}")
            passed += 1
        else:
            _err(f"{name:<20} FAIL  expected={expected}  got={result.worst_severity}")

    _p()
    score = f"{passed}/{len(cases)}"
    if passed == len(cases):
        print(f"  {C.GREEN}{C.BOLD}All tests passed ({score}){C.RESET}")
    else:
        print(f"  {C.YELLOW}Partial ({score}){C.RESET}")

    _p()
    if _ping(args.host, args.port):
        _ok(f"Proxy healthy at {_proxy_url(args.host, args.port)}")
    else:
        _warn(f"Proxy not running (run: tsm enable)")
    _p()
    _sep()
    _p()
    return 0 if passed == len(cases) else 1


# ─── Parser ────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tsm",
        description="🛡️  TSM — The AI Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick start:
  pip install tsm-firewall
  tsm enable                        # start + hook + monitor
  tsm demo                          # interactive demo (no LLM needed)

Common usage:
  tsm hook claude                   # run claude through TSM
  tsm run python my_script.py       # protect any script
  eval "$(tsm enable --eval)"       # hook entire shell session

Scanning:
  tsm scan "My SSN is 123-45-6789"

Proxy:
  tsm start --daemon                # start in background
  tsm status                        # live stats
  tsm stop                          # stop proxy
""",
    )
    p.add_argument("--host", default=_DEFAULT_HOST)
    p.add_argument("--port", default=_DEFAULT_PORT, type=int)

    sub = p.add_subparsers(dest="cmd", metavar="command")

    # enable
    ep = sub.add_parser("enable", help="[START HERE] Start proxy + hook shell + live monitor")
    ep.add_argument("--eval", action="store_true", help="Print raw exports for eval$()")

    # demo
    sub.add_parser("demo", help="Interactive demo — see TSM in action (no LLM needed)")

    # monitor
    sub.add_parser("monitor", help="Tail live request stream")

    # hook
    hp = sub.add_parser("hook", help="Run a tool through TSM (auto-starts proxy)")
    hp.add_argument("tool", help="claude | codex | openai | cursor | aider | python | node")
    hp.add_argument("extra", nargs=argparse.REMAINDER)

    # run
    rp = sub.add_parser("run", help="Run any command through TSM (auto-starts proxy)")
    rp.add_argument("command", nargs=argparse.REMAINDER)
    rp.add_argument("--force", action="store_true")

    # scan
    sp2 = sub.add_parser("scan", help="Scan text for PII instantly")
    sp2.add_argument("text", nargs="+")

    # start
    stp = sub.add_parser("start", help="Start the TSM proxy")
    stp.add_argument("--daemon", "-d", action="store_true")
    stp.add_argument("--skill", help="Skill pack name")

    # stop
    sub.add_parser("stop", help="Stop the TSM proxy")

    # status
    sub.add_parser("status", help="Show proxy statistics")

    # skills
    skp = sub.add_parser("skills", help="Manage skill packs")
    sk_sub = skp.add_subparsers(dest="sub", metavar="action")
    sk_sub.add_parser("list")
    si = sk_sub.add_parser("install")
    si.add_argument("file")
    ss = sk_sub.add_parser("show")
    ss.add_argument("name")

    # test
    sub.add_parser("test", help="Run built-in self-test")

    return p


def main() -> None:
    p = _build_parser()
    args = p.parse_args()

    dispatch = {
        "enable":  cmd_enable,
        "demo":    cmd_demo,
        "monitor": cmd_monitor,
        "hook":    cmd_hook,
        "run":     cmd_run,
        "scan":    cmd_scan,
        "start":   cmd_start,
        "stop":    cmd_stop,
        "status":  cmd_status,
        "skills":  cmd_skills,
        "test":    cmd_test,
    }

    if args.cmd is None:
        # No subcommand → show branded help
        _p()
        print(f"{C.BOLD}{C.CYAN}{'━'*58}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  🛡️  TSM — The AI Firewall{C.RESET}")
        print(f"{C.CYAN}{'━'*58}{C.RESET}")
        _p()
        print(f"  Enterprise-grade AI data protection.")
        print(f"  Run it free. Locally. Right now.")
        _p()
        print(f"  {C.BOLD}Get started:{C.RESET}")
        _p()
        print(f"  {C.GREEN}tsm enable{C.RESET}              {C.DIM}start + hook + monitor{C.RESET}")
        print(f"  {C.GREEN}tsm demo{C.RESET}                {C.DIM}interactive demo (no LLM needed){C.RESET}")
        print(f"  {C.GREEN}tsm hook claude{C.RESET}         {C.DIM}wrap claude with TSM firewall{C.RESET}")
        print(f"  {C.GREEN}tsm run python app.py{C.RESET}   {C.DIM}protect any script{C.RESET}")
        _p()
        print(f"  {C.DIM}tsm --help for full command list{C.RESET}")
        _p()
        _sep()
        _p()
        sys.exit(0)

    handler = dispatch.get(args.cmd)
    if handler is None:
        p.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
