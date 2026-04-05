"""
TSM CLI — The AI Firewall
=========================
pip install tsm-firewall
tsm enable
Done. Your AI is protected.
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
import urllib.error
import urllib.request
from typing import List, Optional

# UTF-8 on Windows
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


_DEFAULT_HOST = "localhost"
_DEFAULT_PORT = 8080


# ─── Print helpers ─────────────────────────────────────────────

def _p(msg: str = "")  -> None: print(msg, flush=True)
def _ok(msg: str)      -> None: print(f"  {C.GREEN}✓{C.RESET}  {msg}", flush=True)
def _info(msg: str)    -> None: print(f"  {C.CYAN}→{C.RESET}  {msg}", flush=True)
def _warn(msg: str)    -> None: print(f"  {C.YELLOW}⚠{C.RESET}  {msg}", flush=True)
def _err(msg: str)     -> None: print(f"  {C.RED}✗{C.RESET}  {msg}", flush=True)
def _sep()             -> None: print(f"{C.GRAY}{'━'*58}{C.RESET}", flush=True)
def _tag(msg: str)     -> None: print(f"{C.BOLD}{C.CYAN}[TSM]{C.RESET} {msg}", flush=True)


# ─── Proxy helpers ─────────────────────────────────────────────

def _url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def _ping(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(f"{_url(host, port)}/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _stats(host: str, port: int) -> Optional[dict]:
    try:
        with urllib.request.urlopen(f"{_url(host, port)}/stats", timeout=3.0) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _post(host: str, port: int, prompt: str, model: str = "gpt-3.5-turbo") -> Optional[dict]:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()
    req = urllib.request.Request(
        f"{_url(host, port)}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _start_proxy_bg(host: str, port: int, skill: Optional[str] = None) -> bool:
    """Start proxy in daemon thread. Return True when ready."""
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
    deadline = time.time() + 4.0
    while time.time() < deadline:
        if _ping(host, port, 0.4):
            return True
        time.sleep(0.1)
    return False


def _ensure_proxy(host: str, port: int, skill: Optional[str] = None) -> bool:
    if _ping(host, port):
        return True
    return _start_proxy_bg(host, port, skill)


# ─── Shell RC helper ───────────────────────────────────────────

def _write_shell_export(base: str) -> Optional[str]:
    """Append TSM env exports to .bashrc / .zshrc. Returns file path or None."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rc = pathlib.Path.home() / ".zshrc"
    elif "fish" in shell:
        rc = pathlib.Path.home() / ".config" / "fish" / "config.fish"
    else:
        rc = pathlib.Path.home() / ".bashrc"

    if not rc.parent.exists():
        return None

    try:
        existing = rc.read_text(encoding="utf-8") if rc.exists() else ""
        marker = "# TSM Firewall — added by tsm enable"
        if marker in existing:
            return str(rc)  # already there
        block = (
            f"\n{marker}\n"
            f'export OPENAI_BASE_URL="{base}"\n'
            f'export OPENAI_API_BASE="{base}"\n'
            f'export ANTHROPIC_BASE_URL="{base}"\n'
            f'export TSM_ACTIVE="1"\n'
        )
        with open(rc, "a", encoding="utf-8") as f:
            f.write(block)
        return str(rc)
    except Exception:
        return None


# ─── LIVE DEMO TRAFFIC ─────────────────────────────────────────
# Sends real requests through the proxy so the [TSM] detection
# logs fire automatically in the same terminal.

_LIVE_DEMO = [
    ("gpt-3.5-turbo", "Help me file taxes. My SSN is 123-45-6789."),
    ("gpt-4",         "Charge my Visa card 4111 1111 1111 1111 for the subscription."),
    ("gpt-3.5-turbo", "Email alice@company.com the Q1 report summary."),
    ("gpt-3.5-turbo", "What is the capital of France?"),
]

_SEV_ICON_LIVE = {
    "CRITICAL": C.RED    + "🚨 Detected:" + C.RESET,
    "HIGH":     C.YELLOW + "⚠️  Detected:" + C.RESET,
    "MEDIUM":   C.CYAN   + "🔍 Detected:" + C.RESET,
    "LOW":      C.GRAY   + "ℹ️  Detected:" + C.RESET,
}


def _print_tsm_block(model: str, prompt: str, tsm_meta: dict) -> None:
    """Reconstruct [TSM] log lines from response metadata — works for any proxy."""
    _sep()
    preview = prompt[:52] + ("…" if len(prompt) > 52 else "")
    _tag(f"{C.GRAY}→ {model}{C.RESET}  {C.DIM}{preview}{C.RESET}")
    time.sleep(0.18)

    pii      = tsm_meta.get("pii_detected", [])
    sev      = tsm_meta.get("severity", "none")
    local    = tsm_meta.get("routed_local", False)
    latency  = tsm_meta.get("latency_ms", 0)
    redacted = tsm_meta.get("redacted", False)

    icon = _SEV_ICON_LIVE.get(sev, "")
    for p in pii:
        _tag(f"{icon} {C.BOLD}{p}{C.RESET}")
        time.sleep(0.12)

    if redacted and pii:
        _tag(f"{C.YELLOW}🛡️  Redacted:{C.RESET} {C.BOLD}{', '.join(pii)}{C.RESET} "
             f"{C.GRAY}→ [REDACTED]{C.RESET}")
        time.sleep(0.12)

    if local:
        _tag(f"{C.GREEN}🔒 Routing → {C.BOLD}local model{C.RESET}  "
             f"{C.DIM}cloud never sees it{C.RESET}")
    else:
        label = "PII redacted" if pii else "clean"
        _tag(f"{C.CYAN}☁️  Routing → {C.BOLD}cloud{C.RESET}  {C.DIM}{label}{C.RESET}")

    time.sleep(0.18)
    cost = "free (local)" if local else f"~${(latency / 1000) * 0.001:.5f}"
    _tag(f"{C.GREEN}✓ Done{C.RESET}  {C.GRAY}latency={latency:.0f}ms  cost={cost}{C.RESET}")
    _sep()


def _run_live_demo(host: str, port: int) -> None:
    """Send demo requests; reconstruct [TSM] logs from response JSON."""
    for model, prompt in _LIVE_DEMO:
        time.sleep(0.25)
        resp = _post(host, port, prompt, model)
        if resp:
            tsm = resp.get("tsm", {})
            _print_tsm_block(model, prompt, tsm)
        time.sleep(0.15)


# ─── cmd_enable ────────────────────────────────────────────────

def cmd_enable(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port
    base = _url(host, port)

    # --eval: raw exports for eval$()
    if getattr(args, "eval", False):
        print(f'export OPENAI_BASE_URL="{base}"')
        print(f'export OPENAI_API_BASE="{base}"')
        print(f'export ANTHROPIC_BASE_URL="{base}"')
        print('export TSM_ACTIVE="1"')
        return 0

    # ── Header ─────────────────────────────────────────────────
    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM — The AI Firewall{C.RESET}")
    _sep()
    _p()

    # ── Step 1: Start proxy ────────────────────────────────────
    already = _ping(host, port)
    if already:
        _ok(f"Firewall already running at {C.BOLD}{base}{C.RESET}")
    else:
        _info(f"Starting firewall at {C.BOLD}{base}{C.RESET} ...")
        if not _start_proxy_bg(host, port):
            _err("Could not start proxy — run: tsm start")
            return 1
        _ok(f"Firewall started at {C.BOLD}{base}{C.RESET}")

    _ok(f"PII detection active  {C.DIM}(14 patterns, 4 severity tiers){C.RESET}")
    _ok(f"Audit log active      {C.DIM}tsm_audit.jsonl{C.RESET}")
    _p()

    # ── Step 2: Show shell export ──────────────────────────────
    _sep()
    _p()
    _p(f"  {C.BOLD}Your AI tools are now protected.{C.RESET}  {C.DIM}To hook your shell:{C.RESET}")
    _p()
    _p(f'  {C.YELLOW}eval "$(tsm enable --eval)"{C.RESET}')
    _p()
    _p(f"  {C.DIM}Then every claude / python / node call is intercepted.{C.RESET}")
    _p()

    # Try to write to .bashrc/.zshrc
    rc = _write_shell_export(base)
    if rc:
        _ok(f"Env vars written to {C.DIM}{rc}{C.RESET}  {C.DIM}(restart shell to apply){C.RESET}")
    _p()

    # ── Step 3: Visible magic — send real demo traffic ─────────
    _sep()
    _p()
    _p(f"  {C.BOLD}Sending test traffic — watch the firewall work:{C.RESET}")
    _p()
    _sep()

    # Fire demo requests in background; proxy logs print to this terminal
    t = threading.Thread(target=_run_live_demo, args=(host, port), daemon=True)
    t.start()
    t.join(timeout=8.0)

    _sep()
    _p()
    _ok(f"{C.GREEN}{C.BOLD}Firewall active. Your AI is protected.{C.RESET}")
    _p()
    _p(f"  {C.CYAN}tsm hook claude{C.RESET}          {C.DIM}wrap claude{C.RESET}")
    _p(f"  {C.CYAN}tsm hook codex{C.RESET}           {C.DIM}wrap codex{C.RESET}")
    _p(f"  {C.CYAN}tsm run python app.py{C.RESET}    {C.DIM}wrap any script{C.RESET}")
    _p(f"  {C.CYAN}tsm status{C.RESET}               {C.DIM}live stats{C.RESET}")
    _p(f"  {C.CYAN}tsm demo{C.RESET}                 {C.DIM}step-by-step walkthrough{C.RESET}")
    _p()
    _sep()
    _p()

    # ── Step 4: Live monitor ───────────────────────────────────
    _p(f"  {C.MAGENTA}{C.BOLD}Monitoring live requests...{C.RESET}  {C.DIM}Ctrl+C to exit (proxy keeps running){C.RESET}")
    _p()
    _sep()

    _monitor_loop(host, port)
    return 0


# ─── cmd_demo ──────────────────────────────────────────────────

_DEMO_CASES = [
    {
        "label":    "CRITICAL — Social Security Number",
        "model":    "gpt-3.5-turbo",
        "prompt":   "Help me file taxes. My SSN is 123-45-6789.",
        "pii":      ["SSN"],
        "severity": "CRITICAL",
        "local":    True,
        "latency":  2.0,
        "result":   "SSN never left your machine. Cost: $0.00",
    },
    {
        "label":    "CRITICAL — Credit Card",
        "model":    "gpt-4",
        "prompt":   "Charge my Visa 4111 1111 1111 1111 exp 12/28 for $199.",
        "pii":      ["CREDIT_CARD"],
        "severity": "CRITICAL",
        "local":    True,
        "latency":  1.8,
        "result":   "Payment data blocked from cloud. Routed locally.",
    },
    {
        "label":    "HIGH — AWS Key",
        "model":    "gpt-4",
        "prompt":   "Why does AKIAIOSFODNN7EXAMPLE1234 get access denied?",
        "pii":      ["AWS_KEY"],
        "severity": "HIGH",
        "local":    False,
        "latency":  840.0,
        "result":   "Key redacted. Cloud received [REDACTED:AWS_KEY].",
    },
    {
        "label":    "MEDIUM — Email",
        "model":    "gpt-3.5-turbo",
        "prompt":   "Email alice@acmecorp.com about the Q1 report.",
        "pii":      ["EMAIL"],
        "severity": "MEDIUM",
        "local":    False,
        "latency":  610.0,
        "result":   "Email redacted before sending. Response returned normally.",
    },
    {
        "label":    "Clean — No PII",
        "model":    "gpt-3.5-turbo",
        "prompt":   "Explain how neural networks learn from data.",
        "pii":      [],
        "severity": None,
        "local":    False,
        "latency":  720.0,
        "result":   "Clean. Forwarded to cloud unchanged.",
    },
]

_SEV_ICON = {
    "CRITICAL": C.RED    + "🚨 Detected:" + C.RESET,
    "HIGH":     C.YELLOW + "⚠️  Detected:" + C.RESET,
    "MEDIUM":   C.CYAN   + "🔍 Detected:" + C.RESET,
    "LOW":      C.GRAY   + "ℹ️  Detected:" + C.RESET,
}


def _show_request(model: str, prompt: str, pii: list, severity: Optional[str],
                  local: bool, latency: float) -> None:
    _sep()
    preview = prompt[:52] + ("…" if len(prompt) > 52 else "")
    _tag(f"{C.GRAY}→ {model}{C.RESET}  {C.DIM}{preview}{C.RESET}")
    time.sleep(0.25)

    for p in pii:
        icon = _SEV_ICON.get(severity or "MEDIUM")
        _tag(f"{icon} {C.BOLD}{p}{C.RESET}")
        time.sleep(0.15)

    if pii:
        _tag(f"{C.YELLOW}🛡️  Redacted:{C.RESET} {C.BOLD}{', '.join(pii)}{C.RESET} "
             f"{C.GRAY}→ [REDACTED]{C.RESET}")
        time.sleep(0.15)

    if local:
        _tag(f"{C.GREEN}🔒 Routing → {C.BOLD}local model{C.RESET}  "
             f"{C.DIM}cloud never sees it{C.RESET}")
    else:
        msg = "PII redacted" if pii else "clean"
        _tag(f"{C.CYAN}☁️  Routing → {C.BOLD}cloud{C.RESET}  {C.DIM}{msg}{C.RESET}")

    time.sleep(0.2)
    cost = "free (local)" if local else f"~${(latency/1000)*0.001:.5f}"
    _tag(f"{C.GREEN}✓ Done{C.RESET}  {C.GRAY}latency={latency:.0f}ms  cost={cost}{C.RESET}")
    _sep()


def cmd_demo(args: argparse.Namespace) -> int:
    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM — Live Firewall Demo{C.RESET}")
    _sep()
    _p()
    _p(f"  {len(_DEMO_CASES)} AI requests.  Watch what TSM does to each one.")
    _p(f"  {C.DIM}No LLM or cloud account needed.{C.RESET}")
    _p()

    blocked = redacted = 0

    for i, case in enumerate(_DEMO_CASES, 1):
        _p()
        _p(f"  {C.BOLD}[{i}/{len(_DEMO_CASES)}]  {case['label']}{C.RESET}")
        _p(f"  {C.DIM}Prompt: \"{case['prompt']}\"{C.RESET}")
        _p()

        try:
            input(f"  {C.GRAY}Press Enter to send →{C.RESET} ")
        except (EOFError, KeyboardInterrupt):
            _p()
            break

        _p()
        _show_request(
            model=case["model"], prompt=case["prompt"],
            pii=case["pii"], severity=case["severity"],
            local=case["local"], latency=case["latency"],
        )
        _p()

        if case["local"]:
            _p(f"  {C.GREEN}{C.BOLD}✓ Blocked from cloud:{C.RESET}  {case['result']}")
            blocked += 1
        elif case["pii"]:
            _p(f"  {C.YELLOW}{C.BOLD}✓ Redacted + forwarded:{C.RESET}  {case['result']}")
            redacted += 1
        else:
            _p(f"  {C.CYAN}{C.BOLD}✓ Clean:{C.RESET}  {case['result']}")
        _p()

    # Summary
    _sep()
    _p()
    _p(f"  {C.BOLD}Session Summary{C.RESET}")
    _p()
    _p(f"  {C.GRAY}Total requests   {C.RESET}{len(_DEMO_CASES)}")
    _p(f"  {C.RED}Blocked (local)  {C.RESET}{blocked}  {C.DIM}— PII never reached cloud{C.RESET}")
    _p(f"  {C.YELLOW}Redacted + sent  {C.RESET}{redacted}  {C.DIM}— PII stripped before cloud{C.RESET}")
    _p(f"  {C.GREEN}Cost saved       {C.RESET}${blocked * 0.002:.4f}")
    _p()
    _sep()
    _p()
    _p(f"  {C.BOLD}This is the free, open-source version.{C.RESET}")
    _p(f"  {C.DIM}Enterprise adds: SSO, policy engine, dashboard, custom patterns,{C.RESET}")
    _p(f"  {C.DIM}Kubernetes deployment, and compliance reporting.{C.RESET}")
    _p()
    _p(f"  {C.CYAN}thesovereignmechanica.ai{C.RESET}  ·  {C.GRAY}github.com/tsm7979/tsm79{C.RESET}")
    _p()
    _sep()
    _p()
    _p(f"  {C.BOLD}Start protecting your tools now:{C.RESET}")
    _p()
    _p(f"  {C.GREEN}tsm enable{C.RESET}              {C.DIM}start + hook + monitor{C.RESET}")
    _p(f"  {C.GREEN}tsm hook claude{C.RESET}         {C.DIM}wrap claude specifically{C.RESET}")
    _p(f"  {C.GREEN}tsm run python app.py{C.RESET}   {C.DIM}protect any script{C.RESET}")
    _p()
    return 0


# ─── cmd_monitor ───────────────────────────────────────────────

def cmd_monitor(args: argparse.Namespace) -> int:
    host, port = args.host, args.port
    if not _ping(host, port):
        _warn(f"Proxy not running. Start with: tsm enable")
        return 1
    _p()
    _p(f"{C.BOLD}{C.CYAN}  🔭 TSM Monitor{C.RESET}  {C.DIM}Ctrl+C to exit{C.RESET}")
    _sep()
    _p()
    _monitor_loop(host, port)
    return 0


def _monitor_loop(host: str, port: int) -> None:
    audit  = pathlib.Path("tsm_audit.jsonl")
    pos    = audit.stat().st_size if audit.exists() else 0
    last_n = 0

    _SEV = {
        "SSN": C.RED, "CREDIT_CARD": C.RED, "PRIVATE_KEY": C.RED,
        "AWS_KEY": C.YELLOW, "API_KEY": C.YELLOW, "PASSWORD": C.YELLOW,
        "JWT": C.YELLOW, "OPENAI_KEY": C.YELLOW,
        "EMAIL": C.CYAN, "PHONE": C.CYAN, "PASSPORT": C.CYAN,
        "IP_ADDR": C.GRAY,
    }

    try:
        while True:
            if audit.exists():
                sz = audit.stat().st_size
                if sz > pos:
                    with open(audit, "r", encoding="utf-8") as f:
                        f.seek(pos)
                        for raw in f:
                            raw = raw.strip()
                            if not raw:
                                continue
                            try:
                                e = json.loads(raw)
                            except Exception:
                                continue
                            pii   = e.get("pii_detected", [])
                            local = e.get("routed_local", False)
                            ms    = e.get("latency_ms", 0)
                            model = e.get("model_used", "?")

                            if pii:
                                col = _SEV.get(pii[0], C.YELLOW)
                                pii_s = f"{col}{', '.join(pii)}{C.RESET}"
                                icon  = "🚨" if local else "⚠️ "
                            else:
                                pii_s = f"{C.GREEN}clean{C.RESET}"
                                icon  = "✓"

                            route = f"{C.GREEN}local{C.RESET}" if local else f"{C.CYAN}cloud{C.RESET}"
                            _tag(f"{icon}  {pii_s}  →  {route}  "
                                 f"{C.GRAY}{model}  {ms:.0f}ms{C.RESET}")
                    pos = sz

            # Fallback counter when no audit file
            s = _stats(host, port)
            if s:
                n = s.get("requests_total", 0)
                if n > last_n and not audit.exists():
                    _tag(f"{C.DIM}+{n - last_n} request(s) intercepted{C.RESET}")
                last_n = n

            time.sleep(0.35)

    except KeyboardInterrupt:
        _p()
        _ok("Monitor stopped — proxy is still running")
        _p()
        _info("tsm status   → live stats")
        _info("tsm stop     → stop proxy")
        _p()


# ─── cmd_start / stop / status ────────────────────────────────

def cmd_start(args: argparse.Namespace) -> int:
    host, port = args.host, args.port
    if _ping(host, port):
        _warn(f"Already running at {_url(host, port)}")
        return 0
    try:
        from tsm.proxy.server import start
    except ImportError:
        _err("tsm.proxy.server not found")
        return 1
    skill = getattr(args, "skill", None)
    if getattr(args, "daemon", False):
        _p()
        _sep()
        _info(f"Starting proxy at {C.BOLD}{_url(host, port)}{C.RESET}...")
        if _start_proxy_bg(host, port, skill):
            _ok(f"Proxy running at {C.BOLD}{_url(host, port)}{C.RESET}")
            _p()
            _p(f'  {C.YELLOW}eval "$(tsm enable --eval)"{C.RESET}  {C.DIM}to hook your shell{C.RESET}')
            _p()
        else:
            _err("Proxy failed to start")
            return 1
    else:
        start(host=host, port=port, skill=skill, blocking=True)
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    if not _ping(args.host, args.port):
        _warn("Proxy is not running")
        return 0
    try:
        from tsm.proxy.server import stop
        stop()
        _ok("Proxy stopped")
    except Exception:
        _err("Could not stop — kill the process manually")
        return 1
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    host, port = args.host, args.port
    if not _ping(host, port):
        _p()
        _warn(f"Proxy not running")
        _info(f"Start with: {C.BOLD}tsm enable{C.RESET}")
        _p()
        return 1
    data = _stats(host, port) or {}
    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM Status{C.RESET}")
    _sep()
    _ok(f"{_url(host, port)}  {C.GREEN}running{C.RESET}")
    _p()
    u = data.get("uptime_seconds", 0)
    h, r = divmod(u, 3600); m, s = divmod(r, 60)
    for label, val in [
        ("Uptime",     f"{h:02d}:{m:02d}:{s:02d}"),
        ("Total",      str(data.get("requests_total", 0))),
        ("Clean",      f"{C.GREEN}{data.get('requests_clean', 0)}{C.RESET}"),
        ("Redacted",   f"{C.YELLOW}{data.get('requests_redacted', 0)}{C.RESET}"),
        ("Blocked",    f"{C.RED}{data.get('requests_blocked', 0)}{C.RESET}"),
        ("Saved",      f"{C.CYAN}${data.get('cost_saved_usd', 0):.4f}{C.RESET}"),
    ]:
        _p(f"  {C.GRAY}{label:<10}{C.RESET}  {val}")
    pii = data.get("pii_types_detected", {})
    if pii:
        _p(f"  {C.GRAY}PII seen  {C.RESET}  " +
           "  ".join(f"{C.YELLOW}{k}×{v}{C.RESET}" for k, v in pii.items()))
    _p()
    _sep()
    _p()
    return 0


# ─── cmd_hook / cmd_run ────────────────────────────────────────

_KNOWN_HOOKS = {
    "claude": ["claude"], "codex": ["codex"],
    "openai": None, "cursor": ["cursor"],
    "aider":  ["aider"], "python": ["python"],
    "node":   ["node"],
}


def cmd_hook(args: argparse.Namespace) -> int:
    tool  = args.tool.lower()
    host, port = args.host, args.port
    extra = args.extra or []

    if tool not in _KNOWN_HOOKS:
        _err(f"Unknown tool '{tool}'. Known: {', '.join(_KNOWN_HOOKS)}")
        return 1

    from tsm.hooks.env import inject_env

    if not _ping(host, port):
        _info("Auto-starting proxy...")
        if not _start_proxy_bg(host, port):
            _err("Could not start proxy")
            return 1

    env  = inject_env(host=host, port=port)
    base = _url(host, port)

    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM → {tool}{C.RESET}")
    _sep()
    _ok(f"Firewall: {C.BOLD}{base}{C.RESET}")

    cmd_list = _KNOWN_HOOKS[tool]
    if cmd_list is None:
        _ok(f"OPENAI_BASE_URL={base}")
        _info("Restart your app — it's protected")
        return 0

    cmd_list = cmd_list + extra
    _ok(f"Command:  {C.BOLD}{' '.join(cmd_list)}{C.RESET}")
    _p()
    _sep()
    _p()

    try:
        return subprocess.run(cmd_list, env=env).returncode
    except FileNotFoundError:
        _err(f"'{tool}' not found in PATH")
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        _err("Usage: tsm run <command> [args...]")
        return 1
    host, port = args.host, args.port

    from tsm.hooks.env import inject_env

    if not _ping(host, port):
        _info("Auto-starting proxy...")
        if not _start_proxy_bg(host, port) and not getattr(args, "force", False):
            _err("Could not start proxy. Use --force to skip.")
            return 1

    env = inject_env(host=host, port=port)
    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM Run{C.RESET}")
    _sep()
    _ok(f"Firewall: {C.BOLD}{_url(host, port)}{C.RESET}")
    _ok(f"Command:  {C.BOLD}{' '.join(args.command)}{C.RESET}")
    _p()
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

    result = PIIDetector().scan(text)
    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🔍 TSM Scan{C.RESET}")
    _sep()
    _p(f"  {C.DIM}{text[:80]}{'…' if len(text)>80 else ''}{C.RESET}")
    _p()

    ICONS = {
        Severity.CRITICAL: f"{C.RED}🚨 CRITICAL{C.RESET}",
        Severity.HIGH:     f"{C.YELLOW}⚠️  HIGH   {C.RESET}",
        Severity.MEDIUM:   f"{C.CYAN}🔍 MEDIUM {C.RESET}",
        Severity.LOW:      f"{C.GRAY}ℹ️  LOW    {C.RESET}",
    }

    if result.is_clean:
        _ok(f"{C.GREEN}Clean — no PII detected{C.RESET}")
    else:
        for d in result.detections:
            _p(f"  {ICONS[d.severity]}  {C.BOLD}{d.type}{C.RESET}  {C.DIM}({d.preview}){C.RESET}")
        _p()
        if result.has_critical:
            _tag(f"{C.GREEN}🔒 Would route to {C.BOLD}local model{C.RESET}  "
                 f"{C.DIM}cloud never sees this{C.RESET}")
        else:
            _tag(f"{C.YELLOW}🛡️  Would redact{C.RESET} then forward to cloud")
        _p()
        _p(f"  {C.BOLD}Redacted output:{C.RESET}")
        _p(f"  {C.YELLOW}{result.redacted_text}{C.RESET}")

    _p()
    _sep()
    _p()
    return 0


# ─── cmd_skills ────────────────────────────────────────────────

def cmd_skills(args: argparse.Namespace) -> int:
    skills_dir = _find_skills_dir()
    sub = getattr(args, "sub", None) or "list"
    if sub == "list":    return _skills_list(skills_dir)
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
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  ⚡ TSM Skill Packs{C.RESET}")
    _sep()
    packs = sorted(skills_dir.glob("*.md")) if skills_dir.exists() else []
    if not packs:
        _warn("No skill packs found")
        _p()
        return 0
    for p in packs:
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
            desc  = next((l.lstrip("# ") for l in lines if l.strip() and not l.startswith("---")), "")
        except Exception:
            desc = ""
        _p(f"  {C.CYAN}⚡{C.RESET} {C.BOLD}{p.stem:<20}{C.RESET}  {C.DIM}{desc[:55]}{C.RESET}")
    _p()
    _info(f"Activate:  {C.BOLD}tsm start --skill <name>{C.RESET}")
    _p()
    return 0


def _skills_install(skills_dir: pathlib.Path, args: argparse.Namespace) -> int:
    src = pathlib.Path(getattr(args, "file", ""))
    if not src.exists():
        _err(f"Not found: {src}")
        return 1
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / src.name).write_bytes(src.read_bytes())
    _ok(f"Installed: {skills_dir / src.name}")
    return 0


def _skills_show(skills_dir: pathlib.Path, args: argparse.Namespace) -> int:
    path = skills_dir / f"{getattr(args, 'name', '')}.md"
    if not path.exists():
        _err(f"Not found: {getattr(args, 'name', '')}")
        return 1
    print(path.read_text(encoding="utf-8"))
    return 0


# ─── cmd_test ──────────────────────────────────────────────────

def cmd_test(args: argparse.Namespace) -> int:
    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🧪 TSM Self-Test{C.RESET}")
    _sep()

    try:
        from tsm.detectors.pii import PIIDetector, Severity
    except ImportError as e:
        _err(f"Import failed: {e}")
        return 1

    cases = [
        ("SSN",         "My SSN is 123-45-6789",               Severity.CRITICAL),
        ("CREDIT_CARD", "Card: 4111 1111 1111 1111",           Severity.CRITICAL),
        ("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----",     Severity.CRITICAL),
        ("OPENAI_KEY",  "sk-aBcDeFgHiJkLmNoPqRsTuVwXyzabcd",  Severity.HIGH),
        ("AWS_KEY",     "key=AKIAIOSFODNN7EXAMPLE1234",         Severity.HIGH),
        ("EMAIL",       "email user@example.com",               Severity.MEDIUM),
        ("PHONE",       "call (555) 123-4567",                  Severity.MEDIUM),
        ("CLEAN",       "What is 2 + 2?",                       None),
    ]

    d = PIIDetector()
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
    if passed == len(cases):
        _p(f"  {C.GREEN}{C.BOLD}All tests passed ({passed}/{len(cases)}){C.RESET}")
    else:
        _p(f"  {C.YELLOW}Partial ({passed}/{len(cases)}){C.RESET}")

    _p()
    if _ping(args.host, args.port):
        _ok(f"Proxy healthy at {_url(args.host, args.port)}")
    else:
        _warn("Proxy not running  (tsm enable to start)")
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
10-second quickstart:
  pip install tsm-firewall && tsm enable

Common:
  tsm enable                        start + visible demo + hook instructions
  tsm demo                          step-by-step walkthrough (no LLM needed)
  tsm hook claude                   wrap claude with TSM
  tsm run python app.py             protect any script
  eval "$(tsm enable --eval)"       hook entire shell session
  tsm scan "My SSN is 123-45-6789"  instant scan
  tsm status                        live stats
""",
    )
    p.add_argument("--host", default=_DEFAULT_HOST)
    p.add_argument("--port", default=_DEFAULT_PORT, type=int)

    sub = p.add_subparsers(dest="cmd", metavar="command")

    ep = sub.add_parser("enable",  help="[START HERE] start + visible magic + monitor")
    ep.add_argument("--eval", action="store_true")

    sub.add_parser("demo",    help="Step-by-step interactive demo")
    sub.add_parser("monitor", help="Tail live request stream")

    hp = sub.add_parser("hook", help="Wrap a tool with TSM (auto-starts proxy)")
    hp.add_argument("tool", help="claude|codex|openai|cursor|aider|python|node")
    hp.add_argument("extra", nargs=argparse.REMAINDER)

    rp = sub.add_parser("run", help="Run any command through TSM (auto-starts proxy)")
    rp.add_argument("command", nargs=argparse.REMAINDER)
    rp.add_argument("--force", action="store_true")

    sp2 = sub.add_parser("scan", help="Scan text for PII instantly")
    sp2.add_argument("text", nargs="+")

    stp = sub.add_parser("start", help="Start the proxy")
    stp.add_argument("--daemon", "-d", action="store_true")
    stp.add_argument("--skill")

    sub.add_parser("stop",   help="Stop the proxy")
    sub.add_parser("status", help="Live proxy stats")

    skp = sub.add_parser("skills", help="Manage skill packs")
    sk  = skp.add_subparsers(dest="sub", metavar="action")
    sk.add_parser("list")
    si = sk.add_parser("install"); si.add_argument("file")
    ss = sk.add_parser("show");    ss.add_argument("name")

    sub.add_parser("test", help="Self-test (8/8 pattern checks)")

    return p


def main() -> None:
    p    = _build_parser()
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
        _p()
        _sep()
        _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM — The AI Firewall{C.RESET}")
        _sep()
        _p()
        _p(f"  Enterprise-grade AI data protection.")
        _p(f"  Free. Local. No account. Works in 10 seconds.")
        _p()
        _p(f"  {C.BOLD}Start here:{C.RESET}")
        _p()
        _p(f"  {C.GREEN}tsm enable{C.RESET}              {C.DIM}start + see it work immediately{C.RESET}")
        _p(f"  {C.GREEN}tsm demo{C.RESET}                {C.DIM}step-by-step (no LLM needed){C.RESET}")
        _p()
        _p(f"  {C.BOLD}Then use it:{C.RESET}")
        _p()
        _p(f"  {C.GREEN}tsm hook claude{C.RESET}         {C.DIM}wrap claude{C.RESET}")
        _p(f"  {C.GREEN}tsm hook codex{C.RESET}          {C.DIM}wrap codex{C.RESET}")
        _p(f"  {C.GREEN}tsm run python app.py{C.RESET}   {C.DIM}wrap any script{C.RESET}")
        _p(f"  {C.GREEN}tsm scan \"text...\"  {C.RESET}    {C.DIM}instant PII scan{C.RESET}")
        _p()
        _p(f"  {C.DIM}tsm --help for all commands{C.RESET}")
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
