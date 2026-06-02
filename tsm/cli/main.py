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
    """
    Start the proxy so it survives this process:
      1. Detached subprocess (preferred — survives parent exit)
      2. Daemon thread fallback (for tsm enable which stays alive anyway)
    Returns True once the proxy responds on /health.
    """
    # --- Detached subprocess ---
    try:
        script = (
            "import os, sys, io\n"
            "sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')\n"
            "sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')\n"
            f"os.environ['TSM_HEADLESS'] = '1'\n"
            f"from tsm.proxy.server import start\n"
            f"start(host={host!r}, port={port}, skill={skill!r}, blocking=True)\n"
        )
        cmd = [sys.executable, "-c", script]
        # Use a log file instead of DEVNULL so the proxy can write safely
        log_path = pathlib.Path.home() / ".tsm" / "proxy.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a", encoding="utf-8", errors="replace")

        popen_kwargs: dict = {"stdout": log_file, "stderr": log_file}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = (
                subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            popen_kwargs["start_new_session"] = True

        subprocess.Popen(cmd, **popen_kwargs)
    except Exception:
        pass

    # Wait up to 5 s for proxy to answer
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if _ping(host, port, 0.4):
            return True
        time.sleep(0.15)

    # --- Thread fallback ---
    try:
        from tsm.proxy.server import start as _srv_start
        t = threading.Thread(
            target=_srv_start,
            kwargs={"host": host, "port": port, "skill": skill, "blocking": True},
            daemon=True,
        )
        t.start()
        deadline2 = time.time() + 5.0
        while time.time() < deadline2:
            if _ping(host, port, 0.4):
                return True
            time.sleep(0.15)
    except Exception:
        pass

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
        "prompt":   "Why does AKIA_DEMO_FIXTURE_AB1234 get access denied?",
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


def cmd_analyze(args: argparse.Namespace) -> int:
    """tsm analyze — risk score, leak breakdown, behavioral profile."""
    from tsm.core.analyze import RiskEngine
    from tsm.core.analytics import spark_bar

    engine = RiskEngine()
    r = engine.run()

    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  TSM Risk Analysis{C.RESET}")
    _sep()
    _p()

    if r.total_requests == 0:
        _info("No data yet.")
        _info("Run: tsm enable   then send some AI requests.")
        _p()
        return 0

    # ── Risk score block ──────────────────────────────────────
    grade_color = {
        "CRITICAL": C.RED, "HIGH": C.RED, "ELEVATED": C.YELLOW,
        "LOW": C.CYAN, "MINIMAL": C.GREEN,
    }.get(r.grade, C.GRAY)

    score_bar = spark_bar(int(r.risk_score), 100, width=30)
    _p(f"  {C.BOLD}Risk Score{C.RESET}   {grade_color}{C.BOLD}{r.risk_score:5.1f} / 100{C.RESET}  "
       f"{grade_color}{r.grade}{C.RESET}")
    _p(f"  {C.GRAY}             [{score_bar}]{C.RESET}")
    _p(f"  {C.GRAY}             {r.grade_message}{C.RESET}")
    _p()

    # ── Traffic summary ───────────────────────────────────────
    s_pct  = int(r.sensitive_pct * 100)
    pr_pct = int(r.prevented_pct * 100)
    _p(f"  {C.GRAY}Intercepted   {C.RESET}{C.BOLD}{r.total_requests}{C.RESET} requests")
    _p(f"  {C.GRAY}Sensitive     {C.RESET}"
       f"{'%s%d%%%s' % (C.YELLOW if s_pct > 20 else C.GREEN, s_pct, C.RESET)} "
       f"of prompts contained PII")
    _p(f"  {C.GRAY}Prevented     {C.RESET}"
       f"{'%s%d%%%s' % (C.GREEN if pr_pct > 80 else C.YELLOW, pr_pct, C.RESET)} "
       f"of PII kept off cloud")
    _p(f"  {C.GRAY}Cost saved    {C.RESET}{C.CYAN}${r.cost_saved:.4f}{C.RESET}")
    _p()

    # ── Leak breakdown ────────────────────────────────────────
    if r.leaks:
        _p(f"  {C.BOLD}Leak breakdown{C.RESET}   (sorted by risk impact)")
        _p()
        max_score = r.leaks[0].risk_score if r.leaks else 1
        for leak in r.leaks:
            bar     = spark_bar(int(leak.risk_score * 10), int(max_score * 10), width=18)
            stopped = f"{C.GREEN}+{leak.prevented} stopped{C.RESET}" if leak.prevented else f"{C.YELLOW}none stopped{C.RESET}"
            risk_col = C.RED if leak.risk_score >= 7 else C.YELLOW if leak.risk_score >= 4 else C.GRAY
            _p(f"  {risk_col}{leak.pii_type:<22}{C.RESET}"
               f"  [{bar}]  ×{leak.count}  {stopped}")
        _p()

    # ── Trend ─────────────────────────────────────────────────
    trend_icon = {"IMPROVING": C.GREEN, "STABLE": C.CYAN,
                  "WORSENING": C.RED, "INSUFFICIENT_DATA": C.GRAY}
    t_col = trend_icon.get(r.trend, C.GRAY)
    _p(f"  {C.BOLD}Trend{C.RESET}   {t_col}{r.trend}{C.RESET}  {C.GRAY}{r.trend_detail}{C.RESET}")
    _p()

    # ── Model exposure ────────────────────────────────────────
    if r.models_exposed:
        exposed_str = "  ".join(
            f"{C.YELLOW}{m}{C.RESET}×{c}" for m, c in list(r.models_exposed.items())[:4]
        )
        _p(f"  {C.BOLD}Models that saw PII{C.RESET}   {exposed_str}")
        _p()

    # ── Recommendations ───────────────────────────────────────
    _p(f"  {C.BOLD}Recommendations{C.RESET}")
    for i, rec in enumerate(r.recommendations, 1):
        _p(f"  {C.CYAN}{i}.{C.RESET} {rec}")
    _p()

    # ── Chain integrity footer ────────────────────────────────
    if r.chain_valid:
        _p(f"  {C.GRAY}Audit: {r.ledger_entries} entries · SHA-256 verified{C.RESET}")
    else:
        _warn(f"Audit chain integrity FAILED — ledger may be tampered")
    _p()
    _sep()
    _p()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from tsm.core.analytics import compute, spark_bar
    from tsm.core.ledger import TrustLedger

    host, port = args.host, args.port
    is_running = _ping(host, port)

    stats = compute()          # reads ~/.tsm/ledger.jsonl
    ledger = TrustLedger()
    chain_ok, chain_count = ledger.verify_chain()

    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  TSM — Trust Ledger{C.RESET}")
    _sep()

    # Proxy status line
    if is_running:
        live_data = _stats(host, port) or {}
        u = live_data.get("uptime_seconds", 0)
        h, r = divmod(u, 3600); m, s = divmod(r, 60)
        _ok(f"Proxy  {C.GREEN}running{C.RESET}  {_url(host, port)}  uptime {h:02d}:{m:02d}:{s:02d}")
    else:
        _warn(f"Proxy not running — showing historical data  ({C.DIM}tsm enable to start{C.RESET})")

    _p()

    total = stats["total"]
    if total == 0:
        _info("No interceptions recorded yet. Run: tsm enable")
        _p()
        _sep()
        _p()
        return 0

    # ── Summary row ───────────────────────────────────────────
    local_pct = int(stats["local_ratio"] * 100)
    _p(f"  {C.GRAY}Intercepted{C.RESET}   {C.BOLD}{total}{C.RESET}  requests")
    _p(f"  {C.GRAY}PII blocked{C.RESET}   {C.YELLOW}{stats['redacted']}{C.RESET}  "
       f"({C.YELLOW}{int(stats['redacted']/total*100) if total else 0}%{C.RESET})")
    _p(f"  {C.GRAY}Routed local{C.RESET}  {C.GREEN}{stats['local_routes']}{C.RESET}  "
       f"({C.GREEN}{local_pct}%{C.RESET}  cloud never saw it)")
    _p(f"  {C.GRAY}Cost saved{C.RESET}    {C.CYAN}${stats['cost_saved']:.4f}{C.RESET}  "
       f"avg latency {stats['avg_latency_ms']}ms")
    _p()

    # ── PII breakdown with bars ───────────────────────────────
    pii = stats["pii_types"]
    if pii:
        _p(f"  {C.BOLD}Detection breakdown{C.RESET}")
        max_v = max(pii.values())
        for typ, cnt in pii.items():
            bar = spark_bar(cnt, max_v, width=16)
            color = C.RED if typ in ("SSN", "CREDIT_CARD", "PRIVATE_KEY") else C.YELLOW
            _p(f"  {color}{typ:<18}{C.RESET}  {bar}  {cnt}")
        _p()

    # ── Severity distribution ─────────────────────────────────
    sev = stats["severity_dist"]
    if sev:
        sev_colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "LOW": C.GRAY, "none": C.GREEN}
        parts = []
        for s_name, cnt in sorted(sev.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","none"].index(x[0]) if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW","none"] else 99):
            col = sev_colors.get(s_name, C.GRAY)
            parts.append(f"{col}{s_name}{C.RESET} ×{cnt}")
        _p(f"  {C.BOLD}Severity{C.RESET}   " + "  ".join(parts))
        _p()

    # ── Chain integrity ───────────────────────────────────────
    if chain_ok:
        _p(f"  {C.GREEN}Chain integrity  verified{C.RESET}  "
           f"{C.GRAY}{chain_count} entries · SHA-256{C.RESET}")
    else:
        _p(f"  {C.RED}Chain integrity  FAILED{C.RESET}  "
           f"{C.GRAY}checked {chain_count} entries{C.RESET}")

    _p()
    _sep()
    _p()
    return 0


# ─── cmd_audit ────────────────────────────────────────────────

def cmd_audit(args: argparse.Namespace) -> int:
    """tsm audit search <term> — search the trust ledger."""
    from tsm.core.ledger import TrustLedger
    import pathlib, json

    sub = getattr(args, "audit_action", "search")
    ledger_path = pathlib.Path.home() / ".tsm" / "ledger.jsonl"

    if sub == "verify":
        ledger = TrustLedger(ledger_path)
        valid, count = ledger.verify_chain()
        _p()
        _sep()
        _p(f"{C.BOLD}{C.CYAN}  TSM Audit Chain Verification{C.RESET}")
        _sep()
        _p()
        if valid:
            _ok(f"Chain intact — {count} entries verified · SHA-256")
        else:
            _err(f"Chain FAILED at entry {count} — possible tampering")
        _p()
        _sep()
        _p()
        return 0 if valid else 1

    # Default: search
    query = getattr(args, "query", None) or ""
    query_lower = query.lower()

    if not ledger_path.exists():
        _warn("No audit ledger found. Run: tsm enable")
        return 1

    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  TSM Audit Search{C.RESET}"
       + (f"  {C.DIM}'{query}'{C.RESET}" if query else "  (all entries)"))
    _sep()
    _p()

    hits = 0
    try:
        with open(ledger_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if entry.get("type") != "intercept":
                    continue

                # Match query against pii_types, model, severity, timestamp
                entry_str = json.dumps(entry).lower()
                if query_lower and query_lower not in entry_str:
                    continue

                hits += 1
                ts      = entry.get("ts", "?")
                model   = entry.get("model", "?")
                pii     = entry.get("pii_types", [])
                sev     = entry.get("severity", "none")
                local   = entry.get("routed_local", False)
                lat     = entry.get("latency_ms", 0)

                sev_col = {
                    "CRITICAL": C.RED, "HIGH": C.YELLOW,
                    "MEDIUM": C.CYAN, "LOW": C.GRAY, "none": C.GREEN,
                }.get(sev, C.GRAY)

                route_str = f"{C.GREEN}local{C.RESET}" if local else f"{C.GRAY}cloud{C.RESET}"
                pii_str   = f"{C.YELLOW}{', '.join(pii)}{C.RESET}" if pii else f"{C.GREEN}clean{C.RESET}"

                _p(f"  {C.GRAY}{ts}{C.RESET}  {model:<20}  {sev_col}{sev:<10}{C.RESET}  "
                   f"{pii_str}  →{route_str}  {C.GRAY}{lat}ms{C.RESET}")

    except OSError as e:
        _err(f"Cannot read ledger: {e}")
        return 1

    _p()
    _p(f"  {C.GRAY}{hits} entr{'y' if hits == 1 else 'ies'} matched{C.RESET}")
    _sep()
    _p()
    return 0


# ─── cmd_report ───────────────────────────────────────────────

def cmd_report(args: argparse.Namespace) -> int:
    """tsm report — compliance-ready summary from the trust ledger."""
    from tsm.core.analytics import compute, load_intercepts
    from tsm.core.ledger import TrustLedger
    from tsm.core.policy import COMPLIANCE_MAP

    stats = compute()
    ledger = TrustLedger()
    chain_ok, chain_count = ledger.verify_chain()

    import time
    date_str = time.strftime("%Y-%m-%d", time.gmtime())

    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  TSM Compliance Report — {date_str}{C.RESET}")
    _sep()
    _p()

    total = stats["total"]
    if total == 0:
        _info("No data yet. Run: tsm enable")
        return 0

    _p(f"  {C.BOLD}Overview{C.RESET}")
    _p(f"  Intercepted     {total} requests")
    _p(f"  PII detected    {stats['redacted']}  ({int(stats['redacted']/total*100)}% of traffic)")
    _p(f"  Routed local    {stats['local_routes']}  (cloud never received sensitive data)")
    _p(f"  Cost saved      ${stats['cost_saved']:.4f}")
    _p(f"  Avg latency     {stats['avg_latency_ms']}ms overhead")
    _p()

    # Compliance breakdown per framework
    pii_types = stats.get("pii_types", {})
    for framework, info in COMPLIANCE_MAP.items():
        covered = {t: pii_types[t] for t in info["pii_types"] if t in pii_types}
        if not covered:
            continue
        total_covered = sum(covered.values())
        _p(f"  {C.BOLD}{framework}{C.RESET}  {C.GRAY}({info['article']}){C.RESET}")
        for pii_type, count in covered.items():
            _p(f"    {pii_type:<24} {count} events prevented")
        _p(f"    {C.GRAY}Recommended action: {info['action']}{C.RESET}")
        _p()

    # Severity breakdown
    sev = stats.get("severity_dist", {})
    if sev:
        _p(f"  {C.BOLD}Severity breakdown{C.RESET}")
        for s_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "none"]:
            if s_name in sev:
                color = {
                    "CRITICAL": C.RED, "HIGH": C.YELLOW,
                    "MEDIUM": C.CYAN, "LOW": C.GRAY, "none": C.GREEN,
                }.get(s_name, C.GRAY)
                _p(f"    {color}{s_name:<12}{C.RESET}  {sev[s_name]}")
        _p()

    # Chain integrity
    if chain_ok:
        _p(f"  {C.GREEN}Audit chain verified{C.RESET}  {chain_count} entries · SHA-256 · tamper-evident")
    else:
        _p(f"  {C.RED}Audit chain FAILED{C.RESET}  integrity check failed at entry {chain_count}")
    _p()
    _sep()
    _p()
    return 0


# ─── cmd_policy ───────────────────────────────────────────────

def cmd_policy(args: argparse.Namespace) -> int:
    """tsm policy — view and configure the active policy."""
    from tsm.core.policy import PolicyEngine, COMPLIANCE_MAP

    engine = PolicyEngine()
    sub = getattr(args, "policy_action", "show")

    if sub == "show" or sub is None:
        data = engine.show()
        _p()
        _sep()
        _p(f"{C.BOLD}{C.CYAN}  TSM Policy{C.RESET}")
        _sep()
        _p()
        frameworks = data.get("compliance", [])
        if frameworks:
            _ok(f"Compliance frameworks: {', '.join(frameworks)}")
        else:
            _info("No compliance frameworks enabled. Try: tsm policy enable GDPR")
        _p()
        rules = data.get("rules", [])
        if rules:
            _p(f"  {C.BOLD}Custom rules ({len(rules)}){C.RESET}")
            for r in rules:
                col = C.RED if r.get("action") == "block" else C.YELLOW
                _p(f"    {col}{r.get('action','?'):<8}{C.RESET}  {r.get('match')}  [{r.get('label','')}]")
        else:
            _p(f"  {C.GRAY}No custom rules. Add with: tsm policy add \"pattern\" block LABEL{C.RESET}")
        _p()
        blocklist = data.get("model_blocklist", [])
        if blocklist:
            _warn(f"Blocked models: {', '.join(blocklist)}")
        _p(f"  {C.GRAY}require_local_for: {data.get('require_local_for', [])}{C.RESET}")
        _p()
        _sep()
        _p()

    elif sub == "enable":
        framework = getattr(args, "framework", None)
        if not framework:
            _err("Usage: tsm policy enable GDPR|HIPAA|PCI-DSS|SOC2")
            return 1
        try:
            engine.enable_compliance(framework)
            _ok(f"Compliance framework enabled: {framework}")
        except ValueError as e:
            _err(str(e))
            return 1

    elif sub == "add":
        match = getattr(args, "match", None)
        action = getattr(args, "action", "block")
        label = getattr(args, "label", match)
        if not match:
            _err("Usage: tsm policy add \"pattern\" block|redact|flag LABEL")
            return 1
        engine.add_rule(match, action, label)
        _ok(f"Rule added: {action} '{match}' [{label}]")

    elif sub == "reset":
        engine.reset()
        _ok("Policy reset to defaults")

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

_VERDICT_STYLE = {
    "block":      (C.RED,     "⛔ BLOCK"),
    "quarantine": (C.YELLOW,  "🧪 QUARANTINE"),
    "escalate":   (C.MAGENTA, "⏏️  ESCALATE → human"),
    "allow":      (C.GREEN,   "✅ ALLOW"),
    "abstain":    (C.GRAY,    "— abstain"),
}
_LAYER_LABEL = {"ai": "AI", "code": "CODE", "human": "HUMAN"}


def cmd_trust(args: argparse.Namespace) -> int:
    """tsm trust "<text>" — run the AI -> Code -> Human triple fail-safe engine."""
    text = " ".join(args.text)
    if not text:
        _err('Usage: tsm trust "<text>"  [--no-ai|--no-code|--human allow|block|escalate|--risk high]')
        return 1

    from tsm.engine import RiskTier, TrustContext, TrustEngine, Verdict
    from tsm.engine.adapters import ai_layer, code_layer, human_layer

    code = None if getattr(args, "no_code", False) else code_layer()
    ai = None if getattr(args, "no_ai", False) else ai_layer()
    human = None
    hv = getattr(args, "human", None)
    if hv:
        human = human_layer(lambda ctx, v=Verdict(hv): v)

    risk = RiskTier(getattr(args, "risk", None) or "low")
    engine = TrustEngine(ai=ai, code=code, human=human,
                         autonomous=not getattr(args, "strict", False))
    d = engine.decide(TrustContext(payload=text, risk=risk))

    _p()
    _sep()
    _p(f"{C.BOLD}{C.CYAN}  🛡️  TSM Trust Engine{C.RESET}  {C.DIM}AI → Code → Human (triple fail-safe){C.RESET}")
    _sep()
    _p(f"  {C.DIM}{text[:72]}{'…' if len(text) > 72 else ''}{C.RESET}")
    _p()

    for r in d.reports:
        lbl = _LAYER_LABEL.get(r.layer.value, r.layer.value)
        if r.status.value == "offline":
            _p(f"  {C.GRAY}{lbl:<6} offline{C.RESET}    {C.DIM}{r.reason}{C.RESET}")
        else:
            col, _name = _VERDICT_STYLE.get(r.verdict.value, (C.GRAY, r.verdict.value))
            tag = "" if r.status.value == "online" else f"{C.GRAY}(degraded){C.RESET} "
            _p(f"  {C.BOLD}{lbl:<6}{C.RESET} {col}{r.verdict.value:<11}{C.RESET}"
               f"{C.GRAY}conf {r.confidence:.2f}{C.RESET}  {tag}{C.DIM}{r.reason}{C.RESET}")
    _p()

    if d.divergences:
        _p(f"  {C.YELLOW}⚠ divergence{C.RESET}  {C.DIM}{'; '.join(d.divergences)}{C.RESET}")
        _p()

    col, label = _VERDICT_STYLE.get(d.verdict.value, (C.GRAY, d.verdict.value))
    autonomy = (f"{C.MAGENTA}autonomous{C.RESET}" if d.autonomous
                else f"{C.CYAN}human-in-loop{C.RESET}")
    consensus = f"  {C.GREEN}consensus{C.RESET}" if d.consensus else ""
    _p(f"  {C.BOLD}Decision{C.RESET}   {col}{C.BOLD}{label}{C.RESET}{consensus}")
    _p(f"  {C.GRAY}mode{C.RESET} {d.mode.value}   {C.GRAY}risk{C.RESET} {d.risk.value}   "
       f"{C.GRAY}rule{C.RESET} {d.rule}   {autonomy}")
    _p(f"  {C.GRAY}{d.explanation}{C.RESET}")
    _p()
    _sep()
    _p()
    return 0 if d.verdict is Verdict.ALLOW else 2


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
        ("AWS_KEY",     "key=AKIA_DEMO_FIXTURE_AB1234",         Severity.HIGH),
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

    sub.add_parser("analyze", help="[KEY FEATURE] risk score, leak breakdown, behavioral profile")
    ep = sub.add_parser("enable",  help="Start firewall + see it work immediately")
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

    tp = sub.add_parser("trust", help="Run the AI→Code→Human trust engine on text")
    tp.add_argument("text", nargs="+")
    tp.add_argument("--no-ai", action="store_true", help="simulate the AI layer offline")
    tp.add_argument("--no-code", action="store_true", help="simulate the Code layer offline")
    tp.add_argument("--human", choices=["allow", "block", "quarantine", "escalate"],
                    help="simulate a human decision in the loop")
    tp.add_argument("--risk", choices=["low", "medium", "high", "critical"],
                    help="risk hint for the request (default: low)")
    tp.add_argument("--strict", action="store_true",
                    help="disable autonomous approvals (require a human for ALLOW)")

    stp = sub.add_parser("start", help="Start the proxy")
    stp.add_argument("--daemon", "-d", action="store_true")
    stp.add_argument("--skill")

    sub.add_parser("stop",   help="Stop the proxy")
    sub.add_parser("status", help="Trust ledger + live analytics")
    sub.add_parser("report", help="Compliance report (GDPR, HIPAA, PCI-DSS, SOC2)")

    ap  = sub.add_parser("audit", help="Search and verify the trust ledger")
    asp = ap.add_subparsers(dest="audit_action", metavar="action")
    av  = asp.add_parser("verify", help="Verify SHA-256 chain integrity")
    aq  = asp.add_parser("search", help="Search ledger entries")
    aq.add_argument("query", nargs="?", default="", help="search term (pii type, model, severity)")

    pp  = sub.add_parser("policy", help="View and configure the active policy")
    psp = pp.add_subparsers(dest="policy_action", metavar="action")
    psp.add_parser("show")
    pe  = psp.add_parser("enable"); pe.add_argument("framework")
    pa  = psp.add_parser("add")
    pa.add_argument("match"); pa.add_argument("action"); pa.add_argument("label", nargs="?", default=None)
    psp.add_parser("reset")

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
        "analyze": cmd_analyze,
        "enable":  cmd_enable,
        "demo":    cmd_demo,
        "monitor": cmd_monitor,
        "hook":    cmd_hook,
        "run":     cmd_run,
        "scan":    cmd_scan,
        "trust":   cmd_trust,
        "start":   cmd_start,
        "stop":    cmd_stop,
        "status":  cmd_status,
        "report":  cmd_report,
        "audit":   cmd_audit,
        "policy":  cmd_policy,
        "skills":  cmd_skills,
        "test":    cmd_test,
    }

    if args.cmd is None:
        _p()
        _sep()
        _p(f"{C.BOLD}{C.CYAN}  TSM — The AI Firewall{C.RESET}")
        _sep()
        _p()
        _p(f"  The default security layer for AI applications.")
        _p(f"  Intercepts every prompt. Detects PII. Prevents leaks.")
        _p(f"  Free. Local. Zero code changes. Works in 10 seconds.")
        _p()
        _p(f"  {C.BOLD}The golden path:{C.RESET}")
        _p()
        _p(f"  {C.GREEN}tsm enable{C.RESET}              {C.DIM}start firewall + see it work{C.RESET}")
        _p(f"  {C.GREEN}tsm analyze{C.RESET}             {C.BOLD}{C.CYAN}risk score · leak breakdown · recommendations{C.RESET}")
        _p()
        _p(f"  {C.BOLD}Protect specific tools:{C.RESET}")
        _p()
        _p(f"  {C.GREEN}tsm hook claude{C.RESET}         {C.DIM}wrap claude CLI{C.RESET}")
        _p(f"  {C.GREEN}tsm hook codex{C.RESET}          {C.DIM}wrap codex{C.RESET}")
        _p(f"  {C.GREEN}tsm run python app.py{C.RESET}   {C.DIM}wrap any script{C.RESET}")
        _p(f"  {C.GREEN}tsm scan \"text\"{C.RESET}         {C.DIM}instant PII scan (no proxy){C.RESET}")
        _p()
        _p(f"  {C.BOLD}Compliance and audit:{C.RESET}")
        _p()
        _p(f"  {C.GREEN}tsm report{C.RESET}              {C.DIM}GDPR / HIPAA / PCI-DSS / SOC2 mapping{C.RESET}")
        _p(f"  {C.GREEN}tsm policy{C.RESET}              {C.DIM}configure custom rules{C.RESET}")
        _p(f"  {C.GREEN}tsm status{C.RESET}              {C.DIM}live stats + chain integrity{C.RESET}")
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
