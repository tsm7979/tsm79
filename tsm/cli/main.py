"""
TSM CLI
=======
The single binary that makes everything work.

    tsm start               — start the AI firewall proxy
    tsm stop                — stop the proxy
    tsm status              — live proxy stats
    tsm enable              — print shell export commands
    tsm hook claude         — run claude through TSM
    tsm hook openai         — run OpenAI-SDK apps through TSM
    tsm hook codex          — run codex through TSM
    tsm run <cmd>           — run any command through TSM
    tsm skills              — list installed skill packs
    tsm skills install <f>  — load a skill pack into proxy
    tsm scan <text>         — scan text for PII without proxy
    tsm test                — run built-in self-test
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

# Force UTF-8 output on Windows so emoji render correctly
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from typing import List, Optional


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


def _ok(msg: str)   -> None: print(f"  {C.GREEN}✓{C.RESET}  {msg}")
def _warn(msg: str) -> None: print(f"  {C.YELLOW}⚠{C.RESET}  {msg}")
def _err(msg: str)  -> None: print(f"  {C.RED}✗{C.RESET}  {msg}")
def _info(msg: str) -> None: print(f"  {C.CYAN}→{C.RESET}  {msg}")
def _sep()          -> None: print(f"{C.GRAY}{'━' * 58}{C.RESET}")


# ─── Proxy helpers ─────────────────────────────────────────────

_DEFAULT_HOST = "localhost"
_DEFAULT_PORT = 8080


def _proxy_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def _ping(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        url = f"{_proxy_url(host, port)}/health"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _stats(host: str, port: int) -> Optional[dict]:
    try:
        url = f"{_proxy_url(host, port)}/stats"
        with urllib.request.urlopen(url, timeout=3.0) as r:
            return json.loads(r.read())
    except Exception:
        return None


# ─── Commands ──────────────────────────────────────────────────

def cmd_start(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port

    if _ping(host, port):
        _warn(f"Proxy already running at {_proxy_url(host, port)}")
        return 0

    print()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM — The AI Firewall{C.RESET}")
    _sep()

    try:
        from tsm.proxy.server import start
    except ImportError:
        _err("tsm.proxy.server not found — is the package installed correctly?")
        return 1

    skill = getattr(args, "skill", None)

    if args.daemon:
        # Start in background thread, then print status
        t = threading.Thread(target=start, kwargs={"host": host, "port": port, "skill": skill, "blocking": True}, daemon=True)
        t.start()
        time.sleep(0.6)
        if _ping(host, port):
            _ok(f"Proxy running at {C.BOLD}{_proxy_url(host, port)}{C.RESET}")
            print()
            print(f"{C.YELLOW}  To protect your shell:{C.RESET}")
            print(f"  {C.CYAN}export OPENAI_BASE_URL={_proxy_url(host, port)}{C.RESET}")
            print()
        else:
            _err("Proxy failed to start")
            return 1
    else:
        # Blocking — stays alive in foreground
        start(host=host, port=port, skill=skill, blocking=True)

    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port

    if not _ping(host, port):
        _warn("Proxy is not running")
        return 0

    try:
        from tsm.proxy.server import stop
        stop()
        _ok("Proxy stopped")
    except Exception:
        # Try sending to a running process via a stop endpoint
        _err("Could not stop proxy — kill the process manually")
        return 1

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port
    url  = _proxy_url(host, port)

    if not _ping(host, port):
        print()
        _warn(f"TSM proxy is {C.RED}not running{C.RESET}")
        print()
        _info(f"Start it with: {C.BOLD}tsm start{C.RESET}")
        print()
        return 1

    data = _stats(host, port) or {}

    print()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM Proxy Status{C.RESET}")
    _sep()
    _ok(f"Proxy running at {C.BOLD}{url}{C.RESET}")
    print()

    uptime = data.get("uptime_seconds", 0)
    h, rem = divmod(uptime, 3600)
    m, s   = divmod(rem, 60)
    print(f"  {C.GRAY}Uptime       {C.RESET}{h:02d}:{m:02d}:{s:02d}")
    print(f"  {C.GRAY}Requests     {C.RESET}{data.get('requests_total', 0)}")
    print(f"  {C.GRAY}Clean        {C.RESET}{C.GREEN}{data.get('requests_clean', 0)}{C.RESET}")
    print(f"  {C.GRAY}Redacted     {C.RESET}{C.YELLOW}{data.get('requests_redacted', 0)}{C.RESET}")
    print(f"  {C.GRAY}Blocked      {C.RESET}{C.RED}{data.get('requests_blocked', 0)}{C.RESET}")
    print(f"  {C.GRAY}Cost saved   {C.RESET}{C.CYAN}${data.get('cost_saved_usd', 0):.4f}{C.RESET}")

    pii = data.get("pii_types_detected", {})
    if pii:
        print(f"  {C.GRAY}PII types    {C.RESET}" + "  ".join(
            f"{C.YELLOW}{k}×{v}{C.RESET}" for k, v in pii.items()
        ))
    print()
    _sep()
    print()
    return 0


def cmd_enable(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port
    base = _proxy_url(host, port)

    running = _ping(host, port)

    print()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM — Enable Firewall Mode{C.RESET}")
    _sep()

    if not running:
        _warn(f"Proxy not detected at {base}")
        _info(f"Start it first: {C.BOLD}tsm start{C.RESET}")
        print()

    print(f"{C.BOLD}  Run this in your shell:{C.RESET}")
    print()
    print(f'  {C.YELLOW}export OPENAI_BASE_URL="{base}"{C.RESET}')
    print(f'  {C.YELLOW}export OPENAI_API_BASE="{base}"{C.RESET}')
    print(f'  {C.YELLOW}export ANTHROPIC_BASE_URL="{base}"{C.RESET}')
    print(f'  {C.YELLOW}export TSM_ACTIVE="1"{C.RESET}')
    print()
    print(f"  {C.DIM}# Or use eval$(tsm enable --eval) to set in one shot{C.RESET}")
    print()

    if args.eval:
        # Print clean export lines for eval$()
        lines = [
            f'export OPENAI_BASE_URL="{base}"',
            f'export OPENAI_API_BASE="{base}"',
            f'export ANTHROPIC_BASE_URL="{base}"',
            'export TSM_ACTIVE="1"',
        ]
        print("\n".join(lines))

    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    tool    = args.tool.lower()
    host    = args.host
    port    = args.port
    extra   = args.extra or []

    from tsm.hooks.env import inject_env

    known = {
        "claude": ["claude"],
        "codex":  ["codex"],
        "openai": None,      # ENV-only
        "cursor": ["cursor"],
        "aider":  ["aider"],
    }

    if tool not in known:
        _err(f"Unknown tool '{tool}'. Known: {', '.join(known)}")
        return 1

    env     = inject_env(host=host, port=port)
    base    = _proxy_url(host, port)
    running = _ping(host, port)

    print()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM Hook → {tool}{C.RESET}")
    _sep()

    if not running:
        _warn(f"Proxy not running at {base}  (start with: tsm start)")
        print()

    if known[tool] is None:
        # ENV-only hook
        _ok(f"Set OPENAI_BASE_URL={base} in your environment")
        print()
        _info("Then restart your app — it's now protected")
        return 0

    cmd = known[tool] + extra
    _ok(f"Launching: {C.BOLD}{' '.join(cmd)}{C.RESET}")
    _ok(f"Proxy:     {C.BOLD}{base}{C.RESET}")
    print()
    _sep()

    try:
        result = subprocess.run(cmd, env=env)
        return result.returncode
    except FileNotFoundError:
        _err(f"'{tool}' not found in PATH — is it installed?")
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        _err("No command specified. Usage: tsm run <command> [args...]")
        return 1

    host  = args.host
    port  = args.port
    base  = _proxy_url(host, port)

    from tsm.hooks.env import inject_env
    env     = inject_env(host=host, port=port)
    running = _ping(host, port)

    print()
    print(f"{C.BOLD}{C.CYAN}  🛡️  TSM Run{C.RESET}")
    _sep()

    if not running:
        _warn(f"Proxy not running at {base}")
        _info("Start with: tsm start")
        print()
        if not args.force:
            _err("Aborting. Use --force to run anyway.")
            return 1

    _ok(f"Command: {C.BOLD}{' '.join(args.command)}{C.RESET}")
    _ok(f"Proxy:   {C.BOLD}{base}{C.RESET}")
    _sep()
    print()

    try:
        result = subprocess.run(args.command, env=env)
        return result.returncode
    except FileNotFoundError:
        _err(f"'{args.command[0]}' not found in PATH")
        return 1


def cmd_skills(args: argparse.Namespace) -> int:
    skills_dir = _find_skills_dir()

    sub = getattr(args, "sub", None) or "list"

    if sub == "list":
        return _skills_list(skills_dir)
    elif sub == "install":
        return _skills_install(skills_dir, args)
    elif sub == "show":
        return _skills_show(skills_dir, args)
    return 0


def _find_skills_dir() -> pathlib.Path:
    # 1. env override
    if "TSM_SKILLS_DIR" in os.environ:
        return pathlib.Path(os.environ["TSM_SKILLS_DIR"])
    # 2. package-bundled skills
    here = pathlib.Path(__file__).parent.parent.parent  # project root
    bundled = here / "skills"
    if bundled.exists():
        return bundled
    # 3. ~/.tsm/skills
    return pathlib.Path.home() / ".tsm" / "skills"


def _skills_list(skills_dir: pathlib.Path) -> int:
    print()
    print(f"{C.BOLD}{C.CYAN}  ⚡ TSM Skill Packs{C.RESET}")
    _sep()

    if not skills_dir.exists():
        _warn(f"Skills directory not found: {skills_dir}")
        print()
        _info("Create skills/*.md files to add skill packs")
        print()
        return 0

    packs = sorted(skills_dir.glob("*.md"))
    if not packs:
        _warn("No skill packs installed")
        print()
        return 0

    for p in packs:
        name = p.stem
        # Read first non-empty line as description
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
            desc  = next((l.lstrip("# ") for l in lines if l.strip() and not l.startswith("---")), "")
        except Exception:
            desc = ""
        print(f"  {C.CYAN}⚡{C.RESET} {C.BOLD}{name:<20}{C.RESET}  {C.DIM}{desc[:60]}{C.RESET}")

    print()
    _info(f"Load a skill:  {C.BOLD}tsm start --skill <name>{C.RESET}")
    print()
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
    name = getattr(args, "name", "")
    path = skills_dir / f"{name}.md"
    if not path.exists():
        _err(f"Skill not found: {name}")
        return 1
    print(path.read_text(encoding="utf-8"))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    text = " ".join(args.text)
    if not text:
        _err("No text provided. Usage: tsm scan <text>")
        return 1

    try:
        from tsm.detectors.pii import PIIDetector, Severity
    except ImportError:
        _err("PII detector not available")
        return 1

    detector = PIIDetector()
    result   = detector.scan(text)

    print()
    print(f"{C.BOLD}{C.CYAN}  🔍 TSM PII Scan{C.RESET}")
    _sep()
    print(f"  Input: {C.DIM}{text[:80]}{C.RESET}")
    print()

    ICONS = {
        Severity.CRITICAL: f"{C.RED}🚨 CRITICAL{C.RESET}",
        Severity.HIGH:     f"{C.YELLOW}⚠️  HIGH    {C.RESET}",
        Severity.MEDIUM:   f"{C.CYAN}🔍 MEDIUM  {C.RESET}",
        Severity.LOW:      f"{C.GRAY}ℹ️  LOW     {C.RESET}",
    }

    if result.is_clean:
        _ok(f"{C.GREEN}Clean — no sensitive data detected{C.RESET}")
    else:
        for d in result.detections:
            print(f"  {ICONS[d.severity]}  {C.BOLD}{d.type}{C.RESET}  {C.DIM}({d.preview}){C.RESET}")
        print()
        if result.has_critical:
            _info(f"→ Would route to {C.BOLD}local model{C.RESET} (critical PII)")
        elif result.has_high:
            _info(f"→ Would {C.BOLD}redact{C.RESET} then route to cloud")
        else:
            _info(f"→ Would {C.BOLD}redact{C.RESET} then route to cloud")
        print()
        print(f"  {C.BOLD}Redacted:{C.RESET}")
        print(f"  {C.YELLOW}{result.redacted_text}{C.RESET}")

    print()
    _sep()
    print()
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    print()
    print(f"{C.BOLD}{C.CYAN}  🧪 TSM Self-Test{C.RESET}")
    _sep()

    try:
        from tsm.detectors.pii import PIIDetector, Severity
    except ImportError as e:
        _err(f"Import failed: {e}")
        return 1

    d = PIIDetector()
    cases = [
        ("SSN",         "Call me at 123-45-6789",             Severity.CRITICAL),
        ("CREDIT_CARD", "Card: 4111 1111 1111 1111",          Severity.CRITICAL),
        ("OPENAI_KEY",  "key: sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ", Severity.HIGH),
        ("EMAIL",       "email me at user@example.com",        Severity.MEDIUM),
        ("PHONE",       "call (555) 123-4567",                 Severity.MEDIUM),
        ("CLEAN",       "What is 2 + 2?",                      None),
    ]

    passed = 0
    for name, text, expected_severity in cases:
        result = d.scan(text)
        if expected_severity is None:
            ok = result.is_clean
        else:
            ok = result.worst_severity == expected_severity

        if ok:
            _ok(f"{name:<20} detected correctly")
            passed += 1
        else:
            _err(f"{name:<20} FAILED — expected {expected_severity}, got {result.worst_severity}")

    print()
    score = f"{passed}/{len(cases)}"
    if passed == len(cases):
        print(f"  {C.GREEN}{C.BOLD}All tests passed ({score}){C.RESET}")
    else:
        print(f"  {C.YELLOW}Partial ({score}){C.RESET}")

    host = args.host
    port = args.port
    print()
    if _ping(host, port):
        _ok(f"Proxy health check passed at {_proxy_url(host, port)}")
    else:
        _warn(f"Proxy not running at {_proxy_url(host, port)} (run: tsm start)")

    print()
    _sep()
    print()
    return 0 if passed == len(cases) else 1


# ─── Argument parser ───────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tsm",
        description="🛡️  TSM — The AI Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tsm start                     # start the proxy on :8080
  tsm enable                    # print shell export commands
  tsm hook claude               # run claude through TSM
  tsm hook claude -- --help     # pass flags to claude
  tsm run python my_script.py   # run any script through TSM
  tsm scan "my SSN is 123-45-6789"
  tsm status                    # live proxy stats
  tsm skills                    # list skill packs
  tsm test                      # run self-test
""",
    )
    p.add_argument("--host", default=_DEFAULT_HOST, help="Proxy host (default: localhost)")
    p.add_argument("--port", default=_DEFAULT_PORT, type=int, help="Proxy port (default: 8080)")

    sub = p.add_subparsers(dest="cmd", metavar="command")

    # start
    sp = sub.add_parser("start", help="Start the TSM proxy")
    sp.add_argument("--daemon", "-d", action="store_true", help="Run in background")
    sp.add_argument("--skill", help="Skill pack to activate")

    # stop
    sub.add_parser("stop", help="Stop the TSM proxy")

    # status
    sub.add_parser("status", help="Show proxy statistics")

    # enable
    ep = sub.add_parser("enable", help="Print shell export commands")
    ep.add_argument("--eval", action="store_true", help="Print only raw exports (for eval$())")

    # hook
    hp = sub.add_parser("hook", help="Run a tool through TSM")
    hp.add_argument("tool", help="Tool name: claude, codex, openai, cursor, aider")
    hp.add_argument("extra", nargs=argparse.REMAINDER, help="Extra args for the tool")

    # run
    rp = sub.add_parser("run", help="Run any command through TSM")
    rp.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")
    rp.add_argument("--force", action="store_true", help="Run even if proxy is not running")

    # skills
    skp = sub.add_parser("skills", help="Manage skill packs")
    sk_sub = skp.add_subparsers(dest="sub", metavar="action")
    sk_sub.add_parser("list", help="List installed skills")
    si = sk_sub.add_parser("install", help="Install a skill pack")
    si.add_argument("file", help="Path to .md skill file")
    ss = sk_sub.add_parser("show", help="Show a skill pack")
    ss.add_argument("name", help="Skill name")

    # scan
    scanp = sub.add_parser("scan", help="Scan text for PII")
    scanp.add_argument("text", nargs="+", help="Text to scan")

    # test
    sub.add_parser("test", help="Run built-in self-test")

    return p


def main() -> None:
    p = _build_parser()
    args = p.parse_args()

    dispatch = {
        "start":  cmd_start,
        "stop":   cmd_stop,
        "status": cmd_status,
        "enable": cmd_enable,
        "hook":   cmd_hook,
        "run":    cmd_run,
        "skills": cmd_skills,
        "scan":   cmd_scan,
        "test":   cmd_test,
    }

    if args.cmd is None:
        p.print_help()
        sys.exit(0)

    handler = dispatch.get(args.cmd)
    if handler is None:
        p.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
