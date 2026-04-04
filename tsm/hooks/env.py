"""
TSM Environment Hook
====================
Injects TSM proxy as drop-in OpenAI replacement by setting
OPENAI_BASE_URL, OPENAI_API_BASE, and ANTHROPIC_BASE_URL
before launching any subprocess.

Usage:
    env = inject_env(host="localhost", port=8080)
    subprocess.run(["claude", ...], env=env)
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Dict, List, Optional


_ORIGINAL_VARS: Dict[str, Optional[str]] = {}
_ACTIVE = False


def inject_env(host: str = "localhost", port: int = 8080) -> Dict[str, str]:
    """
    Return a copy of os.environ with TSM proxy vars injected.
    Does NOT mutate the current process environment.
    """
    base_url = f"http://{host}:{port}"
    env = os.environ.copy()
    env["OPENAI_BASE_URL"]  = base_url
    env["OPENAI_API_BASE"]  = base_url           # legacy SDK compat
    env["ANTHROPIC_BASE_URL"] = base_url         # anthropic SDK compat
    env["TSM_ACTIVE"]        = "1"
    env["TSM_PROXY_HOST"]    = host
    env["TSM_PROXY_PORT"]    = str(port)
    return env


def activate(host: str = "localhost", port: int = 8080) -> None:
    """
    Mutate the current process environment so all child processes
    pick up TSM automatically (use only for shell integration).
    """
    global _ACTIVE, _ORIGINAL_VARS
    base_url = f"http://{host}:{port}"
    for key, val in {
        "OPENAI_BASE_URL":   base_url,
        "OPENAI_API_BASE":   base_url,
        "ANTHROPIC_BASE_URL": base_url,
        "TSM_ACTIVE":        "1",
        "TSM_PROXY_HOST":    host,
        "TSM_PROXY_PORT":    str(port),
    }.items():
        _ORIGINAL_VARS[key] = os.environ.get(key)
        os.environ[key] = val
    _ACTIVE = True


def restore_env() -> None:
    """Undo activate() — restore original env vars."""
    global _ACTIVE
    for key, original in _ORIGINAL_VARS.items():
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original
    _ACTIVE = False


def is_active() -> bool:
    return _ACTIVE or os.environ.get("TSM_ACTIVE") == "1"


def run_with_tsm(
    cmd: List[str],
    host: str = "localhost",
    port: int = 8080,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a command with TSM env injected."""
    env = inject_env(host, port)
    return subprocess.run(cmd, env=env, **kwargs)


def shell_export_lines(host: str = "localhost", port: int = 8080) -> str:
    """Return shell export commands to enable TSM in the current shell."""
    base = f"http://{host}:{port}"
    lines = [
        f'export OPENAI_BASE_URL="{base}"',
        f'export OPENAI_API_BASE="{base}"',
        f'export ANTHROPIC_BASE_URL="{base}"',
        'export TSM_ACTIVE="1"',
    ]
    return "\n".join(lines)
