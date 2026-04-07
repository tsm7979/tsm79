"""
@tsm.protect decorator and scan() context manager.
"""
from __future__ import annotations

import functools
import inspect
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Generator

from sdk.client import TSMClient, DetectResult


# ── Shared default client (lazily created) ────────────────────────────────────

_default_client: TSMClient | None = None

def _client() -> TSMClient:
    global _default_client
    if _default_client is None:
        _default_client = TSMClient()
    return _default_client


# ── Public types ──────────────────────────────────────────────────────────────

@dataclass
class TSMResult:
    risk_score:   float
    action:       str
    pii_types:    list[str]
    severity:     str
    is_clean:     bool
    is_blocked:   bool
    redacted_text: str   # first user message after redaction
    policy_rule:  str | None
    latency_ms:   float

    @classmethod
    def from_detect(cls, result: DetectResult) -> "TSMResult":
        msgs = result.redacted_body.get("messages", [])
        redacted = next((m.get("content", "") for m in msgs if m.get("role") == "user"), "")
        return cls(
            risk_score=result.risk_score,
            action=result.action,
            pii_types=result.pii_types,
            severity=result.severity,
            is_clean=result.action == "allow",
            is_blocked=result.action == "block",
            redacted_text=redacted,
            policy_rule=result.policy_rule,
            latency_ms=result.latency_ms,
        )


class TSMBlockedError(Exception):
    """Raised when a request is blocked by TSM policy and on_block='raise'."""
    def __init__(self, result: TSMResult) -> None:
        self.result = result
        super().__init__(
            f"[TSM] Request blocked — policy: {result.policy_rule}. "
            f"PII detected: {', '.join(result.pii_types)}. "
            f"Risk score: {result.risk_score}"
        )


# ── scan_text helper ──────────────────────────────────────────────────────────

def scan_text(
    text: str,
    model: str = "gpt-3.5-turbo",
    org_id: str = "default",
    user_role: str | None = None,
) -> TSMResult:
    """Scan a text string and return a TSMResult. Synchronous."""
    c      = TSMClient(org_id=org_id)
    result = c.detect_text(text, model=model, user_role=user_role)
    return TSMResult.from_detect(result)


# ── scan() context manager ────────────────────────────────────────────────────

@contextmanager
def scan(
    text: str,
    model: str = "gpt-3.5-turbo",
    org_id: str = "default",
) -> Generator[TSMResult, None, None]:
    """
    Context manager that scans text before the block runs.

    Usage:
        with tsm.scan(user_input) as r:
            if r.is_blocked:
                return "Request blocked by security policy."
            response = call_ai(r.redacted_text)
    """
    result = scan_text(text, model=model, org_id=org_id)
    yield result


# ── @protect decorator ────────────────────────────────────────────────────────

def protect(
    fn: Callable | None = None,
    *,
    org_id:   str = "default",
    on_block: str = "raise",        # "raise" | "return_none" | "passthrough"
    user_role: str | None = None,
    model:    str = "gpt-3.5-turbo",
):
    """
    Decorator that intercepts the first string argument of the wrapped function,
    scans it for PII/secrets, and either:
      - allows the call (with redacted text if needed)
      - blocks it (raises TSMBlockedError or returns None)

    Usage:
        @tsm.protect
        def call_ai(prompt: str) -> str:
            return openai_client.chat(prompt)

        @tsm.protect(org_id="acme", on_block="return_none")
        def safe_chat(message: str) -> str | None:
            ...
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find the first string argument (positional or named)
            text: str | None = None
            new_args = list(args)

            # Check positional args
            sig    = inspect.signature(f)
            params = list(sig.parameters.keys())
            for i, (param, val) in enumerate(zip(params, args)):
                if isinstance(val, str):
                    text = val
                    text_arg_idx = i
                    break

            # Fall back to keyword args
            if text is None:
                for k, v in kwargs.items():
                    if isinstance(v, str):
                        text = v
                        break

            if text is None:
                # Can't find a string to scan — pass through
                return f(*args, **kwargs)

            result = scan_text(text, model=model, org_id=org_id, user_role=user_role)

            if result.is_blocked:
                if on_block == "raise":
                    raise TSMBlockedError(result)
                if on_block == "return_none":
                    return None
                # passthrough — call with original
                return f(*args, **kwargs)

            # Replace the string arg with redacted version if needed
            if not result.is_clean and result.redacted_text:
                if 'text_arg_idx' in dir():
                    new_args[text_arg_idx] = result.redacted_text  # type: ignore[index]

            return f(*new_args, **kwargs)

        return wrapper

    # Support both @tsm.protect and @tsm.protect(...)
    if fn is not None:
        return decorator(fn)
    return decorator
