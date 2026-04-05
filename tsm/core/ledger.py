"""
TSM Trust Ledger
================
Append-only, cryptographically-chained audit trail.

Every request the proxy intercepts gets a signed ledger entry:
  - SHA-256 hash over the entry content
  - Hash chained to the previous entry (tamper-evident)
  - Written to ~/.tsm/ledger.jsonl

The same concept used by `internal/trust/ledger.py` (the enterprise
version with pydantic + SOC2 compliance mapping) — implemented here
with zero external dependencies so the core stays stdlib-only.

Usage:
    from tsm.core.ledger import TrustLedger
    ledger = TrustLedger()
    ledger.log_intercept(model="gpt-4", pii_types=["SSN"], ...)
    valid, count = ledger.verify_chain()
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
from typing import Any, Dict, List, Tuple

_DEFAULT_PATH = pathlib.Path.home() / ".tsm" / "ledger.jsonl"

# Cost estimates per 1K tokens (rough, used for savings calculation)
_COST_PER_1K = {
    "gpt-4": 0.045,
    "gpt-4-turbo": 0.015,
    "gpt-3.5-turbo": 0.001,
    "claude-3-opus": 0.015,
    "claude-3-sonnet": 0.003,
}
_DEFAULT_COST_PER_1K = 0.01


class TrustLedger:
    """
    Append-only, SHA-256-chained audit ledger.

    Each entry stores:
        ts          — ISO-8601 timestamp (UTC)
        type        — entry type (currently "intercept")
        prev        — hash of the previous entry
        ...data...  — entry-specific fields
        hash        — SHA-256(canonical JSON without hash field)

    The chain starts from a genesis hash.  Calling verify_chain() walks
    the full file and confirms every hash and chain link is intact.
    """

    GENESIS = hashlib.sha256(b"tsm-genesis-v1").hexdigest()

    def __init__(self, path: pathlib.Path = _DEFAULT_PATH) -> None:
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = self._load_last_hash()

    # ── Public API ────────────────────────────────────────────────

    def log_intercept(
        self,
        model: str,
        pii_types: List[str],
        severity: str,
        routed_local: bool,
        redacted: bool,
        latency_ms: float,
        prompt_tokens: int = 0,
    ) -> str:
        """Record a proxy interception. Returns the entry hash."""
        cost_saved = 0.0
        if routed_local and prompt_tokens:
            rate = _COST_PER_1K.get(model, _DEFAULT_COST_PER_1K)
            cost_saved = round((prompt_tokens / 1000) * rate, 6)

        return self._append("intercept", {
            "model": model,
            "pii_types": pii_types,
            "severity": severity,
            "routed_local": routed_local,
            "redacted": redacted,
            "latency_ms": round(latency_ms, 1),
            "cost_saved": cost_saved,
            "prompt_tokens": prompt_tokens,
        })

    def verify_chain(self) -> Tuple[bool, int]:
        """
        Walk the full ledger and verify every hash + chain link.

        Returns:
            (is_valid, entries_checked)
        """
        if not self.path.exists():
            return True, 0

        prev_hash = self.GENESIS
        count = 0
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return False, count

                    stored = entry.pop("hash", "")
                    if entry.get("prev") != prev_hash:
                        return False, count

                    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                    computed = hashlib.sha256(canonical.encode()).hexdigest()
                    if computed != stored:
                        return False, count

                    prev_hash = stored
                    entry["hash"] = stored  # restore (non-destructive read)
                    count += 1
        except OSError:
            return False, count

        return True, count

    def entry_count(self) -> int:
        """Fast line count without loading all entries into memory."""
        if not self.path.exists():
            return 0
        try:
            with open(self.path, "rb") as f:
                return sum(1 for line in f if line.strip())
        except OSError:
            return 0

    # ── Internal ──────────────────────────────────────────────────

    def _append(self, entry_type: str, data: Dict[str, Any]) -> str:
        entry: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": entry_type,
            "prev": self._last_hash,
            **data,
        }
        canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry["hash"] = hashlib.sha256(canonical.encode()).hexdigest()

        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # don't crash the proxy if ledger write fails

        self._last_hash = entry["hash"]
        return entry["hash"]

    def _load_last_hash(self) -> str:
        """Read the last hash from disk without loading the whole file."""
        if not self.path.exists():
            return self.GENESIS
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return self.GENESIS
                # Read last 8 KB — enough for any single entry
                f.seek(max(0, size - 8192))
                chunk = f.read().decode("utf-8", errors="replace")
                lines = [l for l in chunk.split("\n") if l.strip()]
                if not lines:
                    return self.GENESIS
                last = json.loads(lines[-1])
                return last.get("hash", self.GENESIS)
        except Exception:
            return self.GENESIS
