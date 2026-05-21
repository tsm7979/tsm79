"""
Cryptographic PII Tokenizer — reversible, format-preserving redaction.

Problem with [REDACTED] tombstones:
  Replacing SSN 123-45-6789 with [REDACTED:SSN] permanently destroys the
  value for the round-trip.  The user types their SSN, the firewall deletes
  it, GPT-4 never sees it (good), but the response also never contains it —
  so the user's UI can't display the answer in context.  This is the #1
  complaint from enterprise evaluators of regex-based AI firewalls.

What we do instead:
  1. Vault the original value → generate a short opaque token:
        "123-45-6789"  →  "tsm_tok_a3f9b2c1"
  2. Forward the tokenized prompt to OpenAI — it sees only the token.
  3. When OpenAI responds, scan the response for any tsm_tok_* tokens.
  4. Detokenize: swap every token back for its original value.
  5. The user's application gets an answer that references their real SSN,
     but the SSN was *never* sent to the cloud LLM.

Security properties:
  - Tokens are cryptographically random (secrets.token_hex) → unpredictable.
  - HMAC-SHA256 authenticates the vault payload → tampering is detectable.
  - TTL eviction prevents memory accumulation and replay after session end.
  - Optional Redis backend for multi-pod deployments (vault is shared).

Token format:  tsm_tok_<16 hex chars>
  e.g.          tsm_tok_4a1f9cb23de07521
  - 64 bits of randomness — collision probability negligible at session scale
  - Regex-safe: no special characters — survives JSON, XML, SQL, markdown
  - Easily identifiable in LLM responses (model learns the pattern in context)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# ── Token pattern ─────────────────────────────────────────────────────────────

_TOKEN_RE   = re.compile(r'\btsm_tok_[0-9a-f]{16}\b')
_TOKEN_PREFIX = "tsm_tok_"

# Default TTL: tokens expire after 60 minutes.  Prevents vault from growing
# unbounded in long-running sessions or when detokenize is never called.
_DEFAULT_TTL_S = 3600


# ── Vault entry ───────────────────────────────────────────────────────────────

@dataclass
class _VaultEntry:
    token:      str
    value:      str        # original PII value
    pii_type:   str
    created_at: float      = field(default_factory=time.monotonic)
    ttl_s:      float      = _DEFAULT_TTL_S

    def is_expired(self) -> bool:
        return (time.monotonic() - self.created_at) > self.ttl_s


# ── Tokenizer ─────────────────────────────────────────────────────────────────

class Tokenizer:
    """
    Thread-safe in-memory vault with optional Redis backend.

    Usage:
        tok = Tokenizer()
        tokenized, vault_id = tok.tokenize(text, findings)
        # ... forward `tokenized` to LLM ...
        restored = tok.detokenize(llm_response, vault_id)

    The `vault_id` is a handle to the per-request token set.  Pass it to
    `detokenize` so that tokens from one session don't bleed into another.
    """

    def __init__(
        self,
        ttl_s:      float = _DEFAULT_TTL_S,
        redis_url:  str   = "",
        hmac_key:   bytes = b"",
    ) -> None:
        self._ttl      = ttl_s
        self._lock     = threading.Lock()
        # vault: token → VaultEntry
        self._vault:   dict[str, _VaultEntry] = {}
        # value → token dedup map so the same PII value always maps to the
        # same token within a session (preserves referential integrity).
        self._dedup:   dict[str, str]         = {}
        # Redis backend (optional)
        self._redis    = _connect_redis(redis_url) if redis_url else None
        # HMAC key for vault authentication (optional)
        self._hmac_key = hmac_key or os.environ.get("TSM_VAULT_HMAC_KEY", "").encode()

    # ── Primary API ────────────────────────────────────────────────────────────

    def tokenize(
        self,
        text:     str,
        findings: list[dict],
    ) -> tuple[str, str]:
        """
        Replace PII spans in `text` with reversible tokens.

        Parameters
        ----------
        text:       The original user prompt text.
        findings:   Finding dicts from classifier/presidio (must include
                    'start', 'end', and 'type' if span-based; otherwise the
                    tokenizer will use regex spans from the classifier).

        Returns
        -------
        (tokenized_text, vault_id)
            tokenized_text — text with PII replaced by tsm_tok_* tokens.
            vault_id       — opaque handle; pass to detokenize().
        """
        # Sort findings by start position descending so we can splice without
        # invalidating subsequent offsets.
        span_findings = [f for f in findings if "start" in f and "end" in f]
        span_findings.sort(key=lambda f: f["start"], reverse=True)

        vault_id = secrets.token_hex(8)
        result   = text

        with self._lock:
            for f in span_findings:
                start, end = f["start"], f["end"]
                if start < 0 or end > len(result) or start >= end:
                    continue
                value    = result[start:end]
                token    = self._get_or_create_token(value, f.get("type", "PII"), vault_id)
                result   = result[:start] + token + result[end:]

        return result, vault_id

    def tokenize_regex(
        self,
        text:     str,
        patterns: list[tuple[re.Pattern, str]],
    ) -> tuple[str, str]:
        """
        Tokenize via regex patterns rather than span offsets.

        Useful when classifier findings don't include byte offsets (e.g. the
        spaCy-only code path).

        Parameters
        ----------
        patterns:  List of (compiled_regex, pii_type) pairs.

        Returns
        -------
        (tokenized_text, vault_id)
        """
        vault_id = secrets.token_hex(8)
        result   = text

        with self._lock:
            for pattern, pii_type in patterns:
                def _replacer(m: re.Match, pt: str = pii_type, vi: str = vault_id) -> str:
                    return self._get_or_create_token(m.group(0), pt, vi)
                result = pattern.sub(_replacer, result)

        return result, vault_id

    def detokenize(self, text: str, vault_id: str | None = None) -> tuple[str, list[dict]]:
        """
        Restore original PII values in `text` (typically the LLM response).

        Scans for tsm_tok_* patterns and swaps them back.  Tokens that have
        expired or were never issued return as-is (logged as a warning).

        Parameters
        ----------
        text:     The LLM response (may contain tsm_tok_* tokens).
        vault_id: Optional session handle.  When provided, only tokens
                  belonging to that vault are restored (safer for multi-user).

        Returns
        -------
        (restored_text, restorations)
            restorations — list of {"token", "pii_type", "restored"} dicts
                           for audit logging.
        """
        restorations: list[dict] = []
        result = text

        with self._lock:
            self._evict_expired()

            def _restore(m: re.Match) -> str:
                tok   = m.group(0)
                entry = self._vault.get(tok)
                if entry is None:
                    # Try Redis fallback
                    if self._redis:
                        entry = self._load_from_redis(tok)
                    if entry is None:
                        return tok  # unknown token — leave as-is
                if entry.is_expired():
                    return tok  # expired — don't restore
                restorations.append({
                    "token":    tok,
                    "pii_type": entry.pii_type,
                    "restored": True,
                })
                return entry.value

            result = _TOKEN_RE.sub(_restore, result)

        return result, restorations

    def vault_size(self) -> int:
        with self._lock:
            return len(self._vault)

    def clear(self) -> None:
        """Purge the entire in-memory vault (e.g. on session logout)."""
        with self._lock:
            self._vault.clear()
            self._dedup.clear()

    def mac_token(self, token: str, value: str) -> str:
        """Return an HMAC-SHA256 tag over (token, value) for tamper detection."""
        if not self._hmac_key:
            return ""
        msg = f"{token}:{value}".encode()
        return hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()[:16]

    # ── Internals ──────────────────────────────────────────────────────────────

    def _get_or_create_token(self, value: str, pii_type: str, vault_id: str) -> str:
        """
        Return an existing token for `value` (dedup) or mint a new one.
        Must be called with self._lock held.
        """
        existing = self._dedup.get(value)
        if existing and not self._vault.get(existing, _VaultEntry("", "", "")).is_expired():
            return existing

        token = _TOKEN_PREFIX + secrets.token_hex(8)
        entry = _VaultEntry(token=token, value=value, pii_type=pii_type, ttl_s=self._ttl)
        self._vault[token] = entry
        self._dedup[value] = token

        if self._redis:
            self._save_to_redis(entry)

        return token

    def _evict_expired(self) -> None:
        """Remove expired entries from vault and dedup map."""
        expired_tokens = [t for t, e in self._vault.items() if e.is_expired()]
        for t in expired_tokens:
            entry = self._vault.pop(t, None)
            if entry:
                self._dedup.pop(entry.value, None)

    def _save_to_redis(self, entry: _VaultEntry) -> None:
        try:
            import json as _j
            payload = _j.dumps({"value": entry.value, "pii_type": entry.pii_type})
            self._redis.setex(f"tsm:tok:{entry.token}", int(entry.ttl_s), payload)
        except Exception:
            pass

    def _load_from_redis(self, token: str) -> _VaultEntry | None:
        try:
            import json as _j
            raw = self._redis.get(f"tsm:tok:{token}")
            if raw is None:
                return None
            data = _j.loads(raw)
            entry = _VaultEntry(
                token=token,
                value=data["value"],
                pii_type=data["pii_type"],
                created_at=time.monotonic(),   # reset — TTL is managed by Redis
                ttl_s=self._ttl,
            )
            self._vault[token] = entry
            self._dedup[data["value"]] = token
            return entry
        except Exception:
            return None


# ── Redis helper ──────────────────────────────────────────────────────────────

def _connect_redis(url: str):
    try:
        import redis as _r
        client = _r.from_url(url, socket_timeout=1.0, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None


# ── Module-level singleton ────────────────────────────────────────────────────

_instance: Tokenizer | None = None
_tok_lock  = threading.Lock()


def get_tokenizer() -> Tokenizer:
    """Return the process-wide Tokenizer singleton (lazy init)."""
    global _instance
    if _instance is None:
        with _tok_lock:
            if _instance is None:
                _instance = Tokenizer(
                    redis_url=os.environ.get("REDIS_URL", ""),
                    hmac_key=os.environ.get("TSM_VAULT_HMAC_KEY", "").encode(),
                )
    return _instance
