"""
Pluggable state backends for behavioral analysis and correlation engine.

InMemoryBackend  — process-local, thread-safe, zero deps (default)
RedisBackend     — distributed, shared across pods via sorted sets

Redis data model for sliding windows:
  Key:    "{prefix}:{org_key}"
  Score:  Unix timestamp (float)
  Member: JSON-encoded event payload (unique by adding a random nonce)

Atomic operations:
  record() → ZREMRANGEBYSCORE (trim stale) + ZADD (new event) + EXPIRE (ttl)
  query()  → ZRANGEBYSCORE (window)
  count()  → ZCOUNT (window)

All Redis operations are fail-open: a RedisError degrades to returning empty
state rather than blocking the request pipeline.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any


# ── Abstract interface ────────────────────────────────────────────────────────

class StateBackend(ABC):
    """Abstract sliding-window state storage."""

    @abstractmethod
    def record(self, key: str, payload: dict, window_secs: float, ttl_secs: float = 0) -> None:
        """Record an event at now under `key`, evicting entries older than `window_secs`."""

    @abstractmethod
    def query(self, key: str, window_secs: float) -> list[dict]:
        """Return all events within the last `window_secs` seconds for `key`."""

    @abstractmethod
    def count(self, key: str, window_secs: float) -> int:
        """Return event count within the last `window_secs` seconds for `key`."""

    @abstractmethod
    def keys_matching(self, prefix: str) -> list[str]:
        """Return all stored keys with the given prefix (for stats/eviction)."""


# ── In-memory backend ─────────────────────────────────────────────────────────

class InMemoryBackend(StateBackend):
    """
    Thread-safe in-memory backend. Events are stored as (timestamp, payload)
    tuples in a per-key list. Stale events are trimmed on every record() and
    query() call. LRU eviction fires when key count hits max_keys.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        # key → list of (monotonic_ts, payload)
        self._data: dict[str, list[tuple[float, dict]]] = {}
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, key: str, payload: dict, window_secs: float, ttl_secs: float = 0) -> None:
        now = time.monotonic()
        cutoff = now - window_secs
        with self._lock:
            if key not in self._data:
                if len(self._data) >= self._max_keys:
                    self._evict_lru()
                self._data[key] = []
            # Trim stale events
            self._data[key] = [(ts, p) for ts, p in self._data[key] if ts >= cutoff]
            self._data[key].append((now, payload))
            self._last_seen[key] = now

    def query(self, key: str, window_secs: float) -> list[dict]:
        now = time.monotonic()
        cutoff = now - window_secs
        with self._lock:
            return [p for ts, p in self._data.get(key, []) if ts >= cutoff]

    def count(self, key: str, window_secs: float) -> int:
        return len(self.query(key, window_secs))

    def keys_matching(self, prefix: str) -> list[str]:
        with self._lock:
            return [k for k in self._data if k.startswith(prefix)]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _evict_lru(self) -> None:
        """Drop the oldest 10% of keys. Must be called with _lock held."""
        n = max(1, self._max_keys // 10)
        oldest = sorted(self._last_seen.items(), key=lambda kv: kv[1])[:n]
        for k, _ in oldest:
            self._data.pop(k, None)
            self._last_seen.pop(k, None)


# ── Redis backend ─────────────────────────────────────────────────────────────

class RedisBackend(StateBackend):
    """
    Distributed sliding-window backend using Redis sorted sets.

    Each logical key maps to a Redis sorted set:
      Redis key  : "{key_prefix}:{key}"
      Score      : Unix wall-clock timestamp (float)
      Member     : JSON string with a random nonce to guarantee uniqueness

    Record pipeline (atomic via MULTI/EXEC on single shard):
      1. ZREMRANGEBYSCORE — evict events older than window
      2. ZADD            — insert new event
      3. EXPIRE          — refresh TTL to avoid orphaned keys

    This backend is fail-open: any RedisError returns empty state rather than
    propagating an exception into the detection pipeline.

    Requires: redis-py >= 4.0 (pip install redis)
    """

    def __init__(self, redis_url: str, key_prefix: str = "tsm:state") -> None:
        try:
            import redis as _redis
        except ImportError as exc:
            raise ImportError(
                "redis-py is required for RedisBackend. Install it with: pip install redis"
            ) from exc

        self._redis = _redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        self._prefix = key_prefix
        # Validate connectivity at construction time — fail fast
        self._redis.ping()

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, key: str, payload: dict, window_secs: float, ttl_secs: float = 0) -> None:
        import redis as _redis
        fk  = self._full_key(key)
        now = time.time()
        effective_ttl = int(ttl_secs) if ttl_secs > 0 else int(window_secs + 60)
        # Embed a nonce so two simultaneous identical payloads produce unique members
        member_payload = {**payload, "_n": uuid.uuid4().hex[:8]}
        member = json.dumps(member_payload, separators=(",", ":"), sort_keys=True)
        try:
            pipe = self._redis.pipeline(transaction=False)
            pipe.zremrangebyscore(fk, "-inf", now - window_secs)
            pipe.zadd(fk, {member: now})
            pipe.expire(fk, effective_ttl)
            pipe.execute()
        except _redis.RedisError:
            # Fail-open: behavioral/correlation analysis is advisory
            pass

    def query(self, key: str, window_secs: float) -> list[dict]:
        import redis as _redis
        fk  = self._full_key(key)
        now = time.time()
        try:
            members = self._redis.zrangebyscore(fk, now - window_secs, "+inf")
            results = []
            for m in members:
                try:
                    d = json.loads(m)
                    d.pop("_n", None)  # strip nonce before returning
                    results.append(d)
                except json.JSONDecodeError:
                    pass
            return results
        except _redis.RedisError:
            return []

    def count(self, key: str, window_secs: float) -> int:
        import redis as _redis
        fk  = self._full_key(key)
        now = time.time()
        try:
            return self._redis.zcount(fk, now - window_secs, "+inf")
        except _redis.RedisError:
            return 0

    def keys_matching(self, prefix: str) -> list[str]:
        import redis as _redis
        full_prefix = f"{self._prefix}:{prefix}"
        try:
            cursor  = 0
            results: list[str] = []
            while True:
                cursor, batch = self._redis.scan(cursor, match=f"{full_prefix}*", count=200)
                results.extend(batch)
                if cursor == 0:
                    break
            return results
        except _redis.RedisError:
            return []

    # ── Internal ──────────────────────────────────────────────────────────────

    def _full_key(self, key: str) -> str:
        return f"{self._prefix}:{key}"


# ── Factory ───────────────────────────────────────────────────────────────────

def create_backend(redis_url: str | None = None) -> StateBackend:
    """
    Return a RedisBackend when a Redis URL is available, otherwise InMemoryBackend.

    Priority:
      1. Explicit `redis_url` argument
      2. REDIS_URL environment variable
      3. InMemoryBackend fallback

    If Redis is configured but unreachable, logs a warning to stderr and falls
    back to InMemoryBackend so the service stays operational.
    """
    url = redis_url or os.environ.get("REDIS_URL", "").strip()
    if url:
        try:
            backend = RedisBackend(url)
            return backend
        except ImportError as exc:
            print(f"[TSM] WARN: {exc} — falling back to in-memory state.", file=sys.stderr)
        except Exception as exc:
            print(
                f"[TSM] WARN: Redis at {url!r} unreachable ({exc!r}) — "
                "falling back to in-memory state. Behavioral analysis will not be "
                "shared across pods.",
                file=sys.stderr,
            )
    return InMemoryBackend()
