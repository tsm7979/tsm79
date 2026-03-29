"""
TSM Layer - Rate Limiting
Token bucket and sliding window rate limiters.
"""

import time
from typing import Dict, Optional
from dataclasses import dataclass
from collections import deque


@dataclass
class RateLimit:
    """Rate limit configuration."""
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    tokens_per_day: int


# Tier-based rate limits
RATE_LIMITS: Dict[str, RateLimit] = {
    "free": RateLimit(
        requests_per_minute=10,
        requests_per_hour=100,
        requests_per_day=1000,
        tokens_per_day=100_000
    ),
    "pro": RateLimit(
        requests_per_minute=60,
        requests_per_hour=1000,
        requests_per_day=10_000,
        tokens_per_day=1_000_000
    ),
    "enterprise": RateLimit(
        requests_per_minute=600,
        requests_per_hour=10_000,
        requests_per_day=100_000,
        tokens_per_day=10_000_000
    ),
}


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()

    def _refill(self):
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def get_wait_time(self, tokens: int = 1) -> float:
        """Get time to wait before tokens are available."""
        self._refill()
        if self.tokens >= tokens:
            return 0.0
        deficit = tokens - self.tokens
        return deficit / self.refill_rate


class SlidingWindowLimiter:
    """Sliding window rate limiter."""

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: deque = deque()

    def allow(self) -> bool:
        """Check if request is allowed."""
        now = time.time()
        cutoff = now - self.window_seconds

        # Remove old requests
        while self.requests and self.requests[0] < cutoff:
            self.requests.popleft()

        # Check limit
        if len(self.requests) < self.limit:
            self.requests.append(now)
            return True

        return False

    def get_remaining(self) -> int:
        """Get remaining requests in window."""
        now = time.time()
        cutoff = now - self.window_seconds

        while self.requests and self.requests[0] < cutoff:
            self.requests.popleft()

        return max(0, self.limit - len(self.requests))

    def get_reset_time(self) -> float:
        """Get time until window resets."""
        if not self.requests:
            return 0.0
        oldest = self.requests[0]
        return max(0.0, (oldest + self.window_seconds) - time.time())


class RateLimiter:
    """Multi-tier rate limiter."""

    def __init__(self):
        self.user_limiters: Dict[str, Dict] = {}

    def _get_limiters(self, user_id: str, tier: str) -> Dict:
        """Get or create limiters for a user."""
        if user_id not in self.user_limiters:
            limits = RATE_LIMITS.get(tier, RATE_LIMITS["free"])
            self.user_limiters[user_id] = {
                'minute': SlidingWindowLimiter(limits.requests_per_minute, 60),
                'hour': SlidingWindowLimiter(limits.requests_per_hour, 3600),
                'day': SlidingWindowLimiter(limits.requests_per_day, 86400),
                'tokens': TokenBucket(limits.tokens_per_day, limits.tokens_per_day / 86400)
            }
        return self.user_limiters[user_id]

    def check_rate_limit(self, user_id: str, tier: str = "free", tokens: int = 0) -> Dict:
        """Check if request is within rate limits."""
        limiters = self._get_limiters(user_id, tier)

        # Check request limits
        if not limiters['minute'].allow():
            return {
                'allowed': False,
                'reason': 'minute_limit_exceeded',
                'reset_seconds': limiters['minute'].get_reset_time()
            }

        if not limiters['hour'].allow():
            return {
                'allowed': False,
                'reason': 'hour_limit_exceeded',
                'reset_seconds': limiters['hour'].get_reset_time()
            }

        if not limiters['day'].allow():
            return {
                'allowed': False,
                'reason': 'day_limit_exceeded',
                'reset_seconds': limiters['day'].get_reset_time()
            }

        # Check token limit
        if tokens > 0 and not limiters['tokens'].consume(tokens):
            return {
                'allowed': False,
                'reason': 'token_limit_exceeded',
                'reset_seconds': limiters['tokens'].get_wait_time(tokens)
            }

        return {
            'allowed': True,
            'remaining': {
                'minute': limiters['minute'].get_remaining(),
                'hour': limiters['hour'].get_remaining(),
                'day': limiters['day'].get_remaining(),
            }
        }


# Global rate limiter
_global_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter
