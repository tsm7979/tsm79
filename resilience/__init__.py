"""
TSM Layer - Resilience
Circuit breakers, retry logic, and fallback strategies for high availability.
"""

import time
import asyncio
from typing import Callable, Any, Optional, Dict
from enum import Enum
from dataclasses import dataclass


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 2  # Successes to close from half-open
    timeout_seconds: int = 60  # Time before trying half-open
    window_seconds: int = 60  # Sliding window for failure counting


class CircuitBreaker:
    """Circuit breaker implementation."""

    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0
        self.opened_at = 0
        self.failures_window = []

    def _clean_window(self):
        """Remove old failures from sliding window."""
        cutoff = time.time() - self.config.window_seconds
        self.failures_window = [f for f in self.failures_window if f > cutoff]

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            # Check if timeout elapsed
            if time.time() - self.opened_at >= self.config.timeout_seconds:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
            else:
                raise CircuitBreakerError(f"Circuit breaker {self.name} is OPEN")

        try:
            # Execute function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Success
            self._on_success()
            return result

        except Exception as e:
            # Failure
            self._on_failure()
            raise e

    def _on_success(self):
        """Handle successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.failures_window = []
        elif self.state == CircuitState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)

    def _on_failure(self):
        """Handle failed call."""
        self.last_failure_time = time.time()
        self.failures_window.append(time.time())
        self._clean_window()

        if self.state == CircuitState.HALF_OPEN:
            # Failed while testing, back to open
            self.state = CircuitState.OPEN
            self.opened_at = time.time()

        elif self.state == CircuitState.CLOSED:
            if len(self.failures_window) >= self.config.failure_threshold:
                # Too many failures, open circuit
                self.state = CircuitState.OPEN
                self.opened_at = time.time()

    def get_state(self) -> Dict:
        """Get circuit breaker state."""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': len(self.failures_window),
            'last_failure_time': self.last_failure_time,
            'opened_at': self.opened_at if self.state == CircuitState.OPEN else None
        }


class CircuitBreakerError(Exception):
    """Circuit breaker is open."""
    pass


class RetryPolicy:
    """Retry policy with exponential backoff."""

    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0,
                 max_delay: float = 60.0, exponential_base: float = 2.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        delay = self.base_delay * (self.exponential_base ** attempt)
        return min(delay, self.max_delay)

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None

        for attempt in range(self.max_attempts):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            except Exception as e:
                last_exception = e

                if attempt < self.max_attempts - 1:
                    delay = self.get_delay(attempt)
                    await asyncio.sleep(delay)
                else:
                    raise last_exception


class ResilienceManager:
    """Manages circuit breakers and retry policies."""

    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_policies: Dict[str, RetryPolicy] = {}

    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(name, config)
        return self.circuit_breakers[name]

    def get_retry_policy(self, name: str, max_attempts: int = 3) -> RetryPolicy:
        """Get or create a retry policy."""
        if name not in self.retry_policies:
            self.retry_policies[name] = RetryPolicy(max_attempts=max_attempts)
        return self.retry_policies[name]

    async def call_with_resilience(self, name: str, func: Callable,
                                   use_circuit_breaker: bool = True,
                                   use_retry: bool = True,
                                   *args, **kwargs) -> Any:
        """Execute function with full resilience (circuit breaker + retry)."""
        if use_circuit_breaker and use_retry:
            circuit_breaker = self.get_circuit_breaker(name)
            retry_policy = self.get_retry_policy(name)
            return await retry_policy.execute(circuit_breaker.call, func, *args, **kwargs)

        elif use_circuit_breaker:
            circuit_breaker = self.get_circuit_breaker(name)
            return await circuit_breaker.call(func, *args, **kwargs)

        elif use_retry:
            retry_policy = self.get_retry_policy(name)
            return await retry_policy.execute(func, *args, **kwargs)

        else:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

    def get_status(self) -> Dict:
        """Get status of all circuit breakers."""
        return {
            'circuit_breakers': [cb.get_state() for cb in self.circuit_breakers.values()],
            'retry_policies': list(self.retry_policies.keys())
        }


# Global resilience manager
_global_resilience: Optional[ResilienceManager] = None


def get_resilience_manager() -> ResilienceManager:
    """Get the global resilience manager."""
    global _global_resilience
    if _global_resilience is None:
        _global_resilience = ResilienceManager()
    return _global_resilience
