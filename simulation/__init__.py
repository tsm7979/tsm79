"""
TSM Layer - Simulation
Sandbox environment for testing requests before execution.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
import time


@dataclass
class SimulationResult:
    """Result of a simulation run."""
    success: bool
    duration_ms: float
    estimated_cost: float
    warnings: list
    errors: list
    metadata: Dict


class Simulator:
    """Simulates LLM requests in a safe sandbox."""

    def __init__(self):
        self.simulation_cache: Dict[str, SimulationResult] = {}

    async def simulate_request(self, prompt: str, model: str, context: Dict = None) -> SimulationResult:
        """Simulate a request before actual execution."""
        start = time.time()
        warnings = []
        errors = []

        # Check for sensitive data
        from firewall import sanitizer
        sensitive_result = sanitizer.sanitize(prompt)
        if sensitive_result.has_sensitive:
            warnings.append(f"Contains sensitive data: {', '.join(sensitive_result.detected_types)}")

        # Estimate tokens
        estimated_tokens = len(prompt.split()) * 1.3  # Rough estimate

        # Estimate cost
        cost_per_1k_tokens = 0.002  # Example
        estimated_cost = (estimated_tokens / 1000) * cost_per_1k_tokens

        # Check policy compliance
        from policy import get_policy_engine
        policy = get_policy_engine()
        policy_check = await policy.evaluate(prompt, context or {})
        if not policy_check.get('allowed', True):
            warnings.append(f"Policy violation: {policy_check.get('reason')}")

        # Check rate limits
        if context and context.get('user_id'):
            from ratelimit import get_rate_limiter
            limiter = get_rate_limiter()
            rate_check = limiter.check_rate_limit(
                context['user_id'],
                context.get('tier', 'free'),
                tokens=int(estimated_tokens)
            )
            if not rate_check['allowed']:
                warnings.append(f"Rate limit: {rate_check['reason']}")

        duration = (time.time() - start) * 1000

        result = SimulationResult(
            success=len(errors) == 0,
            duration_ms=duration,
            estimated_cost=estimated_cost,
            warnings=warnings,
            errors=errors,
            metadata={
                'estimated_tokens': estimated_tokens,
                'model': model,
                'has_pii': len(warnings) > 0
            }
        )

        return result

    def dry_run(self, prompt: str, model: str) -> Dict:
        """Quick dry run without full simulation."""
        return {
            'prompt_length': len(prompt),
            'estimated_tokens': len(prompt.split()) * 1.3,
            'model': model,
            'would_execute': True
        }


# Global simulator
_global_simulator: Optional[Simulator] = None


def get_simulator() -> Simulator:
    """Get the global simulator."""
    global _global_simulator
    if _global_simulator is None:
        _global_simulator = Simulator()
    return _global_simulator
