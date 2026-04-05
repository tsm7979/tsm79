"""
TSM Layer Router
================

REAL Poly-LLM intelligent routing with cost tracking.
"""

from typing import Dict, Any
import logging
from router.orchestrator import (
    PolyLLMOrchestrator,
    LLMRequest,
    TaskType,
    LLMProvider
)

logger = logging.getLogger(__name__)


# Global orchestrator instance with real routing
orchestrator = PolyLLMOrchestrator(
    default_provider=LLMProvider.OPENAI,
    enable_fallback=True,
    max_retries=2
)


class DecisionEngine:
    """
    REAL routing engine - uses PolyLLMOrchestrator.

    Maps TSM requests to LLM task types and gets intelligent routing.
    """

    def __init__(self):
        self.orchestrator = orchestrator

    async def select(
        self,
        input_data: str,
        risk: Dict[str, Any],
        context: Dict[str, Any],
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Select optimal target using REAL poly-LLM routing.

        Args:
            input_data: Sanitized input
            risk: Risk classification
            context: User/org context
            options: User preferences

        Returns:
            Routing decision with target and reasoning
        """
        options = options or {}

        # Extract risk tier
        risk_tier = risk.tier.value if hasattr(risk, "tier") else risk.get("tier", "low")
        requires_local = risk.requires_local_only if hasattr(risk, "requires_local_only") else False

        # Map input to task type
        task_type = self._infer_task_type(input_data, risk_tier)

        # Override to local if high risk
        if requires_local or risk_tier in ["critical", "high"]:
            return {
                "type": "model",
                "target": "local",
                "model": "llama3.2",
                "reason": f"High risk ({risk_tier}) - forced local routing",
                "estimated_cost": 0.0,
                "task_type": task_type.value
            }

        # Check for tool execution
        if "scan" in input_data.lower() or "execute" in input_data.lower():
            return {
                "type": "tool",
                "target": "security_scan",
                "reason": "Tool execution detected",
                "estimated_cost": 0.0
            }

        # Create LLM request
        request = LLMRequest(
            task_type=task_type,
            prompt=input_data,
            context=context,
            max_tokens=options.get("max_tokens", 2000),
            temperature=options.get("temperature", 0.7)
        )

        # Get routing from orchestrator
        provider, model = self.orchestrator.route(request)

        return {
            "type": "model",
            "target": provider.value,
            "model": model,
            "reason": f"Routed {task_type.value} to {provider.value}/{model}",
            "task_type": task_type.value,
            "estimated_cost": self._estimate_cost(provider, model, len(input_data))
        }

    def _infer_task_type(self, input_data: str, risk_tier: str) -> TaskType:
        """Infer task type from input text."""
        input_lower = input_data.lower()

        # Code-related
        if any(kw in input_lower for kw in ["code", "function", "class", "bug", "vulnerability", "exploit"]):
            if any(kw in input_lower for kw in ["generate", "fix", "patch", "write"]):
                return TaskType.CODE_GENERATION
            return TaskType.CODE_ANALYSIS

        # Search-related
        if any(kw in input_lower for kw in ["cve", "search", "lookup", "find", "standard"]):
            return TaskType.SEARCH

        # Summarization
        if any(kw in input_lower for kw in ["summarize", "summary", "report"]):
            return TaskType.SUMMARIZATION

        # Classification
        if any(kw in input_lower for kw in ["classify", "categorize", "type"]):
            return TaskType.CLASSIFICATION

        # Default: reasoning
        return TaskType.REASONING

    def _estimate_cost(self, provider: LLMProvider, model: str, input_len: int) -> float:
        """Estimate cost based on provider and input length."""
        if provider == LLMProvider.LOCAL:
            return 0.0

        # Rough estimate: ~4 chars per token
        tokens = input_len // 4

        # Cost per 1K tokens (average input + output)
        cost_per_1k = {
            LLMProvider.OPENAI: {"gpt-4o": 0.01, "gpt-4": 0.045, "gpt-3.5-turbo": 0.001},
            LLMProvider.ANTHROPIC: {"claude-3-sonnet": 0.009, "claude-3-opus": 0.045},
            LLMProvider.GOOGLE: {"gemini-1.5-pro": 0.003, "gemini-pro": 0.0004}
        }

        provider_costs = cost_per_1k.get(provider, {})
        rate = provider_costs.get(model, 0.01)

        return (tokens / 1000) * rate


# Global instance
decision_engine = DecisionEngine()
