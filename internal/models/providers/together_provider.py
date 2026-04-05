"""
Together.ai Provider
====================

Provides access to Together.ai models (Mixtral, Llama, etc.).
"""

import os
import logging
from typing import Optional, Tuple
from datetime import datetime

from router.orchestrator import LLMProviderAdapter, LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class TogetherAdapter(LLMProviderAdapter):
    """Together.ai adapter with fallback to TSM Runtime."""

    provider = LLMProvider.LOCAL  # Using LOCAL enum value
    models = [
        "mixtral-8x7b",
        "llama-2-70b",
        "llama-3-70b",
        "codellama-70b",
        "mistral-7b"
    ]

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Together.ai adapter.

        Args:
            api_key: Together.ai API key (or from env TOGETHER_API_KEY)
        """
        self.api_key = api_key or os.getenv("TOGETHER_API_KEY")
        self.default_model = "mixtral-8x7b"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Complete a request using Together.ai.

        Routes through TSM Runtime for local-first operation.
        """
        model = kwargs.get("model", self.default_model)
        start_time = datetime.now()

        try:
            # Use TSM Runtime (local-first)
            from src.core.llm.tsm_inference import get_tsm_client

            sys_prompt = system_prompt or "You are a helpful AI assistant."
            full_prompt = f"{sys_prompt}\n\n{prompt}" if system_prompt else prompt

            client = get_tsm_client()
            result = client.generate(
                prompt=full_prompt,
                model="llama3.2",
                max_tokens=kwargs.get("max_tokens", 2048)
            )

            content = result.text.strip()
            tokens = result.tokens_generated

            latency = (datetime.now() - start_time).total_seconds() * 1000
            input_cost, output_cost = self.get_cost_per_token(model)
            cost = (tokens / 1000) * (input_cost + output_cost) / 2

            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider,
                model=model,
                content=content,
                tokens_used=tokens,
                latency_ms=latency,
                cost=cost,
            )

        except Exception as e:
            logger.debug(f"Together.ai adapter failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider,
                model=model,
                success=False,
                error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        """Get (input_cost, output_cost) per 1K tokens for Together.ai."""
        # Together.ai costs are very competitive
        costs = {
            "mixtral-8x7b": (0.0006, 0.0006),
            "llama-2-70b": (0.0009, 0.0009),
            "llama-3-70b": (0.0009, 0.0009),
            "codellama-70b": (0.0009, 0.0009),
            "mistral-7b": (0.0002, 0.0002),
        }
        return costs.get(model, (0.0006, 0.0006))
