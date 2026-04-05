"""
Groq Provider
=============

Provides access to Groq's ultra-fast LLM inference (Mixtral, Llama).
Known for extremely low latency.
"""

import os
import logging
from typing import Optional, Tuple
from datetime import datetime

from router.orchestrator import LLMProviderAdapter, LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class GroqAdapter(LLMProviderAdapter):
    """Groq adapter with fallback to TSM Runtime."""

    provider = LLMProvider.LOCAL  # Using LOCAL enum value
    models = [
        "mixtral-8x7b-32768",
        "llama2-70b-4096",
        "llama3-70b-8192",
        "gemma-7b-it"
    ]

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Groq adapter.

        Args:
            api_key: Groq API key (or from env GROQ_API_KEY)
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.default_model = "mixtral-8x7b-32768"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Complete a request using Groq.

        Routes through TSM Runtime for local-first operation.
        Groq is known for ultra-low latency (often <100ms).
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
            logger.debug(f"Groq adapter failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider,
                model=model,
                success=False,
                error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        """Get (input_cost, output_cost) per 1K tokens for Groq."""
        # Groq has very competitive pricing (often free tier available)
        costs = {
            "mixtral-8x7b-32768": (0.00027, 0.00027),
            "llama2-70b-4096": (0.00070, 0.00080),
            "llama3-70b-8192": (0.00059, 0.00079),
            "gemma-7b-it": (0.00010, 0.00010),
        }
        return costs.get(model, (0.0003, 0.0003))
