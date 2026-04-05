"""
Azure OpenAI Provider
=====================

Provides access to Azure OpenAI Service models.
"""

import os
import logging
from typing import Optional, Tuple
from datetime import datetime

from router.orchestrator import LLMProviderAdapter, LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class AzureOpenAIAdapter(LLMProviderAdapter):
    """Azure OpenAI adapter with fallback to TSM Runtime."""

    provider = LLMProvider.AZURE
    models = ["gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-35-turbo"]

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        api_version: str = "2024-02-15-preview"
    ):
        """
        Initialize Azure OpenAI adapter.

        Args:
            api_key: Azure OpenAI API key (or from env AZURE_OPENAI_KEY)
            endpoint: Azure OpenAI endpoint (or from env AZURE_OPENAI_ENDPOINT)
            api_version: API version to use
        """
        self.api_key = api_key or os.getenv("AZURE_OPENAI_KEY")
        self.endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT")
        self.api_version = api_version
        self.default_model = "gpt-4o"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Complete a request using Azure OpenAI.

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
                model="llama3.2",  # TSM Runtime model
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
            logger.debug(f"Azure OpenAI adapter failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider,
                model=model,
                success=False,
                error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        """Get (input_cost, output_cost) per 1K tokens for Azure."""
        # Azure costs are similar to OpenAI
        costs = {
            "gpt-4": (0.03, 0.06),
            "gpt-4-turbo": (0.01, 0.03),
            "gpt-4o": (0.005, 0.015),
            "gpt-35-turbo": (0.0005, 0.0015),
        }
        return costs.get(model, (0.01, 0.03))
