# backend/src/core/llm/model_providers/base_provider.py

"""Base provider interface for all LLM integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from datetime import datetime


@dataclass
class ModelResponse:
    """Standardized response from any LLM provider."""
    
    content: str
    model: str
    provider: str
    tokens_used: int
    latency_ms: float
    metadata: Dict[str, Any]
    timestamp: datetime
    
    @property
    def cost_estimate(self) -> float:
        """Estimate cost based on tokens and model."""
        # Simplified cost estimation - can be enhanced
        cost_per_1k = {
            "gpt-4": 0.03,
            "gpt-4-turbo": 0.01,
            "gpt-3.5-turbo": 0.002,
            "claude-3-opus": 0.015,
            "claude-3-sonnet": 0.003,
            "gemini-pro": 0.00025,
        }.get(self.model, 0.001)
        
        return (self.tokens_used / 1000) * cost_per_1k


class BaseModelProvider(ABC):
    """Abstract base class for all LLM providers."""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """
        Initialize provider.
        
        Args:
            api_key: API key for the provider
            **kwargs: Additional provider-specific configuration
        """
        self.api_key = api_key
        self.config = kwargs
        self._request_count = 0
        self._total_tokens = 0
        
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> ModelResponse:
        """
        Generate text from the model.
        
        Args:
            prompt: The input prompt
            model: Specific model to use (provider-specific)
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            **kwargs: Additional provider-specific parameters
            
        Returns:
            ModelResponse with generated content
            
        Raises:
            LLMError: If generation fails
        """
        pass
    
    @abstractmethod
    async def generate_streaming(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs
    ):
        """
        Generate text with streaming response.
        
        Args:
            prompt: The input prompt
            model: Specific model to use
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            **kwargs: Additional parameters
            
        Yields:
            Chunks of generated text
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if provider is available and configured.
        
        Returns:
            True if provider can be used, False otherwise
        """
        pass
    
    def get_default_model(self) -> str:
        """Get the default model for this provider."""
        return "default"

    async def generate_with_messages(
        self,
        messages: List[Dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> "ModelResponse":
        """
        Multi-turn chat with full message history.
        Default: flatten history to a single prompt and call generate().
        Providers that natively support multi-turn should override this.
        """
        # Flatten history: system + user/assistant pairs → single prompt
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                parts.insert(0, f"[System]: {content}")
            elif role == "user":
                parts.append(f"[User]: {content}")
            elif role == "assistant":
                parts.append(f"[Assistant]: {content}")
        prompt = "\n".join(parts)
        return await self.generate(
            prompt=prompt, model=model, temperature=temperature,
            max_tokens=max_tokens, **kwargs
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get provider usage statistics."""
        return {
            "requests": self._request_count,
            "total_tokens": self._total_tokens,
            "provider": self.__class__.__name__,
        }
