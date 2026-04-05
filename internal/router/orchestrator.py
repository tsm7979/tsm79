"""
Poly-LLM Orchestrator

Routes requests to the appropriate LLM based on task type:
- ChatGPT -> reasoning & prioritization
- Gemini -> CVEs, standards, external info
- Claude -> code patterns & diffs

Integrates with the Learning System to reduce LLM calls over time.
"""

from __future__ import annotations

import uuid
import logging
import asyncio
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    """Available LLM providers."""
    
    OPENAI = "openai"           # GPT-4, GPT-3.5
    ANTHROPIC = "anthropic"     # Claude
    GOOGLE = "google"           # Gemini
    LOCAL = "local"             # TSM Runtime, vLLM
    AZURE = "azure"             # Azure OpenAI


class TaskType(str, Enum):
    """Types of LLM tasks for routing."""
    
    REASONING = "reasoning"           # Analysis, prioritization
    CODE_ANALYSIS = "code_analysis"   # Code review, patterns
    CODE_GENERATION = "code_generation"  # Fix generation
    SEARCH = "search"                 # CVE lookup, standards
    SUMMARIZATION = "summarization"   # Report generation
    CLASSIFICATION = "classification"  # Categorization


@dataclass
class LLMRequest:
    """A request to an LLM."""
    
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: TaskType = TaskType.REASONING
    prompt: str = ""
    system_prompt: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    max_tokens: int = 2000
    temperature: float = 0.7
    priority: str = "normal"  # low, normal, high, critical
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "task_type": self.task_type.value,
            "prompt": self.prompt[:100] + "..." if len(self.prompt) > 100 else self.prompt,
            "max_tokens": self.max_tokens,
            "priority": self.priority,
        }


@dataclass
class LLMResponse:
    """Response from an LLM."""
    
    request_id: str = ""
    provider: LLMProvider = LLMProvider.OPENAI
    model: str = ""
    content: str = ""
    tokens_used: int = 0
    latency_ms: float = 0
    cost: float = 0.0
    success: bool = True
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "provider": self.provider.value,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "latency_ms": self.latency_ms,
            "cost": self.cost,
            "success": self.success,
        }


class LLMProviderAdapter(ABC):
    """Abstract adapter for LLM providers."""
    
    provider: LLMProvider
    models: List[str]
    
    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """Send a completion request."""
        pass
    
    @abstractmethod
    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        """Get (input_cost, output_cost) per 1K tokens."""
        pass


async def _tsm_generate(prompt: str, system_prompt: Optional[str] = None,
                        model: str = "llama3.2",
                        timeout: float = 30.0) -> Tuple[str, int]:
    """Shared TSM Runtime call. Returns (content, token_count)."""
    from src.core.llm.tsm_inference import get_tsm_client
    full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
    result = get_tsm_client().generate(prompt=full_prompt, model=model, max_tokens=2048)
    content = result.text.strip()
    tokens = result.tokens_generated or (len(full_prompt.split()) + len(content.split()))
    return content, tokens


class OpenAIAdapter(LLMProviderAdapter):
    """OpenAI GPT adapter — routes through TSM Runtime (local-first)."""

    provider = LLMProvider.OPENAI
    models = ["gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-3.5-turbo"]

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.default_model = "gpt-4o"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        model = kwargs.get("model", self.default_model)
        start_time = datetime.now()

        try:
            sys_prompt = system_prompt or "You are a reasoning and analysis expert."
            content, tokens = await _tsm_generate(prompt, sys_prompt)

            latency = (datetime.now() - start_time).total_seconds() * 1000
            input_cost, output_cost = self.get_cost_per_token(model)
            cost = (tokens / 1000) * (input_cost + output_cost) / 2

            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                content=content, tokens_used=tokens,
                latency_ms=latency, cost=cost,
            )
        except Exception as e:
            logger.debug(f"OpenAI adapter (TSM) failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                success=False, error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        costs = {
            "gpt-4": (0.03, 0.06), "gpt-4-turbo": (0.01, 0.03),
            "gpt-4o": (0.005, 0.015), "gpt-3.5-turbo": (0.0005, 0.0015),
        }
        return costs.get(model, (0.01, 0.03))


class AnthropicAdapter(LLMProviderAdapter):
    """Anthropic Claude adapter — routes through TSM Runtime (local-first)."""

    provider = LLMProvider.ANTHROPIC
    models = ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"]

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.default_model = "claude-3-sonnet"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        model = kwargs.get("model", self.default_model)
        start_time = datetime.now()

        try:
            sys_prompt = system_prompt or "You are a code security expert. Analyze code for vulnerabilities."
            content, tokens = await _tsm_generate(prompt, sys_prompt)

            latency = (datetime.now() - start_time).total_seconds() * 1000
            input_cost, output_cost = self.get_cost_per_token(model)
            cost = (tokens / 1000) * (input_cost + output_cost) / 2

            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                content=content, tokens_used=tokens,
                latency_ms=latency, cost=cost,
            )
        except Exception as e:
            logger.debug(f"Anthropic adapter (TSM) failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                success=False, error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        costs = {
            "claude-3-opus": (0.015, 0.075), "claude-3-sonnet": (0.003, 0.015),
            "claude-3-haiku": (0.00025, 0.00125),
        }
        return costs.get(model, (0.003, 0.015))


class GeminiAdapter(LLMProviderAdapter):
    """Google Gemini adapter — routes through TSM Runtime (local-first)."""

    provider = LLMProvider.GOOGLE
    models = ["gemini-pro", "gemini-ultra", "gemini-1.5-pro"]

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.default_model = "gemini-1.5-pro"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        model = kwargs.get("model", self.default_model)
        start_time = datetime.now()

        try:
            sys_prompt = system_prompt or "You are a search and CVE lookup expert."
            content, tokens = await _tsm_generate(prompt, sys_prompt)

            latency = (datetime.now() - start_time).total_seconds() * 1000
            input_cost, output_cost = self.get_cost_per_token(model)
            cost = (tokens / 1000) * (input_cost + output_cost) / 2

            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                content=content, tokens_used=tokens,
                latency_ms=latency, cost=cost,
            )
        except Exception as e:
            logger.debug(f"Gemini adapter (TSM) failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                success=False, error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        costs = {
            "gemini-pro": (0.00025, 0.0005), "gemini-ultra": (0.0025, 0.0075),
            "gemini-1.5-pro": (0.00125, 0.005),
        }
        return costs.get(model, (0.00125, 0.005))


class LocalLLMAdapter(LLMProviderAdapter):
    """Local LLM adapter (TSM Runtime)."""

    provider = LLMProvider.LOCAL
    models = ["llama3.2", "mistral", "codellama", "phi"]

    def __init__(self):
        self.default_model = "llama3.2"

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        model = kwargs.get("model", self.default_model)
        start_time = datetime.now()

        try:
            content, tokens = await _tsm_generate(
                prompt, system_prompt, model=model
            )
            latency = (datetime.now() - start_time).total_seconds() * 1000

            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                content=content, tokens_used=tokens,
                latency_ms=latency, cost=0.0,
            )
        except Exception as e:
            logger.debug(f"Local LLM adapter failed: {e}")
            return LLMResponse(
                request_id=kwargs.get("request_id", ""),
                provider=self.provider, model=model,
                success=False, error=str(e),
            )

    def get_cost_per_token(self, model: str) -> Tuple[float, float]:
        return (0.0, 0.0)


@dataclass
class RoutingRule:
    """Rule for routing requests to providers."""
    
    name: str
    task_types: List[TaskType]
    provider: LLMProvider
    model: str
    priority: int = 0  # Higher = more preferred
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, request: LLMRequest) -> bool:
        """Check if this rule matches the request."""
        if request.task_type not in self.task_types:
            return False
        
        # Check conditions
        for key, value in self.conditions.items():
            if request.context.get(key) != value:
                return False
        
        return True


class PolyLLMOrchestrator(BaseModel):
    """
    Poly-LLM Orchestrator.
    
    Routes requests to the most appropriate LLM based on task type:
    - ChatGPT: Reasoning, analysis, prioritization
    - Gemini: External search, CVE lookup, standards
    - Claude: Code analysis, fix generation
    - Local: Cost-sensitive or private tasks
    
    Integrates with the Learning System to reduce usage over time.
    
    Attributes:
        name: Orchestrator identifier
        default_provider: Fallback provider
        enable_fallback: Try backup providers on failure
        max_retries: Max retry attempts
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    name: str = Field(default="poly_llm_orchestrator")
    default_provider: LLMProvider = Field(default=LLMProvider.OPENAI)
    enable_fallback: bool = Field(default=True)
    max_retries: int = Field(default=2)
    
    on_request: Optional[Callable[[LLMRequest], None]] = Field(default=None)
    on_response: Optional[Callable[[LLMResponse], None]] = Field(default=None)
    
    _adapters: Dict[LLMProvider, LLMProviderAdapter] = {}
    _routing_rules: List[RoutingRule] = []
    _request_history: List[LLMRequest] = []
    _response_history: List[LLMResponse] = []
    _total_cost: float = 0.0
    _total_tokens: int = 0
    
    def __init__(self, **data: Any):
        super().__init__(**data)
        self._adapters = {}
        self._routing_rules = []
        self._request_history = []
        self._response_history = []
        self._total_cost = 0.0
        self._total_tokens = 0
        
        # Initialize default adapters
        self._adapters = {
            LLMProvider.OPENAI: OpenAIAdapter(),
            LLMProvider.ANTHROPIC: AnthropicAdapter(),
            LLMProvider.GOOGLE: GeminiAdapter(),
            LLMProvider.LOCAL: LocalLLMAdapter(),
        }
        
        # Default routing rules
        self._routing_rules = [
            RoutingRule(
                name="reasoning_to_gpt",
                task_types=[TaskType.REASONING, TaskType.CLASSIFICATION],
                provider=LLMProvider.OPENAI,
                model="gpt-4o",
                priority=10,
            ),
            RoutingRule(
                name="code_to_claude",
                task_types=[TaskType.CODE_ANALYSIS, TaskType.CODE_GENERATION],
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-sonnet",
                priority=10,
            ),
            RoutingRule(
                name="search_to_gemini",
                task_types=[TaskType.SEARCH],
                provider=LLMProvider.GOOGLE,
                model="gemini-1.5-pro",
                priority=10,
            ),
            RoutingRule(
                name="summary_to_local",
                task_types=[TaskType.SUMMARIZATION],
                provider=LLMProvider.LOCAL,
                model="llama3",
                priority=5,
            ),
        ]
    
    def add_adapter(self, provider: LLMProvider, adapter: LLMProviderAdapter) -> None:
        """Add or replace a provider adapter."""
        self._adapters[provider] = adapter
    
    def add_routing_rule(self, rule: RoutingRule) -> None:
        """Add a routing rule."""
        self._routing_rules.append(rule)
        self._routing_rules.sort(key=lambda r: r.priority, reverse=True)
    
    def route(self, request: LLMRequest) -> Tuple[LLMProvider, str]:
        """
        Route a request to the appropriate provider and model.
        
        Returns:
            Tuple of (provider, model)
        """
        for rule in self._routing_rules:
            if rule.matches(request):
                logger.debug(f"Routing via rule: {rule.name}")
                return (rule.provider, rule.model)
        
        # Default fallback
        return (self.default_provider, "gpt-4o")
    
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """
        Send a completion request to the appropriate LLM.
        
        Args:
            request: The LLM request
            
        Returns:
            LLMResponse from the selected provider
        """
        self._request_history.append(request)
        
        if self.on_request:
            self.on_request(request)
        
        # Route the request
        provider, model = self.route(request)
        
        logger.info(f"Routing {request.task_type.value} to {provider.value}/{model}")
        
        # Get adapter
        adapter = self._adapters.get(provider)
        if not adapter:
            return LLMResponse(
                request_id=request.request_id,
                success=False,
                error=f"No adapter for provider: {provider.value}",
            )
        
        # Send request with retries
        response = None
        for attempt in range(self.max_retries + 1):
            response = await adapter.complete(
                prompt=request.prompt,
                system_prompt=request.system_prompt,
                model=model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                request_id=request.request_id,
            )
            
            if response.success:
                break
            
            if attempt < self.max_retries and self.enable_fallback:
                # Try fallback provider
                fallback = self._get_fallback_provider(provider)
                if fallback:
                    logger.warning(f"Falling back from {provider.value} to {fallback.value}")
                    adapter = self._adapters.get(fallback)
                    if not adapter:
                        break
        
        # Track metrics
        self._response_history.append(response)
        self._total_cost += response.cost
        self._total_tokens += response.tokens_used
        
        if self.on_response:
            self.on_response(response)
        
        return response
    
    def _get_fallback_provider(self, failed: LLMProvider) -> Optional[LLMProvider]:
        """Get a fallback provider when one fails."""
        fallback_order = [
            LLMProvider.OPENAI,
            LLMProvider.ANTHROPIC,
            LLMProvider.GOOGLE,
            LLMProvider.LOCAL,
        ]
        
        for provider in fallback_order:
            if provider != failed and provider in self._adapters:
                return provider
        
        return None
    
    async def batch_complete(
        self,
        requests: List[LLMRequest],
    ) -> List[LLMResponse]:
        """Send multiple requests concurrently."""
        tasks = [self.complete(req) for req in requests]
        return await asyncio.gather(*tasks)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        provider_counts = {}
        for response in self._response_history:
            provider = response.provider.value
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        return {
            "total_requests": len(self._request_history),
            "total_responses": len(self._response_history),
            "success_rate": sum(1 for r in self._response_history if r.success) / max(len(self._response_history), 1),
            "total_tokens": self._total_tokens,
            "total_cost": self._total_cost,
            "requests_by_provider": provider_counts,
            "avg_latency_ms": sum(r.latency_ms for r in self._response_history) / max(len(self._response_history), 1),
        }
    
    def get_cost_breakdown(self) -> Dict[str, float]:
        """Get cost breakdown by provider."""
        costs = {}
        for response in self._response_history:
            provider = response.provider.value
            costs[provider] = costs.get(provider, 0) + response.cost
        return costs


# Convenience functions
def create_reasoning_request(
    prompt: str,
    context: Optional[Dict[str, Any]] = None,
) -> LLMRequest:
    """Create a reasoning request (routes to GPT)."""
    return LLMRequest(
        task_type=TaskType.REASONING,
        prompt=prompt,
        context=context or {},
        system_prompt="You are a security reasoning expert. Analyze the issue and provide clear recommendations.",
    )


def create_code_analysis_request(
    prompt: str,
    code: str,
) -> LLMRequest:
    """Create a code analysis request (routes to Claude)."""
    return LLMRequest(
        task_type=TaskType.CODE_ANALYSIS,
        prompt=prompt,
        context={"code": code},
        system_prompt="You are a code security expert. Analyze the code for vulnerabilities and suggest fixes.",
    )


def create_search_request(
    query: str,
) -> LLMRequest:
    """Create a search request (routes to Gemini)."""
    return LLMRequest(
        task_type=TaskType.SEARCH,
        prompt=query,
        system_prompt="Search for relevant CVEs, security standards, and best practices.",
    )
