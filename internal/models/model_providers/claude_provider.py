# backend/src/core/llm/model_providers/claude_provider.py
"""
Claude-compatible provider — SOVEREIGN LOCAL MODE.

Routes all requests through the local TSM/Ollama inference endpoint.
No Anthropic API key or SDK is required.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from src.utils.errors import LLMError
from gateway.base_provider import BaseModelProvider, ModelResponse

_LOCAL_BASE  = os.getenv("TSM_INFERENCE_URL", "http://localhost:11434")
_CHAT_URL    = f"{_LOCAL_BASE}/v1/chat/completions"
_TIMEOUT     = httpx.Timeout(connect=5.0, read=120.0, write=None, pool=5.0)
_DEFAULT_MODEL = os.getenv("LOCAL_LLM_MODEL", "llama3")


class ClaudeProvider(BaseModelProvider):
    """
    Local inference provider masquerading as Claude.
    All calls are forwarded to the Ollama-compatible local server.
    The API interface (method signatures) is preserved for drop-in compatibility.
    """

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key, **kwargs)
        # api_key intentionally ignored — not needed for local inference
        self._base_url = os.getenv("TSM_INFERENCE_URL", "http://localhost:11434")
        self._chat_url = f"{self._base_url}/v1/chat/completions"

    def is_available(self) -> bool:
        """Local provider is always available (no cloud key needed)."""
        return True

    def get_default_model(self) -> str:
        return _DEFAULT_MODEL

    async def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    self._chat_url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                )
                if resp.status_code != 200:
                    raise LLMError(f"Local LLM HTTP {resp.status_code}: {resp.text[:300]}")
                return resp.json()
        except httpx.TimeoutException as e:
            raise LLMError(f"Local LLM timed out: {e}")
        except httpx.RequestError as e:
            raise LLMError(
                f"Local LLM unreachable at {self._chat_url}. Is Ollama running? Error: {e}"
            )

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> ModelResponse:
        """Generate using local inference (previously Anthropic Claude)."""
        model = model or self.get_default_model()
        start_time = time.time()

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        data = await self._post(payload)

        latency_ms = (time.time() - start_time) * 1000
        choice = data["choices"][0]
        content = choice["message"].get("content") or ""
        usage = data.get("usage", {})
        tokens_used = usage.get("total_tokens", 0)

        self._request_count += 1
        self._total_tokens += tokens_used

        return ModelResponse(
            content=content,
            model=model,
            provider="local_llm",
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            metadata={
                "finish_reason": choice.get("finish_reason"),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "endpoint": self._chat_url,
            },
            timestamp=datetime.utcnow(),
        )

    async def generate_streaming(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ):
        """Stream tokens from local inference endpoint."""
        model = model or self.get_default_model()
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "stream": True,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                async with client.stream(
                    "POST",
                    self._chat_url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        body = await response.aread()
                        raise LLMError(f"Local LLM stream HTTP {response.status_code}: {body[:200]}")
                    async for line in response.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        raw = line[6:].strip()
                        if raw == "[DONE]":
                            break
                        try:
                            chunk = json.loads(raw)
                            delta = chunk["choices"][0]["delta"]
                            text = delta.get("content")
                            if text:
                                yield text
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
        except httpx.HTTPStatusError as e:
            raise LLMError(f"Local LLM streaming error: {e.response.status_code}")
