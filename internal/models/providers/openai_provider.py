# backend/src/core/llm/model_providers/openai_provider.py
"""
OpenAI-compatible provider — SOVEREIGN LOCAL MODE.

Routes all requests through the local TSM inference endpoint (Ollama-compatible).
No external OpenAI API calls are made. The OpenAI-compatible REST schema is used
to talk to the local model server, so zero SDK dependencies are needed.

Local inference server:  TSM_INFERENCE_URL  (default: http://localhost:11434)
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from utils.errors import LLMError
from .base_provider import BaseModelProvider, ModelResponse

# ── Local endpoint (Ollama-compatible OpenAI schema) ──────────────────────────
_LOCAL_BASE  = os.getenv("TSM_INFERENCE_URL", "http://localhost:11434")
_CHAT_URL    = f"{_LOCAL_BASE}/v1/chat/completions"
_CONNECT_TO  = 5.0
_READ_TO     = 120.0
_TIMEOUT     = httpx.Timeout(connect=_CONNECT_TO, read=_READ_TO, write=None, pool=5.0)

_DEFAULT_MODEL = os.getenv("LOCAL_LLM_MODEL", "llama3")


def _headers() -> Dict[str, str]:
    return {"Content-Type": "application/json"}


class OpenAIProvider(BaseModelProvider):
    """
    Local inference provider using the OpenAI-compatible REST schema.

    Talks to the local Ollama / TSM inference server.  All callers that
    previously used the OpenAI SDK continue to work unchanged because the
    REST contract is identical (chat/completions format).

    Supports:
    - Single-turn generation  (generate)
    - Multi-turn chat history (generate_with_messages)
    - Tool/function calling   (generate_with_tools)
    - Streaming               (generate_streaming)
    """

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key, **kwargs)
        # api_key is ignored — local server needs none
        self._base_url = os.getenv("TSM_INFERENCE_URL", "http://localhost:11434")
        self._chat_url = f"{self._base_url}/v1/chat/completions"

    # ── Availability ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Always True — we never need an API key for local inference."""
        return True

    def get_default_model(self) -> str:
        return _DEFAULT_MODEL

    # ── Internal: raw POST ────────────────────────────────────────────────────

    async def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Direct POST to local /v1/chat/completions — raises LLMError on failure."""
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    self._chat_url,
                    headers=_headers(),
                    json=payload,
                )
                if resp.status_code != 200:
                    raise LLMError(
                        f"Local LLM HTTP {resp.status_code}: {resp.text[:300]}"
                    )
                return resp.json()
        except httpx.TimeoutException as e:
            raise LLMError(f"Local LLM request timed out: {e}")
        except httpx.RequestError as e:
            raise LLMError(
                f"Local LLM unreachable at {self._chat_url}. "
                f"Is Ollama running? Error: {e}"
            )

    # ── Single-turn generation ────────────────────────────────────────────────

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        system: Optional[str] = None,
        **kwargs,
    ) -> ModelResponse:
        """Single-turn: wraps prompt in a user message."""
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.generate_with_messages(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    # ── Multi-turn chat ───────────────────────────────────────────────────────

    async def generate_with_messages(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> ModelResponse:
        """Multi-turn: accepts full history in OpenAI message format."""
        model = model or self.get_default_model()
        t0 = time.time()

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        data = await self._post(payload)

        latency_ms = (time.time() - t0) * 1000
        choice = data["choices"][0]
        content = choice["message"].get("content") or ""
        usage = data.get("usage", {})
        tokens = usage.get("total_tokens", 0)

        self._request_count += 1
        self._total_tokens += tokens

        return ModelResponse(
            content=content,
            model=model,
            provider="local_llm",
            tokens_used=tokens,
            latency_ms=latency_ms,
            metadata={
                "finish_reason": choice.get("finish_reason"),
                "model_used": data.get("model", model),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "endpoint": self._chat_url,
            },
            timestamp=datetime.utcnow(),
        )

    # ── Tool-calling loop ─────────────────────────────────────────────────────

    async def generate_with_tools(
        self,
        messages: List[Dict],
        tools: List[Dict],
        tool_executor,           # async callable: (name, args_dict) -> str
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
        max_iterations: int = 5,
    ) -> ModelResponse:
        """Deterministic tool-calling loop (local model)."""
        model = model or self.get_default_model()
        t0 = time.time()
        history = list(messages)

        for _iteration in range(max_iterations):
            payload: Dict[str, Any] = {
                "model": model,
                "messages": history,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": temperature,
            }
            if max_tokens:
                payload["max_tokens"] = max_tokens

            data = await self._post(payload)
            choice = data["choices"][0]
            assistant_msg = choice["message"]
            finish_reason = choice.get("finish_reason")

            history.append(assistant_msg)

            if finish_reason != "tool_calls":
                content = assistant_msg.get("content") or ""
                usage = data.get("usage", {})
                tokens = usage.get("total_tokens", 0)
                self._request_count += 1
                self._total_tokens += tokens
                return ModelResponse(
                    content=content,
                    model=model,
                    provider="local_llm",
                    tokens_used=tokens,
                    latency_ms=(time.time() - t0) * 1000,
                    metadata={
                        "finish_reason": finish_reason,
                        "iterations": _iteration + 1,
                        "tool_calls_made": _iteration,
                    },
                    timestamp=datetime.utcnow(),
                )

            import asyncio
            tool_calls = assistant_msg.get("tool_calls", [])

            async def _exec(tc):
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    args = {}
                try:
                    result = await tool_executor(name, args)
                except Exception as exc:
                    result = f"Tool error: {exc}"
                return {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": str(result),
                }

            tool_results = await asyncio.gather(*[_exec(tc) for tc in tool_calls])
            history.extend(tool_results)

        last = next(
            (m.get("content", "") for m in reversed(history) if m.get("role") == "assistant"),
            "Reached maximum tool-call iterations without a final answer.",
        )
        return ModelResponse(
            content=last,
            model=model,
            provider="local_llm",
            tokens_used=self._total_tokens,
            latency_ms=(time.time() - t0) * 1000,
            metadata={"finish_reason": "max_iterations", "iterations": max_iterations},
            timestamp=datetime.utcnow(),
        )

    # ── Streaming ─────────────────────────────────────────────────────────────

    async def generate_streaming(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        system: Optional[str] = None,
        **kwargs,
    ) -> AsyncIterator[str]:
        """Stream tokens from local /v1/chat/completions with stream=True."""
        model = model or self.get_default_model()
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
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
                    headers=_headers(),
                    json=payload,
                ) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        raise LLMError(f"Local LLM stream HTTP {resp.status_code}: {body[:200]}")
                    async for line in resp.aiter_lines():
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
        except httpx.TimeoutException as e:
            raise LLMError(f"Local LLM stream timed out: {e}")
        except httpx.RequestError as e:
            raise LLMError(f"Local LLM stream error: {e}")
