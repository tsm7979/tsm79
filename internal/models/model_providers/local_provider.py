# backend/src/core/llm/model_providers/local_provider.py
"""
Local model provider — sovereign, zero-cloud inference via the TSM client.

Uses llama-cpp-python in-process with the attached TSM99 1B sovereign model (GGUF).
Falls back to HTTP when the library is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

from src.utils.errors import LLMError
from gateway.base_provider import BaseModelProvider, ModelResponse

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = os.getenv("LOCAL_LLM_MODEL", os.getenv("TSM_DEFAULT_MODEL", "tsm99-1b"))
_DEFAULT_MAX_TOKENS = 2048


class LocalProvider(BaseModelProvider):
    """
    Local model provider — TSM99 1B sovereign model (GGUF) via TSM Inference Client.

    This is the primary orchestrating entity of the platform.
    All agent, planning, security, and governance reasoning runs through here.
    """

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key, **kwargs)
        self._tsm_client = None
        self.model_name = _DEFAULT_MODEL

    def _get_tsm(self):
        if self._tsm_client is None:
            from src.core.llm.tsm_inference import get_tsm_client
            self._tsm_client = get_tsm_client()
        return self._tsm_client

    # ── Availability ───────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """
        Always returns True — local provider is the sovereign fallback.
        Worst case it returns a "no backend" message, which is handled gracefully.
        """
        return True

    def get_default_model(self) -> str:
        return self.model_name

    # ── Single-prompt generation ───────────────────────────────────────────────

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Generate from a raw prompt string (single-turn)."""
        model = model or self.get_default_model()
        start = time.monotonic()

        try:
            tsm = self._get_tsm()
            result = await asyncio.to_thread(
                tsm.generate,
                prompt=prompt,
                model=model,
                max_tokens=max_tokens or _DEFAULT_MAX_TOKENS,
                temperature=temperature,
            )
            latency_ms = (time.monotonic() - start) * 1000
            tokens = result.tokens_generated or len(result.text.split())
            self._request_count += 1
            self._total_tokens += tokens

            return ModelResponse(
                content=result.text,
                model=result.model or model,
                provider="local",
                tokens_used=tokens,
                cost_estimate=0.0,
                latency_ms=latency_ms,
                metadata={"backend": result.backend, "finish_reason": result.finish_reason},
                timestamp=datetime.utcnow(),
            )
        except Exception as exc:
            raise LLMError(f"Local TSM inference failed: {exc}") from exc

    # ── Multi-turn chat generation ─────────────────────────────────────────────

    async def generate_with_messages(
        self,
        messages: List[Dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """
        Multi-turn chat via the native Llama-3 chat_completion API.
        This uses the model's built-in instruct template — no manual prompt engineering.
        """
        model = model or self.get_default_model()
        start = time.monotonic()

        try:
            tsm = self._get_tsm()
            result = await asyncio.to_thread(
                tsm.chat,
                messages=messages,
                model=model,
                max_tokens=max_tokens or _DEFAULT_MAX_TOKENS,
                temperature=temperature,
            )
            latency_ms = (time.monotonic() - start) * 1000
            tokens = result.tokens_generated or len(result.text.split())
            self._request_count += 1
            self._total_tokens += tokens

            return ModelResponse(
                content=result.text,
                model=result.model or model,
                provider="local",
                tokens_used=tokens,
                cost_estimate=0.0,
                latency_ms=latency_ms,
                metadata={"backend": result.backend, "finish_reason": result.finish_reason},
                timestamp=datetime.utcnow(),
            )
        except Exception as exc:
            raise LLMError(f"Local TSM chat failed: {exc}") from exc

    # ── Tool-calling loop (local version) ─────────────────────────────────────

    async def generate_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        tool_executor,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        max_iterations: int = 5,
    ) -> ModelResponse:
        """
        ReAct-style tool-calling loop for local models.
        Since 1B models don't natively support JSON function-calling, we inject
        a structured tool manifest into the system prompt and parse the output.
        """
        import json
        import re

        model = model or self.get_default_model()
        history = list(messages)

        # Build tool manifest for the system prompt
        tool_manifest = "\n".join(
            f"- {t['function']['name']}: {t['function'].get('description', '')}"
            for t in tools
        )
        tool_names = [t["function"]["name"] for t in tools]

        # Inject tool awareness into system context
        tool_system = (
            f"\n\nAvailable tools (call as JSON: {{\"tool\": \"name\", \"args\": {{...}}}}):\n"
            f"{tool_manifest}\n"
            "When you need a tool, respond with only the JSON call. "
            "When you have the final answer, respond normally."
        )

        if history and history[0]["role"] == "system":
            history[0]["content"] += tool_system
        else:
            history.insert(0, {"role": "system", "content": tool_system})

        for _i in range(max_iterations):
            response = await self.generate_with_messages(
                history, model=model, max_tokens=max_tokens or 512, temperature=0.1
            )
            text = response.content.strip()

            # Detect JSON tool call
            json_match = re.search(r'\{[^{}]*"tool"\s*:\s*"([^"]+)"[^{}]*\}', text, re.DOTALL)
            if json_match:
                try:
                    call = json.loads(json_match.group(0))
                    tool_name = call.get("tool", "")
                    if tool_name in tool_names:
                        tool_result = await tool_executor(tool_name, call.get("args", {}))
                        history.append({"role": "assistant", "content": text})
                        history.append({
                            "role": "user",
                            "content": f"Tool result for {tool_name}:\n{tool_result}"
                        })
                        continue
                except (json.JSONDecodeError, Exception):
                    pass

            # No tool call — final answer
            return response

        return await self.generate_with_messages(history, model=model, max_tokens=max_tokens or 512)

    # ── Streaming ─────────────────────────────────────────────────────────────

    async def generate_streaming(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream text chunks from the local model."""
        messages = [{"role": "user", "content": prompt}]
        tsm = self._get_tsm()

        async def _stream():
            for chunk in await asyncio.to_thread(
                lambda: list(tsm.chat_stream(
                    messages=messages,
                    max_tokens=max_tokens or _DEFAULT_MAX_TOKENS,
                    temperature=temperature,
                ))
            ):
                yield chunk

        # Yield synchronously from the collected chunks
        tsm = self._get_tsm()
        try:
            chunks = await asyncio.to_thread(
                lambda: list(tsm.chat_stream(
                    messages=messages,
                    max_tokens=max_tokens or _DEFAULT_MAX_TOKENS,
                    temperature=temperature,
                ))
            )
            for chunk in chunks:
                yield chunk
        except Exception:
            # Fall back to single-shot
            response = await self.generate(prompt, model=model, temperature=temperature, max_tokens=max_tokens)
            yield response.content
