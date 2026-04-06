"""
Anthropic Adapter
=================
Forwards requests to api.anthropic.com when ANTHROPIC_API_KEY is set.
Translates OpenAI chat format → Anthropic Messages API and back.
Zero external dependencies.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Iterator

from tsm.adapters.base import BaseAdapter, AdapterResponse

_API_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MODEL = "claude-haiku-4-5-20251001"


def _map_model(openai_model: str) -> str:
    """Map common OpenAI model names to Anthropic equivalents."""
    table = {
        "gpt-4":            "claude-opus-4-6",
        "gpt-4o":           "claude-sonnet-4-6",
        "gpt-4-turbo":      "claude-sonnet-4-6",
        "gpt-3.5-turbo":    "claude-haiku-4-5-20251001",
        "gpt-3.5":          "claude-haiku-4-5-20251001",
    }
    return table.get(openai_model, openai_model if openai_model.startswith("claude") else _DEFAULT_MODEL)


def _to_anthropic_messages(messages: list) -> tuple[str | None, list]:
    """Split OpenAI message list into (system_prompt, user/assistant turns)."""
    system = None
    turns  = []
    for m in messages:
        role    = m.get("role", "user")
        content = m.get("content", "")
        if role == "system":
            system = content
        else:
            turns.append({"role": role, "content": content})
    return system, turns


class AnthropicAdapter(BaseAdapter):
    name = "anthropic"

    def __init__(self) -> None:
        self._key = os.environ.get("ANTHROPIC_API_KEY", "")

    def available(self) -> bool:
        return bool(self._key) and self._key not in ("sk-ant-...", "your-key-here", "not-needed")

    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key":         self._key,
            "anthropic-version": _ANTHROPIC_VERSION,
        }

    def forward(self, body: Dict[str, Any]) -> AdapterResponse:
        openai_model = body.get("model", _DEFAULT_MODEL)
        model        = _map_model(openai_model)
        messages     = body.get("messages", [])
        system, turns = _to_anthropic_messages(messages)

        payload: Dict[str, Any] = {
            "model":      model,
            "messages":   turns,
            "max_tokens": body.get("max_tokens", 4096),
        }
        if system:
            payload["system"] = system
        if body.get("temperature") is not None:
            payload["temperature"] = body["temperature"]

        url = f"{_API_BASE}/v1/messages"
        try:
            data    = self._post(url, payload, self._headers())
            content = data["content"][0]["text"]
            usage   = data.get("usage", {})
            return AdapterResponse(
                content=content,
                model=data.get("model", model),
                finish_reason=data.get("stop_reason", "stop"),
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                raw=data,
            )
        except Exception as e:
            return AdapterResponse(
                content=f"[TSM] Anthropic forwarding failed: {e}",
                model=model,
                error=str(e),
            )

    def forward_stream(self, body: Dict[str, Any]) -> Iterator[str]:
        openai_model = body.get("model", _DEFAULT_MODEL)
        model        = _map_model(openai_model)
        messages     = body.get("messages", [])
        system, turns = _to_anthropic_messages(messages)

        payload: Dict[str, Any] = {
            "model":      model,
            "messages":   turns,
            "max_tokens": body.get("max_tokens", 4096),
            "stream":     True,
        }
        if system:
            payload["system"] = system

        url     = f"{_API_BASE}/v1/messages"
        data    = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", **self._headers()}
        req     = urllib.request.Request(url, data=data, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                for line in r:
                    line = line.decode("utf-8").strip()
                    if not line.startswith("data:"):
                        continue
                    raw_json = line[5:].strip()
                    if raw_json == "[DONE]":
                        break
                    try:
                        event = json.loads(raw_json)
                    except json.JSONDecodeError:
                        continue

                    etype = event.get("type", "")
                    if etype == "content_block_delta":
                        delta_text = event.get("delta", {}).get("text", "")
                        chunk = json.dumps({
                            "id":      f"chatcmpl-ant-{int(time.time()*1000)}",
                            "object":  "chat.completion.chunk",
                            "created": int(time.time()),
                            "model":   model,
                            "choices": [{"index": 0, "delta": {"content": delta_text}, "finish_reason": None}],
                        })
                        yield chunk
                    elif etype == "message_stop":
                        final = json.dumps({
                            "id":      f"chatcmpl-ant-{int(time.time()*1000)}",
                            "object":  "chat.completion.chunk",
                            "created": int(time.time()),
                            "model":   model,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        })
                        yield final
        except Exception as e:
            yield json.dumps({
                "id": "err", "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": f"[TSM] Anthropic stream error: {e}"}, "finish_reason": None}],
            })
        yield "[DONE]"
