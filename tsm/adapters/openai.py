"""
OpenAI Adapter
==============
Forwards requests to api.openai.com when OPENAI_API_KEY is set.
Supports chat/completions and completions endpoints.
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

_API_BASE = "https://api.openai.com"


class OpenAIAdapter(BaseAdapter):
    name = "openai"

    def __init__(self) -> None:
        self._key = os.environ.get("OPENAI_API_KEY", "")

    def available(self) -> bool:
        return bool(self._key) and self._key not in ("sk-...", "your-key-here", "not-needed")

    def forward(self, body: Dict[str, Any]) -> AdapterResponse:
        url = f"{_API_BASE}/v1/chat/completions"
        try:
            data = self._post(url, {**body, "stream": False}, {
                "Authorization": f"Bearer {self._key}",
            })
            choice   = data["choices"][0]
            content  = choice["message"]["content"]
            model    = data.get("model", body.get("model", "gpt-3.5-turbo"))
            usage    = data.get("usage", {})
            return AdapterResponse(
                content=content,
                model=model,
                finish_reason=choice.get("finish_reason", "stop"),
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                raw=data,
            )
        except Exception as e:
            return AdapterResponse(
                content=f"[TSM] OpenAI forwarding failed: {e}",
                model=body.get("model", "gpt-3.5-turbo"),
                error=str(e),
            )

    def forward_stream(self, body: Dict[str, Any]) -> Iterator[str]:
        url = f"{_API_BASE}/v1/chat/completions"
        payload = json.dumps({**body, "stream": True}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._key}",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                for line in r:
                    line = line.decode("utf-8").strip()
                    if line.startswith("data: "):
                        yield line[6:]  # strip 'data: ' prefix
        except Exception as e:
            error_chunk = json.dumps({
                "id": "err", "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": f"[TSM] Stream error: {e}"}, "finish_reason": None}],
            })
            yield error_chunk
            yield "[DONE]"
