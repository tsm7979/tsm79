"""
Ollama Adapter
==============
Forwards requests to a local Ollama instance (http://localhost:11434).
Falls back gracefully when Ollama is not running.
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

_OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


class OllamaAdapter(BaseAdapter):
    name = "ollama"

    def available(self) -> bool:
        try:
            req = urllib.request.Request(f"{_OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception:
            return False

    def forward(self, body: Dict[str, Any]) -> AdapterResponse:
        model = body.get("model", "llama3")
        messages = body.get("messages", [])
        url = f"{_OLLAMA_BASE}/api/chat"
        try:
            data = self._post(url, {
                "model":    model,
                "messages": messages,
                "stream":   False,
                "options":  body.get("options", {}),
            }, {})
            msg     = data.get("message", {})
            content = msg.get("content", "")
            usage   = data.get("usage", {})
            return AdapterResponse(
                content=content,
                model=data.get("model", model),
                finish_reason=data.get("done_reason", "stop"),
                prompt_tokens=usage.get("prompt_tokens", data.get("prompt_eval_count", 0)),
                completion_tokens=usage.get("completion_tokens", data.get("eval_count", 0)),
                raw=data,
            )
        except Exception as e:
            return AdapterResponse(
                content=f"[TSM] Ollama forwarding failed: {e}",
                model=model,
                error=str(e),
            )

    def forward_stream(self, body: Dict[str, Any]) -> Iterator[str]:
        model    = body.get("model", "llama3")
        messages = body.get("messages", [])
        url      = f"{_OLLAMA_BASE}/api/chat"
        payload  = json.dumps({
            "model":    model,
            "messages": messages,
            "stream":   True,
            "options":  body.get("options", {}),
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                for line in r:
                    line = line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        chunk_data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    content = chunk_data.get("message", {}).get("content", "")
                    done    = chunk_data.get("done", False)
                    sse_chunk = json.dumps({
                        "id":      f"chatcmpl-ollama-{int(time.time()*1000)}",
                        "object":  "chat.completion.chunk",
                        "created": int(time.time()),
                        "model":   model,
                        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": "stop" if done else None}],
                    })
                    yield sse_chunk
                    if done:
                        break
        except Exception as e:
            yield json.dumps({
                "id": "err", "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": f"[TSM] Ollama stream error: {e}"}, "finish_reason": None}],
            })
        yield "[DONE]"
