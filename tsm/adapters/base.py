"""
TSM Adapter Base
================
Every model provider (OpenAI, Anthropic, Ollama, Azure) implements
this interface. The proxy calls get_adapter() and then adapter.forward().

Zero external dependencies — all HTTP via urllib.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Optional


@dataclass
class AdapterResponse:
    """Unified response from any adapter."""
    content:       str
    model:         str
    finish_reason: str       = "stop"
    prompt_tokens: int       = 0
    completion_tokens: int   = 0
    raw:           Dict      = field(default_factory=dict)
    error:         Optional[str] = None

    def to_openai_dict(self, request_id: str) -> Dict[str, Any]:
        """Return OpenAI-compatible chat.completion response."""
        import time
        return {
            "id":      request_id,
            "object":  "chat.completion",
            "created": int(time.time()),
            "model":   self.model,
            "choices": [{
                "index":         0,
                "message":       {"role": "assistant", "content": self.content},
                "finish_reason": self.finish_reason,
            }],
            "usage": {
                "prompt_tokens":     self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens":      self.prompt_tokens + self.completion_tokens,
            },
        }


class BaseAdapter:
    """Base class for all model adapters."""
    name: str = "base"

    def available(self) -> bool:
        """Return True if this adapter can handle requests right now."""
        raise NotImplementedError

    def forward(self, body: Dict[str, Any]) -> AdapterResponse:
        """Forward a (possibly redacted) request body and return a response."""
        raise NotImplementedError

    def forward_stream(self, body: Dict[str, Any]) -> Iterator[str]:
        """
        Yield raw SSE data lines for streaming requests.
        Each yielded string is the raw JSON for a chunk (without 'data: ' prefix).
        Yield '[DONE]' to signal end of stream.
        """
        # Default: non-streaming fallback, yield as single chunk
        resp = self.forward(body)
        import time, json as _json
        chunk = {
            "id": f"chatcmpl-{int(time.time()*1000)}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": resp.model,
            "choices": [{"index": 0, "delta": {"content": resp.content}, "finish_reason": None}],
        }
        yield _json.dumps(chunk)
        final = {**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        yield _json.dumps(final)
        yield "[DONE]"

    # ── HTTP helpers ──────────────────────────────────────────

    def _post(self, url: str, body: Dict, headers: Dict, timeout: int = 30) -> Dict:
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            **headers,
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {body_text[:200]}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection failed: {e.reason}")
