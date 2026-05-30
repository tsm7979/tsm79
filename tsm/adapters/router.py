"""
Adapter Router
==============
Selects the correct model adapter based on model name and available API keys.

Priority:
  1. Model name prefix determines provider (claude-* → Anthropic, gpt-* → OpenAI, llama/mistral/etc → Ollama)
  2. API key availability in environment confirms the adapter can be used
  3. Falls back to a demo adapter if nothing is available

Usage:
    adapter = get_adapter(model="gpt-4o")
    response = adapter.forward(body)
"""
from __future__ import annotations

import os
from typing import Any, Dict

from tsm.adapters.base import BaseAdapter, AdapterResponse


# ── lazy imports to avoid loading unused adapters ──────────────────────────

def _openai() -> "OpenAIAdapter":
    from tsm.adapters.openai import OpenAIAdapter
    return OpenAIAdapter()

def _anthropic() -> "AnthropicAdapter":
    from tsm.adapters.anthropic import AnthropicAdapter
    return AnthropicAdapter()

def _ollama() -> "OllamaAdapter":
    from tsm.adapters.ollama import OllamaAdapter
    return OllamaAdapter()


# ── model name → provider heuristics ──────────────────────────────────────

_ANTHROPIC_PREFIXES = ("claude",)
_OPENAI_PREFIXES    = ("gpt-", "o1", "o3", "text-davinci", "text-curie", "text-babbage", "text-ada")
_OLLAMA_PREFIXES    = ("llama", "mistral", "mixtral", "phi", "gemma", "qwen", "deepseek", "vicuna", "orca", "neural", "tinyllama")


def _provider_from_model(model: str) -> str:
    m = model.lower()
    for p in _ANTHROPIC_PREFIXES:
        if m.startswith(p):
            return "anthropic"
    for p in _OPENAI_PREFIXES:
        if m.startswith(p):
            return "openai"
    for p in _OLLAMA_PREFIXES:
        if m.startswith(p):
            return "ollama"
    # fallback: check which keys are set
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "demo"


# ── demo / fallback adapter ────────────────────────────────────────────────

class _DemoAdapter(BaseAdapter):
    """Returns a plain-text response when no real adapter is available."""
    name = "demo"

    def available(self) -> bool:
        return True

    def forward(self, body: Dict[str, Any]) -> AdapterResponse:
        model = body.get("model", "demo")
        msgs  = body.get("messages", [])
        last  = next((m["content"] for m in reversed(msgs) if m.get("role") == "user"), "")
        content = (
            f"[TSM Demo] No API key configured. "
            f"Set OPENAI_API_KEY or ANTHROPIC_API_KEY to forward real requests. "
            f"Your message was: '{last[:80]}'"
        )
        return AdapterResponse(content=content, model=model)


# ── public API ─────────────────────────────────────────────────────────────

def get_adapter(model: str = "gpt-3.5-turbo") -> BaseAdapter:
    """
    Return the best adapter for the given model name.

    Selection order:
      1. Parse model name prefix → infer provider
      2. Instantiate that adapter and confirm it's available()
      3. If not available, try other configured adapters
      4. Last resort: DemoAdapter (never fails, explains missing config)
    """
    provider = _provider_from_model(model)

    candidates = {
        "anthropic": _anthropic,
        "openai":    _openai,
        "ollama":    _ollama,
    }

    # try preferred provider first
    if provider in candidates:
        adapter = candidates[provider]()
        if adapter.available():
            return adapter

    # try remaining providers in priority order
    for name, factory in candidates.items():
        if name == provider:
            continue
        try:
            adapter = factory()
            if adapter.available():
                return adapter
        except Exception:
            continue

    return _DemoAdapter()
