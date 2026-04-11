"""
TSM LangChain integration — CallbackHandler.

Intercepts every LLM call at the LangChain callback layer.
No changes to chains, agents, or tools required.

Usage:
    from sdk.integrations.langchain import TSMCallbackHandler
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(
        callbacks=[TSMCallbackHandler(org_id="acme", on_block="raise")],
    )

    # The handler scans every prompt before LangChain sends it.
    # Blocked requests raise TSMBlockedError.
    # Redacted requests replace the prompt transparently.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sdk.client import TSMClient
from sdk.protect import TSMBlockedError, TSMResult

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.messages import BaseMessage
    from langchain_core.outputs import LLMResult
    _LANGCHAIN_OK = True
except ImportError:
    _LANGCHAIN_OK = False
    # Stub so the class definition doesn't fail at import time
    class BaseCallbackHandler:  # type: ignore[no-redef]
        pass


class TSMCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that passes every prompt through TSM detection.

    Args:
        org_id:    workspace identifier for multi-tenant installs
        on_block:  "raise" (default) | "skip" — what to do when blocked
        user_role: optional role for policy matching
        url:       detector service URL (default: TSM_DETECTOR_URL env)
    """

    def __init__(
        self,
        org_id:    str = "default",
        on_block:  str = "raise",
        user_role: str | None = None,
        url:       str = "",
    ) -> None:
        if not _LANGCHAIN_OK:
            raise ImportError(
                "langchain-core is not installed. "
                "Run: pip install langchain-core"
            )
        super().__init__()
        self._client    = TSMClient(url=url, org_id=org_id)
        self._on_block  = on_block
        self._user_role = user_role
        self._org_id    = org_id

    def on_chat_model_start(
        self,
        serialized:  dict[str, Any],
        messages:    list[list[BaseMessage]],
        *,
        run_id:      UUID,
        **kwargs:    Any,
    ) -> None:
        """Called before every ChatModel invocation."""
        for batch in messages:
            for i, msg in enumerate(batch):
                text = msg.content if isinstance(msg.content, str) else str(msg.content)
                result = self._client.detect_text(text, user_role=self._user_role)
                tsm    = TSMResult.from_detect(result)

                if tsm.is_blocked:
                    if self._on_block == "raise":
                        raise TSMBlockedError(tsm)
                    # "skip" — silently drop
                    return

                # Replace message content with redacted version.
                # LangChain messages may be immutable (frozen Pydantic models in v0.2+),
                # so we replace the item in the list rather than mutating msg.content.
                if not tsm.is_clean and tsm.redacted_text:
                    try:
                        msg.content = tsm.redacted_text  # type: ignore[assignment]
                    except (AttributeError, TypeError, ValueError):
                        # Immutable message — replace slot in the batch list
                        batch[i] = msg.model_copy(update={"content": tsm.redacted_text})  # type: ignore[attr-defined]

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts:    list[str],
        *,
        run_id:     UUID,
        **kwargs:   Any,
    ) -> None:
        """Called before every LLM (non-chat) invocation."""
        for i, prompt in enumerate(prompts):
            result = self._client.detect_text(prompt, user_role=self._user_role)
            tsm    = TSMResult.from_detect(result)

            if tsm.is_blocked:
                if self._on_block == "raise":
                    raise TSMBlockedError(tsm)
                return

            if not tsm.is_clean and tsm.redacted_text:
                prompts[i] = tsm.redacted_text

    def on_llm_end(self, response: LLMResult, *, run_id: UUID, **kwargs: Any) -> None:
        pass  # no-op — responses not currently scanned (add output scanning here)

    def on_llm_error(self, error: Exception, *, run_id: UUID, **kwargs: Any) -> None:
        pass
