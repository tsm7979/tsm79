"""TSM Layer Models - REAL execution with poly-LLM orchestrator"""
from typing import Dict, Any
import logging
from router.orchestrator import (
    PolyLLMOrchestrator,
    LLMRequest,
    TaskType,
    LLMProvider
)

logger = logging.getLogger(__name__)

class ModelExecutor:
    """REAL model calls using PolyLLMOrchestrator"""

    def __init__(self):
        # Reuse the orchestrator from router
        from router import orchestrator
        self.orchestrator = orchestrator

    async def call(self, model: str, input_text: str, context: Dict[str, Any] = None) -> str:
        """
        Call a model using the real poly-LLM orchestrator.

        This routes through TSM Runtime which provides:
        - Local-first inference (privacy)
        - Cost tracking
        - Fallback chains
        """
        context = context or {}

        logger.info(f"ModelExecutor.call: model={model}, input_len={len(input_text)}")

        # Map model name to task type (best guess)
        task_type = TaskType.REASONING
        if "code" in model.lower():
            task_type = TaskType.CODE_ANALYSIS
        elif "search" in model.lower():
            task_type = TaskType.SEARCH

        # Create request
        request = LLMRequest(
            task_type=task_type,
            prompt=input_text,
            context=context,
            max_tokens=2000,
            temperature=0.7
        )

        # Execute via orchestrator
        try:
            response = await self.orchestrator.complete(request)

            if response.success:
                logger.info(
                    f"Model call SUCCESS: {response.provider.value}/{response.model} "
                    f"(tokens={response.tokens_used}, cost=${response.cost:.4f})"
                )
                return response.content
            else:
                logger.warning(f"Model call FAILED: {response.error}")
                return f"[ERROR] {response.error}"

        except Exception as e:
            logger.error(f"ModelExecutor exception: {e}")
            return f"[EXCEPTION] {str(e)}"

executor = ModelExecutor()
