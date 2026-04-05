"""
Learning Bridge: Connects Plan Validation outcomes to the Learning System
This closes the feedback loop: Validation → Learning → Future Improvement
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging
import json
from pathlib import Path
from datetime import datetime

from ..verification.plan_validator import PlanValidator, ValidationResult
from .pattern_store import PatternStore

logger = logging.getLogger(__name__)

@dataclass
class ExecutionOutcome:
    """Outcome of a plan execution for learning"""
    plan_id: str
    goal: str
    intent_type: str
    tech_stack: list
    validation_result: ValidationResult
    execution_success: bool
    user_feedback: Optional[str] = None
    execution_time: float = 0.0
    quality_score: float = 0.0  # 0.0 - 1.0
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class LearningBridge:
    """
    BRIDGE BETWEEN PLAN VALIDATION AND LEARNING SYSTEM
    
    Responsibilities:
    1. Store execution outcomes for future retrieval
    2. Connect successful plans to pattern store
    3. Feed user feedback back to RAG for query refinement
    4. Track what worked vs what didn't
    """
    
    def __init__(self, storage_path: str = "data/learning"):
        self.storage_path = Path(storage_path)
        self.pattern_store = PatternStore(str(self.storage_path / "patterns"))
        self.outcomes_file = self.storage_path / "execution_outcomes.jsonl"
        self.outcomes_file.parent.mkdir(parents=True, exist_ok=True)
    
    def record_outcome(
        self,
        plan_id: str,
        context: Dict[str, Any],
        validation_result: ValidationResult,
        execution_success: bool,
        user_feedback: Optional[str] = None,
        quality_score: float = 0.5
    ) -> None:
        """
        Record an execution outcome for learning.
        
        This is called AFTER execution to store what worked.
        """
        outcome = ExecutionOutcome(
            plan_id=plan_id,
            goal=context.get("goal", ""),
            intent_type=context.get("intent_type", ""),
            tech_stack=context.get("tech_stack", []),
            validation_result=validation_result,
            execution_success=execution_success,
            user_feedback=user_feedback,
            quality_score=quality_score
        )
        
        # Persist outcome
        self._persist_outcome(outcome)
        
        # Update pattern store if this was a known pattern
        pattern_id = self._generate_pattern_id(context)
        if execution_success:
            # Successful execution - boost pattern confidence
            if self.pattern_store.get_pattern(pattern_id):
                self.pattern_store.register_outcome(pattern_id, success=True)
            else:
                # Create new pattern from success
                self.pattern_store.create_pattern(
                    pattern_id=pattern_id,
                    signature=f"{context.get('intent_type', '')}:{context.get('goal', '')[:50]}"
                )
                self.pattern_store.register_outcome(pattern_id, success=True)
        else:
            # Failed execution - reduce pattern confidence
            if self.pattern_store.get_pattern(pattern_id):
                self.pattern_store.register_outcome(pattern_id, success=False)
        
        logger.info(f"Recorded outcome for plan {plan_id}: success={execution_success}")
    
    def get_similar_outcomes(
        self, 
        context: Dict[str, Any],
        limit: int = 5
    ) -> list:
        """
        Retrieve similar past outcomes for context.
        
        Used by RAG to enhance future queries with past learnings.
        """
        intent_type = context.get("intent_type", "")
        tech_stack = set(context.get("tech_stack", []))
        
        similar = []
        
        # Read outcomes file
        if self.outcomes_file.exists():
            with open(self.outcomes_file, "r") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        # Simple similarity: same intent type or overlapping tech stack
                        if (data.get("intent_type") == intent_type or 
                            set(data.get("tech_stack", [])) & tech_stack):
                            similar.append(data)
        
        # Sort by quality score and recency
        similar.sort(key=lambda x: (x.get("quality_score", 0), x.get("created_at", "")), reverse=True)
        
        return similar[:limit]
    
    def get_pattern_confidence(self, context: Dict[str, Any]) -> float:
        """
        Get confidence score for this type of task.
        
        Higher confidence = more past successes = less LLM needed.
        """
        pattern_id = self._generate_pattern_id(context)
        pattern = self.pattern_store.get_pattern(pattern_id)
        
        if pattern:
            return pattern.confidence
        return 0.0  # No prior experience
    
    def should_skip_llm(self, context: Dict[str, Any]) -> bool:
        """
        Determine if we can skip LLM based on past learnings.
        
        If we have high-confidence pattern, we can use cached solution.
        """
        confidence = self.get_pattern_confidence(context)
        return confidence >= 0.8  # 80%+ confidence = skip LLM
    
    def _generate_pattern_id(self, context: Dict[str, Any]) -> str:
        """Generate a pattern ID from context"""
        intent = context.get("intent_type", "unknown")
        goal_hash = hash(context.get("goal", "")[:50]) % 10000
        return f"{intent}_{goal_hash}"
    
    def _persist_outcome(self, outcome: ExecutionOutcome) -> None:
        """Persist outcome to file"""
        data = {
            "plan_id": outcome.plan_id,
            "goal": outcome.goal,
            "intent_type": outcome.intent_type,
            "tech_stack": outcome.tech_stack,
            "execution_success": outcome.execution_success,
            "user_feedback": outcome.user_feedback,
            "quality_score": outcome.quality_score,
            "created_at": outcome.created_at.isoformat() if outcome.created_at else None,
            "validation": {
                "valid": outcome.validation_result.valid,
                "confidence": outcome.validation_result.confidence,
                "security_risk": outcome.validation_result.security_risk
            }
        }
        
        with open(self.outcomes_file, "a") as f:
            f.write(json.dumps(data) + "\n")
