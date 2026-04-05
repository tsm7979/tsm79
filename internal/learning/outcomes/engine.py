"""
Outcome Intelligence Engine

Learns from what actually worked. Tracks fix effectiveness,
updates confidence weights, and detects regressions.

This is the core learning component that:
- Never trains external LLMs
- Trains internal system artifacts (playbooks, policies)
- Accumulates operational intelligence over time

The Learning Loop:
Detection -> Reasoning -> Action -> Validation -> Learning (HERE)
"""

from __future__ import annotations

import uuid
import json
import hashlib
import logging
import statistics
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from collections import defaultdict

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class FixSource(str, Enum):
    """Source of the fix."""
    
    PLAYBOOK = "playbook"
    POLY_LLM = "poly_llm"
    HUMAN = "human"
    AUTO_GENERATED = "auto_generated"


class VerificationStatus(str, Enum):
    """Verification result status."""
    
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    PENDING = "pending"


@dataclass
class FixOutcome:
    """
    Records the outcome of a fix attempt.
    
    This is the primary learning data structure.
    Each outcome feeds back into playbook confidence.
    
    Attributes:
        outcome_id: Unique identifier
        finding_id: The finding that was fixed
        finding_type: Type of finding
        playbook_id: Playbook used (if any)
        fix_source: Where the fix came from
        execution_context: Environment details
        verification_result: Whether the fix worked
        metrics: Performance metrics
        regression_detected: Whether fix caused regression
    """
    
    outcome_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    finding_type: str = ""
    playbook_id: Optional[str] = None
    fix_source: FixSource = FixSource.PLAYBOOK
    
    # Context
    execution_context: Dict[str, Any] = field(default_factory=dict)
    
    # Results
    verification_result: Dict[str, Any] = field(default_factory=dict)
    
    # Metrics
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Learning signals
    regression_detected: bool = False
    human_override: bool = False
    
    # Timestamps
    executed_at: datetime = field(default_factory=datetime.now)
    verified_at: Optional[datetime] = None
    
    @property
    def is_success(self) -> bool:
        """Check if this was a successful fix."""
        status = self.verification_result.get("status", "")
        return status == VerificationStatus.PASS.value and not self.regression_detected
    
    @property
    def time_to_fix_seconds(self) -> float:
        """Get time to fix in seconds."""
        return self.metrics.get("time_to_fix_seconds", 0)
    
    @property
    def risk_reduction_score(self) -> float:
        """Get risk reduction score."""
        return self.metrics.get("risk_reduction_score", 0.0)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome_id": self.outcome_id,
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "playbook_id": self.playbook_id,
            "fix_source": self.fix_source.value,
            "execution_context": self.execution_context,
            "verification_result": self.verification_result,
            "metrics": self.metrics,
            "regression_detected": self.regression_detected,
            "human_override": self.human_override,
            "executed_at": self.executed_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ConfidenceUpdate:
    """
    Represents a confidence update event.
    
    Tracks how confidence changed based on outcomes.
    """
    
    playbook_id: str
    previous_confidence: float
    new_confidence: float
    delta: float
    reason: str
    outcome_id: str
    timestamp: datetime = field(default_factory=datetime.now)


class OutcomeStore:
    """
    Persistent store for fix outcomes.
    
    Stores learning data locally for playbook updates.
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = Path(storage_path) if storage_path else None
        self._outcomes: Dict[str, FixOutcome] = {}
        self._by_finding_type: Dict[str, List[str]] = defaultdict(list)
        self._by_playbook: Dict[str, List[str]] = defaultdict(list)
        
        if self.storage_path:
            self._load()
    
    def store(self, outcome: FixOutcome) -> None:
        """Store an outcome."""
        self._outcomes[outcome.outcome_id] = outcome
        self._by_finding_type[outcome.finding_type].append(outcome.outcome_id)
        
        if outcome.playbook_id:
            self._by_playbook[outcome.playbook_id].append(outcome.outcome_id)
        
        if self.storage_path:
            self._persist(outcome)
    
    def get(self, outcome_id: str) -> Optional[FixOutcome]:
        """Get an outcome by ID."""
        return self._outcomes.get(outcome_id)
    
    def get_by_finding_type(self, finding_type: str) -> List[FixOutcome]:
        """Get all outcomes for a finding type."""
        ids = self._by_finding_type.get(finding_type, [])
        return [self._outcomes[id] for id in ids if id in self._outcomes]
    
    def get_by_playbook(self, playbook_id: str) -> List[FixOutcome]:
        """Get all outcomes for a playbook."""
        ids = self._by_playbook.get(playbook_id, [])
        return [self._outcomes[id] for id in ids if id in self._outcomes]
    
    def get_recent(self, limit: int = 100) -> List[FixOutcome]:
        """Get recent outcomes."""
        sorted_outcomes = sorted(
            self._outcomes.values(),
            key=lambda o: o.executed_at,
            reverse=True
        )
        return sorted_outcomes[:limit]
    
    def _persist(self, outcome: FixOutcome) -> None:
        """Persist outcome to disk."""
        if not self.storage_path:
            return
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        file_path = self.storage_path / "outcomes.jsonl"
        
        with open(file_path, "a") as f:
            f.write(outcome.to_json().replace("\n", " ") + "\n")
    
    def _load(self) -> None:
        """Load outcomes from disk."""
        if not self.storage_path:
            return
        
        file_path = self.storage_path / "outcomes.jsonl"
        if not file_path.exists():
            return
        
        try:
            with open(file_path) as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        outcome = FixOutcome(
                            outcome_id=data["outcome_id"],
                            finding_id=data["finding_id"],
                            finding_type=data["finding_type"],
                            playbook_id=data.get("playbook_id"),
                            fix_source=FixSource(data["fix_source"]),
                            execution_context=data.get("execution_context", {}),
                            verification_result=data.get("verification_result", {}),
                            metrics=data.get("metrics", {}),
                            regression_detected=data.get("regression_detected", False),
                            human_override=data.get("human_override", False),
                        )
                        self._outcomes[outcome.outcome_id] = outcome
                        self._by_finding_type[outcome.finding_type].append(outcome.outcome_id)
                        if outcome.playbook_id:
                            self._by_playbook[outcome.playbook_id].append(outcome.outcome_id)
            
            logger.info(f"Loaded {len(self._outcomes)} outcomes from storage")
        except Exception as e:
            logger.error(f"Failed to load outcomes: {e}")


class OutcomeIntelligenceEngine(BaseModel):
    """
    Outcome Intelligence Engine - The Learning Core.
    
    Learns from what actually worked:
    - Tracks fix effectiveness
    - Updates playbook confidence
    - Detects regressions
    - Builds risk pattern models
    
    This replaces LLM calls over time with learned knowledge.
    
    Attributes:
        name: Engine identifier
        storage_path: Path for persistent storage
        reward_on_success: Confidence increase on success
        penalty_on_failure: Confidence decrease on failure
        regression_penalty: Extra penalty for regressions
        min_confidence: Minimum confidence threshold
        max_confidence: Maximum confidence threshold
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    name: str = Field(default="outcome_intelligence")
    storage_path: Optional[str] = Field(default=None)
    
    # Learning parameters
    reward_on_success: float = Field(default=0.02)
    penalty_on_failure: float = Field(default=0.05)
    regression_penalty: float = Field(default=0.10)
    min_confidence: float = Field(default=0.0)
    max_confidence: float = Field(default=1.0)
    
    # Callbacks
    on_confidence_update: Optional[Callable[[ConfidenceUpdate], None]] = Field(default=None)
    on_regression_detected: Optional[Callable[[FixOutcome], None]] = Field(default=None)
    
    # Internal state
    _store: OutcomeStore = None
    _pattern_store: Any = None # PatternStore type hint issue resolving
    _confidence_history: List[ConfidenceUpdate] = []
    _playbook_confidence: Dict[str, float] = {}
    
    def __init__(self, **data: Any):
        super().__init__(**data)
        from learning.pattern_store import PatternStore # Lazy import to avoid circular dep
        self._store = OutcomeStore(self.storage_path)
        self._pattern_store = PatternStore(self.storage_path)
        self._confidence_history = []
        self._playbook_confidence = {}
    
    def _load(self) -> None:
        """Reload outcomes from storage."""
        if self._store:
            self._store._load()
    
    def record_outcome(
        self,
        finding_id: str,
        finding_type: str,
        fix_source: FixSource,
        verification_status: str,
        playbook_id: Optional[str] = None,
        time_to_fix_seconds: float = 0,
        risk_reduction_score: float = 0,
        regression_detected: bool = False,
        execution_context: Optional[Dict[str, Any]] = None,
    ) -> FixOutcome:
        """
        Record a fix outcome and update learning.
        
        This is the main learning entry point. Every fix result
        feeds into the intelligence system.
        
        Args:
            finding_id: The finding that was fixed
            finding_type: Type of finding
            fix_source: Where the fix came from
            verification_status: Pass/fail status
            playbook_id: Playbook used (if any)
            time_to_fix_seconds: Time to fix
            risk_reduction_score: Risk reduction achieved
            regression_detected: Whether regression occurred
            execution_context: Environment context
            
        Returns:
            The recorded FixOutcome
        """
        outcome = FixOutcome(
            finding_id=finding_id,
            finding_type=finding_type,
            playbook_id=playbook_id,
            fix_source=fix_source,
            verification_result={"status": verification_status},
            metrics={
                "time_to_fix_seconds": time_to_fix_seconds,
                "risk_reduction_score": risk_reduction_score,
            },
            regression_detected=regression_detected,
            execution_context=execution_context or {},
            verified_at=datetime.now(),
        )
        
        # Store the outcome
        self._store.store(outcome)

        # Update Pattern Store (Legacy "Playbook" ID is effectively Pattern ID here)
        if playbook_id:
             # Ensure pattern exists or create it
            if not self._pattern_store.get_pattern(playbook_id):
                 self._pattern_store.create_pattern(playbook_id, f"auto_pattern_{playbook_id}")
            self._pattern_store.register_outcome(playbook_id, outcome.is_success)
        
        # Update playbook confidence if applicable
        if playbook_id:
            self._update_confidence(outcome)
        
        # Check for regression
        if regression_detected and self.on_regression_detected:
            self.on_regression_detected(outcome)
        
        logger.info(
            f"Outcome recorded: {finding_type} - "
            f"{'SUCCESS' if outcome.is_success else 'FAILURE'}"
        )
        
        return outcome
    
    def _update_confidence(self, outcome: FixOutcome) -> None:
        """Update playbook confidence based on outcome."""
        if not outcome.playbook_id:
            return
        
        current = self._playbook_confidence.get(outcome.playbook_id, 0.5)
        
        if outcome.is_success:
            delta = self.reward_on_success
            reason = "successful_fix"
        else:
            delta = -self.penalty_on_failure
            reason = "failed_fix"
            
            if outcome.regression_detected:
                delta -= self.regression_penalty
                reason = "regression_detected"
        
        new_confidence = max(
            self.min_confidence,
            min(self.max_confidence, current + delta)
        )
        
        self._playbook_confidence[outcome.playbook_id] = new_confidence
        
        update = ConfidenceUpdate(
            playbook_id=outcome.playbook_id,
            previous_confidence=current,
            new_confidence=new_confidence,
            delta=delta,
            reason=reason,
            outcome_id=outcome.outcome_id,
        )
        
        self._confidence_history.append(update)
        
        if self.on_confidence_update:
            self.on_confidence_update(update)
        
        logger.debug(
            f"Confidence updated: {outcome.playbook_id} "
            f"{current:.3f} -> {new_confidence:.3f} ({reason})"
        )
    
    def get_playbook_confidence(self, playbook_id: str) -> float:
        """Get the current confidence for a playbook."""
        return self._playbook_confidence.get(playbook_id, 0.5)
    
    def set_playbook_confidence(self, playbook_id: str, confidence: float) -> None:
        """Set confidence for a playbook (for initialization)."""
        self._playbook_confidence[playbook_id] = max(
            self.min_confidence,
            min(self.max_confidence, confidence)
        )
    
    def get_effectiveness_stats(self, finding_type: str) -> Dict[str, Any]:
        """
        Get effectiveness statistics for a finding type.
        
        Returns aggregated learning about what works.
        """
        outcomes = self._store.get_by_finding_type(finding_type)
        
        if not outcomes:
            return {
                "finding_type": finding_type,
                "total_fixes": 0,
                "success_rate": 0.0,
                "data_available": False,
            }
        
        successful = [o for o in outcomes if o.is_success]
        playbook_fixes = [o for o in outcomes if o.fix_source == FixSource.PLAYBOOK]
        llm_fixes = [o for o in outcomes if o.fix_source == FixSource.POLY_LLM]
        
        fix_times = [o.time_to_fix_seconds for o in outcomes if o.time_to_fix_seconds > 0]
        
        return {
            "finding_type": finding_type,
            "total_fixes": len(outcomes),
            "successful_fixes": len(successful),
            "success_rate": len(successful) / len(outcomes) if outcomes else 0,
            "playbook_fixes": len(playbook_fixes),
            "llm_fixes": len(llm_fixes),
            "regressions": len([o for o in outcomes if o.regression_detected]),
            "avg_time_to_fix": statistics.mean(fix_times) if fix_times else 0,
            "data_available": True,
        }
    
    def get_playbook_stats(self, playbook_id: str) -> Dict[str, Any]:
        """Get statistics for a specific playbook."""
        outcomes = self._store.get_by_playbook(playbook_id)
        
        if not outcomes:
            return {
                "playbook_id": playbook_id,
                "total_uses": 0,
                "success_rate": 0.0,
                "confidence": self.get_playbook_confidence(playbook_id),
            }
        
        successful = [o for o in outcomes if o.is_success]
        
        return {
            "playbook_id": playbook_id,
            "total_uses": len(outcomes),
            "successful_fixes": len(successful),
            "failed_fixes": len(outcomes) - len(successful),
            "success_rate": len(successful) / len(outcomes),
            "regressions": len([o for o in outcomes if o.regression_detected]),
            "confidence": self.get_playbook_confidence(playbook_id),
            "last_used": max(o.executed_at for o in outcomes).isoformat(),
        }
    
    def get_llm_reduction_metrics(self) -> Dict[str, Any]:
        """
        Calculate LLM usage reduction over time.
        
        Shows how learning reduces dependency on external LLMs.
        """
        all_outcomes = self._store.get_recent(limit=1000)
        
        if not all_outcomes:
            return {"llm_reduction": 0, "data_available": False}
        
        # Split into time periods
        now = datetime.now()
        recent = [o for o in all_outcomes if (now - o.executed_at).days < 30]
        older = [o for o in all_outcomes if (now - o.executed_at).days >= 30]
        
        def llm_ratio(outcomes):
            if not outcomes:
                return 1.0
            llm = len([o for o in outcomes if o.fix_source == FixSource.POLY_LLM])
            return llm / len(outcomes)
        
        recent_ratio = llm_ratio(recent)
        older_ratio = llm_ratio(older)
        
        reduction = (older_ratio - recent_ratio) / older_ratio if older_ratio > 0 else 0
        
        return {
            "total_fixes": len(all_outcomes),
            "recent_llm_ratio": recent_ratio,
            "older_llm_ratio": older_ratio,
            "llm_reduction_percent": reduction * 100,
            "playbook_adoption_rate": 1 - recent_ratio,
            "data_available": True,
        }
    
    def should_use_playbook(
        self,
        playbook_id: str,
        min_confidence: float = 0.7,
    ) -> Tuple[bool, float, str]:
        """
        Decide whether to use a playbook or fall back to LLM.
        
        Args:
            playbook_id: The playbook to evaluate
            min_confidence: Minimum confidence to use playbook
            
        Returns:
            Tuple of (use_playbook, confidence, reason)
        """
        confidence = self.get_playbook_confidence(playbook_id)
        
        if confidence >= min_confidence:
            return (True, confidence, "confidence_sufficient")
        elif confidence >= min_confidence * 0.8:
            return (False, confidence, "confidence_marginal_use_llm")
        else:
            return (False, confidence, "confidence_low_use_llm")
    
    def export_intelligence(self) -> Dict[str, Any]:
        """Export accumulated intelligence for backup/transfer."""
        return {
            "name": self.name,
            "exported_at": datetime.now().isoformat(),
            "playbook_confidence": self._playbook_confidence.copy(),
            "confidence_history_count": len(self._confidence_history),
            "outcome_count": len(self._store._outcomes),
        }
