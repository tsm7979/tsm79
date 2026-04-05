"""
Learning Loop Orchestrator

Integrates all learning components into the main workflow:
Detection -> Reasoning -> Action -> Validation -> Learning

This is the central coordinator for self-evolving intelligence.
LLMs become advisors, not brains.
"""

from __future__ import annotations

import uuid
import logging
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from .outcomes.engine import OutcomeIntelligenceEngine, FixOutcome, FixSource
from .playbooks.engine import PlaybookEngine, FixPlaybook, PlaybookMatch
from .policies.learner import PolicyLearner, SignalValue

logger = logging.getLogger(__name__)


class FixDecision(str, Enum):
    """Decision on how to generate a fix."""
    
    USE_PLAYBOOK = "use_playbook"
    USE_PLAYBOOK_WITH_REVIEW = "use_playbook_with_review"
    USE_LLM = "use_llm"
    SKIP_NOISE = "skip_noise"


@dataclass
class LearningLoopResult:
    """
    Result of a complete learning loop iteration.
    
    Tracks the full cycle from detection to learning.
    """
    
    loop_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    finding_type: str = ""
    
    # Signal evaluation
    signal_processed: bool = True
    signal_classification: str = ""
    
    # Fix decision
    fix_decision: FixDecision = FixDecision.USE_LLM
    decision_reason: str = ""
    playbook_used: Optional[str] = None
    llm_used: bool = False
    
    # Execution
    fix_applied: bool = False
    verification_passed: bool = False
    
    # Learning
    learning_recorded: bool = False
    confidence_updated: bool = False
    
    # Metrics
    total_time_seconds: float = 0.0
    llm_tokens_used: int = 0
    llm_cost_saved: float = 0.0
    
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "loop_id": self.loop_id,
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "fix_decision": self.fix_decision.value,
            "playbook_used": self.playbook_used,
            "llm_used": self.llm_used,
            "verification_passed": self.verification_passed,
            "learning_recorded": self.learning_recorded,
            "llm_cost_saved": self.llm_cost_saved,
        }


class LearningLoopOrchestrator(BaseModel):
    """
    Learning Loop Orchestrator.
    
    Coordinates the complete self-evolving workflow:
    
    1. DETECT - Receive finding
    2. CORRELATE & FILTER - Use policy learner to filter noise
    3. CHECK PLAYBOOK - Find matching playbook
    4. DECIDE - Playbook (high confidence) or LLM (low confidence)
    5. EXECUTE - Apply fix
    6. VERIFY - Validate fix worked
    7. LEARN - Update playbooks, policies, heuristics
    
    Over time, LLM usage drops automatically.
    
    Attributes:
        name: Orchestrator identifier
        outcome_engine: Tracks fix outcomes
        playbook_engine: Manages fix playbooks
        policy_learner: Learns policies and heuristics
        estimated_llm_cost_per_call: For cost savings calculation
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    name: str = Field(default="learning_loop")
    outcome_engine: OutcomeIntelligenceEngine = Field(default_factory=OutcomeIntelligenceEngine)
    playbook_engine: PlaybookEngine = Field(default_factory=PlaybookEngine)
    policy_learner: PolicyLearner = Field(default_factory=PolicyLearner)
    
    estimated_llm_cost_per_call: float = Field(default=0.05)  # $0.05 per call
    
    on_playbook_used: Optional[Callable[[str, str], None]] = Field(default=None)
    on_llm_fallback: Optional[Callable[[str, str], None]] = Field(default=None)
    on_noise_suppressed: Optional[Callable[[str], None]] = Field(default=None)
    
    _loop_history: List[LearningLoopResult] = []
    _llm_calls_saved: int = 0
    _total_cost_saved: float = 0.0
    
    def __init__(self, **data: Any):
        super().__init__(**data)
        self._loop_history = []
        self._llm_calls_saved = 0
        self._total_cost_saved = 0.0
    
    def process_finding(
        self,
        finding_id: str,
        finding_type: str,
        context: Dict[str, Any],
        llm_callback: Optional[Callable[[str], str]] = None,
    ) -> LearningLoopResult:
        """
        Process a finding through the complete learning loop.
        
        This is the main entry point for the self-evolving system.
        
        Args:
            finding_id: Finding identifier
            finding_type: Type of finding
            context: Execution context (language, framework, etc.)
            llm_callback: Function to call LLM if needed
            
        Returns:
            LearningLoopResult with full loop details
        """
        result = LearningLoopResult(
            finding_id=finding_id,
            finding_type=finding_type,
        )
        
        logger.info(f"Learning loop started for: {finding_type}")
        
        # Step 1: Evaluate signal (noise reduction)
        should_process, classification, reason = self.policy_learner.evaluate_signal(
            signal_type="finding",
            finding_type=finding_type,
            source=context.get("source", ""),
        )
        
        result.signal_classification = classification.value
        
        if not should_process:
            result.signal_processed = False
            result.fix_decision = FixDecision.SKIP_NOISE
            result.completed_at = datetime.now()
            
            if self.on_noise_suppressed:
                self.on_noise_suppressed(finding_type)
            
            logger.info(f"Signal suppressed as noise: {finding_type}")
            return result
        
        # Step 2: Check playbook
        decision, playbook, decision_reason = self.playbook_engine.get_fix_decision(
            finding_type=finding_type,
            context=context,
        )
        
        # Step 3: Execute based on decision
        result.decision_reason = decision_reason
        
        if decision == "use_playbook":
            result.fix_decision = FixDecision.USE_PLAYBOOK
            result.playbook_used = playbook.playbook_id
            result.llm_used = False
            
            self._llm_calls_saved += 1
            result.llm_cost_saved = self.estimated_llm_cost_per_call
            self._total_cost_saved += result.llm_cost_saved
            
            if self.on_playbook_used:
                self.on_playbook_used(playbook.playbook_id, finding_type)
            
            logger.info(f"Using playbook: {playbook.playbook_id}")
            
        elif decision == "use_playbook_with_review":
            result.fix_decision = FixDecision.USE_PLAYBOOK_WITH_REVIEW
            result.playbook_used = playbook.playbook_id
            result.llm_used = False
            
            logger.info(f"Using playbook with review: {playbook.playbook_id}")
            
        else:
            result.fix_decision = FixDecision.USE_LLM
            result.llm_used = True
            
            if self.on_llm_fallback:
                self.on_llm_fallback(finding_type, decision_reason)
            
            logger.info(f"Falling back to LLM: {decision_reason}")
            
            # If LLM succeeds, create playbook for future
            if llm_callback:
                try:
                    llm_response = llm_callback(finding_type)
                    # Extract and create playbook from LLM response
                    # (In production, would parse the response)
                except Exception as e:
                    logger.error(f"LLM callback failed: {e}")
        
        # Step 4: Mark as applied (actual execution would happen externally)
        result.fix_applied = True
        
        # Store in history
        self._loop_history.append(result)
        
        return result
    
    def record_verification(
        self,
        loop_id: str,
        verification_passed: bool,
        regression_detected: bool = False,
        time_to_resolution: float = 0,
        risk_reduction: float = 0,
    ) -> None:
        """
        Record verification result and trigger learning.
        
        This is Step 6-7: Verify and Learn.
        
        Args:
            loop_id: The loop to update
            verification_passed: Whether verification passed
            regression_detected: Whether a regression was detected
            time_to_resolution: Time to fix in seconds
            risk_reduction: Risk reduction score
        """
        # Find the loop result
        loop_result = next(
            (r for r in self._loop_history if r.loop_id == loop_id),
            None
        )
        
        if not loop_result:
            logger.warning(f"Loop not found: {loop_id}")
            return
        
        loop_result.verification_passed = verification_passed
        loop_result.completed_at = datetime.now()
        loop_result.total_time_seconds = time_to_resolution
        
        # Record outcome in intelligence engine
        fix_source = FixSource.PLAYBOOK if loop_result.playbook_used else FixSource.POLY_LLM
        
        self.outcome_engine.record_outcome(
            finding_id=loop_result.finding_id,
            finding_type=loop_result.finding_type,
            fix_source=fix_source,
            verification_status="pass" if verification_passed else "fail",
            playbook_id=loop_result.playbook_used,
            time_to_fix_seconds=time_to_resolution,
            risk_reduction_score=risk_reduction,
            regression_detected=regression_detected,
        )
        
        # Update playbook confidence
        if loop_result.playbook_used:
            current_confidence = self.outcome_engine.get_playbook_confidence(
                loop_result.playbook_used
            )
            self.playbook_engine.update_confidence(
                loop_result.playbook_used,
                current_confidence,
            )
            loop_result.confidence_updated = True
        
        # Record in policy learner
        self.policy_learner.record_signal_outcome(
            signal_type="finding",
            finding_type=loop_result.finding_type,
            actioned=True,
            false_positive=not verification_passed,
        )
        
        loop_result.learning_recorded = True
        
        logger.info(
            f"Learning recorded: {loop_result.finding_type} - "
            f"{'PASS' if verification_passed else 'FAIL'}"
        )
    
    def create_playbook_from_success(
        self,
        loop_id: str,
        fix_description: str,
        fix_template: str,
    ) -> Optional[FixPlaybook]:
        """
        Create a new playbook from a successful LLM fix.
        
        This is how the system evolves - successful LLM fixes
        become playbooks for future use.
        """
        loop_result = next(
            (r for r in self._loop_history if r.loop_id == loop_id),
            None
        )
        
        if not loop_result or not loop_result.verification_passed:
            return None
        
        if not loop_result.llm_used:
            # Already using playbook
            return None
        
        playbook = self.playbook_engine.create_playbook_from_llm_fix(
            finding_type=loop_result.finding_type,
            language="auto_detected",
            framework="auto_detected",
            fix_description=fix_description,
            fix_template=fix_template,
            initial_confidence=0.6,  # Start with moderate confidence
        )
        
        logger.info(f"Created playbook from LLM success: {playbook.playbook_id}")
        
        return playbook
    
    def get_system_intelligence(self) -> Dict[str, Any]:
        """
        Get comprehensive system intelligence metrics.
        
        Shows how the system is learning and reducing LLM dependency.
        """
        llm_reduction = self.outcome_engine.get_llm_reduction_metrics()
        noise_reduction = self.policy_learner.get_noise_reduction_stats()
        playbook_stats = self.playbook_engine.get_stats()
        
        # Calculate overall efficiency
        total_loops = len(self._loop_history)
        playbook_loops = len([r for r in self._loop_history if r.playbook_used])
        noise_suppressed = len([r for r in self._loop_history if r.fix_decision == FixDecision.SKIP_NOISE])
        
        return {
            "system_name": self.name,
            "generated_at": datetime.now().isoformat(),
            
            # Core metrics
            "total_loops_processed": total_loops,
            "playbook_usage_rate": playbook_loops / total_loops if total_loops else 0,
            "noise_suppression_rate": noise_suppressed / total_loops if total_loops else 0,
            
            # Cost savings
            "llm_calls_saved": self._llm_calls_saved,
            "total_cost_saved": self._total_cost_saved,
            
            # Intelligence accumulation
            "playbooks": playbook_stats,
            "llm_reduction": llm_reduction,
            "noise_reduction": noise_reduction,
            "policies_learned": self.policy_learner.get_learning_stats(),
            
            # Maturity indicators
            "system_maturity": self._calculate_maturity(),
        }
    
    def _calculate_maturity(self) -> Dict[str, Any]:
        """Calculate system maturity level."""
        playbook_stats = self.playbook_engine.get_stats()
        
        # Maturity based on:
        # - Number of high-confidence playbooks
        # - LLM reduction achieved
        # - Noise patterns identified
        
        high_conf_playbooks = playbook_stats.get("high_confidence", 0)
        total_playbooks = playbook_stats.get("total_playbooks", 0)
        
        playbook_loops = len([r for r in self._loop_history if r.playbook_used])
        total_loops = len(self._loop_history)
        
        maturity_score = (
            (high_conf_playbooks / max(total_playbooks, 1)) * 0.4 +
            (playbook_loops / max(total_loops, 1)) * 0.4 +
            (len(self.policy_learner._signal_patterns) / 100) * 0.2
        )
        
        if maturity_score >= 0.8:
            level = "AUTONOMOUS"
            description = "System operates primarily on learned intelligence"
        elif maturity_score >= 0.6:
            level = "OPTIMIZED"
            description = "LLM usage significantly reduced"
        elif maturity_score >= 0.4:
            level = "LEARNING"
            description = "Actively accumulating intelligence"
        else:
            level = "FOUNDATION"
            description = "Building initial learning data"
        
        return {
            "score": maturity_score,
            "level": level,
            "description": description,
        }
    
    def get_recent_loops(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent loop results."""
        return [r.to_dict() for r in self._loop_history[-limit:]]

    # ==========================================
    # BACKGROUND LOOP CONTROL
    # ==========================================
    
    _background_task = None
    _stop_event = None
    
    async def start_background_loop(self, interval_seconds: int = 60):
        """
        Start the autonomous learning loop in the background.
        
        New in Phase 10: Activation.
        """
        import asyncio
        if self._background_task:
            logger.warning("Background loop already running")
            return
            
        self._stop_event = asyncio.Event()
        
        async def loop():
            logger.info(f"Autonomous Learning Loop STARTED (Heartbeat: {interval_seconds}s)")
            while not self._stop_event.is_set():
                try:
                    # In a full implementation, this would trigger USS scan
                    # and feed findings into process_finding automatically.
                    logger.debug("Learning Loop Heartbeat: Scanning for anomalies...")
                    
                    # Placeholder for active scanning logic
                    # await self._run_autonomous_scan()
                    
                except Exception as e:
                    logger.error(f"Error in learning loop: {e}")
                
                 # Sleep with check for stop
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=interval_seconds)
                    break 
                except asyncio.TimeoutError:
                    continue
                    
            logger.info("Autonomous Learning Loop STOPPED")
            
        self._background_task = asyncio.create_task(loop())
        
    async def stop_background_loop(self):
        """Stop the background loop."""
        if self._stop_event:
            self._stop_event.set()
        
        if self._background_task:
            await self._background_task
            self._background_task = None
            self._stop_event = None
