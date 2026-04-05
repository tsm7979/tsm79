"""
Policy & Heuristic Learner

Learns which risks matter, which signals are noise,
and which actions reduce risk fastest.

This reduces:
- Reasoning calls
- Search calls
- Token usage

By learning system-specific patterns over time.
"""

from __future__ import annotations

import uuid
import json
import logging
import statistics
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SignalType(str, Enum):
    """Types of signals for learning."""
    
    FINDING = "finding"
    ALERT = "alert"
    EVENT = "event"
    METRIC = "metric"


class SignalValue(str, Enum):
    """Value classification of a signal."""
    
    HIGH_VALUE = "high_value"      # Take action
    MEDIUM_VALUE = "medium_value"  # Consider action
    LOW_VALUE = "low_value"        # Monitor
    NOISE = "noise"                # Suppress


@dataclass
class SignalPattern:
    """
    A learned pattern about a signal type.
    
    Tracks how valuable/noisy different signals are.
    """
    
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signal_type: str = ""
    finding_type: str = ""
    source: str = ""
    
    # Learning data
    occurrences: int = 0
    actioned: int = 0
    resolved_without_action: int = 0
    false_positives: int = 0
    
    # Derived scores
    action_rate: float = 0.0
    false_positive_rate: float = 0.0
    value_score: float = 0.5
    
    # Classification
    classification: SignalValue = SignalValue.MEDIUM_VALUE
    
    last_seen: datetime = field(default_factory=datetime.now)
    
    def record_occurrence(self, actioned: bool = False, false_positive: bool = False) -> None:
        """Record a signal occurrence."""
        self.occurrences += 1
        if actioned:
            self.actioned += 1
        if false_positive:
            self.false_positives += 1
        
        self.last_seen = datetime.now()
        self._recalculate_scores()
    
    def _recalculate_scores(self) -> None:
        """Recalculate derived scores."""
        if self.occurrences > 0:
            self.action_rate = self.actioned / self.occurrences
            self.false_positive_rate = self.false_positives / self.occurrences
            
            # Value score: high action rate + low FP rate = high value
            self.value_score = self.action_rate * (1 - self.false_positive_rate)
            
            # Classification
            if self.value_score >= 0.7:
                self.classification = SignalValue.HIGH_VALUE
            elif self.value_score >= 0.4:
                self.classification = SignalValue.MEDIUM_VALUE
            elif self.value_score >= 0.1:
                self.classification = SignalValue.LOW_VALUE
            else:
                self.classification = SignalValue.NOISE
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "signal_type": self.signal_type,
            "finding_type": self.finding_type,
            "source": self.source,
            "occurrences": self.occurrences,
            "actioned": self.actioned,
            "false_positive_rate": self.false_positive_rate,
            "value_score": self.value_score,
            "classification": self.classification.value,
        }


@dataclass
class RiskPattern:
    """
    A learned pattern about risk.
    
    Tracks which issues actually cause problems.
    """
    
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: str = ""
    environment: str = ""
    
    # Risk metrics
    total_occurrences: int = 0
    led_to_incident: int = 0
    required_emergency_fix: int = 0
    caused_downtime: int = 0
    
    # Derived
    incident_rate: float = 0.0
    risk_score: float = 0.5
    
    def record_occurrence(
        self,
        led_to_incident: bool = False,
        emergency_fix: bool = False,
        caused_downtime: bool = False,
    ) -> None:
        """Record a risk occurrence."""
        self.total_occurrences += 1
        if led_to_incident:
            self.led_to_incident += 1
        if emergency_fix:
            self.required_emergency_fix += 1
        if caused_downtime:
            self.caused_downtime += 1
        
        self._recalculate_risk()
    
    def _recalculate_risk(self) -> None:
        """Recalculate risk score."""
        if self.total_occurrences > 0:
            self.incident_rate = self.led_to_incident / self.total_occurrences
            
            # Risk = weighted combination of outcomes
            self.risk_score = (
                (self.led_to_incident * 0.4) +
                (self.required_emergency_fix * 0.3) +
                (self.caused_downtime * 0.3)
            ) / self.total_occurrences
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "finding_type": self.finding_type,
            "environment": self.environment,
            "total_occurrences": self.total_occurrences,
            "incident_rate": self.incident_rate,
            "risk_score": self.risk_score,
        }


@dataclass
class ActionEffectiveness:
    """
    Tracks effectiveness of different actions.
    
    Learns which actions reduce risk fastest.
    """
    
    action_type: str = ""
    finding_type: str = ""
    
    # Metrics
    times_used: int = 0
    successful: int = 0
    failed: int = 0
    avg_time_to_resolution: float = 0.0
    avg_risk_reduction: float = 0.0
    
    # Derived
    success_rate: float = 0.0
    effectiveness_score: float = 0.0
    
    _resolution_times: List[float] = field(default_factory=list)
    _risk_reductions: List[float] = field(default_factory=list)
    
    def record_action(
        self,
        successful: bool,
        time_to_resolution: float,
        risk_reduction: float,
    ) -> None:
        """Record an action."""
        self.times_used += 1
        if successful:
            self.successful += 1
        else:
            self.failed += 1
        
        self._resolution_times.append(time_to_resolution)
        self._risk_reductions.append(risk_reduction)
        
        self._recalculate()
    
    def _recalculate(self) -> None:
        """Recalculate effectiveness metrics."""
        if self.times_used > 0:
            self.success_rate = self.successful / self.times_used
            self.avg_time_to_resolution = statistics.mean(self._resolution_times) if self._resolution_times else 0
            self.avg_risk_reduction = statistics.mean(self._risk_reductions) if self._risk_reductions else 0
            
            # Effectiveness = success * risk_reduction / time
            time_factor = 1 / (1 + self.avg_time_to_resolution / 300)  # 5 min baseline
            self.effectiveness_score = self.success_rate * self.avg_risk_reduction * time_factor
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "finding_type": self.finding_type,
            "times_used": self.times_used,
            "success_rate": self.success_rate,
            "avg_time_to_resolution": self.avg_time_to_resolution,
            "avg_risk_reduction": self.avg_risk_reduction,
            "effectiveness_score": self.effectiveness_score,
        }


class PolicyLearner(BaseModel):
    """
    Policy & Heuristic Learner.
    
    Learns:
    - Which risks matter (RiskPatterns)
    - Which signals are noise (SignalPatterns)
    - Which actions reduce risk fastest (ActionEffectiveness)
    
    This directly reduces LLM usage by:
    - Suppressing noise before reasoning
    - Prioritizing by learned risk
    - Selecting proven actions
    
    Attributes:
        name: Learner identifier
        noise_threshold: Value score below which to suppress
        risk_threshold: Risk score for prioritization
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    name: str = Field(default="policy_learner")
    noise_threshold: float = Field(default=0.1)
    risk_threshold: float = Field(default=0.5)
    
    on_noise_suppressed: Optional[Callable[[str], None]] = Field(default=None)
    on_risk_escalated: Optional[Callable[[str], None]] = Field(default=None)
    
    _signal_patterns: Dict[str, SignalPattern] = {}
    _risk_patterns: Dict[str, RiskPattern] = {}
    _action_effectiveness: Dict[str, ActionEffectiveness] = {}
    _suppressed_count: int = 0
    _total_signals: int = 0
    
    def __init__(self, **data: Any):
        super().__init__(**data)
        self._signal_patterns = {}
        self._risk_patterns = {}
        self._action_effectiveness = {}
        self._suppressed_count = 0
        self._total_signals = 0
    
    def evaluate_signal(
        self,
        signal_type: str,
        finding_type: str,
        source: str = "",
    ) -> Tuple[bool, SignalValue, str]:
        """
        Evaluate whether a signal should be processed or suppressed.
        
        Args:
            signal_type: Type of signal
            finding_type: Finding type if applicable
            source: Signal source
            
        Returns:
            Tuple of (should_process, classification, reason)
        """
        key = f"{signal_type}|{finding_type}|{source}"
        self._total_signals += 1
        
        pattern = self._signal_patterns.get(key)
        
        if not pattern:
            # New pattern - process and start learning
            pattern = SignalPattern(
                signal_type=signal_type,
                finding_type=finding_type,
                source=source,
            )
            self._signal_patterns[key] = pattern
            return (True, SignalValue.MEDIUM_VALUE, "new_pattern")
        
        # Check if noise
        if pattern.classification == SignalValue.NOISE:
            self._suppressed_count += 1
            if self.on_noise_suppressed:
                self.on_noise_suppressed(key)
            return (False, SignalValue.NOISE, f"noise_score={pattern.value_score:.2f}")
        
        return (True, pattern.classification, f"value_score={pattern.value_score:.2f}")
    
    def record_signal_outcome(
        self,
        signal_type: str,
        finding_type: str,
        source: str = "",
        actioned: bool = False,
        false_positive: bool = False,
    ) -> None:
        """Record the outcome of a signal for learning."""
        key = f"{signal_type}|{finding_type}|{source}"
        
        if key not in self._signal_patterns:
            self._signal_patterns[key] = SignalPattern(
                signal_type=signal_type,
                finding_type=finding_type,
                source=source,
            )
        
        self._signal_patterns[key].record_occurrence(actioned, false_positive)
    
    def get_risk_priority(
        self,
        finding_type: str,
        environment: str = "production",
    ) -> Tuple[float, str]:
        """
        Get the learned risk priority for a finding type.
        
        Returns:
            Tuple of (risk_score, explanation)
        """
        key = f"{finding_type}|{environment}"
        
        pattern = self._risk_patterns.get(key)
        
        if not pattern:
            # Default priority for unknown patterns
            return (0.5, "no_learning_data")
        
        if pattern.risk_score >= self.risk_threshold:
            if self.on_risk_escalated:
                self.on_risk_escalated(key)
            return (pattern.risk_score, f"high_risk_incident_rate={pattern.incident_rate:.2f}")
        
        return (pattern.risk_score, f"risk_score={pattern.risk_score:.2f}")
    
    def record_risk_outcome(
        self,
        finding_type: str,
        environment: str = "production",
        led_to_incident: bool = False,
        emergency_fix: bool = False,
        caused_downtime: bool = False,
    ) -> None:
        """Record a risk outcome for learning."""
        key = f"{finding_type}|{environment}"
        
        if key not in self._risk_patterns:
            self._risk_patterns[key] = RiskPattern(
                finding_type=finding_type,
                environment=environment,
            )
        
        self._risk_patterns[key].record_occurrence(
            led_to_incident, emergency_fix, caused_downtime
        )
    
    def get_best_action(
        self,
        finding_type: str,
        available_actions: List[str],
    ) -> Tuple[str, float, str]:
        """
        Get the most effective action based on learning.
        
        Args:
            finding_type: Type of finding
            available_actions: List of possible actions
            
        Returns:
            Tuple of (best_action, effectiveness_score, reason)
        """
        best_action = None
        best_score = 0.0
        
        for action in available_actions:
            key = f"{action}|{finding_type}"
            effectiveness = self._action_effectiveness.get(key)
            
            if effectiveness and effectiveness.effectiveness_score > best_score:
                best_score = effectiveness.effectiveness_score
                best_action = action
        
        if best_action:
            return (best_action, best_score, "learned_effectiveness")
        
        # Default to first action if no learning data
        return (available_actions[0] if available_actions else "none", 0.0, "no_learning_data")
    
    def record_action_outcome(
        self,
        action_type: str,
        finding_type: str,
        successful: bool,
        time_to_resolution: float,
        risk_reduction: float,
    ) -> None:
        """Record an action outcome for learning."""
        key = f"{action_type}|{finding_type}"
        
        if key not in self._action_effectiveness:
            self._action_effectiveness[key] = ActionEffectiveness(
                action_type=action_type,
                finding_type=finding_type,
            )
        
        self._action_effectiveness[key].record_action(
            successful, time_to_resolution, risk_reduction
        )
    
    def get_noise_reduction_stats(self) -> Dict[str, Any]:
        """Get statistics on noise reduction."""
        noise_patterns = [
            p for p in self._signal_patterns.values()
            if p.classification == SignalValue.NOISE
        ]
        
        return {
            "total_signals_processed": self._total_signals,
            "signals_suppressed": self._suppressed_count,
            "suppression_rate": self._suppressed_count / self._total_signals if self._total_signals else 0,
            "noise_patterns_identified": len(noise_patterns),
            "total_patterns_learned": len(self._signal_patterns),
        }
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get overall learning statistics."""
        return {
            "signal_patterns": len(self._signal_patterns),
            "risk_patterns": len(self._risk_patterns),
            "action_patterns": len(self._action_effectiveness),
            "noise_reduction": self.get_noise_reduction_stats(),
            "high_risk_patterns": len([
                p for p in self._risk_patterns.values()
                if p.risk_score >= self.risk_threshold
            ]),
        }
    
    def export_policies(self) -> Dict[str, Any]:
        """Export learned policies for backup/analysis."""
        return {
            "name": self.name,
            "exported_at": datetime.now().isoformat(),
            "signal_patterns": [p.to_dict() for p in self._signal_patterns.values()],
            "risk_patterns": [p.to_dict() for p in self._risk_patterns.values()],
            "action_effectiveness": [a.to_dict() for a in self._action_effectiveness.values()],
        }
