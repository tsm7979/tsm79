"""
Self-Evolving Learning System

Implements the Learning Loop for self-improving autonomous control.
Intelligence accumulates in playbooks, policies, and heuristics - not LLMs.

The 5th Loop: Detection -> Reasoning -> Action -> Validation -> LEARNING

Key Components:
- OutcomeIntelligenceEngine: Learn from what worked
- PlaybookEngine: Replace LLM calls with proven fixes
- PolicyLearner: Learn which risks matter, filter noise
- LearningLoopOrchestrator: Coordinate the complete cycle

Over time, LLM usage drops automatically as the system learns.
"""

from .orchestrator import (
    LearningLoopOrchestrator,
    LearningLoopResult,
    FixDecision,
)
from .outcomes import (
    OutcomeIntelligenceEngine,
    FixOutcome,
    FixSource,
)
from .playbooks import (
    PlaybookEngine,
    FixPlaybook,
    FixStrategy,
    PlaybookMatch,
)
from .policies import (
    PolicyLearner,
    SignalPattern,
    RiskPattern,
    SignalValue,
)

__all__ = [
    # Main orchestrator
    "LearningLoopOrchestrator",
    "LearningLoopResult",
    "FixDecision",
    
    # Outcomes
    "OutcomeIntelligenceEngine",
    "FixOutcome",
    "FixSource",
    
    # Playbooks
    "PlaybookEngine",
    "FixPlaybook",
    "FixStrategy",
    "PlaybookMatch",
    
    # Policies
    "PolicyLearner",
    "SignalPattern",
    "RiskPattern",
    "SignalValue",
]

__version__ = "1.0.0"
